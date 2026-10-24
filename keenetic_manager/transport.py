"""Minimal RFC854 Telnet transport for a LAN-only Keenetic CLI.

Credentials and unfiltered running-config stay in process memory. Responses to
large commands are read incrementally with inactivity *and* hard deadlines.
"""
from __future__ import annotations
import re
import socket
import time
from typing import Callable

IAC, DONT, DO, WONT, WILL, SB, SE = 255, 254, 253, 252, 251, 250, 240
PROMPT = re.compile(rb"(?:^|[\r\n])\s*\([a-z][a-z0-9/_ -]*\)>\s*$", re.I)
LOGIN = re.compile(rb"(?:login|username)\s*:\s*$", re.I)
PASSWORD = re.compile(rb"password\s*:\s*$", re.I)
# Several Keenetic builds/terminal configurations have different pager prompts.
MORE = re.compile(rb"(?:--\s*More\s*--|\[\s*More\s*\]|Press (?:space|any key)(?: to continue)?)", re.I)
FAIL = re.compile(r"(?im)^.*(?:\berror\b|invalid command|authentication failed|access denied|permission denied|unknown command).*$")
ANSI_ESCAPE = re.compile(rb"\x1b(?:\[[0-?]*[ -/]*[@-~]|\][^\x07]*(?:\x07|\x1b\\))")

class TransportError(RuntimeError):
    pass

class TelnetSession:
    def __init__(self, host: str, port: int, login: str, password: str, timeout: float = 65,
                 progress: Callable[[str], None] | None = None, journal=None):
        self.host, self.port = host, port
        self.login, self.password = login, password
        self.timeout = timeout
        self.progress = progress
        self.journal = journal
        self.sock: socket.socket | None = None
        self._state = 0
        self._iac_cmd = 0

    def __enter__(self):
        if not self.host or not self.login or not self.password:
            raise TransportError("Укажи IP, логин и пароль Keenetic")
        try:
            self.sock = socket.create_connection((self.host, self.port), timeout=8)
            self.sock.settimeout(0.5)
            if self.journal:
                self.journal.record('telnet', f'Подключение к {self.host}:{self.port}', status='start')
            self._login()
            if self.journal:
                self.journal.record('telnet', 'Авторизация подтверждена (пароль не записывается)', status='ok')
        except Exception as exc:
            if self.journal:
                self.journal.record('telnet', f'Не удалось открыть сессию: {type(exc).__name__}: {exc}', status='error')
            self.__exit__(None, None, None)
            raise
        return self

    def __exit__(self, *args):
        if self.sock:
            try:
                self.sock.close()
            except OSError:
                pass
        self.sock = None

    def _decode_telnet(self, chunk: bytes) -> bytes:
        result = bytearray()
        for byte in chunk:
            if self._state == 0:
                if byte == IAC:
                    self._state = 1
                else:
                    result.append(byte)
            elif self._state == 1:
                if byte == IAC:
                    result.append(IAC); self._state = 0
                elif byte in (DO, DONT, WILL, WONT):
                    self._iac_cmd = byte; self._state = 2
                elif byte == SB:
                    self._state = 3
                else:
                    self._state = 0
            elif self._state == 2:
                # Refuse optional capabilities; CLI uses textual prompts only.
                if self._iac_cmd in (DO, WILL) and self.sock:
                    self.sock.sendall(bytes([IAC, WONT if self._iac_cmd == DO else DONT, byte]))
                self._state = 0
            elif self._state == 3:
                if byte == IAC:
                    self._state = 4
            elif self._state == 4:
                self._state = 0 if byte == SE else 3
        return bytes(result)

    def _read_until(self, conditions: list[re.Pattern], timeout: float | None = None,
                    *, limit: int = 24_000_000, inactivity: float | None = None,
                    context: str = "CLI") -> tuple[str, int]:
        """Read until CLI prompt, without truncating multi-thousand-route output.

        timeout is a hard *total* deadline; inactivity is separately enforced.
        A slow but continuously streaming configuration won't be treated as idle.
        """
        total = self.timeout if timeout is None else timeout
        quiet_limit = min(total, 90) if inactivity is None else inactivity
        start = last_activity = time.monotonic()
        chunks = bytearray()
        last_report = start
        while True:
            now = time.monotonic()
            if now - start >= total or now - last_activity >= quiet_limit:
                detail = "нет ответа" if not chunks else f"получено {len(chunks):,} байт"
                raise TransportError(
                    f"Тайм-аут {context}: {detail} за {int(now - start)} с. "
                    "Связь/полный ответ не подтверждены, изменения не подтверждены."
                )
            try:
                data = self.sock.recv(65536) if self.sock else b""
                if not data:
                    raise TransportError("Роутер закрыл Telnet-соединение")
            except socket.timeout:
                continue
            except OSError as ex:
                raise TransportError(f"Ошибка TCP: {ex}") from ex
            clean = self._decode_telnet(data)
            if not clean:
                continue
            chunks.extend(clean)
            last_activity = time.monotonic()
            if len(chunks) > limit:
                raise TransportError(f"Ответ {context} превысил безопасный лимит {limit//1000000} МБ")
            # Repeated page prompts can be split across TCP fragments.
            tail = bytes(chunks[-512:])
            match = MORE.search(tail)
            if match:
                start_index = len(chunks) - len(tail) + match.start()
                end_index = len(chunks) - len(tail) + match.end()
                del chunks[start_index:end_index]
                if self.sock:
                    self.sock.sendall(b" ")
            # Do not copy/re-scan the full accumulated configuration on each recv.
            end = ANSI_ESCAPE.sub(b"", bytes(chunks[-512:])).strip()
            for idx, cond in enumerate(conditions):
                if cond.search(end):
                    return chunks.decode("utf-8", errors="replace").replace("\x00", ""), idx
            if self.progress and last_activity - last_report >= 1.5:
                # Only aggregate progress: never leak config contents or keys.
                try:
                    self.progress(f"{context}: получено {len(chunks)//1024} КБ, "
                                  f"прошло {int(last_activity - start)} с")
                except Exception:
                    pass
                last_report = last_activity

    def _send(self, value: str) -> None:
        if self.sock:
            self.sock.sendall(value.encode("utf-8") + b"\r\n")

    def _login(self):
        greeting, match = self._read_until([PROMPT, LOGIN, PASSWORD], timeout=25,
                                           inactivity=25, context="авторизация")
        if match == 0:
            return
        if match == 1:
            self._send(self.login)
            greeting, match = self._read_until([PROMPT, PASSWORD], timeout=25,
                                               inactivity=25, context="ожидание пароля")
            if match == 0:
                return
        self._send(self.password)
        reply, status = self._read_until([PROMPT, LOGIN, PASSWORD], timeout=25,
                                         inactivity=25, context="вход")
        if status != 0:
            raise TransportError("Авторизация не удалась; проверь логин и пароль")

    def command(self, command: str, *, timeout: float | None = None,
                inactivity: float | None = None) -> str:
        if not re.fullmatch(r"[a-zA-Z0-9 /._\-]+", command):
            raise TransportError("Команда содержит недопустимые символы")
        if self.journal:
            self.journal.record('telnet-command', 'Отправлена команда', command=command, status='start')
        try:
            self._send(command)
            reply, _ = self._read_until([PROMPT], timeout=timeout, inactivity=inactivity,
                                        context=command)
            failed = not command.startswith('show ') and FAIL.search(reply)
            if self.journal:
                self.journal.record('telnet-reply', 'Ответ Keenetic' if not failed else 'Ошибка Keenetic',
                                    command=command, response=reply,
                                    status='error' if failed else 'ok')
            if failed:
                raise TransportError('Keenetic сообщил об ошибке: ' + failed.group(0)[:250])
            return reply
        except Exception as exc:
            if self.journal and not (isinstance(exc, TransportError) and str(exc).startswith('Keenetic сообщил')):
                self.journal.record('telnet-error', f'{type(exc).__name__}: {exc}', command=command, status='error')
            raise
