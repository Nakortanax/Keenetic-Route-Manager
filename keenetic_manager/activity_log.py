"""Privacy-aware, rotating *local* event history for Keenetic operations.

The CLI response to 'show running-config' is intentionally reduced to route
statements. Authentication dialogue and key-bearing interface fields never
reach the journal. This is a diagnostic log, NOT a router configuration backup.
"""
from __future__ import annotations

from collections import deque
from datetime import datetime
import json
import os
from pathlib import Path
import re
import threading

SECRET = re.compile(
    r"(?i)(?:private[-_ ]?key|preshared[-_ ]?key|public[-_ ]?key|password|passwd|"
    r"authorization|auth[-_ ]?token|access[-_ ]?token|secret|api[-_ ]?key|"
    r"ssh-rsa|ssh-ed25519|-----BEGIN|-----END)"
)
INLINE = re.compile(r"(?i)\b(password|token|secret|key)\s*[:=]\s*\S+")
ROUTE = re.compile(r"^\s*ip route(?:\s|$)", re.I)
SAFE_INTERFACE = re.compile(
    r"^\s*(?:Interface, name|id|interface-name|description|type|link|connected|state|status)\s*[:=]", re.I
)


def redact(text: str) -> str:
    """Remove entire sensitive lines rather than risk partial key exposure."""
    cleaned = []
    for line in str(text).splitlines():
        if SECRET.search(line):
            cleaned.append('[СКРЫТО: конфиденциальные данные]')
        else:
            cleaned.append(INLINE.sub(r'\1=[СКРЫТО]', line))
    return '\n'.join(cleaned)


def safe_response(command: str, reply: str) -> str:
    """Store useful CLI replies, never an unfiltered router configuration."""
    lines = reply.splitlines()
    command = command.strip().lower()
    if command == 'show running-config':
        allowed = [line for line in lines if ROUTE.match(line)]
        return f'Маршрутных строк: {len(allowed)}; прочих строк скрыто: {len(lines) - len(allowed)}\n' + redact('\n'.join(allowed))
    if command == 'show interface':
        allowed = [line for line in lines if SAFE_INTERFACE.match(line)]
        return f'Строк интерфейсов: {len(allowed)}; остальные строки скрыты\n' + redact('\n'.join(allowed))
    return redact(reply)


class ActivityJournal:
    def __init__(self, directory: Path | None = None, *, max_bytes: int = 5_000_000, backups: int = 4):
        root = Path(os.getenv('LOCALAPPDATA') or Path.home()) / 'KeeneticRouteManager' / 'logs'
        self.directory = Path(directory) if directory is not None else root
        self.directory.mkdir(parents=True, exist_ok=True)
        self.path = self.directory / 'activity.jsonl'
        self.max_bytes = max_bytes
        self.backups = backups
        self._lock = threading.RLock()

    def record(self, kind: str, message: str, *, command: str = '', response: str = '', status: str = 'info') -> None:
        item = {
            'time': datetime.now().astimezone().isoformat(timespec='seconds'),
            'type': str(kind), 'status': str(status), 'message': redact(str(message)),
        }
        if command:
            item['command'] = redact(command)
            if response:
                item['response'] = safe_response(command, response)
        elif response:
            item['response'] = redact(response)
        data = json.dumps(item, ensure_ascii=False) + '\n'
        with self._lock:
            if self.path.exists() and self.path.stat().st_size + len(data.encode('utf-8')) > self.max_bytes:
                self._rotate()
            with self.path.open('a', encoding='utf-8', newline='\n') as out:
                out.write(data)

    def _rotate(self):
        oldest = self.directory / f'activity.{self.backups}.jsonl'
        if oldest.exists():
            oldest.unlink()
        for i in range(self.backups - 1, 0, -1):
            p = self.directory / f'activity.{i}.jsonl'
            if p.exists():
                p.replace(self.directory / f'activity.{i+1}.jsonl')
        if self.path.exists():
            self.path.replace(self.directory / 'activity.1.jsonl')

    def recent(self, count: int = 90) -> list[dict]:
        if not self.path.exists():
            return []
        with self._lock:
            with self.path.open('rb') as fh:
                # Avoid reading hundreds of MB into the UI if settings are changed.
                fh.seek(0, 2)
                size = fh.tell()
                fh.seek(max(0, size - 1_000_000))
                data = fh.read().decode('utf-8', errors='replace')
        lines = data.splitlines()
        if size > 1_000_000:
            lines = lines[1:]
        records = []
        for line in deque(lines, maxlen=count):
            try:
                value = json.loads(line)
                if isinstance(value, dict):
                    records.append(value)
            except json.JSONDecodeError:
                pass
        return records

    def export_plain(self, path: Path) -> int:
        """Export all available rotated events chronologically, with redaction."""
        count = 0
        with self._lock:
            files = [self.directory / f'activity.{i}.jsonl' for i in range(self.backups, 0, -1)] + [self.path]
            with Path(path).open('w', encoding='utf-8') as out:
                for file in files:
                    if not file.exists():
                        continue
                    with file.open('r', encoding='utf-8') as inp:
                        for raw in inp:
                            try:
                                event = json.loads(raw)
                            except json.JSONDecodeError:
                                continue
                            pieces = [f"[{event.get('time', '')}] {event.get('type', '')} / {event.get('status', '')}: {event.get('message', '')}"]
                            if event.get('command'):
                                pieces.append('> ' + event['command'])
                            if event.get('response'):
                                pieces.append('< ' + event['response'])
                            out.write(redact('\n'.join(pieces)) + '\n\n')
                            count += 1
        return count

    def render(self, count: int = 90, *, response_limit: int = 2400) -> str:
        lines = []
        for r in self.recent(count):
            prefix = f"[{r.get('time', '')}] {r.get('type', '')} / {r.get('status', '')}"
            lines.append(prefix + ' — ' + r.get('message', ''))
            if r.get('command'):
                lines.append('  > ' + r['command'])
            if r.get('response'):
                value = r['response']
                if len(value) > response_limit:
                    value = value[:response_limit] + f'\n  … ещё {len(r["response"]) - response_limit} символов в локальном журнале'
                lines.append('  < ' + value.replace('\n', '\n    '))
        return '\n'.join(lines) if lines else 'Записей пока нет.'
