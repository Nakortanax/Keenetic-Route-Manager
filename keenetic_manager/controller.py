"""Router operations, separate from Qt. No credentials ever written to disk.

A write is allowed only if the full running-config route set was parsed, fresh
configuration matches the GUI snapshot, and user confirmed the generated CLI.
"""
from __future__ import annotations
from collections import Counter
from datetime import datetime
from pathlib import Path
import ipaddress
import os
import socket
from .core import (Route, parse_running_config, parse_interface_descriptions, can_edit,
                   ordered_edit_commands, save_export)
from .transport import TelnetSession, TransportError


def check_lan_host(host: str) -> str:
    try:
        ip = ipaddress.ip_address(host)
    except ValueError as ex:
        raise ValueError('Укажи IPv4-адрес роутера в локальной сети') from ex
    if ip.version != 4 or not ip.is_private:
        raise ValueError('Telnet разрешён только к частным IPv4-адресам LAN')
    return str(ip)


def route_fingerprint(routes: list[Route]) -> Counter:
    return Counter((r.cidr, r.interface, r.auto, r.metric, r.gateway, r.reject, r.disabled) for r in routes)


def resolve_site(domain: str) -> list[str]:
    from .metadata import normalize_domain
    name = normalize_domain(domain)
    ips = set()
    for item in socket.getaddrinfo(name, None, socket.AF_INET, socket.SOCK_STREAM):
        addr = item[4][0]
        if ipaddress.IPv4Address(addr).is_global:
            ips.add(addr)
    if not ips:
        raise ValueError('DNS не вернул публичных IPv4-адресов')
    return sorted(ips, key=lambda s: int(ipaddress.IPv4Address(s)))


class RouterClient:
    def __init__(self, host: str, port: int, login: str, password: str, journal=None):
        self.host = check_lan_host(host)
        self.port = int(port)
        if not 1 <= self.port <= 65535 or not login or not password:
            raise ValueError('Проверь порт, логин и пароль Keenetic')
        self.login, self.password = login, password
        self.journal = journal

    def _session(self, progress=None):
        return TelnetSession(self.host, self.port, self.login, self.password, progress=progress, journal=self.journal)

    def ping(self, progress=None):
        with self._session(progress) as session:
            return session.command('show version', timeout=40, inactivity=35)

    @staticmethod
    def _read(session):
        config = session.command('show running-config', timeout=900, inactivity=90)
        routes, rejected = parse_running_config(config)
        if not routes and not rejected:
            raise TransportError('В конфигурации нет статических маршрутов; проверь подключение')
        interfaces = parse_interface_descriptions(session.command('show interface', timeout=300, inactivity=90))
        return routes, interfaces, rejected

    def read(self, progress=None):
        with self._session(progress) as session:
            return self._read(session)

    def apply(self, adds: list[Route], removes: list[Route], old: list[Route], progress=None):
        if not old or not adds and not removes:
            raise ValueError('Нет подтверждённых изменений')
        if len(adds)+len(removes) > 1000 or any(not can_edit(r) for r in adds+removes):
            raise ValueError('Изменение неподдерживаемых маршрутов или более 1000 операций запрещено')
        commands = ordered_edit_commands(adds, removes)
        with self._session(progress) as session:
            fresh, interfaces, rejected = self._read(session)
            if rejected:
                raise TransportError(f'Неизвестные строки конфигурации: {len(rejected)}. Запись отменена')
            if route_fingerprint(fresh) != route_fingerprint(old):
                raise TransportError('Маршруты изменились после чтения. Обнови список и повтори операцию')
            for r in removes:
                if r.key not in {x.key for x in fresh}:
                    raise TransportError(f'{r.cidr}: удаляемый маршрут уже отсутствует')
            for r in adds:
                if r.interface not in interfaces:
                    raise TransportError(f'Интерфейс {r.interface} больше не существует на Keenetic')
                if any(x.key == r.key and x.disabled for x in fresh):
                    raise TransportError(f'{r.cidr}: найден отключённый маршрут того же интерфейса')
            root = Path(os.getenv('LOCALAPPDATA', str(Path.home()))) / 'KeeneticRouteManager' / 'backups'
            root.mkdir(parents=True, exist_ok=True)
            backup = root / ('routes-' + datetime.now().strftime('%Y%m%d-%H%M%S-%f') + '.json')
            save_export(backup, fresh, 'json')
            if self.journal:
                self.journal.record('backup', f'Сохранены {len(fresh)} маршрутов перед изменениями: {backup}', status='ok')
            for cmd in commands:
                session.command(cmd, timeout=35)
            actual, ifaces, unknown = self._read(session)
            if unknown:
                raise TransportError(f'После записи {len(unknown)} неопознанных строк; не сохранено. Бэкап: {backup}')
            actual_keys = {r.key for r in actual}
            if not {r.key for r in adds}.issubset(actual_keys):
                raise TransportError(f'Новые маршруты не подтверждены; не сохранено. Бэкап: {backup}')
            if ({r.key for r in removes}-{r.key for r in adds}) & actual_keys:
                raise TransportError(f'Старые маршруты остались; не сохранено. Бэкап: {backup}')
            specs = {(r.cidr,r.interface,r.auto,r.metric,r.disabled) for r in actual}
            if not {(r.cidr,r.interface,r.auto,r.metric,r.disabled) for r in adds}.issubset(specs):
                raise TransportError(f'Параметры маршрутов не совпали; не сохранено. Бэкап: {backup}')
            session.command('system configuration save', timeout=45)
            if self.journal:
                self.journal.record('router', f'Изменения подтверждены повторным чтением: добавлено {len(adds)}, удалено {len(removes)}. Сохранено.', status='ok')
        return actual, ifaces, backup
