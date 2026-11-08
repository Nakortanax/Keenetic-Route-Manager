"""KeeneticOS 5.0/5.2 FQDN object groups and policy-aware DNS routes.

Never interpolates unvalidated values into CLI; only changes explicitly chosen
FQDN groups/rules. Other route tables and policy settings remain untouched.
"""
from __future__ import annotations

import ipaddress
import json
import os
import re
from dataclasses import dataclass, replace
from datetime import datetime
from pathlib import Path

from .controller import RouterClient
from .core import parse_interface_descriptions
from .transport import TransportError

NAME = re.compile(r"[A-Za-z][A-Za-z0-9_-]{0,63}\Z")
DOMAIN = re.compile(r"(?=.{1,253}\Z)[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+\Z")
GLOBAL = "GLOBAL"


@dataclass(frozen=True)
class DnsGroup:
    name: str
    includes: tuple[str, ...] = ()
    excludes: tuple[str, ...] = ()
    description: str = ""


@dataclass(frozen=True)
class DnsRule:
    scope: str
    group: str
    interface: str
    auto: bool = False
    reject: bool = False


@dataclass(frozen=True)
class DnsSnapshot:
    groups: tuple[DnsGroup, ...]
    rules: tuple[DnsRule, ...]
    policies: tuple[str, ...]
    errors: tuple[str, ...] = ()

    def group(self, name):
        return next((g for g in self.groups if g.name == name), None)


@dataclass(frozen=True)
class DnsOp:
    commands: tuple[str, ...]
    inverse: tuple[str, ...]


@dataclass(frozen=True)
class DnsPlan:
    label: str
    ops: tuple[DnsOp, ...]
    expected: DnsSnapshot
    interface: str = ""

    def preview(self):
        return "\n".join(cmd for op in self.ops for cmd in op.commands)


def _route(scope, tokens, errors, line):
    # route object-group GROUP INTERFACE [auto] [reject]
    if len(tokens) < 4 or tokens[:2] != ["route", "object-group"]:
        errors.append(f"Неизвестный DNS-маршрут: {line[:140]}")
        return None
    group, interface = tokens[2:4]
    flags = tokens[4:]
    if not NAME.fullmatch(group) or not NAME.fullmatch(interface) or any(x not in {"auto", "reject"} for x in flags) or len(set(flags)) != len(flags):
        errors.append(f"Не поддерживается DNS-маршрут (шлюз/опции): {line[:140]}")
        return None
    return DnsRule(scope, group, interface, "auto" in flags, "reject" in flags)


def parse_dns_config(config: str) -> DnsSnapshot:
    groups = {}
    rules = []
    policies = set()
    errors = []
    context = None
    for raw in config.splitlines():
        line = raw.strip()
        if not line:
            continue
        if line == "!":
            context = None
            continue
        if not raw[:1].isspace():
            context = None
            if line.startswith("object-group fqdn "):
                parts = line.split()
                if len(parts) == 3 and NAME.fullmatch(parts[2]):
                    name = parts[2]
                    if name in groups:
                        errors.append("Повторно определена группа: " + name)
                    else:
                        groups[name] = DnsGroup(name)
                    context = ("group", name)
                elif len(parts) == 5 and parts[3] in ("include", "exclude"):
                    name = parts[2]
                    if name not in groups:
                        groups[name] = DnsGroup(name)
                    key = "includes" if parts[3] == "include" else "excludes"
                    group = groups[name]
                    groups[name] = replace(group, **{key: getattr(group, key) + (parts[4],)})
                else:
                    errors.append("Неизвестное определение FQDN-группы: " + line[:140])
            elif line.startswith("ip policy "):
                parts = line.split()
                if len(parts) >= 3 and NAME.fullmatch(parts[2]):
                    policies.add(parts[2])
                    if len(parts) == 3:
                        context = ("policy", parts[2])
                    elif parts[3:5] == ["dns-proxy", "route"]:
                        rule = _route(parts[2], parts[4:], errors, line)
                        if rule:
                            rules.append(rule)
                else:
                    errors.append("Неизвестное имя политики: " + line[:140])
            elif line == "dns-proxy":
                context = ("global", GLOBAL)
            elif line.startswith("dns-proxy route object-group "):
                rule = _route(GLOBAL, line.split()[1:], errors, line)
                if rule:
                    rules.append(rule)
            continue
        if context is None:
            continue
        kind, name = context
        if kind == "group":
            group = groups[name]
            if line.startswith("include ") or line.startswith("exclude "):
                key = "includes" if line.startswith("include ") else "excludes"
                value = line.split(None, 1)[1]
                groups[name] = replace(group, **{key: getattr(group, key) + (value,)})
            elif line.startswith("description "):
                groups[name] = replace(group, description=line[len("description "):])
            else:
                errors.append(f"Нераспознанная строка группы {name}: {line[:120]}")
        elif kind == "policy" and line.startswith("dns-proxy route "):
            rule = _route(name, line.split()[1:], errors, line)
            if rule:
                rules.append(rule)
        elif kind == "global" and line.startswith("route object-group "):
            rule = _route(GLOBAL, line.split(), errors, line)
            if rule:
                rules.append(rule)
    if any(r.group not in groups for r in rules):
        errors.append("DNS-маршрут ссылается на отсутствующую FQDN-группу")
    return DnsSnapshot(tuple(sorted(groups.values(), key=lambda g: g.name)), tuple(rules), tuple(sorted(policies)), tuple(errors))


def _validate_name(name):
    if not NAME.fullmatch(name):
        raise ValueError("Имя группы/интерфейса: латинские буквы, цифры, '-' или '_'; первая — буква")
    return name


def parse_entries(text: str) -> tuple[str, ...]:
    entries = []
    for raw in text.splitlines():
        raw = raw.strip()
        if not raw:
            continue
        if any(x in raw for x in ("*", ";", "#", " ", "\t")):
            raise ValueError(f"Недопустимый адрес в списке: {raw[:100]}")
        if ":" in raw:
            raise ValueError("IPv6 пока доступен только для просмотра; через Telnet-команды приложения не поддерживается")
        if "/" in raw or re.fullmatch(r"\d+(?:\.\d+){3}", raw):
            try:
                ip = ipaddress.ip_network(raw, strict=False)
            except ValueError as exc:
                raise ValueError(f"Неверная IP-сеть: {raw}") from exc
            if ip.version != 4:
                raise ValueError("Поддерживаются только IPv4-подсети и домены")
            normalized = str(ip) if "/" in raw else str(ip.network_address)
        else:
            try:
                normalized = raw.encode("idna").decode("ascii").lower().rstrip(".")
            except UnicodeError as exc:
                raise ValueError(f"Некорректный домен: {raw}") from exc
            if not DOMAIN.fullmatch(normalized):
                raise ValueError(f"Некорректный домен: {raw}")
        if normalized not in entries:
            entries.append(normalized)
        if len(entries) > 1000:
            raise ValueError("Не более 1000 записей в одном списке")
    return tuple(entries)


def _safe(snapshot):
    if snapshot.errors:
        raise ValueError("Есть нераспознанные DNS-настройки. Запись заблокирована: " + "; ".join(snapshot.errors[:3]))


def _entry_op(name, kind, item, remove=False):
    cmd = f"object-group fqdn {name} {kind} {item}"
    submenu = (f"object-group fqdn {name}", f"no {kind} {item}", "exit")
    return DnsOp(submenu, (cmd,)) if remove else DnsOp((cmd,), submenu)


def plan_group(snapshot: DnsSnapshot, name: str, includes: str, excludes: str = "") -> DnsPlan:
    _safe(snapshot)
    _validate_name(name)
    new_inc, new_exc = parse_entries(includes), parse_entries(excludes)
    if not new_inc:
        raise ValueError("Группа должна содержать хотя бы один домен или IPv4-адрес")
    old = snapshot.group(name)
    ops = []
    if old is None:
        ops.append(DnsOp((f"object-group fqdn {name}", "exit"), (f"no object-group fqdn {name}",)))
        old = DnsGroup(name)
    # Keep pre-existing order; append newly included domains after retained ones.
    for kind, before, after in (("include", old.includes, new_inc), ("exclude", old.excludes, new_exc)):
        if len(set(before)) != len(before):
            raise ValueError(f"В {name} найдены повторяющиеся {kind}. Исправь группу в Keenetic вручную")
        for entry in before:
            if entry not in after:
                ops.append(_entry_op(name, kind, entry, remove=True))
        for entry in after:
            if entry not in before:
                ops.append(_entry_op(name, kind, entry))
    if not ops:
        return DnsPlan("Список не изменён", (), snapshot)
    inc = tuple(x for x in old.includes if x in new_inc) + tuple(x for x in new_inc if x not in old.includes)
    exc = tuple(x for x in old.excludes if x in new_exc) + tuple(x for x in new_exc if x not in old.excludes)
    groups = tuple(sorted((g for g in snapshot.groups if g.name != name), key=lambda g: g.name)) + (replace(old, includes=inc, excludes=exc),)
    expected = replace(snapshot, groups=tuple(sorted(groups, key=lambda g: g.name)))
    return DnsPlan(f"Изменение FQDN-группы {name}", tuple(ops), expected)


def _rule_command(rule: DnsRule, remove=False):
    prefix = "dns-proxy" if rule.scope == GLOBAL else f"ip policy {rule.scope} dns-proxy"
    cmd = f"{prefix} route object-group {rule.group} {rule.interface}"
    if remove:
        return "no " + cmd
    return cmd + (" auto" if rule.auto else "") + (" reject" if rule.reject else "")


def plan_rule(snapshot: DnsSnapshot, group: str, scope: str, interface: str = "", auto=True, reject=True, remove=False) -> DnsPlan:
    _safe(snapshot)
    if not snapshot.group(group):
        raise ValueError("Сначала создай группу и сохрани список адресов")
    if scope != GLOBAL and scope not in snapshot.policies:
        raise ValueError("Выбранная политика не обнаружена на Keenetic")
    current = [r for r in snapshot.rules if r.scope == scope and r.group == group]
    if len(current) > 1:
        raise ValueError("Для группы найдено несколько правил в одной политике; ручная проверка обязательна")
    old = current[0] if current else None
    ops = []
    next_rules = tuple(r for r in snapshot.rules if r != old) if old else snapshot.rules
    if old:
        ops.append(DnsOp((_rule_command(old, True),), (_rule_command(old),)))
    if not remove:
        _validate_name(interface)
        new = DnsRule(scope, group, interface, bool(auto), bool(reject))
        if old == new:
            return DnsPlan("Правило уже настроено", (), snapshot, interface)
        ops.append(DnsOp((_rule_command(new),), (_rule_command(new, True),)))
        next_rules += (new,)
    if not ops:
        return DnsPlan("Правило отсутствует", (), snapshot)
    return DnsPlan("Удаление DNS-правила" if remove else "Настройка DNS-правила", tuple(ops), replace(snapshot, rules=next_rules), "" if remove else interface)


class DnsClient(RouterClient):
    @staticmethod
    def _read_dns(session):
        config = session.command("show running-config", timeout=900, inactivity=90)
        snapshot = parse_dns_config(config)
        interfaces = parse_interface_descriptions(session.command("show interface", timeout=300, inactivity=90))
        return snapshot, interfaces

    def read_dns(self, progress=None):
        with self._session(progress) as session:
            return self._read_dns(session)

    def apply_dns(self, old: DnsSnapshot, plan: DnsPlan, progress=None):
        if not plan.ops:
            raise ValueError("Нет изменений для записи")
        _safe(old)
        with self._session(progress) as session:
            fresh, interfaces = self._read_dns(session)
            if fresh != old:
                raise TransportError("DNS-группы или правила изменились после чтения. Обнови DNS-список")
            if plan.interface and plan.interface not in interfaces:
                raise TransportError("Выбранный интерфейс больше не существует на Keenetic")
            root = Path(os.getenv("LOCALAPPDATA", str(Path.home()))) / "KeeneticRouteManager" / "backups"
            root.mkdir(parents=True, exist_ok=True)
            backup = root / ("dns-" + datetime.now().strftime("%Y%m%d-%H%M%S-%f") + ".json")
            snapshot_data = {
                "groups": [{"name": g.name, "includes": g.includes, "excludes": g.excludes, "description": g.description} for g in fresh.groups],
                "rules": [vars(r) for r in fresh.rules],
                "policies": fresh.policies,
            }
            with backup.open("x", encoding="utf-8") as handle:
                json.dump(snapshot_data, handle, indent=2, ensure_ascii=False)
            if self.journal:
                self.journal.record("backup", f"Резерв DNS-групп и правил: {backup}", status="ok")
            attempted = []
            try:
                for op in plan.ops:
                    attempted.append(op)
                    self._commands(session, op.commands)
                actual, _ = self._read_dns(session)
                if actual != plan.expected:
                    raise TransportError("DNS-конфигурация после записи не совпадает с планом")
                session.command("system configuration save", timeout=45)
            except Exception as exc:
                for op in reversed(attempted):
                    try:
                        self._commands(session, op.inverse)
                    except Exception:
                        pass
                try:
                    restored, _ = self._read_dns(session)
                    recovered = restored == fresh
                except Exception:
                    recovered = False
                if self.journal:
                    self.journal.record("rollback", f"DNS-откат: {'подтверждён' if recovered else 'НЕ ПОДТВЕРЖДЁН'}; резерв: {backup}", status="ok" if recovered else "error")
                raise TransportError(f"DNS-изменение не сохранено: {exc}. Откат {'подтверждён' if recovered else 'не подтверждён'}; проверь роутер вручную. Резерв: {backup}") from exc
        return actual, interfaces, str(backup)

    @staticmethod
    def _commands(session, commands):
        # After entering object-group config mode, always return to (config).
        entered = False
        for command in commands:
            try:
                session.command(command, timeout=50)
            except Exception:
                if entered:
                    try:
                        session.command("exit", timeout=15)
                    except Exception:
                        pass
                raise
            if command.startswith("object-group fqdn ") and len(command.split()) == 3:
                entered = True
            if command == "exit":
                entered = False