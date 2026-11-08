"""Keenetic DNS-proxy FQDN policy routes. Never change unrelated routing rules."""
from __future__ import annotations
from dataclasses import dataclass
import re
from .transport import TransportError

IDENT = re.compile(r"^[A-Za-z][A-Za-z0-9_-]{0,62}$")
DOMAIN = re.compile(r"^(?=.{1,253}$)(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,63}$")
GROUP_PREFIX = "KRM_"
ROUTE_RE = re.compile(r"^ip policy (\S+) dns-proxy route object-group (\S+) (\S+)(?: (auto))?$", re.I)
INCLUDE_RE = re.compile(r"^object-group fqdn (\S+) include (\S+)$", re.I)
GROUP_RE = re.compile(r"^object-group fqdn (\S+)$", re.I)

@dataclass(frozen=True)
class DnsRule:
    policy: str
    group: str
    interface: str
    auto: bool
    domains: tuple[str, ...]

    @property
    def managed(self):
        return self.group.startswith(GROUP_PREFIX)

def safe_identifier(text: str) -> str:
    text = text.strip()
    if not IDENT.fullmatch(text):
        raise ValueError("Допустимы только латинские буквы, цифры, _ и -, имя начинается с буквы")
    return text

def safe_domain(text: str) -> str:
    text = text.strip().lower().rstrip(".")
    if not DOMAIN.fullmatch(text):
        raise ValueError("Неверное имя домена (пример: example.org)")
    return text

def parse_dns_config(config: str) -> tuple[list[DnsRule], set[str], dict[str, tuple[str, ...]]]:
    groups: set[str] = set()
    domains: dict[str, list[str]] = {}
    entries = []
    for line in config.splitlines():
        line = line.strip()
        m = GROUP_RE.fullmatch(line)
        if m:
            groups.add(m.group(1))
            continue
        m = INCLUDE_RE.fullmatch(line)
        if m:
            groups.add(m.group(1))
            domains.setdefault(m.group(1), []).append(m.group(2))
            continue
        m = ROUTE_RE.fullmatch(line)
        if m:
            entries.append((m.group(1), m.group(2), m.group(3), bool(m.group(4))))
    domain_map = {k: tuple(dict.fromkeys(v)) for k,v in domains.items()}
    return [DnsRule(p,g,i,a,domain_map.get(g,())) for p,g,i,a in entries], groups, domain_map

def create_commands(policy: str, group: str, domain: str, interface: str) -> list[str]:
    policy, group, interface = map(safe_identifier,(policy,group,interface))
    domain = safe_domain(domain)
    if not group.startswith(GROUP_PREFIX):
        raise ValueError("Новые группы программы должны иметь префикс KRM_")
    return [f"object-group fqdn {group}",
            f"object-group fqdn {group} include {domain}",
            f"ip policy {policy} dns-proxy route object-group {group} {interface} auto"]

def remove_commands(rule: DnsRule) -> list[str]:
    if not rule.managed:
        raise ValueError("Чужие DNS-группы защищены от удаления")
    if len(rule.domains) != 1 or not rule.auto:
        raise ValueError("У группы нестандартная структура; автоматическое удаление запрещено")
    return [f"no ip policy {rule.policy} dns-proxy route object-group {rule.group} {rule.interface} auto",
            f"no object-group fqdn {rule.group} include {rule.domains[0]}",
            f"no object-group fqdn {rule.group}"]

def _read_config(session) -> str:
    return session.command("show running-config", timeout=900, inactivity=90)

class DnsRouter:
    def __init__(self, client):
        self.client = client

    def read(self, progress=None):
        with self.client._session(progress) as session:
            return parse_dns_config(_read_config(session))[0]

    def apply(self, *, policy, group, domain, interface, remove=False, progress=None):
        with self.client._session(progress) as session:
            before = _read_config(session)
            rules, groups, domains = parse_dns_config(before)
            if remove:
                matches = [r for r in rules if r.policy == policy and r.group == group
                           and r.interface == interface]
                if len(matches) != 1:
                    raise TransportError("Невозможно однозначно определить удаляемое правило")
                rule = matches[0]
                if sum(r.group == group for r in rules) != 1:
                    raise TransportError("Группа используется несколькими правилами; удаление запрещено")
                commands = remove_commands(rule)
            else:
                commands = create_commands(policy, group, domain, interface)
                if group in groups or any(r.group == group for r in rules):
                    raise TransportError("Группа уже существует. Выбери новое имя KRM_...")
            # A read-only dry run is shown in the GUI before this call.
            applied = []
            try:
                for command in commands:
                    session.command(command, timeout=45)
                    applied.append(command)
                after = _read_config(session)
                updated, updated_groups, updated_domains = parse_dns_config(after)
                if remove:
                    if group in updated_groups or any(r.group == group for r in updated):
                        raise TransportError("После удаления группа осталась в конфигурации")
                    untouched = [r for r in rules if r != rule]
                    if sorted((r.policy,r.group,r.interface,r.auto) for r in updated) != sorted(
                        (r.policy,r.group,r.interface,r.auto) for r in untouched):
                        raise TransportError("Другие DNS-правила изменились; запись отменена")
                else:
                    target = [r for r in updated if r.policy == policy and r.group == group
                              and r.interface == interface and r.auto]
                    if len(target) != 1 or safe_domain(domain) not in tuple(
                            x.lower() for x in updated_domains.get(group,())):
                        raise TransportError("Созданное правило не подтверждено повторным чтением")
                    for old in rules:
                        if old not in updated:
                            raise TransportError("Исходное DNS-правило изменилось; запись отменена")
                session.command("system configuration save", timeout=45)
                return updated
            except Exception as exc:
                # Important: do not save on failure. Keenetic's running config might
                # still be modified; never claim that it was rolled back.
                raise TransportError(
                    f"DNS-операция не подтверждена: {exc}. Сохранение не выполнено. "
                    "Проверь running-config и журнал; частичные изменения возможны."
                ) from exc
