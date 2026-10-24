"""Plan site-specific IPv4 routing without touching broad shared networks.

Static routes describe prefixes, not a site's identity. Route-policy rules may
also affect the actual path, so a longest-prefix match is an estimate only.
"""
from __future__ import annotations

from dataclasses import dataclass
from ipaddress import IPv4Address, IPv4Network
from .core import Route, can_edit


@dataclass(frozen=True)
class SiteIpStatus:
    ip: str
    matches: tuple[Route, ...]
    best: tuple[Route, ...]

    @property
    def label(self) -> str:
        if not self.best:
            return "Нет статического маршрута"
        return ", ".join(sorted({r.interface or ("шлюз " + r.gateway) for r in self.best}))


def site_ip_status(ip: str, routes: list[Route]) -> SiteIpStatus:
    addr = IPv4Address(ip)
    matches = tuple(sorted((r for r in routes if addr in r.network),
                           key=lambda r: (r.network.prefixlen, not r.disabled), reverse=True))
    enabled = tuple(r for r in matches if not r.disabled)
    prefix = max((r.network.prefixlen for r in enabled), default=-1)
    best = tuple(r for r in enabled if r.network.prefixlen == prefix)
    return SiteIpStatus(str(addr), matches, best)


def plan_site_interface_change(ips: list[str], routes: list[Route], target_interface: str,
                               *, auto: bool = True) -> tuple[list[Route], list[Route], list[str]]:
    """Return adds, removes, explanations or raise when a safe edit is impossible.

    - Never delete/reassign a shared /24, /16, ... network to move one site.
    - For host-route changes, remove only editable competing active /32 routes.
    - An exact target /32 route can already exist; do not add it twice.
    - A broad target route suffices only if no equal/more-specific other active
      route wins. Changes through a non-editable exact route are refused.
    """
    if not target_interface:
        raise ValueError("Не выбран интерфейс")
    adds: list[Route] = []
    removes: list[Route] = []
    notes: list[str] = []
    for ip in dict.fromkeys(ips):
        status = site_ip_status(ip, routes)
        addr = IPv4Address(ip)
        host = IPv4Network(f"{ip}/32")
        best = status.best
        # An exact active route to this interface is enough unless a competing
        # exact route exists, in which case remove the competing exact record.
        exact_target = [r for r in status.matches if not r.disabled and r.network == host
                        and r.interface == target_interface and r.is_interface_route
                        and can_edit(r)]
        exact_other = [r for r in status.matches if not r.disabled and r.network == host
                       and (r.interface != target_interface or not r.is_interface_route)]
        bad_exact = [r for r in exact_other if not can_edit(r)]
        if bad_exact:
            raise ValueError(f"{ip}: существует защищённый точный маршрут (шлюз/reject/другое). "
                             "Его нельзя менять автоматически.")
        # A disabled entry for the target prefix is not safe to duplicate.
        if not exact_target and any(r.disabled and r.network == host and r.interface == target_interface
                                    for r in status.matches):
            raise ValueError(f"{ip}: на выбранном интерфейсе уже есть отключённый /32. "
                             "Сначала проверь его состояние вручную.")
        if not exact_target and any(r.network == host and r.interface == target_interface
                                    and not r.disabled and not can_edit(r) for r in status.matches):
            raise ValueError(f"{ip}: точный маршрут выбранного интерфейса защищён; "
                             "автоматическое изменение небезопасно.")
        if exact_target:
            if exact_other:
                removes.extend(exact_other)
                notes.append(f"{ip}: оставляем /32 → {target_interface}, убираем {len(exact_other)} конкурирующих /32")
            else:
                notes.append(f"{ip}: уже есть точный маршрут через {target_interface}, без изменений")
            continue
        # Existing best routes all point to target: broad route already suffices.
        if best and all(can_edit(r) and r.interface == target_interface for r in best):
            notes.append(f"{ip}: покрыт маршрутом {best[0].cidr} → {target_interface}, без изменений")
            continue
        if exact_other:
            removes.extend(exact_other)
        adds.append(Route(host, target_interface, auto=auto))
        suffix = (f"; удаляем {len(exact_other)} прежних /32" if exact_other else
                  "; широкие маршруты не меняем" if status.matches else "; маршрута раньше не было")
        notes.append(f"{ip}: создаём отдельный /32 → {target_interface}{suffix}")
    # Deduplicate before applying transaction.
    adds = list(dict.fromkeys(adds))
    removes = list(dict.fromkeys(removes))
    return adds, removes, notes
