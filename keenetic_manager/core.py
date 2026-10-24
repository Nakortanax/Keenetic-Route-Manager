"""Pure routing model and format adapters; no network side effects."""
from __future__ import annotations

from dataclasses import dataclass, replace
import csv
import io
import ipaddress
import json
import re
from pathlib import Path

IPv4Network = ipaddress.IPv4Network

@dataclass(frozen=True)
class Route:
    network: IPv4Network
    interface: str
    auto: bool = False
    metric: str = ""
    raw: str = ""
    gateway: str = ""
    reject: bool = False
    disabled: bool = False

    @property
    def cidr(self) -> str:
        return self.network.with_prefixlen

    @property
    def is_interface_route(self) -> bool:
        return bool(self.interface and not self.gateway)

    @property
    def key(self) -> tuple[str, str]:
        return (self.cidr, self.interface)

    def to_dict(self) -> dict:
        return {"network": self.cidr, "interface": self.interface,
                "gateway": self.gateway, "auto": self.auto,
                "metric": self.metric, "raw": self.raw, "reject": self.reject,
                "disabled": self.disabled}


def normalized_network(token: str, mask: str | None = None) -> IPv4Network:
    if token.lower() == "default":
        return ipaddress.ip_network("0.0.0.0/0")
    if mask is not None:
        return ipaddress.ip_network(f"{token}/{mask}", strict=False)
    if "/" in token:
        return ipaddress.ip_network(token, strict=False)
    return ipaddress.ip_network(f"{token}/32", strict=False)


ROUTE_LINE = re.compile(r"^\s*ip\s+route\s+(.+?)\s*$", re.I)
BAT_ROUTE = re.compile(r"^\s*route\s+add\s+(\S+)\s+mask\s+(\S+)\s+\S+(?:\s+.*)?$", re.I)
INTERFACE_HEAD = re.compile(r'^Interface, name\s*=\s*"([^"]+)"', re.I)
INTERFACE_ID = re.compile(r'^\s*id:\s*(\S+)', re.I)
INTERFACE_DESC = re.compile(r'^\s*description:\s*(.*?)\s*$', re.I)
INTERFACE_TYPE = re.compile(r'^\s*type:\s*(\S+)', re.I)


def parse_cli_route(line: str) -> Route | None:
    """Parse the IPv4 static-route forms Keenetic prints in running-config.

    Be deliberately strict: an unknown flag must not be silently discarded
    and later lost during an edit. The original CLI line is kept only in RAM.
    """
    match = ROUTE_LINE.match(line)
    if not match:
        return None
    # Keenetic can append human annotations: `!description`.
    body = match.group(1).split("!", 1)[0].strip()
    parts = body.split()
    if len(parts) < 2:
        return None
    destination = parts.pop(0)
    if destination.lower() != "default":
        try:
            ipaddress.IPv4Network(destination if "/" in destination else destination + "/32", strict=False)
        except ValueError:
            return None
    mask = None
    if parts and destination.lower() != "default" and "/" not in destination:
        # A second dotted IPv4 may be a NETMASK or a GATEWAY. A valid
        # contiguous netmask is checked first, otherwise it is a gateway.
        candidate = parts[0]
        if candidate.startswith("/") and candidate[1:].isdigit():
            mask = candidate[1:]
            parts.pop(0)
        elif re.fullmatch(r"[0-9]{1,2}", candidate) and len(parts) > 1:
            mask = candidate
            parts.pop(0)
        elif "." in candidate:
            try:
                ipaddress.IPv4Network(f"{destination}/{candidate}", strict=False)
                mask = candidate
                parts.pop(0)
            except ValueError:
                pass
    try:
        net = normalized_network(destination, mask)
    except ValueError:
        return None
    if not parts:
        return None
    target = parts.pop(0)
    if target.lower() in ("auto", "reject", "metric"):
        return None
    try:
        ipaddress.IPv4Address(target)
        gateway, interface = target, ""
    except ValueError:
        gateway, interface = "", target
        if not safe_interface(interface):
            return None
    if gateway and parts and safe_interface(parts[0]) and parts[0].lower() not in ("auto", "reject", "metric"):
        # If the gateway is explicit, an optional interface can follow.
        interface = parts.pop(0)
    auto = reject = False
    metric = ""
    while parts:
        token = parts.pop(0).lower()
        if token == "auto" and not auto:
            auto = True
        elif token == "reject" and not reject:
            reject = True
        elif token == "metric" and not metric and parts:
            if not parts[0].isdigit():
                return None
            metric = parts.pop(0)
        elif token.isdigit() and not metric:
            metric = token
        else:
            return None
    if metric and not (0 <= int(metric) <= 2**31 - 1):
        return None
    return Route(net, interface, auto, metric, line.strip(), gateway, reject)


def parse_running_config(text: str) -> tuple[list[Route], list[str]]:
    """Read routes including Keenetic's *following-line* disable marker.

    On KeeneticOS >= 5, ``ip route disable`` immediately after an ``ip route``
    record is a property of that route, NOT a separate static route. When the
    marker is orphaned or ambiguous, keep the safe read-only error behavior.
    """
    routes: list[Route] = []
    rejected: list[str] = []
    last_route_index: int | None = None
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("!"):
            continue
        if stripped.lower() == "ip route disable":
            if last_route_index is None or routes[last_route_index].disabled:
                rejected.append(stripped)
            else:
                routes[last_route_index] = replace(routes[last_route_index], disabled=True)
            last_route_index = None
        elif ROUTE_LINE.match(line):
            route = parse_cli_route(line)
            if route:
                routes.append(route)
                last_route_index = len(routes) - 1
            else:
                rejected.append(stripped)
                last_route_index = None
        else:
            last_route_index = None
    return routes, rejected


def parse_interface_descriptions(text: str) -> dict[str, str]:
    """Map actual IP routing interfaces to their Keenetic CLI aliases.

    Keenetic `show interface` also includes *physical switch ports* such as
    `GigabitEthernet1/0` (type Port) and access-point/radio objects. These
    cannot be targets of `ip route` and MUST NEVER appear in a route picker.

    Interface `ISP` is the routable alias of system ID GigabitEthernet1.
    Names in running-config are aliases (`ISP`, `Wireguard2`, etc), and those
    are the names to use when adding or removing static routes.
    """
    entries: dict[str, str] = {}
    heading: str | None = None
    identifier: str | None = None
    description = ""
    interface_type = ""
    # The model may contain interfaces that are not currently connected;
    # filter by TYPE, never link state. Reject 'Port' and Wi-Fi subobjects.
    forbidden_types = {"port", "wifimaster", "wifistation", "accesspoint"}

    def flush() -> None:
        if not heading:
            return
        sys_id = identifier or heading
        if interface_type.casefold() in forbidden_types:
            return
        if not is_route_interface_name(sys_id):
            return
        alias = heading if safe_interface(heading) else sys_id
        if not safe_interface(alias):
            return
        label = description or heading
        if alias != sys_id:
            label = f"{alias} · {label} (ID: {sys_id})"
        entries[alias] = label

    for line in text.splitlines():
        match = INTERFACE_HEAD.match(line)
        if match:
            flush()
            heading, identifier, description, interface_type = match.group(1), None, "", ""
            continue
        if heading:
            identity = INTERFACE_ID.match(line)
            if identity and not identifier:
                identifier = identity.group(1)
            kind = INTERFACE_TYPE.match(line)
            if kind and not interface_type:
                interface_type = kind.group(1)
            details = INTERFACE_DESC.match(line)
            if details and details.group(1):
                description = details.group(1)
    flush()
    return entries


def is_route_interface_name(identifier: str) -> bool:
    """Disallow device components (including the exact reported bad WAN port)."""
    if not safe_interface(identifier):
        return False
    if re.fullmatch(r"(?:GigabitEthernet|FastEthernet|Ethernet)\d+/\d+", identifier, re.I):
        return False
    if re.match(r"^WifiMaster", identifier, re.I):
        return False
    return True


def parse_bat_routes(text: str, interface: str) -> tuple[list[Route], list[str]]:
    routes, invalid = [], []
    for raw in text.splitlines():
        stripped = raw.strip()
        if not stripped or stripped.startswith(("::", "rem ", "REM ", "#", "@echo", "echo ")):
            continue
        match = BAT_ROUTE.match(stripped)
        if not match:
            invalid.append(stripped)
            continue
        try:
            net = normalized_network(match.group(1), match.group(2))
        except ValueError:
            invalid.append(stripped)
            continue
        routes.append(Route(net, interface, True, raw=stripped))
    return routes, invalid


def parse_text_routes(text: str, interface: str) -> tuple[list[Route], list[str]]:
    """Accept BAT, Keenetic CLI, and naked IPv4/CIDR; reject unknown lines."""
    routes, rejected = [], []
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith(("#", "::")):
            continue
        if line.lower().startswith("route add "):
            rr, invalid = parse_bat_routes(line, interface)
            routes.extend(rr); rejected.extend(invalid)
        elif line.lower().startswith("ip route "):
            r = parse_cli_route(line)
            if r:
                routes.append(Route(r.network, interface, r.auto, r.metric, r.raw, r.gateway, r.reject))
            else:
                rejected.append(line)
        else:
            try:
                routes.append(Route(normalized_network(line), interface, True))
            except ValueError:
                rejected.append(line)
    return routes, rejected


def safe_interface(value: str) -> bool:
    return bool(re.fullmatch(r"[A-Za-z][A-Za-z0-9._/\-]{0,70}", value))


def can_edit(route: Route) -> bool:
    # Forbid default-route edits through the GUI. Gateway-backed routes are read-only.
    return (route.is_interface_route and route.network.prefixlen > 0
            and safe_interface(route.interface) and not route.reject and not route.disabled
            and (not route.metric or int(route.metric) <= 255))


def _cli_destination(network: IPv4Network) -> str:
    """Use the documented Keenetic CLI syntax instead of CIDR guessing."""
    if network.prefixlen == 32:
        return str(network.network_address)
    return f"{network.network_address} {network.netmask}"


def add_command(route: Route) -> str:
    if not can_edit(route):
        raise ValueError("Изменение маршрута запрещено: gateway/default/reject/неподдерживаемая метрика")
    return f"ip route {_cli_destination(route.network)} {route.interface}" + (" auto" if route.auto else "") + (f" {route.metric}" if route.metric else "")


def delete_command(route: Route) -> str:
    if not can_edit(route):
        raise ValueError("Удаление маршрута запрещено: gateway/default/reject/неподдерживаемая метрика")
    return f"no ip route {_cli_destination(route.network)} {route.interface}"


def ordered_edit_operations(adds: list[Route], removes: list[Route]) -> list[tuple[str, str]]:
    """Build (CLI, undo CLI) pairs without transient duplicate exact prefixes.

    Keenetic may fail with Netlink EEXIST if two routes for the same host
    coexist across interfaces. For moves, remove the old host route FIRST.
    Other broader prefixes remain untouched. Undo is only best effort and
    needs subsequent router-state verification.
    """
    if len({r.key for r in adds}) != len(adds) or len({r.key for r in removes}) != len(removes):
        raise ValueError("Повторяющиеся команды изменения маршрутов")
    shared = {r.cidr for r in adds} & {r.cidr for r in removes}
    paired_removals = [r for r in removes if r.cidr in shared]
    paired_additions = [r for r in adds if r.cidr in shared]
    stand_alone_additions = [r for r in adds if r.cidr not in shared]
    stand_alone_removals = [r for r in removes if r.cidr not in shared]
    steps = []
    for prefix in dict.fromkeys(r.cidr for r in paired_removals):
        for r in paired_removals:
            if r.cidr == prefix:
                steps.append((delete_command(r), add_command(r)))
        for r in paired_additions:
            if r.cidr == prefix:
                steps.append((add_command(r), delete_command(r)))
    for r in stand_alone_additions:
        steps.append((add_command(r), delete_command(r)))
    for r in stand_alone_removals:
        steps.append((delete_command(r), add_command(r)))
    return steps


def ordered_edit_commands(adds: list[Route], removes: list[Route]) -> list[str]:
    """Preview exactly the operations used by the executor."""
    return [command for command, _ in ordered_edit_operations(adds, removes)]


def coverage(route: Route, existing: list[Route]) -> tuple[bool, list[Route]]:
    covering = [x for x in existing if route.network.subnet_of(x.network)]
    return any(x.interface == route.interface and not x.disabled for x in covering), [x for x in covering if x.interface != route.interface or x.disabled]


def plan_add(routes: list[Route], existing: list[Route]) -> tuple[list[Route], list[Route], list[tuple[Route, list[Route]]]]:
    to_add, duplicates, conflicts = [], [], []
    accepted = list(existing)
    for item in routes:
        included, overlaps = coverage(item, accepted)
        if included:
            duplicates.append(item)
        else:
            if overlaps:
                conflicts.append((item, overlaps))
            to_add.append(item)
            accepted.append(item)
    return to_add, duplicates, conflicts


def export_text(routes: list[Route], kind: str) -> str:
    if kind == "json":
        return json.dumps([x.to_dict() for x in routes], ensure_ascii=False, indent=2) + "\n"
    if kind == "csv":
        dst = io.StringIO()
        writer = csv.writer(dst)
        writer.writerow(["network", "interface", "gateway", "auto", "metric", "reject", "disabled"])
        for r in routes:
            writer.writerow([r.cidr, r.interface, r.gateway, str(r.auto).lower(), r.metric, str(r.reject).lower(), str(r.disabled).lower()])
        return dst.getvalue()
    if kind == "bat":
        return "".join(f"route add {r.network.network_address} mask {r.network.netmask} 0.0.0.0\r\n" for r in routes if r.is_interface_route and not r.reject and not r.disabled)
    if kind == "cli":
        return "".join((r.raw or add_command(r)) + "\n" + ("ip route disable\n" if r.disabled else "") for r in routes)
    raise ValueError(f"Формат {kind} не поддерживается")


def save_export(path: Path, routes: list[Route], kind: str) -> None:
    path.write_text(export_text(routes, kind), encoding="utf-8")
