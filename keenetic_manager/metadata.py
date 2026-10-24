"""Local-only IP route annotations, never sent to Keenetic.

No reverse DNS or network owner lookup proves the actual website served by an IP.
"""
from __future__ import annotations

import ipaddress
import json
import os
from dataclasses import dataclass, asdict, field
from datetime import datetime, timezone
from pathlib import Path
import re
import socket
import tempfile
import urllib.request
from typing import Callable

MAX_LABEL = 200
MAX_DOMAINS = 15
SCHEMA_VERSION = 1


def utcnow():
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def normalize_cidr(value: str) -> str:
    if "/" not in value:
        value = value + "/32"
    return str(ipaddress.IPv4Network(value, strict=False))


def normalize_domain(value: str) -> str:
    raw = value.lower().strip().rstrip(".")
    if not raw or len(raw) > 253 or not re.fullmatch(r"[a-z0-9.-]+", raw):
        raise ValueError("Некорректное имя домена")
    if "." not in raw or ".." in raw or raw.startswith((".", "-")):
        raise ValueError("Некорректное имя домена")
    return raw


@dataclass
class Note:
    manual: str = ""
    sites: list[str] = field(default_factory=list)
    ptr: str = ""
    ptr_verified: bool = False
    owner: str = ""
    checked_at: str = ""

    @property
    def site_label(self):
        if self.manual:
            return self.manual
        if self.sites:
            return ", ".join(self.sites)
        if self.ptr:
            return self.ptr + (" (PTR проверен)" if self.ptr_verified else " (PTR)")
        return ""

    @property
    def source(self):
        if self.manual:
            return "Вручную"
        if self.sites:
            return "Домен→IP"
        if self.ptr:
            return "PTR+DNS" if self.ptr_verified else "PTR (не подтверждён)"
        if self.owner:
            return "RDAP (сеть)"
        return ""

    def to_dict(self):
        return asdict(self)

    @classmethod
    def from_dict(cls, value):
        if not isinstance(value, dict):
            return cls()
        def strval(k):
            return str(value.get(k, ""))[:MAX_LABEL]
        sites = []
        for v in value.get("sites", []) if isinstance(value.get("sites", []), list) else []:
            try:
                site = normalize_domain(str(v))
            except ValueError:
                continue
            if site not in sites:
                sites.append(site)
        return cls(manual=strval("manual"), sites=sites[:MAX_DOMAINS],
                   ptr=strval("ptr"), ptr_verified=value.get("ptr_verified") is True,
                   owner=strval("owner"), checked_at=strval("checked_at"))


class MetadataStore:
    """Annotation key is network CIDR, independent of the route interface.

    A single site may use many IPs; a single IP may host many sites.
    Annotations are never attached to a broader prefix when a host resolves
    inside it: this avoids claiming all IPs in the prefix host that site.
    """
    def __init__(self, path: Path):
        self.path = Path(path)
        self.notes: dict[str, Note] = {}
        self.load()

    @staticmethod
    def default_path(router_ip: str):
        ip = str(ipaddress.IPv4Address(router_ip))
        base = Path(os.getenv("LOCALAPPDATA", str(Path.home()))) / "KeeneticRouteManager" / "metadata"
        return base / f"{ip}.json"

    def load(self):
        if not self.path.exists():
            return
        data = json.loads(self.path.read_text(encoding="utf-8"))
        if not isinstance(data, dict) or data.get("version") != SCHEMA_VERSION:
            raise ValueError("Неподдерживаемый формат локальных пояснений")
        records = data.get("routes", {})
        if not isinstance(records, dict):
            raise ValueError("Некорректная база пояснений")
        self.notes = {}
        for key, value in records.items():
            try:
                self.notes[normalize_cidr(key)] = Note.from_dict(value)
            except ValueError:
                continue

    def save(self):
        self.path.parent.mkdir(parents=True, exist_ok=True)
        payload = {"version": SCHEMA_VERSION, "routes": {k: v.to_dict() for k,v in sorted(self.notes.items())}}
        body = json.dumps(payload, indent=2, ensure_ascii=False) + "\n"
        fd, tmp = tempfile.mkstemp(prefix="notes-", suffix=".tmp", dir=self.path.parent)
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as f:
                f.write(body)
            os.replace(tmp, self.path)
        finally:
            if os.path.exists(tmp):
                os.unlink(tmp)

    def get(self, network: str) -> Note:
        return self.notes.get(normalize_cidr(network), Note())

    def set_manual(self, network: str, value: str):
        key = normalize_cidr(network)
        note = self.notes.setdefault(key, Note())
        note.manual = value.strip()[:MAX_LABEL]
        self.save()

    def add_site(self, domain: str, addresses: list[str]):
        domain = normalize_domain(domain)
        for ip in addresses:
            key = normalize_cidr(str(ipaddress.IPv4Address(ip)))
            note = self.notes.setdefault(key, Note())
            if domain not in note.sites:
                note.sites.append(domain)
            note.sites = note.sites[-MAX_DOMAINS:]
        self.save()

    def add_enrichment(self, network: str, *, ptr: str = "", verified: bool = False, owner: str = ""):
        key = normalize_cidr(network)
        note = self.notes.setdefault(key, Note())
        # Preserve manually assigned labels and forward DNS observations.
        note.ptr = ptr.strip()[:MAX_LABEL]
        note.ptr_verified = verified
        note.owner = owner.strip()[:MAX_LABEL]
        note.checked_at = utcnow()
        self.save()

    def to_json_export(self, routes):
        return json.dumps([
            {**r.to_dict(), "annotation": self.get(r.cidr).to_dict()}
            for r in routes
        ], indent=2, ensure_ascii=False) + "\n"


def resolve_ptr(ip: str, *, resolver: Callable = socket.gethostbyaddr,
                forward: Callable = socket.gethostbyname_ex) -> tuple[str, bool]:
    """Reverse lookup, then verify forward DNS still contains the queried IP.

    Even forward-confirmed PTR is a hostname, NOT website attribution.
    """
    addr = str(ipaddress.IPv4Address(ip))
    if not ipaddress.IPv4Address(addr).is_global:
        return "", False
    try:
        raw = resolver(addr)[0].rstrip(".")
        host = normalize_domain(raw)
    except (socket.error, ValueError, IndexError, TypeError):
        return "", False
    try:
        verified = addr in forward(host)[2]
    except (socket.error, IndexError, TypeError):
        verified = False
    return host, bool(verified)


def rdap_owner(ip: str, *, opener: Callable = urllib.request.urlopen, timeout: float = 5.) -> str:
    """Fetch a network registration holder, not a hosted website.

    External request goes to rdap.org and is only made by explicit user action.
    """
    addr = ipaddress.IPv4Address(ip)
    if not addr.is_global:
        return ""
    request = urllib.request.Request(f"https://rdap.org/ip/{addr}", headers={
        "Accept": "application/rdap+json, application/json", "User-Agent": "KeeneticRouteManager/0.1.5"})
    try:
        with opener(request, timeout=timeout) as response:
            # Limit server response to avoid uncontrolled memory use.
            data = json.loads(response.read(200_000).decode("utf-8"))
        if not isinstance(data, dict):
            return ""
        value = data.get("name") or data.get("handle") or ""
        if not isinstance(value, str):
            return ""
        return value.strip()[:MAX_LABEL]
    except (OSError, ValueError, UnicodeError, TypeError):
        return ""


def identify_network(cidr: str, *, reverse=resolve_ptr, owner_lookup=rdap_owner) -> dict:
    net = ipaddress.IPv4Network(cidr, strict=False)
    ip = str(net.network_address)
    ptr, verified = reverse(ip) if net.prefixlen == 32 else ("", False)
    return {"ptr": ptr, "verified": verified, "owner": owner_lookup(ip)}
