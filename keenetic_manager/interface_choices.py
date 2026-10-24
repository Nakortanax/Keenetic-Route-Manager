"""UI-independent, safe interface picker options obtained from show interface."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Mapping

from .core import safe_interface, is_route_interface_name


@dataclass(frozen=True)
class InterfaceChoice:
    identifier: str
    label: str


def build_interface_choices(interfaces: Mapping[str, str], *, only_vpn: bool = False) -> list[InterfaceChoice]:
    """Keep the system ID in the label, even when descriptions are identical.

    Never accept arbitrary text from a picker as a router interface name.
    """
    choices: list[InterfaceChoice] = []
    for identifier, description in interfaces.items():
        if not is_route_interface_name(identifier):
            continue
        if only_vpn and not identifier.lower().startswith("wireguard"):
            continue
        clean_description = " ".join(str(description or "").split())[:90]
        if identifier == "ISP" and "GigabitEthernet1" in clean_description:
            # Keenetic route CLI uses ISP, system interface ID is GigabitEthernet1.
            label = "ISP — проводной Ethernet [GigabitEthernet1]"
        else:
            label = (f"{clean_description}  [{identifier}]"
                     if clean_description and clean_description.casefold() != identifier.casefold()
                     else identifier)
        choices.append(InterfaceChoice(identifier, label))
    return sorted(choices, key=lambda x: (not x.identifier.lower().startswith("wireguard"), x.label.casefold(), x.identifier))


def default_interface(interfaces: Mapping[str, str], selected: str = "") -> str:
    """Prefer the filtered interface, then the new AWG by description.

    Never invent interfaces if the router did not report them.
    """
    if selected in interfaces and is_route_interface_name(selected):
        return selected
    for identifier, description in interfaces.items():
        if (is_route_interface_name(identifier) and identifier.lower().startswith("wireguard")
                and str(description).strip().casefold() == "amnezia_for_awg"):
            return identifier
    choices = build_interface_choices(interfaces)
    return choices[0].identifier if len(choices) == 1 else ""
