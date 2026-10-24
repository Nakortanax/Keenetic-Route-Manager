import os
import unittest
from pathlib import Path
from keenetic_manager.core import parse_interface_descriptions, is_route_interface_name, add_command, Route, ordered_edit_commands
from keenetic_manager.interface_choices import build_interface_choices, default_interface
from ipaddress import IPv4Network

class ActualKeeneticInterfaces(unittest.TestCase):
    def setUp(self):
        # Official output supplied from the user's Racer 5.2 beta: includes
        # alias ISP and a separate physical port named 0.
        self.source = Path(__file__).resolve().parent / 'fixtures' / 'keenetic-show-interface.txt'
        self.interfaces = parse_interface_descriptions(self.source.read_text(encoding='utf-8'))

    def test_isp_is_cli_alias_not_ethernet_port(self):
        self.assertIn('ISP', self.interfaces)
        self.assertIn('GigabitEthernet1', self.interfaces['ISP'])
        self.assertNotIn('GigabitEthernet1/0', self.interfaces)
        self.assertNotIn('GigabitEthernet0/0', self.interfaces)
        self.assertEqual(add_command(Route(IPv4Network('188.114.96.1/32'), 'ISP', True)),
                         'ip route 188.114.96.1 ISP auto')

    def test_picker_excludes_all_physical_and_wifi_objects(self):
        choices = build_interface_choices(self.interfaces)
        values = {option.identifier for option in choices}
        self.assertIn('ISP', values)
        self.assertIn('Wireguard2', values)
        self.assertNotIn('GigabitEthernet1/0', values)
        self.assertNotIn('GigabitEthernet0/0', values)
        self.assertFalse(any(x.startswith('WifiMaster') for x in values))
        self.assertNotIn('AccessPoint', values)
        self.assertEqual(default_interface(self.interfaces), 'Wireguard2')

    def test_switch_uses_add_first_and_remove_after(self):
        old = Route(IPv4Network('188.114.96.1/32'), 'Wireguard2', True)
        new = Route(IPv4Network('188.114.96.1/32'), 'ISP', True)
        self.assertEqual(ordered_edit_commands([new], [old]), [
            'ip route 188.114.96.1 ISP auto',
            'no ip route 188.114.96.1 Wireguard2',
        ])

    def test_edit_same_interface_preserves_replacement_order(self):
        old = Route(IPv4Network('188.114.96.1/32'), 'Wireguard2', True)
        new = Route(IPv4Network('188.114.96.1/32'), 'Wireguard2', False)
        self.assertEqual(ordered_edit_commands([new], [old]), [
            'no ip route 188.114.96.1 Wireguard2',
            'ip route 188.114.96.1 Wireguard2',
        ])

    def test_identifier_filter_rejects_components_even_without_type(self):
        for item in ['GigabitEthernet1/0', 'FastEthernet1/2','Ethernet1/5','WifiMaster1/AccessPoint0']:
            self.assertFalse(is_route_interface_name(item))
        self.assertTrue(is_route_interface_name('GigabitEthernet1'))
        self.assertTrue(is_route_interface_name('Wireguard2'))
