"""Regression tests for KeeneticOS 5.2 duplicate-host Netlink error."""
import os
import tempfile
import unittest
from ipaddress import ip_network
from unittest.mock import patch

from keenetic_manager.core import Route, ordered_edit_operations, ordered_edit_commands
from keenetic_manager.controller import RouterClient, route_fingerprint
from keenetic_manager.transport import TransportError


def route(ip, iface):
    return Route(ip_network(ip, strict=False), iface, auto=True)


class FakeCLI:
    def __init__(self, current, error_on=None):
        self.current = list(current)
        self.error_on = error_on
        self.commands = []
        self.saved = False

    def __enter__(self):
        return self

    def __exit__(self, *_):
        return None

    def command(self, text, **_):
        self.commands.append(text)
        if text == 'system configuration save':
            self.saved = True
            return 'Saved'
        if text == self.error_on:
            raise TransportError('Io::Netlink error: file exists')
        if text.startswith('no ip route '):
            name, iface = text[len('no ip route '):].split(' ')[:2]
            self.current = [r for r in self.current if r.key != (name+'/32', iface)]
        if text.startswith('ip route '):
            name, iface, *_ = text[len('ip route '):].split()
            r = route(name+'/32', iface)
            if any(x.cidr == r.cidr for x in self.current):
                raise TransportError('Io::Netlink error: file exists')
            self.current.append(r)
        return 'ok'


class RouteMigration(unittest.TestCase):
    def setUp(self):
        self.old = route('188.114.96.3/32', 'Wireguard2')
        self.new = route('188.114.96.3/32', 'ISP')
        self.client = RouterClient('192.168.1.1', 23, 'admin', 'test-only-password')

    def execute(self, fake, adds, removes, existing):
        with tempfile.TemporaryDirectory() as tmp:
            with patch.dict(os.environ, {'LOCALAPPDATA': tmp}), \
                 patch.object(self.client, '_session', return_value=fake), \
                 patch.object(self.client, '_read', side_effect=lambda _: (list(fake.current), {'ISP': 'Ethernet', 'Wireguard2':'AWG'}, [])):
                return self.client.apply(adds, removes, existing)

    def test_remove_before_add(self):
        self.assertEqual(ordered_edit_commands([self.new], [self.old]), [
            'no ip route 188.114.96.3 Wireguard2',
            'ip route 188.114.96.3 ISP auto'])
        fake = FakeCLI([self.old])
        routes, _, _ = self.execute(fake, [self.new], [self.old], [self.old])
        self.assertEqual(route_fingerprint(routes), route_fingerprint([self.new]))
        self.assertTrue(fake.saved)

    def test_failure_rolls_back_without_saving(self):
        fake = FakeCLI([self.old], error_on='ip route 188.114.96.3 ISP auto')
        with self.assertRaisesRegex(TransportError, 'восстановлены'):
            self.execute(fake, [self.new], [self.old], [self.old])
        self.assertFalse(fake.saved)
        self.assertEqual(route_fingerprint(fake.current), route_fingerprint([self.old]))

    def test_existing_duplicate_routes_blocked_before_mutation(self):
        fake = FakeCLI([self.old, self.new])
        with self.assertRaisesRegex(TransportError, 'одновременно есть маршруты'):
            self.execute(fake, [], [self.old], [self.old, self.new])
        self.assertFalse(fake.commands)
        self.assertFalse(fake.saved)

    def test_inverse_steps(self):
        self.assertEqual(ordered_edit_operations([self.new], [self.old]), [
            ('no ip route 188.114.96.3 Wireguard2', 'ip route 188.114.96.3 Wireguard2 auto'),
            ('ip route 188.114.96.3 ISP auto', 'no ip route 188.114.96.3 ISP')])


class JournalCleaning(unittest.TestCase):
    def test_erase_sequence_removed(self):
        from keenetic_manager.activity_log import redact
        self.assertEqual(redact('ip\x1b[K route\x1b[K 1.2.3.4 ISP auto'),
                         'ip route 1.2.3.4 ISP auto')


if __name__ == '__main__':
    unittest.main()
