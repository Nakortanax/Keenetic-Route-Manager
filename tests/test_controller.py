import unittest
from ipaddress import ip_network
from keenetic_manager.controller import check_lan_host, route_fingerprint
from keenetic_manager.core import Route
class RouterClientSafety(unittest.TestCase):
    def test_only_private_ipv4(self):
        self.assertEqual(check_lan_host('192.168.1.1'), '192.168.1.1')
        for ip in ('8.8.8.8', '::1', 'keenetic.local'):
            with self.assertRaises(ValueError): check_lan_host(ip)
    def test_fingerprint_state_sensitive(self):
        a=Route(ip_network('10.0.0.1/32'), 'Wireguard2', auto=True)
        b=Route(ip_network('10.0.0.1/32'), 'Wireguard2', auto=False)
        self.assertNotEqual(route_fingerprint([a]), route_fingerprint([b]))
