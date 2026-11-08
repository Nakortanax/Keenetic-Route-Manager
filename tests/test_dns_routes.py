"""Offline tests for the DNS-FQDN routing model (no router connection)."""
import unittest
from keenetic_manager.dns_routes import (
    create_commands, remove_commands, parse_dns_config, safe_domain, DnsRule
)

EXAMPLE = """\
object-group fqdn DNS_TEST_2IP
object-group fqdn DNS_TEST_2IP include 2ip.io
ip policy Policy1 dns-proxy route object-group DNS_TEST_2IP Wireguard2 auto
object-group fqdn KRM_MY_SITE
object-group fqdn KRM_MY_SITE include example.org
ip policy Policy1 dns-proxy route object-group KRM_MY_SITE Wireguard0 auto
"""

class DnsRoutesTests(unittest.TestCase):
    def test_parse_existing_and_managed(self):
        rules, groups, domains = parse_dns_config(EXAMPLE)
        self.assertEqual(len(rules), 2)
        self.assertFalse(rules[0].managed)
        self.assertTrue(rules[1].managed)
        self.assertEqual(rules[0].domains, ("2ip.io",))
        self.assertIn("KRM_MY_SITE", groups)

    def test_generate_known_keenetic_commands(self):
        self.assertEqual(create_commands("Policy1", "KRM_MY_SITE", "example.org", "Wireguard2"), [
            "object-group fqdn KRM_MY_SITE",
            "object-group fqdn KRM_MY_SITE include example.org",
            "ip policy Policy1 dns-proxy route object-group KRM_MY_SITE Wireguard2 auto"
        ])

    def test_protect_manual_group(self):
        rule = DnsRule("Policy1", "DNS_TEST_2IP", "Wireguard2", True, ("2ip.io",))
        with self.assertRaises(ValueError):
            remove_commands(rule)

    def test_reject_unsafe_identifiers(self):
        with self.assertRaises(ValueError):
            create_commands("Policy1", "KRM_X;reboot", "example.org", "Wireguard2")
        with self.assertRaises(ValueError):
            safe_domain("example.org; reboot")

    def test_multiple_domains_not_auto_removed(self):
        rule = DnsRule("Policy1","KRM_A","Wireguard2",True,("one.org","two.org"))
        with self.assertRaises(ValueError):
            remove_commands(rule)

if __name__ == "__main__":
    unittest.main()
