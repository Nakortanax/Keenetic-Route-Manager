"""Offline tests for DNS-based routing; no router or network needed."""
import tempfile
import unittest
from unittest.mock import patch
from pathlib import Path

from keenetic_manager.dns_routes import (
    GLOBAL, DnsGroup, DnsRule, DnsSnapshot, parse_dns_config,
    parse_entries, plan_group, plan_rule, DnsClient,
)


CONFIG = '''
object-group fqdn DNS_WG2_INSTAGRAM
    description "Instagram"
    include instagram.com
    include cdninstagram.com
    include 31.13.64.0/18
    exclude ads.example.com
!
object-group fqdn domain-list0
    include vk.com
!
ip policy Policy0
    description AMNvpn
    permit global Wireguard2
!
ip policy Policy1
    description PC
    permit global ISP
    dns-proxy route object-group DNS_WG2_INSTAGRAM Wireguard2 auto reject
    dns-proxy route object-group domain-list0 ISP auto
!
dns-proxy
    rebind-protect auto
    route object-group DNS_WG2_INSTAGRAM Wireguard0 auto
!
'''


class ParseTests(unittest.TestCase):
    def test_nested_groups_and_scoped_rules(self):
        s = parse_dns_config(CONFIG)
        self.assertEqual(s.errors, ())
        self.assertEqual(s.policies, ("Policy0", "Policy1"))
        self.assertEqual(s.group("DNS_WG2_INSTAGRAM").includes,
                         ("instagram.com", "cdninstagram.com", "31.13.64.0/18"))
        self.assertEqual(s.group("DNS_WG2_INSTAGRAM").excludes, ("ads.example.com",))
        self.assertEqual(s.rules, (
            DnsRule("Policy1", "DNS_WG2_INSTAGRAM", "Wireguard2", True, True),
            DnsRule("Policy1", "domain-list0", "ISP", True, False),
            DnsRule(GLOBAL, "DNS_WG2_INSTAGRAM", "Wireguard0", True, False),
        ))

    def test_empty_legacy_config_has_policies(self):
        s = parse_dns_config("ip route 1.1.1.1 ISP auto\n!\nip policy Policy1\n    permit global ISP\n!\n")
        self.assertEqual(s.errors, ())
        self.assertEqual(s.groups, ())
        self.assertEqual(s.policies, ("Policy1",))

    def test_unknown_group_item_is_readonly(self):
        s = parse_dns_config("object-group fqdn DNS_TEST\n    unknown-option yes\n!\n")
        self.assertTrue(s.errors)
        with self.assertRaisesRegex(ValueError, "Запись заблокирована"):
            plan_group(s, "DNS_TEST", "google.com")

    def test_unsupported_gateway_rule_blocked(self):
        s = parse_dns_config("object-group fqdn DNS_TEST\n    include google.com\n!\n" +
                             "dns-proxy\n    route object-group DNS_TEST 192.0.2.1 Wireguard0 auto\n!\n")
        self.assertTrue(s.errors)


class PlanTests(unittest.TestCase):
    def setUp(self):
        self.old = parse_dns_config(CONFIG)

    def test_domain_validation_and_ipv4_normalization(self):
        self.assertEqual(parse_entries("Instagram.COM\n31.13.72.174\n10.0.0.1/24\ninstagram.com"),
                         ("instagram.com", "31.13.72.174", "10.0.0.0/24"))
        for invalid in ("a;system", "*.example.com", "x y.com", "1.2.3.999", "2001:db8::/32"):
            with self.subTest(invalid=invalid), self.assertRaises(ValueError):
                parse_entries(invalid)

    def test_new_group(self):
        plan = plan_group(self.old, "DNS_WG2_NEW", "example.com\n4.4.4.0/24")
        self.assertIn("object-group fqdn DNS_WG2_NEW", plan.preview())
        self.assertIn("object-group fqdn DNS_WG2_NEW include example.com", plan.preview())
        self.assertEqual(plan.expected.group("DNS_WG2_NEW").includes, ("example.com", "4.4.4.0/24"))
        self.assertEqual(plan.expected.rules, self.old.rules)

    def test_modify_only_selected_group_and_use_submode_for_removal(self):
        plan = plan_group(self.old, "DNS_WG2_INSTAGRAM", "instagram.com\nthreads.net", "")
        self.assertIn("no include cdninstagram.com", plan.preview())
        self.assertIn("object-group fqdn DNS_WG2_INSTAGRAM include threads.net", plan.preview())
        self.assertIn("no exclude ads.example.com", plan.preview())
        self.assertNotIn("no object-group fqdn", plan.preview())
        self.assertEqual(plan.expected.group("domain-list0"), self.old.group("domain-list0"))
        self.assertEqual(plan.expected.rules, self.old.rules)

    def test_existing_group_no_change(self):
        g = self.old.group("DNS_WG2_INSTAGRAM")
        plan = plan_group(self.old, g.name, "\n".join(g.includes), "\n".join(g.excludes))
        self.assertEqual(plan.ops, ())
        self.assertEqual(plan.expected, self.old)

    def test_rule_retarget_policy_only(self):
        plan = plan_rule(self.old, "DNS_WG2_INSTAGRAM", "Policy1", "ISP", True, True)
        self.assertEqual(plan.ops[0].commands,
                         ("no ip policy Policy1 dns-proxy route object-group DNS_WG2_INSTAGRAM Wireguard2",))
        self.assertEqual(plan.ops[1].commands,
                         ("ip policy Policy1 dns-proxy route object-group DNS_WG2_INSTAGRAM ISP auto reject",))
        self.assertEqual(plan.expected.rules[-1].interface, "ISP")
        self.assertIn(DnsRule(GLOBAL, "DNS_WG2_INSTAGRAM", "Wireguard0", True, False), plan.expected.rules)
        self.assertEqual(plan.expected.groups, self.old.groups)

    def test_rule_bind_and_remove(self):
        added = plan_rule(self.old, "domain-list0", "Policy0", "Wireguard2")
        self.assertEqual(added.ops[0].commands,
                         ("ip policy Policy0 dns-proxy route object-group domain-list0 Wireguard2 auto reject",))
        removed = plan_rule(self.old, "DNS_WG2_INSTAGRAM", "Policy1", remove=True)
        self.assertEqual(len(removed.ops), 1)
        self.assertNotIn(DnsRule("Policy1", "DNS_WG2_INSTAGRAM", "Wireguard2", True, True), removed.expected.rules)

    def test_no_unknown_policy_or_invalid_interface(self):
        with self.assertRaisesRegex(ValueError, "политика"):
            plan_rule(self.old, "DNS_WG2_INSTAGRAM", "Policy99", "Wireguard2")
        with self.assertRaises(ValueError):
            plan_rule(self.old, "DNS_WG2_INSTAGRAM", "Policy1", "Wireguard2; exit")


class ApplySafetyTests(unittest.TestCase):
    class Session:
        def __init__(self, fail=None):
            self.calls = []
            self.fail = fail

        def __enter__(self):
            return self

        def __exit__(self, *_):
            pass

        def command(self, text, **_):
            self.calls.append(text)
            if text == self.fail:
                raise RuntimeError("synthetic router error")
            return "OK"

    def setUp(self):
        self.old = parse_dns_config(CONFIG)
        self.plan = plan_rule(self.old, "domain-list0", "Policy0", "Wireguard2")
        self.client = DnsClient.__new__(DnsClient)
        self.client.journal = None

    def test_apply_verifies_then_saves_and_backs_up(self):
        s = self.Session()
        with tempfile.TemporaryDirectory() as home, \
                patch.dict("os.environ", {"LOCALAPPDATA": home}), \
                patch.object(DnsClient, "_session", return_value=s), \
                patch.object(DnsClient, "_read_dns", side_effect=[
                    (self.old, {"Wireguard2": "VPN"}),
                    (self.plan.expected, {"Wireguard2": "VPN"}),
                ]):
            result = self.client.apply_dns(self.old, self.plan)
            self.assertEqual(result[0], self.plan.expected)
            self.assertTrue(Path(result[2]).exists())
        self.assertEqual(s.calls[0], self.plan.ops[0].commands[0])
        self.assertEqual(s.calls[-1], "system configuration save")

    def test_changed_dns_snapshot_blocks_all_commands(self):
        s = self.Session()
        changed = plan_group(self.old, "DNS_NEW", "example.com").expected
        with patch.object(DnsClient, "_session", return_value=s), \
             patch.object(DnsClient, "_read_dns", return_value=(changed, {"Wireguard2": "VPN"})):
            with self.assertRaisesRegex(RuntimeError, "изменились"):
                self.client.apply_dns(self.old, self.plan)
        self.assertEqual(s.calls, [])

    def test_router_failure_attempts_rollback_without_save(self):
        command = self.plan.ops[0].commands[0]
        s = self.Session(fail=command)
        with tempfile.TemporaryDirectory() as home, \
                patch.dict("os.environ", {"LOCALAPPDATA": home}), \
                patch.object(DnsClient, "_session", return_value=s), \
                patch.object(DnsClient, "_read_dns", side_effect=[
                    (self.old, {"Wireguard2": "VPN"}),
                    (self.old, {"Wireguard2": "VPN"}),
                ]):
            with self.assertRaisesRegex(RuntimeError, "не сохранено"):
                self.client.apply_dns(self.old, self.plan)
        self.assertNotIn("system configuration save", s.calls)
        self.assertIn(self.plan.ops[0].inverse[0], s.calls)


if __name__ == "__main__":
    unittest.main()