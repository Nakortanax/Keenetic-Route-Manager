import unittest
from ipaddress import IPv4Network
from keenetic_manager.core import Route
from keenetic_manager.site_routes import site_ip_status, plan_site_interface_change
from keenetic_manager.interface_choices import build_interface_choices
from keenetic_manager.core import parse_interface_descriptions, add_command, delete_command


def route(cidr, iface, auto=True, **kwargs):
    return Route(IPv4Network(cidr), iface, auto, **kwargs)


class SiteMoveTests(unittest.TestCase):
    def test_route_lookup_uses_longest_prefix_and_shows_all(self):
        rr=[route('188.114.0.0/16','Wireguard2'),route('188.114.96.1/32','ISP')]
        d=site_ip_status('188.114.96.1',rr)
        self.assertEqual(len(d.matches),2)
        self.assertEqual(d.label,'ISP')
        self.assertEqual(d.best[0].cidr,'188.114.96.1/32')

    def test_switch_shared_network_adds_host_only(self):
        rr=[route('188.114.0.0/16','Wireguard2')]
        adds,removes,notes=plan_site_interface_change(['188.114.96.1','188.114.97.1'],rr,'ISP')
        self.assertEqual({x.cidr for x in adds},{'188.114.96.1/32','188.114.97.1/32'})
        self.assertEqual({x.interface for x in adds},{'ISP'})
        self.assertEqual(removes,[])
        self.assertIn('ip route 188.114.96.1 ISP auto',[add_command(x) for x in adds])
        self.assertTrue(any('широкие маршруты не меняем' in n for n in notes))

    def test_switch_exact_to_other_interface_removes_exact(self):
        rr=[route('188.114.96.1/32','Wireguard2'),route('188.114.0.0/16','Wireguard2')]
        adds,removes,_=plan_site_interface_change(['188.114.96.1'],rr,'ISP')
        self.assertEqual([x.cidr for x in removes],['188.114.96.1/32'])
        self.assertEqual(adds[0].interface,'ISP')
        self.assertEqual(delete_command(removes[0]), 'no ip route 188.114.96.1 Wireguard2')

    def test_already_covered_by_target_does_not_write(self):
        rr=[route('188.114.0.0/16','Wireguard2')]
        adds,removes,notes=plan_site_interface_change(['188.114.96.1'],rr,'Wireguard2')
        self.assertEqual(adds,[])
        self.assertEqual(removes,[])
        self.assertTrue(any('покрыт' in note for note in notes))

    def test_target_broad_but_other_host_removes_exact(self):
        rr=[route('188.114.0.0/16','ISP'),route('188.114.96.1/32','Wireguard2')]
        adds,removes,_=plan_site_interface_change(['188.114.96.1'],rr,'ISP')
        self.assertEqual([x.cidr for x in adds],['188.114.96.1/32'])
        self.assertEqual([x.cidr for x in removes],['188.114.96.1/32'])

    def test_disabled_target_exact_is_not_duplicated(self):
        rr=[route('188.114.96.1/32','ISP',disabled=True)]
        with self.assertRaisesRegex(ValueError,'отключённый'):
            plan_site_interface_change(['188.114.96.1'],rr,'ISP')

    def test_gateway_host_must_not_be_silently_removed(self):
        rr=[route('188.114.96.1/32','',gateway='192.168.0.1')]
        with self.assertRaisesRegex(ValueError,'защищённый'):
            plan_site_interface_change(['188.114.96.1'],rr,'Wireguard2')

    def test_exact_same_target_competing_interface(self):
        rr=[route('188.114.96.1/32','ISP'),route('188.114.96.1/32','Wireguard2')]
        adds,removes,_=plan_site_interface_change(['188.114.96.1'],rr,'ISP')
        self.assertEqual(adds,[])
        self.assertEqual([x.interface for x in removes],['Wireguard2'])

    def test_disabled_route_not_considered_active(self):
        rr=[route('188.114.96.1/32','Wireguard2',disabled=True)]
        d=site_ip_status('188.114.96.1',rr)
        self.assertEqual(len(d.matches),1)
        self.assertEqual(d.best,())
        adds,removes,_=plan_site_interface_change(['188.114.96.1'],rr,'ISP')
        self.assertEqual(len(adds),1)
        self.assertEqual(removes,[])

    def test_isp_is_route_cli_name_for_ethernet(self):
        src=('Interface, name = "ISP"\n                id: GigabitEthernet1\n'
             '       description:                        Ethernet\n'
             'Interface, name = "Wireguard2"\n                id: Wireguard2\n'
             '       description: amnezia_for_awg\n')
        interfaces=parse_interface_descriptions(src)
        self.assertIn('ISP',interfaces)
        self.assertNotIn('GigabitEthernet1',interfaces)
        options={x.identifier:x.label for x in build_interface_choices(interfaces)}
        self.assertEqual(options['ISP'],'ISP — проводной Ethernet [GigabitEthernet1]')
        self.assertIn('Wireguard2',options)

if __name__ == '__main__': unittest.main()
