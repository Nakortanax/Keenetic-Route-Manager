import unittest
from ipaddress import ip_network
from keenetic_manager.core import *

class RouteTests(unittest.TestCase):
    def test_parses_cli_host(self):
        r=parse_cli_route('ip route 185.244.36.22 Wireguard2 auto')
        self.assertEqual(r.cidr,'185.244.36.22/32')
        self.assertTrue(r.auto)
        self.assertEqual(r.interface,'Wireguard2')
    def test_parses_cli_mask(self):
        r=parse_cli_route('ip route 185.244.36.0 255.255.255.0 Wireguard2 auto')
        self.assertEqual(r.cidr,'185.244.36.0/24')
    def test_gateway_readonly(self):
        r=parse_cli_route('ip route 1.1.1.1 192.168.0.1')
        self.assertFalse(can_edit(r))
    def test_default_readonly(self):
        r=parse_cli_route('ip route default ISP')
        self.assertFalse(can_edit(r))
    def test_interface_parser(self):
        src='Interface, name = "Wireguard2"\n      id: Wireguard2\n      description: amnezia_for_awg\nInterface, name = "Wireguard0"\n      id: Wireguard0\n      description: old'
        self.assertEqual(parse_interface_descriptions(src)['Wireguard2'],'amnezia_for_awg')
    def test_bat(self):
        rr, errors=parse_bat_routes('route add 185.244.36.22 mask 255.255.255.255 0.0.0.0','Wireguard2')
        self.assertFalse(errors)
        self.assertEqual(rr[0].cidr,'185.244.36.22/32')
    def test_coverage(self):
        old=[Route(ip_network('87.245.0.0/16'), 'Wireguard2')]
        new=Route(ip_network('87.245.138.105/32'),'Wireguard2')
        self.assertTrue(coverage(new, old)[0])
    def test_conflict(self):
        old=[Route(ip_network('87.245.0.0/16'), 'Wireguard0')]
        new=Route(ip_network('87.245.138.105/32'),'Wireguard2')
        self.assertFalse(coverage(new, old)[0])
        self.assertEqual(len(coverage(new,old)[1]),1)
    def test_commands(self):
        r=Route(ip_network('185.244.36.22/32'),'Wireguard2',True)
        self.assertEqual(add_command(r),'ip route 185.244.36.22 Wireguard2 auto')
        self.assertEqual(delete_command(r),'no ip route 185.244.36.22 Wireguard2')
    def test_cli_network_mask_format(self):
        r=Route(ip_network('10.44.0.0/16'),'Wireguard2',True)
        self.assertEqual(add_command(r), 'ip route 10.44.0.0 255.255.0.0 Wireguard2 auto')
        self.assertEqual(delete_command(r), 'no ip route 10.44.0.0 255.255.0.0 Wireguard2')

    def test_parses_multiple_routes(self):
        text='some password SECRET\nip route 192.0.2.0 255.255.255.0 ISP\nip route 185.244.36.22 Wireguard2 auto\n'
        r,e=parse_running_config(text)
        self.assertFalse(e)
        self.assertEqual(len(r),2)
        self.assertNotIn('SECRET',export_text(r,'json'))
    def test_keenetic_reject_flag_is_readonly_and_preserved(self):
        r=parse_cli_route('ip route 185.244.36.0 255.255.255.0 Wireguard2 auto reject ! site')
        self.assertEqual(r.cidr,'185.244.36.0/24')
        self.assertTrue(r.reject)
        self.assertFalse(can_edit(r))
        self.assertIn('"reject": true', export_text([r], 'json'))
        self.assertFalse(export_text([r], 'bat').strip())

    def test_disabled_route_attaches_to_previous(self):
        blob=("ip route 198.51.100.10 Wireguard0 auto\n"
              "ip route disable\n"
              "ip route 185.244.36.22 Wireguard2 auto\n")
        routes, errors=parse_running_config(blob)
        self.assertEqual(errors, [])
        self.assertEqual(len(routes), 2)
        self.assertTrue(routes[0].disabled)
        self.assertFalse(routes[1].disabled)
        self.assertFalse(can_edit(routes[0]))
        self.assertTrue(can_edit(routes[1]))
        self.assertIn('"disabled": true',export_text(routes,'json'))
        self.assertIn('true',export_text(routes,'csv'))
        self.assertIn('ip route disable',export_text(routes,'cli'))
        self.assertNotIn('198.51.100.10',export_text(routes,'bat'))
        self.assertIn('185.244.36.22',export_text(routes,'bat'))

    def test_disable_orphan_does_not_unlock_writes(self):
        routes, errors=parse_running_config('ip route disable\nip route 185.244.36.22 Wireguard2 auto')
        self.assertEqual(len(routes),1)
        self.assertEqual(errors,['ip route disable'])

    def test_disable_marker_not_applied_across_another_command(self):
        routes,errors=parse_running_config('ip route 185.244.36.22 Wireguard2 auto\n'
                                          'ip domain name test\nip route disable')
        self.assertEqual(len(routes),1)
        self.assertFalse(routes[0].disabled)
        self.assertEqual(errors,['ip route disable'])

    def test_repeated_disable_fails_closed(self):
        routes,errors=parse_running_config('ip route 185.244.36.22 Wireguard2 auto\n'
                                          'ip route disable\nip route disable')
        self.assertTrue(routes[0].disabled)
        self.assertEqual(errors,['ip route disable'])

    def test_disabled_is_not_active_coverage(self):
        r=Route(ip_network('185.244.36.22/32'),'Wireguard2')
        disabled=Route(ip_network('185.244.36.0/24'),'Wireguard2',disabled=True)
        self.assertFalse(coverage(r,[disabled])[0])
        self.assertEqual(coverage(r,[disabled])[1],[disabled])

    def test_3478_routes_and_one_disable_marker(self):
        entries=[f'ip route 10.{(i//256)%256}.{i%256}.0 255.255.255.0 Wireguard2 auto' for i in range(3478)]
        entries.insert(214,'ip route disable')
        routes,errors=parse_running_config('\n'.join(entries))
        self.assertEqual(len(routes),3478)
        self.assertFalse(errors)
        self.assertEqual(sum(r.disabled for r in routes),1)

    def test_metric_positional_and_keyed(self):
        a=parse_cli_route('ip route 8.8.8.8 Wireguard2 auto 15')
        b=parse_cli_route('ip route 8.8.8.8 Wireguard2 metric 15 auto')
        self.assertEqual(a.metric,'15')
        self.assertEqual(b.metric,'15')
        self.assertEqual(add_command(a),'ip route 8.8.8.8 Wireguard2 auto 15')

    def test_route_with_gateway_interface_and_prefix(self):
        r=parse_cli_route('ip route 10.3.4.0 /24 192.168.0.1 ISP auto')
        self.assertEqual(r.cidr,'10.3.4.0/24')
        self.assertEqual(r.interface,'ISP')
        self.assertEqual(r.gateway,'192.168.0.1')
        self.assertFalse(can_edit(r))

    def test_unknown_route_option_must_not_be_discarded(self):
        r,e=parse_running_config('ip route 192.0.2.0 255.255.255.0 Wireguard2 auto foobar')
        self.assertFalse(r)
        self.assertEqual(len(e),1)

    def test_import_cannot_drop_reject_flag(self):
        r,e=parse_text_routes('ip route 1.1.1.0 255.255.255.0 Wireguard2 auto reject', 'Wireguard2')
        self.assertFalse(e)
        self.assertTrue(r[0].reject)
        self.assertFalse(can_edit(r[0]))

    def test_csv_export(self):
        r=[Route(ip_network('1.2.3.4/32'),'Wireguard2')]
        self.assertIn('1.2.3.4/32,Wireguard2',export_text(r,'csv'))
    def test_import_unknowable(self):
        r,e=parse_text_routes('route add 1.2.3.4 mask 255.255.255.255 0.0.0.0\nBAD CMD','Wireguard2')
        self.assertEqual(len(r),1)
        self.assertEqual(e,['BAD CMD'])
    def test_testdata_2900_routes(self):
        from pathlib import Path
        file=Path(__file__).parents[1]/'test-fixtures'/'sample_routes.bat'
        if not file.exists():return
        r,errs=parse_bat_routes(file.read_text(),'Wireguard2')
        self.assertFalse(errs)
        self.assertGreater(len(r),100)

if __name__=='__main__':unittest.main()
