import unittest
from keenetic_manager.interface_choices import build_interface_choices, default_interface
from keenetic_manager.core import parse_interface_descriptions

class InterfaceChoicesTests(unittest.TestCase):
    def setUp(self):
        self.interfaces = {
            'GigabitEthernet1': 'Ethernet',
            'Wireguard0': 'amnezia_for_awg_1',
            'Wireguard1': 'Wireguard VPN Server',
            'Wireguard2': 'amnezia_for_awg',
            'Bridge0': 'Primary',
        }

    def test_friendly_labels_show_id_and_description(self):
        choices = build_interface_choices(self.interfaces)
        self.assertEqual(len(choices),5)
        self.assertIn('amnezia_for_awg  [Wireguard2]', [x.label for x in choices])
        self.assertEqual(choices[0].identifier,'Wireguard2')

    def test_vpn_first(self):
        names = [x.identifier for x in build_interface_choices(self.interfaces)]
        self.assertTrue(all(n.startswith('Wireguard') for n in names[:3]))
        self.assertFalse(any(n.startswith('Wireguard') for n in names[3:]))

    def test_id_is_unique_even_if_duplicate_descriptions(self):
        choices=build_interface_choices({'Wireguard0':'amnezia','Wireguard2':'amnezia'})
        self.assertEqual(len(set(x.label for x in choices)),2)

    def test_rejects_malformed_ids(self):
        choices=build_interface_choices({'Wireguard2':'amnezia_for_awg','bad; system configuration save':'danger'})
        self.assertEqual([x.identifier for x in choices], ['Wireguard2'])

    def test_prefer_specific_interface_filter(self):
        self.assertEqual(default_interface(self.interfaces,'GigabitEthernet1'),'GigabitEthernet1')

    def test_prefers_new_awg_description_when_no_filter(self):
        self.assertEqual(default_interface(self.interfaces),'Wireguard2')
        self.assertEqual(default_interface(self.interfaces,'Wireguard999'),'Wireguard2')

    def test_does_not_guess_with_multiple_interfaces_and_no_awg(self):
        self.assertEqual(default_interface({'Wireguard0':'old','Bridge0':'LAN'}),'')

    def test_does_not_invent_interface(self):
        self.assertEqual(build_interface_choices({}),[])
        self.assertEqual(default_interface({}),'')

    def test_real_keenetic_style_text(self):
        text=('Interface, name = "ISP"\n                id: GigabitEthernet1\n       description: Ethernet\n'
              'Interface, name = "Wireguard0"\n                id: Wireguard0\n       description: amnezia_for_awg_1\n'
              'Interface, name = "Wireguard2"\n                id: Wireguard2\n       description: amnezia_for_awg\n')
        parsed=parse_interface_descriptions(text)
        self.assertEqual(default_interface(parsed),'Wireguard2')
        self.assertIn('amnezia_for_awg  [Wireguard2]', [x.label for x in build_interface_choices(parsed)])

if __name__=='__main__': unittest.main()
