import os
import unittest

try:
    from PySide6.QtWidgets import QApplication
    from PySide6.QtCore import Qt
    HAVE_QT=True
except ImportError:
    HAVE_QT=False

@unittest.skipUnless(HAVE_QT, 'PySide6 not installed in test environment')
class QtSmoke(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        os.environ['QT_QPA_PLATFORM']='offscreen'
        cls.app=QApplication.instance() or QApplication([])

    def test_window_layout(self):
        from main import MainWindow
        window=MainWindow()
        self.assertEqual(window.stack.count(),5)
        self.assertEqual(window.model.columnCount(),9)
        self.assertEqual(window.ip.text(),'192.168.1.1')
        self.assertFalse(window.loaded)
        window.close()

    def test_model_search_and_titles(self):
        from main import RouteModel, RouteFilter
        from keenetic_manager.core import Route
        from ipaddress import ip_network
        model=RouteModel(); model.update([Route(ip_network('185.244.36.22/32'), 'Wireguard2')],{'Wireguard2':'amnezia_for_awg'},None)
        proxy=RouteFilter();proxy.setSourceModel(model)
        proxy.set_search('185.244')
        self.assertEqual(proxy.rowCount(),1)
        proxy.set_search('not-present')
        self.assertEqual(proxy.rowCount(),0)
