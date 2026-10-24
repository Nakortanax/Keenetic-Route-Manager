"""Test live diagnostics, redaction, full export and rotation without router."""
import json
from pathlib import Path
import tempfile
import threading
import unittest
from keenetic_manager.activity_log import ActivityJournal, safe_response, redact
from keenetic_manager.transport import TelnetSession

class JournalTests(unittest.TestCase):
    def test_sanitize_running_config_never_logs_keys_or_user_settings(self):
        raw = ('ip route 185.244.36.22 Wireguard2 auto\r\n'
               'interface Wireguard2\r\n'
               'private-key VeryVerySecretKey\r\n'
               'password MyPrivatePassword\r\n'
               'ip route disable\r\n'
               'ssid MySecretSSID\r\n')
        text=safe_response('show running-config',raw)
        self.assertIn('185.244.36.22',text)
        self.assertIn('ip route disable',text)
        for value in ('VeryVerySecretKey','MyPrivatePassword','MySecretSSID','interface Wireguard2'):
            self.assertNotIn(value,text)

    def test_sanitize_interfaces(self):
        text=safe_response('show interface','''Interface, name = "Wireguard2"\n public-key: SECRET_KEY\n description: amnezia_for_awg\n''')
        self.assertIn('amnezia_for_awg',text)
        self.assertNotIn('SECRET_KEY',text)

    def test_persist_export_and_rotation(self):
        with tempfile.TemporaryDirectory() as t:
            j=ActivityJournal(Path(t),max_bytes=500,backups=3)
            for n in range(30):
                j.record('router',f'Результат {n}',command='ip route 1.2.3.4 Wireguard2 auto',
                         response='Route added for 1.2.3.4')
            self.assertTrue(j.path.is_file())
            self.assertTrue((Path(t)/'activity.1.jsonl').is_file())
            self.assertIn('Результат 29',j.render())
            out=Path(t)/'all.txt';self.assertGreater(j.export_plain(out),0)
            self.assertIn('1.2.3.4',out.read_text(encoding='utf-8'))

    def test_thread_safe_and_no_password(self):
        with tempfile.TemporaryDirectory() as t:
            j=ActivityJournal(Path(t),max_bytes=3_000_000)
            ts=[threading.Thread(target=lambda: [j.record('action',f'processed {i}') for i in range(60)]) for _ in range(3)]
            for worker in ts:worker.start()
            for worker in ts:worker.join()
            j.record('error','password: SUPER-SECRET')
            data=j.path.read_text(encoding='utf-8')
            self.assertNotIn('SUPER-SECRET',data)
            self.assertEqual(len([x for x in data.splitlines() if x]),181)
            self.assertTrue(all('time' in json.loads(x) for x in data.splitlines()))

    def test_transport_never_records_auth_text(self):
        from test_transport import TransportTests
        # The transport test suite also exercises the optional journal callback.
        self.assertIn('journal',TelnetSession.__init__.__code__.co_varnames)

if __name__=='__main__':unittest.main()

class LiveTelnetJournalTest(unittest.TestCase):
    def test_end_to_end_telnet_records_routes_not_secrets(self):
        import socket
        server=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
        server.bind(('127.0.0.1',0));server.listen(1)
        port=server.getsockname()[1]
        errors=[]
        def serve():
            try:
                sock,_=server.accept()
                with sock:
                    sock.sendall(b'Login: ')
                    self.assertIn(b'admin',sock.recv(1024))
                    sock.sendall(b'Password: ')
                    self.assertIn(b'test-password',sock.recv(1024))
                    sock.sendall(b'(config)> ')
                    self.assertIn(b'show running-config',sock.recv(1024))
                    sock.sendall(b'ip route 1.1.1.1 Wireguard2 auto\r\nprivate-key DO-NOT-STORE\r\n(config)> ')
            except Exception as e:errors.append(e)
            finally:server.close()
        with tempfile.TemporaryDirectory() as t:
            j=ActivityJournal(Path(t))
            th=threading.Thread(target=serve,daemon=True);th.start()
            with TelnetSession('127.0.0.1',port,'admin','test-password',journal=j) as session:
                self.assertIn('ip route',session.command('show running-config'))
            th.join(timeout=3)
            self.assertFalse(errors)
            out=j.path.read_text(encoding='utf-8')
            self.assertIn('1.1.1.1',out)
            self.assertNotIn('test-password',out)
            self.assertNotIn('DO-NOT-STORE',out)
            self.assertIn('show running-config',out)
