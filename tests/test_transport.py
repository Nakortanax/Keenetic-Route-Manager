"""Local in-memory fake Telnet server; does not contact an actual router."""
import socket
import threading
import unittest
from keenetic_manager.transport import TelnetSession

class TransportTests(unittest.TestCase):
    def test_handshake_and_read(self):
        server=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
        server.bind(('127.0.0.1',0));server.listen(1)
        port=server.getsockname()[1]
        failures=[]
        def serving():
            try:
                conn,_=server.accept()
                with conn:
                    conn.sendall(b'Welcome to Keenetic\r\nLogin: ')
                    for expected, response in (
                        (b'admin',b'Password: '),
                        (b'secret',b'(config)> '),
                        (b'show running-config',b'ip route 1.1.1.0 255.255.255.0 Wireguard2 auto\r\n(config)> '),
                    ):
                        val=conn.recv(1024)
                        if expected not in val:raise AssertionError((val,expected))
                        conn.sendall(response)
            except Exception as exc:
                failures.append(exc)
            finally:
                server.close()
        runner=threading.Thread(target=serving,daemon=True);runner.start()
        with TelnetSession('127.0.0.1',port,'admin','secret') as connection:
            self.assertIn('ip route',connection.command('show running-config'))
        runner.join(timeout=4)
        self.assertFalse(failures,failures)

    def test_large_streamed_running_config(self):
        import time
        from keenetic_manager.core import parse_running_config
        server=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
        server.bind(('127.0.0.1',0));server.listen(1)
        port=server.getsockname()[1]
        errors=[]
        lines=[f"ip route 10.{(n//256)%256}.{n%256}.0 255.255.255.0 Wireguard2 auto\r\n" for n in range(3500)]
        payload="".join(lines).encode()
        def serving():
            try:
                c,_=server.accept()
                with c:
                    c.sendall(b"Login: ")
                    self.assertIn(b"admin",c.recv(1024))
                    c.sendall(b"Password: ")
                    self.assertIn(b"secret",c.recv(1024))
                    c.sendall(b"(config)> ")
                    self.assertIn(b"show running-config",c.recv(1024))
                    # Stream in small bursts to model constrained router output.
                    for i in range(0,len(payload),1321):
                        c.sendall(payload[i:i+1321])
                        time.sleep(0.001)
                    c.sendall(b"(config)> ")
            except Exception as exc:
                errors.append(exc)
            finally:
                server.close()
        runner=threading.Thread(target=serving,daemon=True);runner.start()
        with TelnetSession('127.0.0.1',port,'admin','secret') as session:
            answer=session.command("show running-config",timeout=10,inactivity=4)
        runner.join(timeout=4)
        self.assertFalse(errors,errors)
        routes,rejected=parse_running_config(answer)
        self.assertFalse(rejected)
        self.assertEqual(len(routes),3500)

    def test_pager_and_ansi_prompt(self):
        server=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
        server.bind(('127.0.0.1',0));server.listen(1)
        port=server.getsockname()[1]
        failures=[]
        def serving():
            try:
                c,_=server.accept()
                with c:
                    c.sendall(b'Login: ')
                    c.recv(1024)
                    c.sendall(b'Password: ')
                    c.recv(1024)
                    c.sendall(b'(config)> ')
                    c.recv(1024)
                    c.sendall(b'ip route 1.2.3.4 Wireguard2 auto\r\n--Mo')
                    c.sendall(b're--')
                    self.assertIn(b' ',c.recv(1024))
                    c.sendall(b'\r\nip route 5.6.7.8 Wireguard2 auto\r\n\x1b[0m(config)> ')
            except Exception as exc:
                failures.append(exc)
            finally:server.close()
        runner=threading.Thread(target=serving,daemon=True);runner.start()
        with TelnetSession('127.0.0.1',port,'admin','secret') as session:
            answer=session.command("show running-config",timeout=10,inactivity=4)
        runner.join(timeout=4)
        self.assertFalse(failures,failures)
        self.assertIn('ip route 1.2.3.4',answer)
        self.assertIn('ip route 5.6.7.8',answer)

if __name__=='__main__':unittest.main()
