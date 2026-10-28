# SPDX-License-Identifier: GPL-3.0-or-later
"""Exercise the native error destination reservation through actual Linux sockets."""
import json
from pathlib import Path
import select
import socket
import subprocess
import sys
import unittest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'scripts'))
from ipv6_host_native import reserve_error_destination

POLICY = Path('/proc/sys/net/ipv4/ip_local_reserved_ports')


def child(parent_namespace, existing):
    subprocess.run(['ip', 'link', 'set', 'lo', 'up'], check=True)
    Path('/proc/sys/net/ipv4/ip_local_port_range').write_text('59999 60000\n')
    POLICY.write_text(existing + '\n')
    clock_paths = [Path('/proc/sys/' + name.replace('.', '/')) for name in (
        'net.ipv4.icmp_msgs_per_sec', 'net.ipv4.icmp_msgs_burst',
        'net.ipv6.icmp.ratelimit', 'net.ipv6.icmp.ratemask')]
    clocks = {path: path.read_text() if path.exists() else None for path in clock_paths}
    before = POLICY.read_text()
    reservation = reserve_error_destination(parent_namespace)
    assert reservation['before'] == before
    assert reservation['port'] == 59999
    assert reservation['network_namespace'] != parent_namespace
    assert reservation['ephemeral_range'].split() == ['59999', '60000']
    assert reserve_error_destination(parent_namespace)['before'] == reservation['after']
    expected = '1-3,59999,65000\n' if existing else '59999\n'
    assert POLICY.read_text() == expected
    payload = bytes(at * 7 + 3 for at in range(32))
    for number in range(16):
        with socket.socket(socket.AF_INET6, socket.SOCK_DGRAM) as peer:
            peer.setsockopt(socket.IPPROTO_IPV6, 25, 1)
            peer.connect(('::1', 59999))
            assert peer.getsockname()[1] == 60000
            assert peer.send(payload) == len(payload)
            poller = select.poll()
            poller.register(peer, select.POLLERR)
            events = poller.poll(5000)
            assert events and events[0][1] & select.POLLERR
            received, controls, flags, address = peer.recvmsg(32, 192, socket.MSG_ERRQUEUE)
            assert received == payload and flags & socket.MSG_ERRQUEUE
            assert address[:2] == ('::1', 59999)
            assert len(controls) == 1 and controls[0][:2] == (41, 25)
            assert int.from_bytes(controls[0][2][:4], 'little') == 111
    with socket.socket(socket.AF_INET6, socket.SOCK_DGRAM) as explicit:
        explicit.bind(('::1', 59999))
        assert explicit.getsockname()[1] == 59999
    assert all((path.read_text() if path.exists() else None) == value
               for path, value in clocks.items())
    print(json.dumps(dict(passed=True, allocation_cases=16, reservation=reservation)))


class ErrorDestination(unittest.TestCase):
    def test_parent_namespace_is_rejected_without_writing(self):
        before = POLICY.read_bytes()
        with self.assertRaisesRegex(ValueError, 'private network namespace'):
            reserve_error_destination(Path('/proc/self/ns/net').stat().st_ino)
        self.assertEqual(POLICY.read_bytes(), before)

    def test_actual_allocation_and_errors_preserve_existing_reservations(self):
        before = POLICY.read_bytes()
        for existing in ('', '1-3,65000'):
            with self.subTest(existing=existing):
                observed = subprocess.run(['unshare', '--net', sys.executable, str(Path(__file__)),
                    '--child', str(Path('/proc/self/ns/net').stat().st_ino), existing],
                    stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=20)
                self.assertEqual(observed.returncode, 0, observed.stderr)
                result = json.loads(observed.stdout)
                self.assertTrue(result['passed'])
                self.assertEqual(result['allocation_cases'], 16)
        self.assertEqual(POLICY.read_bytes(), before)


if __name__ == '__main__':
    if len(sys.argv) > 1 and sys.argv[1] == '--child':
        child(int(sys.argv[2]), sys.argv[3])
    else:
        unittest.main()
