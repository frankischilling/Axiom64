#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Exercise the actual ICMP fixture after live and TIME_WAIT automatic port ownership."""
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]


def namespace(program, mode, parent):
    if os.readlink('/proc/self/ns/net') == parent:
        raise RuntimeError('port controls must run in their own network namespace')
    subprocess.run(['ip', 'link', 'set', 'lo', 'up'], check=True)
    for address in ('10.23.1.1', '10.23.1.2', '10.23.2.2'):
        subprocess.run(['ip', 'address', 'add', address + '/32', 'dev', 'lo'], check=True)
    Path('/proc/sys/net/ipv4/ip_local_port_range').write_text('41000 41003\n')
    os.execv(program, [program, mode])


class PortOwnership(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if os.geteuid():
            raise RuntimeError('run as root to create isolated native network namespaces')
        cls.temporary = tempfile.TemporaryDirectory(prefix='axiom-icmp-port-ownership-')
        cls.addClassCleanup(cls.temporary.cleanup)
        cls.program = Path(cls.temporary.name) / 'program'
        subprocess.run(['gcc', '-std=c11', '-O2', '-Wall', '-Wextra', '-Werror', '-pthread',
                        str(ROOT / 'scripts/tests/tcp_icmp_port_ownership.c'),
                        '-o', str(cls.program)], check=True)

    def check_case(self, mode):
        process = subprocess.run(['unshare', '--net', sys.executable, '-B', __file__,
                                  '--namespace', str(self.program), mode,
                                  os.readlink('/proc/self/ns/net')], capture_output=True,
                                 text=True, timeout=15)
        self.assertEqual(process.returncode, 0, process.stdout + process.stderr)
        self.assertIn('TCP_ICMP_PORT_OWNERSHIP_PASS', process.stdout)

    def test_fresh_reclamation_port(self):
        self.check_case('fresh')

    def test_live_automatic_source_preserves_reclamation_port(self):
        self.check_case('live')

    def test_time_wait_automatic_source_preserves_reclamation_port(self):
        self.check_case('closed')


if __name__ == '__main__':
    if len(sys.argv) == 5 and sys.argv[1] == '--namespace':
        namespace(*sys.argv[2:])
    else:
        unittest.main()
