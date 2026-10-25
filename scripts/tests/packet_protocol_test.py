# SPDX-License-Identifier: GPL-3.0-or-later
"""Check actual packet demultiplexing with original captured Ethernet bytes."""
from pathlib import Path
import os
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'scripts'))
from ipv6_router_capture import qemu_records


class PacketProtocol(unittest.TestCase):
    def test_outgoing_all_protocol_and_incoming_selected_protocol(self):
        capture = ROOT / 'scripts/tests/fixtures/ipv6-device-pending/axiom-carrier-probing/lane0.pcap'
        frame = next(row['frame'] for row in qemu_records(capture)
                     if len(row['frame']) == 86 and row['frame'][54] == 135)
        with tempfile.TemporaryDirectory(prefix='axiom64-packet-protocol-') as temporary:
            directory = Path(temporary)
            packet = directory / 'original-frame.bin'
            packet.write_bytes(frame)
            program = directory / 'model'
            build = subprocess.run(['g++', '-std=c++20', '-O2', '-g', '-Wall', '-Wextra', '-Werror',
                '-fsanitize=address,undefined', '-fno-omit-frame-pointer', '-ffunction-sections',
                '-fdata-sections', '-Wl,--gc-sections', '-Ikernel/include',
                'kernel/tests/net/packet.cpp', '-o', str(program)], cwd=ROOT,
                stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
            self.assertEqual(build.returncode, 0, build.stdout.decode(errors='replace'))
            environment = dict(os.environ, ASAN_OPTIONS='detect_leaks=1',
                               UBSAN_OPTIONS='halt_on_error=1:print_stacktrace=1')
            for direction in ('outgoing', 'incoming'):
                with self.subTest(direction=direction):
                    result = subprocess.run([str(program), direction, str(packet)], env=environment,
                        stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=5)
                    self.assertEqual(result.returncode, 0, result.stdout.decode(errors='replace'))
                    self.assertIn(b'passed=true', result.stdout)
            self.assertEqual(packet.read_bytes(), frame)


if __name__ == '__main__':
    unittest.main()