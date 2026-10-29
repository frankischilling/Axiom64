# SPDX-License-Identifier: GPL-3.0-or-later
"""Require Linux administrative-down flags in the actual packet client."""
from pathlib import Path
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]


class PacketAdministrativeFlags(unittest.TestCase):
    def test_native_flags_pass_and_operational_or_missing_flags_reject(self):
        with tempfile.TemporaryDirectory(prefix='axiom64-packet-administrative-') as temporary:
            program = Path(temporary) / 'administrative'
            build = subprocess.run(['gcc', '-std=gnu11', '-O2', '-Wall', '-Wextra', '-Werror',
                'userspace/tests/net/packet_administrative_model.c', '-Wl,--wrap=ioctl',
                '-o', str(program)], cwd=ROOT, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
            self.assertEqual(build.returncode, 0, build.stdout.decode(errors='replace'))
            for name in ('linux', 'running', 'up', 'both', 'empty'):
                with self.subTest(name=name):
                    result = subprocess.run([str(program), name], stdout=subprocess.PIPE,
                                            stderr=subprocess.STDOUT, timeout=2)
                    self.assertEqual(result.returncode, 0 if name == 'linux' else 1,
                                     result.stdout.decode(errors='replace'))
                    self.assertIn(b'PACKET_ADMIN_FLAGS index=1 flags=', result.stdout)
                    if name == 'linux':
                        self.assertIn(b'PACKET_ADMINISTRATIVE_MODEL_PASS', result.stdout)


if __name__ == '__main__':
    unittest.main()
