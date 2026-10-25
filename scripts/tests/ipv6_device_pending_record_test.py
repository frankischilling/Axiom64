# SPDX-License-Identifier: GPL-3.0-or-later
"""Exercise the actual client's first-ready selection across inventory and polling."""
from pathlib import Path
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]


class FirstReadyRecord(unittest.TestCase):
    def test_first_observation_is_retained_once(self):
        with tempfile.TemporaryDirectory(prefix='axiom64-pending-record-') as temporary:
            program = Path(temporary) / 'first-ready'
            subprocess.run(['gcc', '-std=gnu11', '-O2', '-Wall', '-Wextra', '-Werror',
                            'userspace/tests/net/ipv6_device_pending_model.c', '-o', str(program)],
                           cwd=ROOT, check=True, capture_output=True)
            for case in ('first-inventory-ready', 'tentative', 'exhausted', 'administrative',
                         'mtu', 'already-recorded', 'invalid-flags', 'finite-lifetime'):
                with self.subTest(case=case):
                    result = subprocess.run([str(program), case], capture_output=True, timeout=2)
                    if case in ('invalid-flags', 'finite-lifetime'):
                        self.assertNotEqual(result.returncode, 0)
                        self.assertIn(b'exact first ready device during carrier loss',
                                      result.stdout + result.stderr)
                    else:
                        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                        self.assertEqual(result.stdout, b'IPV6_DEVICE_FIRST_READY_MODEL_PASS\n')


if __name__ == '__main__':
    unittest.main()
