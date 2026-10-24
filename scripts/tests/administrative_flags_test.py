# SPDX-License-Identifier: GPL-3.0-or-later
"""Check administrative flag observations through the actual IPv4 and UDP clients."""
from pathlib import Path
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]


class AdministrativeFlags(unittest.TestCase):
    def test_both_actual_helpers_require_down_and_not_running(self):
        with tempfile.TemporaryDirectory(prefix='axiom64-administrative-flags-') as temporary:
            for profile in ('ipv4', 'udp'):
                program = Path(temporary) / profile
                command = ['gcc', '-std=gnu11', '-O2', '-Wall', '-Wextra', '-Werror',
                    '-ffunction-sections', '-fdata-sections',
                    'userspace/tests/net/administrative_flags_model.c',
                    *(['-DIPV4_CONTROL_MODEL'] if profile == 'ipv4' else []),
                    '-Wl,--gc-sections', '-Wl,--wrap=ioctl', '-pthread', '-o', str(program)]
                result = subprocess.run(command, cwd=ROOT, capture_output=True)
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                for flags in ('1002', '1003', '1042', '1043'):
                    with self.subTest(profile=profile, flags=flags):
                        result = subprocess.run([str(program), flags], capture_output=True, timeout=2)
                        if flags == '1002':
                            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                            self.assertEqual(result.stdout,
                                (profile.upper() + '_ADMIN_DOWN index=1 flags=1002\n').encode())
                        else:
                            self.assertNotEqual(result.returncode, 0)
                            self.assertIn(b'clears operational flags', result.stderr)


if __name__ == '__main__':
    unittest.main()
