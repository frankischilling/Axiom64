# SPDX-License-Identifier: GPL-3.0-or-later
"""Require complete actual device records even when writes fail."""
from pathlib import Path
import re
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]


class DeviceRecords(unittest.TestCase):
    def test_one_checked_write_preserves_every_field(self):
        with tempfile.TemporaryDirectory(prefix='axiom64-device-record-') as temporary:
            program = Path(temporary) / 'device-record'
            build = subprocess.run(['gcc', '-std=gnu11', '-O2', '-Wall', '-Wextra', '-Werror',
                '-ffunction-sections', '-fdata-sections',
                'userspace/tests/net/ipv6_device_record_model.c', '-Wl,--gc-sections',
                '-Wl,--wrap=write', '-o', str(program)], cwd=ROOT, capture_output=True)
            self.assertEqual(build.returncode, 0, build.stdout + build.stderr)
            for case in ('ordinary', 'maximum', 'short', 'interrupted'):
                with self.subTest(case=case):
                    result = subprocess.run([str(program), case], capture_output=True, timeout=2)
                    if case in ('short', 'interrupted'):
                        self.assertNotEqual(result.returncode, 0)
                        self.assertIn(b'complete device query record', result.stdout + result.stderr)
                        continue
                    self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                    match = re.fullmatch(rb'IPV6_DEVICE_CONTROL lane=1 phase=(\d+) kind=2 action=2 '
                        rb'subject=0 stage=4 flags=([0-9a-f]+) preferred=4294967295 valid=4294967295 '
                        rb'target=fe80000000000000123456789abcdef0 observed_ns=(\d+)\n', result.stdout)
                    self.assertIsNotNone(match, result.stdout)
                    self.assertEqual(tuple(int(value, 16 if at == 1 else 10)
                        for at, value in enumerate(match.groups())),
                        (254, 0xffffffff, 0xffffffffffffffff) if case == 'maximum' else (7, 0x880, 123456789))


if __name__ == '__main__':
    unittest.main()
