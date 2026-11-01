# SPDX-License-Identifier: GPL-3.0-or-later
"""Exercise the real socket guard when its serial acknowledgment runs late."""
from pathlib import Path
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]


class SourceGuard(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temporary = tempfile.TemporaryDirectory(prefix='axiom64-source-guard-')
        cls.addClassCleanup(cls.temporary.cleanup)
        cls.program = Path(cls.temporary.name) / 'guard'
        subprocess.run(['gcc', '-std=c11', '-O2', '-Wall', '-Wextra', '-Werror',
                        str(ROOT / 'scripts/tests/native_source_guard_regression.c'),
                        '-o', str(cls.program)], cwd=ROOT, check=True, capture_output=True)

    def run_scenario(self, name):
        return subprocess.run([str(self.program), name], text=True, capture_output=True, timeout=5)

    def test_acknowledgment_after_error_preserves_prior_empty_proof(self):
        value = self.run_scenario('late-ack')
        self.assertEqual(value.returncode, 0, value.stderr)
        self.assertIn('IPV4_SOURCE_GUARD case=0 packets=1 revents=0', value.stdout)
        self.assertIn('IPV4_SOURCE_GUARD_ACK case=0', value.stdout)

    def test_early_ready_consumed_short_missing_and_duplicate_proofs_fail(self):
        for name in ('early-ready', 'already-consumed', 'short-quiet', 'missing-proof', 'duplicate-ack'):
            with self.subTest(scenario=name):
                value = self.run_scenario(name)
                self.assertEqual(value.returncode, 1)
                self.assertIn('IPV4_SOURCE_WIRE_FAIL', value.stderr)


if __name__ == '__main__':
    unittest.main()
