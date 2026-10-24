# SPDX-License-Identifier: GPL-3.0-or-later
"""Keep actual native client arguments and exit status intact across the launcher."""
import json
from pathlib import Path
import subprocess
import sys
import unittest

SCRIPT = Path(__file__).resolve().parents[1] / 'ipv6_dad_test.py'


class NativeClientLaunch(unittest.TestCase):
    def run_launch(self, arguments):
        return subprocess.run([sys.executable, '-B', str(SCRIPT), '--launch', *arguments],
                              stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=10)

    def test_client_options_are_forwarded_without_parsing(self):
        arguments = ['--retain-exhausted-routes', 'two words', '--directory', 'client-owned-value']
        result = self.run_launch([sys.executable, '-c',
            'import json,sys;print(json.dumps(sys.argv[1:]))', *arguments])
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(json.loads(result.stdout.splitlines()[0]), arguments)
        self.assertEqual(result.stdout.splitlines()[-1], 'TCP_FAULT_NATIVE_DONE status=0')

    def test_failed_client_status_is_preserved(self):
        result = self.run_launch(['/bin/false'])
        self.assertEqual(result.returncode, 1)
        self.assertEqual(result.stdout.strip(), 'TCP_FAULT_NATIVE_DONE status=1')

    def test_empty_client_command_is_rejected(self):
        result = self.run_launch([])
        self.assertEqual(result.returncode, 2)
        self.assertIn('error:', result.stderr)


if __name__ == '__main__':
    unittest.main()
