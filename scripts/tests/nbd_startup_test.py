# SPDX-License-Identifier: GPL-3.0-or-later
"""Retain actual early-exit and stalled-backend state under the original bound."""
import json
from pathlib import Path
import signal
import sys
import tempfile
import time
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import account_logbook_rotation_ext2 as rotation


class NbdStartupTests(unittest.TestCase):
    def test_early_exit_retains_actual_status_and_empty_log(self):
        with tempfile.TemporaryDirectory(prefix='nbd-early-exit-') as temporary:
            directory = Path(temporary)
            command = [sys.executable, '-c', 'raise SystemExit(23)']
            with patch.object(rotation, 'backend_command', return_value=command):
                with self.assertRaisesRegex(RuntimeError, 'bounded disposable NBD backend did not start'):
                    rotation.start_backend(directory / 'disk.raw', directory, directory, 0)
            self.assertEqual((directory / 'backend.log').read_bytes(), b'')
            report = json.loads((directory / 'backend-startup.json').read_text())
            self.assertFalse(report['passed'])
            self.assertEqual(report['deadline_seconds'], 5)
            self.assertEqual(report['failure'], 'process-exit')
            self.assertEqual(report['returncode'], 23)
            self.assertEqual(report['command'], command)
            self.assertLess(report['observation_elapsed_ns'], 5_000_000_000)
            self.assertEqual(len(report['executable']['sha256']), 64)

    def test_stopped_child_hits_five_seconds_and_is_reaped_with_original_state(self):
        with tempfile.TemporaryDirectory(prefix='nbd-stopped-child-') as temporary:
            directory = Path(temporary)
            pidfile = directory / 'child.pid'
            script = ('import os,signal,sys; from pathlib import Path; '
                      'Path(sys.argv[1]).write_text(str(os.getpid())); '
                      'os.kill(os.getpid(),signal.SIGSTOP)')
            command = [sys.executable, '-c', script, str(pidfile)]
            began = time.monotonic_ns()
            with patch.object(rotation, 'backend_command', return_value=command):
                with self.assertRaisesRegex(RuntimeError, 'bounded disposable NBD backend did not start'):
                    rotation.start_backend(directory / 'disk.raw', directory, directory, 0)
            elapsed = time.monotonic_ns() - began
            report = json.loads((directory / 'backend-startup.json').read_text())
            self.assertFalse(report['passed'])
            self.assertEqual(report['deadline_seconds'], 5)
            self.assertEqual(report['failure'], 'deadline')
            self.assertGreaterEqual(report['observation_elapsed_ns'], 5_000_000_000)
            self.assertLess(elapsed, 10_000_000_000)
            self.assertIn('State:\tT', report['process_before_termination']['status']['text'])
            self.assertEqual(report['returncode'], -signal.SIGKILL)
            self.assertFalse(Path('/proc/' + pidfile.read_text()).exists())
            self.assertEqual((directory / 'backend.log').read_bytes(), b'')
            self.assertTrue(report['process_before_termination']['maps']['text'])
            self.assertEqual(len(report['executable']['sha256']), 64)

    def test_launch_failure_closes_log_and_retains_its_type(self):
        with tempfile.TemporaryDirectory(prefix='nbd-launch-failure-') as temporary:
            directory = Path(temporary)
            command = [str(directory / 'missing-backend')]
            with patch.object(rotation, 'backend_command', return_value=command):
                with self.assertRaises(FileNotFoundError):
                    rotation.start_backend(directory / 'disk.raw', directory, directory, 0)
            report = json.loads((directory / 'backend-startup.json').read_text())
            self.assertEqual(report['failure'], 'launch')
            self.assertEqual(report['exception_type'], 'FileNotFoundError')
            self.assertIsNone(report['pid'])
            self.assertFalse(report['executable']['found'])
            self.assertFalse(any(path.resolve() == directory / 'backend.log'
                                 for path in Path('/proc/self/fd').iterdir() if path.exists()))


if __name__ == '__main__':
    unittest.main()
