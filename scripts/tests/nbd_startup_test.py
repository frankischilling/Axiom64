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
import account_management_ext2 as management


class NbdStartupTests(unittest.TestCase):
    backend_module = rotation

    def start_backend(self, directory):
        return self.backend_module.start_backend(directory / 'disk.raw', directory, directory, 0)

    def stop_backend(self, process, output):
        self.backend_module.stop_backend(process, output)

    def test_actual_nbdkit_socket_retains_command_and_releases_ownership(self):
        with tempfile.TemporaryDirectory(prefix='nbd-actual-startup-') as temporary:
            directory = Path(temporary)
            disk = directory / 'disk.raw'
            disk.write_bytes(bytes(512))
            original = disk.read_bytes()
            process, output, socket, trace, command = self.start_backend(directory)
            try:
                self.assertIsNone(process.poll())
                self.assertTrue(socket.is_socket())
                report = json.loads((directory / 'backend-startup.json').read_text())
                self.assertTrue(report['passed'])
                self.assertEqual(report['command'], command)
                self.assertEqual(report['pid'], process.pid)
                self.assertEqual(report['deadline_seconds'], 5)
                self.assertIsNone(report['failure'])
                self.assertLess(report['observation_elapsed_ns'], 5_000_000_000)
                self.assertTrue(report['configuration_trace']['exists'])
                self.assertEqual(report['configuration_trace']['bytes'], trace.stat().st_size)
                self.assertEqual(len(report['executable']['sha256']), 64)
                self.assertEqual(disk.read_bytes(), original)
            finally:
                self.stop_backend(process, output)
            self.assertTrue(output.closed)
            self.assertIsNotNone(process.returncode)
            self.assertFalse(Path('/proc/' + str(process.pid)).exists())

    def test_early_exit_retains_actual_status_and_empty_log(self):
        with tempfile.TemporaryDirectory(prefix='nbd-early-exit-') as temporary:
            directory = Path(temporary)
            command = [sys.executable, '-c', 'raise SystemExit(23)']
            with patch.object(self.backend_module, 'backend_command', return_value=command):
                with self.assertRaisesRegex(RuntimeError, 'bounded disposable NBD backend did not start'):
                    self.start_backend(directory)
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
            with patch.object(self.backend_module, 'backend_command', return_value=command):
                with self.assertRaisesRegex(RuntimeError, 'bounded disposable NBD backend did not start'):
                    self.start_backend(directory)
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
            with patch.object(self.backend_module, 'backend_command', return_value=command):
                with self.assertRaises(FileNotFoundError):
                    self.start_backend(directory)
            report = json.loads((directory / 'backend-startup.json').read_text())
            self.assertEqual(report['failure'], 'launch')
            self.assertEqual(report['exception_type'], 'FileNotFoundError')
            self.assertIsNone(report['pid'])
            self.assertFalse(report['executable']['found'])
            self.assertFalse(any(path.resolve() == directory / 'backend.log'
                                 for path in Path('/proc/self/fd').iterdir() if path.exists()))


class AdministrationNbdStartupTests(NbdStartupTests):
    backend_module = management

    def start_backend(self, directory):
        return self.backend_module.backend_start(directory / 'disk.raw', directory, directory, 0,
                                                 'writeback', 'write', 0, 'observe')

    def stop_backend(self, process, output):
        self.backend_module.backend_stop(process, output)


if __name__ == '__main__':
    unittest.main()
