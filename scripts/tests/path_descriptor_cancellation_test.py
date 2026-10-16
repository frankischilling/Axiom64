# SPDX-License-Identifier: GPL-3.0-or-later
"""Exercise real process reaping at the cancellation observer's procfs seam."""
from contextlib import contextmanager
import errno
from pathlib import Path
import signal
import subprocess
import sys
import time
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parent))
import path_descriptor_storage_test as cancellation


@contextmanager
def owned_worker(program='import time; time.sleep(30)'):
    process = subprocess.Popen([sys.executable, '-c', program], start_new_session=True,
                               stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                               stderr=subprocess.DEVNULL)
    try:
        yield process, Path('/proc') / str(process.pid) / 'status'
    finally:
        if process.poll() is None:
            process.kill()
        process.wait(timeout=3)


class RecordedStatus:
    def __init__(self, existed, read):
        self.existed, self.read = existed, read

    def exists(self):
        return self.existed

    def read_text(self):
        return self.read()


class CancellationObservation(unittest.TestCase):
    def test_live_worker_is_rejected(self):
        with owned_worker() as (_, status):
            self.assertFalse(cancellation.child_stopped(status))

    def test_real_unreaped_zombie_is_stopped(self):
        with owned_worker('import os; os._exit(0)') as (_, status):
            deadline = time.monotonic() + 3
            while 'State:\tZ' not in status.read_text():
                self.assertLess(time.monotonic(), deadline)
                time.sleep(.01)
            self.assertTrue(cancellation.child_stopped(status))

    def test_already_reaped_worker_is_stopped(self):
        with owned_worker() as (process, status):
            process.kill()
            process.wait(timeout=3)
            self.assertTrue(cancellation.child_stopped(status))

    def test_reaping_between_metadata_and_open_is_stopped(self):
        with owned_worker() as (process, status):
            existed = status.exists()
            self.assertTrue(existed)
            process.kill()
            process.wait(timeout=3)
            observed = RecordedStatus(existed, status.read_text)
            self.assertTrue(cancellation.child_stopped(observed))

    def test_open_proc_file_after_actual_reaping_is_stopped(self):
        with owned_worker() as (process, status), status.open() as stream:
            existed = status.exists()
            self.assertTrue(existed)
            process.kill()
            process.wait(timeout=3)
            # The Linux kernel supplies ESRCH from this real stale proc file.
            observed = RecordedStatus(existed, stream.read)
            self.assertTrue(cancellation.child_stopped(observed))

    def test_cleanup_reaping_race_is_already_complete(self):
        with owned_worker() as (process, status):
            existed = status.exists()
            self.assertTrue(existed)
            group = process.pid
            process.kill()
            process.wait(timeout=3)
            snapshot = RecordedStatus(existed, status.read_text)
            with patch.object(cancellation, 'Path', return_value=snapshot):
                cancellation.cleanup_child_group(group, process.pid)

    def test_cleanup_still_checks_group_ownership(self):
        with owned_worker() as (process, _):
            cancellation.cleanup_child_group(process.pid + 100000, process.pid)
            self.assertIsNone(process.poll())
            cancellation.cleanup_child_group(process.pid, process.pid)
            self.assertEqual(process.wait(timeout=3), -signal.SIGKILL)

    def test_unrelated_read_errors_are_not_hidden(self):
        for error in (PermissionError(errno.EACCES, 'control'), OSError(errno.EIO, 'control')):
            def read():
                raise error
            with self.subTest(error=type(error).__name__):
                with self.assertRaises(type(error)):
                    cancellation.child_stopped(RecordedStatus(True, read))


if __name__ == '__main__':
    unittest.main()
