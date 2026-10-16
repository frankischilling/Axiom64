# SPDX-License-Identifier: GPL-3.0-or-later
"""Keep bounded host-memory device files and retain their exact guest-written bytes."""
from contextlib import redirect_stderr
from io import StringIO
from pathlib import Path
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from account_management_ext2 import working_disk


class RotationDiskTests(unittest.TestCase):
    def test_memory_device_copies_actual_bytes_on_success_and_guest_failure(self):
        for fail in (False, True):
            with self.subTest(fail=fail), tempfile.TemporaryDirectory(prefix='rotation-memory-test-') as temporary:
                retained = Path(temporary) / 'disk.raw'
                retained.write_bytes(b'original guest disk\n')
                device = None
                try:
                    with working_disk(retained, prefer_memory=True) as device:
                        self.assertEqual(device.parent.parent, Path('/dev/shm'))
                        self.assertEqual(device.read_bytes(), b'original guest disk\n')
                        device.write_bytes(b'actual guest writes after error or completion\n')
                        self.assertEqual(retained.read_bytes(), b'original guest disk\n')
                        if fail:
                            raise RuntimeError('actual observer rejection')
                except RuntimeError as error:
                    self.assertTrue(fail)
                    self.assertEqual(str(error), 'actual observer rejection')
                self.assertEqual(retained.read_bytes(), b'actual guest writes after error or completion\n')
                self.assertFalse(device.exists())

    def test_low_capacity_or_unavailable_memory_uses_linux_disk(self):
        for available in (SimpleNamespace(free=0), OSError('memory storage unavailable')):
            with self.subTest(available=available), tempfile.TemporaryDirectory(prefix='rotation-memory-test-') as temporary:
                retained = Path(temporary) / 'disk.raw'
                retained.write_bytes(b'original\n')
                kwargs = dict(side_effect=available) if isinstance(available, OSError) else dict(return_value=available)
                with patch('account_management_ext2.shutil.disk_usage', **kwargs):
                    with working_disk(retained, prefer_memory=True) as device:
                        self.assertEqual(device.parent.parent, Path('/tmp'))
                        device.write_bytes(b'fallback actual bytes\n')
                self.assertEqual(retained.read_bytes(), b'fallback actual bytes\n')

    def test_large_fixture_keeps_disk_backing(self):
        with tempfile.TemporaryDirectory(prefix='rotation-memory-test-') as temporary:
            retained = Path(temporary) / 'disk.raw'
            with retained.open('wb') as stream:
                stream.truncate(32 * 1024 * 1024 + 1)
            with working_disk(retained, prefer_memory=True) as device:
                self.assertEqual(device.parent.parent, Path('/tmp'))
                self.assertEqual(device.stat().st_size, retained.stat().st_size)

    def test_rejected_evidence_copy_preserves_actual_memory_device(self):
        with tempfile.TemporaryDirectory(prefix='rotation-memory-test-') as temporary:
            directory = Path(temporary)
            retained = directory / 'disk.raw'
            retained.write_bytes(b'original\n')
            device = None
            checkpoint = None
            diagnostics = StringIO()
            try:
                with self.assertRaises(OSError), redirect_stderr(diagnostics):
                    with working_disk(retained, prefer_memory=True) as device:
                        device.write_bytes(b'actual failed guest disk\n')
                        retained.rename(directory / 'original.raw')
                        retained.mkdir()
                checkpoint = Path(diagnostics.getvalue().split('path=', 1)[1].strip())
                self.assertTrue(checkpoint.exists())
                self.assertEqual(checkpoint.parent.parent, Path('/tmp'))
                self.assertEqual(checkpoint.read_bytes(), b'actual failed guest disk\n')
                self.assertEqual((directory / 'original.raw').read_bytes(), b'original\n')
            finally:
                if checkpoint and checkpoint.exists():
                    self.assertIn(checkpoint.parent.parent, (Path('/tmp'), Path('/dev/shm')))
                    self.assertTrue(checkpoint.parent.name.startswith('axiom64-management-disk-'))
                    checkpoint.unlink()
                    checkpoint.parent.rmdir()
                if device and device.exists():
                    self.assertEqual(device.parent.parent, Path('/dev/shm'))
                    self.assertTrue(device.parent.name.startswith('axiom64-management-disk-'))
                    device.unlink()
                    device.parent.rmdir()


if __name__ == '__main__':
    unittest.main()
