# SPDX-License-Identifier: GPL-3.0-or-later
"""Read complete guest exports across actual kernel serial diagnostics."""
import hashlib
from pathlib import Path
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from account_logbook_rotation_ext2 import serial_files

FIXTURE = Path(__file__).parent / 'fixtures/account-rotation-interrupted-data.txt'
NAME = 'archive-0000000000000004/auth.log'
EXPECTED = '9fa19d452a488e40891da169e5a666f8b99ef07f98a65c73c778a3fb202a00e1'
DIAGNOSTIC = b'RANDOM_RESEEDED source=rdseed bits=256\n'


class RotationSerialTests(unittest.TestCase):
    def test_actual_interrupted_export_keeps_exact_native_file(self):
        original = FIXTURE.read_bytes()
        files = serial_files(FIXTURE, 'retry')
        self.assertEqual(set(files), {NAME})
        self.assertEqual(len(files[NAME]), 681)
        self.assertEqual(hashlib.sha256(files[NAME]).hexdigest(), EXPECTED)
        self.assertEqual(FIXTURE.read_bytes(), original)

    def test_complete_known_diagnostic_at_every_payload_boundary(self):
        raw = FIXTURE.read_bytes().replace(b'\r\n', b'\n')
        self.assertEqual(raw.count(DIAGNOSTIC), 1)
        raw = raw.replace(DIAGNOSTIC, b'')
        start = raw.index(b' hex=') + 5
        payload_end = raw.index(b'\n', start)
        with tempfile.TemporaryDirectory(prefix='axiom64-rotation-serial-') as temporary:
            path = Path(temporary) / 'guest.log'
            for ending in (b'\n', b'\r\n'):
                for offset in range(start, payload_end + 1):
                    interrupted = raw[:offset] + DIAGNOSTIC + raw[offset:]
                    path.write_bytes(interrupted.replace(b'\n', ending))
                    self.assertEqual(hashlib.sha256(serial_files(path, 'retry')[NAME]).hexdigest(),
                                     EXPECTED, (ending, offset))

    def test_unknown_partial_and_changed_exports_are_not_accepted(self):
        raw = FIXTURE.read_bytes().replace(b'\r\n', b'\n')
        with tempfile.TemporaryDirectory(prefix='axiom64-rotation-serial-negative-') as temporary:
            path = Path(temporary) / 'guest.log'
            for diagnostic in (b'RANDOM_RESEEDED source=rdseed bits=',
                               DIAGNOSTIC[:-1], b'UNKNOWN_KERNEL_RECORD\n', b'child progress\n'):
                path.write_bytes(raw.replace(DIAGNOSTIC, diagnostic))
                with self.assertRaises((AssertionError, ValueError)):
                    serial_files(path, 'retry')
            path.write_bytes(raw.replace(DIAGNOSTIC, b'0'))
            with self.assertRaises((AssertionError, ValueError)):
                serial_files(path, 'retry')


if __name__ == '__main__':
    unittest.main()
