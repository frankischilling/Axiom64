#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Keep real fixture bytes independent while bounding allocated disk storage."""
import hashlib
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import fixture_archive as storage


class FixtureStorageTest(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name) / 'build'
        self.root.mkdir()
        self.source = self.root / 'seed.raw'
        with self.source.open('xb') as stream:
            stream.write(b'first payload')
            stream.seek(4 * 1024 * 1024)
            stream.write(b'middle payload')
            stream.truncate(8 * 1024 * 1024)
        self.original = storage.fingerprint(self.source)

    def test_sparse_copy_preserves_all_bytes_and_independent_writes(self):
        copied = self.root / 'case.raw'
        result = storage.sparse_copy_fixture(self.source, copied, self.root)
        self.assertEqual(storage.fingerprint(copied), self.original)
        self.assertLess(result['allocated_bytes'], self.source.stat().st_size // 2)
        self.assertEqual(self.source.stat().st_nlink, 1)
        self.assertEqual(copied.stat().st_nlink, 1)
        with copied.open('r+b') as stream:
            stream.write(b'guest changes')
        self.assertEqual(storage.fingerprint(self.source), self.original)
        self.assertNotEqual(storage.fingerprint(copied), self.original)

    def test_existing_destination_is_preserved(self):
        copied = self.root / 'case.raw'
        copied.write_bytes(b'unique prior evidence')
        with self.assertRaisesRegex(RuntimeError, 'fresh owned destination'):
            storage.sparse_copy_fixture(self.source, copied, self.root)
        self.assertEqual(copied.read_bytes(), b'unique prior evidence')

    def test_copy_rejects_escaping_and_symbolic_paths(self):
        for copied in (self.root.parent / 'escape.raw', self.root / 'alias.raw'):
            with self.subTest(destination=copied):
                if copied.parent == self.root:
                    copied.symlink_to(self.source)
                with self.assertRaisesRegex(RuntimeError, 'fresh owned destination'):
                    storage.sparse_copy_fixture(self.source, copied, self.root)
        alias = self.root / 'source-alias.raw'
        alias.symlink_to(self.source)
        with self.assertRaisesRegex(RuntimeError, 'owned build directory'):
            storage.sparse_copy_fixture(alias, self.root / 'other.raw', self.root)

    def test_incomplete_copy_is_rejected_and_retained(self):
        copied = self.root / 'case.raw'

        def partial(command, check):
            copied.write_bytes(b'partial copy')
            return subprocess.CompletedProcess(command, 0)

        with patch.object(storage.subprocess, 'run', side_effect=partial):
            with self.assertRaisesRegex(RuntimeError, 'changed the original bytes'):
                storage.sparse_copy_fixture(self.source, copied, self.root)
        self.assertEqual(copied.read_bytes(), b'partial copy')
        self.assertEqual(storage.fingerprint(self.source), self.original)

    def test_retirement_preserves_separate_canonical_bytes(self):
        canonical = self.root / 'retained.raw'
        storage.sparse_copy_fixture(self.source, canonical, self.root)
        before = canonical.stat()
        result = storage.retire_duplicate_fixture(self.source, canonical, self.root)
        self.assertFalse(self.source.exists())
        self.assertEqual(storage.fingerprint(canonical), self.original)
        self.assertEqual(result['fingerprint'], self.original)
        self.assertEqual(canonical.stat().st_ino, before.st_ino)

    def test_retirement_refuses_different_bytes_or_same_file(self):
        canonical = self.root / 'different.raw'
        canonical.write_bytes(b'other evidence')
        with self.assertRaisesRegex(RuntimeError, 'differs from its retained copy'):
            storage.retire_duplicate_fixture(self.source, canonical, self.root)
        with self.assertRaisesRegex(RuntimeError, 'separate retained copy'):
            storage.retire_duplicate_fixture(self.source, self.source, self.root)
        self.assertEqual(storage.fingerprint(self.source), self.original)

    def test_retirement_refuses_a_changed_canonical_during_verification(self):
        canonical = self.root / 'retained.raw'
        storage.sparse_copy_fixture(self.source, canonical, self.root)
        fingerprint = storage.fingerprint

        def changed(path):
            result = fingerprint(path)
            if path == self.source:
                with canonical.open('r+b') as stream:
                    stream.write(b'changed witness')
            return result

        with patch.object(storage, 'fingerprint', side_effect=changed):
            with self.assertRaisesRegex(RuntimeError, 'changed during storage verification'):
                storage.retire_duplicate_fixture(self.source, canonical, self.root)
        self.assertEqual(storage.fingerprint(self.source), self.original)


if __name__ == '__main__':
    unittest.main()
