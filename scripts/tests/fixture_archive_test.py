#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Verify disk retention before cleanup and reject foreign or aliased files."""
import gzip
import hashlib
import os
from pathlib import Path
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from fetch import ROOT
from fixture_archive import archive_fixture


class Archive(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix='fixture-archive-test-', dir=ROOT / 'build')
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.path = self.root / 'root.raw'
        self.data = bytes(range(256)) * 8192
        self.path.write_bytes(self.data)

    def test_verified_copy_can_retire_its_original(self):
        record = archive_fixture(self.path, remove=True)
        self.assertFalse(self.path.exists())
        with gzip.open(record['path'], 'rb') as stream:
            self.assertEqual(stream.read(), self.data)
        self.assertEqual(record['original'], dict(bytes=len(self.data), sha256=hashlib.sha256(self.data).hexdigest()))
        self.assertLess(record['compressed']['bytes'], record['original']['bytes'])

    def test_existing_archive_preserves_original(self):
        archive_fixture(self.path)
        with self.assertRaises(FileExistsError):
            archive_fixture(self.path, remove=True)
        self.assertEqual(self.path.read_bytes(), self.data)

    def test_foreign_source_is_not_removed(self):
        with tempfile.TemporaryDirectory(prefix='axiom64-foreign-fixture-') as temporary:
            path = Path(temporary) / 'root.raw'
            path.write_bytes(self.data)
            with self.assertRaises(RuntimeError):
                archive_fixture(path, remove=True)
            self.assertEqual(path.read_bytes(), self.data)

    def test_symlink_and_shared_inode_are_not_removed(self):
        link = self.root / 'link.raw'
        link.symlink_to(self.path)
        with self.assertRaises(RuntimeError):
            archive_fixture(link, remove=True)
        link.unlink()
        os.link(self.path, link)
        with self.assertRaises(RuntimeError):
            archive_fixture(self.path, remove=True)
        self.assertEqual(self.path.read_bytes(), self.data)


if __name__ == '__main__':
    unittest.main()
