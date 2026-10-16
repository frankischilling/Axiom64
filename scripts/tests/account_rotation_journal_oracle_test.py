# SPDX-License-Identifier: GPL-3.0-or-later
"""Keep interrupted journal eligibility separate from strict filesystem success."""
import gzip
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from account_logbook_rotation_ext2 import fsck

FIXTURES = Path(__file__).parent / 'fixtures'


class RotationJournalOracle(unittest.TestCase):
    def fixture(self, name):
        proof = json.loads((FIXTURES / (name + '.json')).read_text())
        archive = (FIXTURES / (name + '.raw.gz')).read_bytes()
        self.assertEqual(hashlib.sha256(archive).hexdigest(), proof['archive_sha256'])
        raw = gzip.decompress(archive)
        self.assertEqual(hashlib.sha256(raw).hexdigest(), proof['original']['sha256'])
        return raw, proof

    def test_pending_retirement_keeps_failed_checks_and_untouched_guest_input(self):
        for name in ('account-rotation-journal-retirement', 'account-journal-retirement'):
            with self.subTest(name=name), tempfile.TemporaryDirectory(dir='/tmp') as temporary:
                raw, proof = self.fixture(name)
                directory = Path(temporary)
                disk = directory / 'guest-input.raw'
                disk.write_bytes(raw)
                check = fsck(disk, directory, 'interrupted', pending_recovery=True)
                self.assertFalse(check['passed'])
                self.assertEqual(check['expected_checked_recovery']['inodes'], proof['expected_retired_inodes'])
                observation = json.loads((directory / 'journal-oracle.json').read_text())
                self.assertFalse(observation['raw_filesystem_check']['passed'])
                self.assertFalse(observation['filesystem_check']['passed'])
                self.assertTrue(observation['journal_only'])
                self.assertTrue(observation['guest_input_unchanged'])
                self.assertFalse(Path(observation['command'][-1]).exists())
                self.assertEqual(disk.read_bytes(), raw)

    def test_retirement_without_pending_recovery_is_rejected(self):
        raw, _ = self.fixture('account-rotation-journal-retirement')
        with tempfile.TemporaryDirectory(dir='/tmp') as temporary:
            directory = Path(temporary)
            disk = directory / 'guest-input.raw'
            disk.write_bytes(raw)
            with self.assertRaisesRegex(RuntimeError, 'unrepaired actual ext2'):
                fsck(disk, directory, 'strict')
            self.assertEqual(disk.read_bytes(), raw)
            self.assertFalse((directory / 'journal-oracle.json').exists())

    def test_committed_journal_allocations_require_replay_before_classification(self):
        raw, _ = self.fixture('account-rotation-journal-allocation')
        with tempfile.TemporaryDirectory(dir='/tmp') as temporary:
            directory = Path(temporary)
            disk = directory / 'guest-input.raw'
            disk.write_bytes(raw)
            check = fsck(disk, directory, 'interrupted', pending_recovery=True)
            self.assertTrue(check['passed'])
            observation = json.loads((directory / 'journal-oracle.json').read_text())
            self.assertFalse(observation['raw_filesystem_check']['passed'])
            self.assertTrue(observation['filesystem_check']['passed'])
            self.assertTrue(observation['observation_modified'])
            self.assertTrue(observation['guest_input_unchanged'])
            self.assertEqual(disk.read_bytes(), raw)

    def test_zero_exit_with_skipped_journal_is_a_failed_raw_check(self):
        raw, _ = self.fixture('account-generation-journal-replay')
        with tempfile.TemporaryDirectory(dir='/tmp') as temporary:
            directory = Path(temporary)
            disk = directory / 'guest-input.raw'
            disk.write_bytes(raw)
            check = fsck(disk, directory, 'interrupted', pending_recovery=True)
            observation = json.loads((directory / 'journal-oracle.json').read_text())
            self.assertEqual(observation['raw_filesystem_check']['returncode'], 0)
            self.assertFalse(observation['raw_filesystem_check']['passed'])
            self.assertFalse(check['passed'])
            self.assertEqual(check['expected_checked_recovery']['inodes'], [41])
            with self.assertRaisesRegex(RuntimeError, 'unrepaired actual ext2'):
                fsck(disk, directory, 'strict')
            self.assertEqual(disk.read_bytes(), raw)

    def test_unrelated_directory_damage_still_fails(self):
        raw, _ = self.fixture('account-rotation-journal-retirement')
        with tempfile.TemporaryDirectory(dir='/tmp') as temporary:
            directory = Path(temporary)
            disk = directory / 'guest-input.raw'
            disk.write_bytes(raw)
            subprocess.run(['debugfs', '-w', '-R', 'set_inode_field <2> links_count 1', str(disk)],
                           check=True, capture_output=True)
            damaged = disk.read_bytes()
            self.assertNotEqual(damaged, raw)
            with self.assertRaisesRegex(RuntimeError, 'unrepaired actual ext2'):
                fsck(disk, directory, 'interrupted', pending_recovery=True)
            self.assertEqual(disk.read_bytes(), damaged)


if __name__ == '__main__':
    unittest.main()
