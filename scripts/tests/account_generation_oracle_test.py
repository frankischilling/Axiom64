# SPDX-License-Identifier: GPL-3.0-or-later
"""Compare the actual retained failure with the guest's pre-retry account view."""
from pathlib import Path
import gzip
import hashlib
import json
import sys
import subprocess
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from account_management_ext2 import recovery_input, recovery_selection, selected_files


class AccountGenerationOracle(unittest.TestCase):
    def test_unrelated_directory_damage_is_not_accepted_as_retirement(self):
        fixture = Path(__file__).parent / 'fixtures/account-journal-retirement.raw.gz'
        with gzip.open(fixture, 'rb') as stream:
            raw = stream.read()
        with tempfile.TemporaryDirectory(prefix='axiom64-account-oracle-damage-', dir='/tmp') as temporary:
            directory = Path(temporary)
            disk = directory / 'negative-input.raw'
            disk.write_bytes(raw)
            subprocess.run(['debugfs', '-w', '-R', 'set_inode_field <2> links_count 1', str(disk)],
                           check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            negative = disk.read_bytes()
            self.assertNotEqual(negative, raw)
            with self.assertRaisesRegex(RuntimeError, 'unrepaired ext2 failed independent check'):
                recovery_input(disk, '/build-static', directory, pending_recovery=True)
            self.assertEqual(disk.read_bytes(), negative)

    def test_journal_replayed_retirement_keeps_raw_failure_and_requires_bounded_eligibility(self):
        fixtures = Path(__file__).parent / 'fixtures'
        proof = json.loads((fixtures / 'account-journal-retirement.json').read_text())
        archive = fixtures / 'account-journal-retirement.raw.gz'
        self.assertEqual(hashlib.sha256(archive.read_bytes()).hexdigest(), proof['archive_sha256'])
        with gzip.open(archive, 'rb') as stream:
            raw = stream.read()
        self.assertEqual(hashlib.sha256(raw).hexdigest(), proof['original']['sha256'])
        with tempfile.TemporaryDirectory(prefix='axiom64-account-retirement-regression-', dir='/tmp') as temporary:
            directory = Path(temporary)
            disk = directory / 'actual-input.raw'
            disk.write_bytes(raw)
            check, selected, observation = recovery_input(disk, '/build-static', directory, pending_recovery=True)
            self.assertFalse(observation['raw_filesystem_check']['passed'])
            self.assertFalse(check['passed'])
            self.assertEqual(check['expected_checked_recovery']['inodes'], proof['expected_retired_inodes'])
            self.assertTrue(observation['guest_input_unchanged'])
            self.assertEqual(disk.read_bytes(), raw)
            self.assertIn(b'fault-user:', selected[1]['passwd'])

    def test_committed_journal_selection_matches_actual_guest_without_changing_input(self):
        fixtures = Path(__file__).parent / 'fixtures'
        proof = json.loads((fixtures / 'account-generation-journal-replay.json').read_text())
        archive = fixtures / 'account-generation-journal-replay.raw.gz'
        self.assertEqual(hashlib.sha256(archive.read_bytes()).hexdigest(), proof['archive_sha256'])
        with gzip.open(archive, 'rb') as stream:
            raw = stream.read()
        self.assertEqual(len(raw), proof['original']['bytes'])
        self.assertEqual(hashlib.sha256(raw).hexdigest(), proof['original']['sha256'])
        with tempfile.TemporaryDirectory(prefix='axiom64-account-oracle-regression-', dir='/tmp') as temporary:
            directory = Path(temporary)
            disk = directory / 'actual-guest-input.raw'
            disk.write_bytes(raw)
            old, files = selected_files(disk, '/build-static')
            self.assertNotEqual(old, proof['expected_revision'])
            self.assertNotIn(b'fault-user:', files['passwd'])
            (revision, files), observation = recovery_selection(disk, '/build-static', directory)
            self.assertEqual(revision, proof['expected_revision'])
            self.assertEqual({name: hashlib.sha256(value).hexdigest() for name, value in files.items()},
                             proof['expected_files'])
            self.assertEqual(disk.read_bytes(), raw)
            self.assertTrue(observation['guest_input_unchanged'])
            self.assertTrue(observation['journal_only'])
            self.assertNotEqual(observation['command'][-1], str(disk))
            self.assertFalse(Path(observation['command'][-1]).exists())


if __name__ == '__main__':
    unittest.main()
