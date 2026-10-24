# SPDX-License-Identifier: GPL-3.0-or-later
"""Reject ambiguous candidates while tolerating the actual Linux DAD handoff."""
import argparse
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
DIRECTORY = None


class DadInventory(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temporary = None if DIRECTORY else tempfile.TemporaryDirectory()
        cls.directory = DIRECTORY or Path(cls.temporary.name)
        if DIRECTORY:
            cls.directory.mkdir(exist_ok=False)
        cls.program = cls.directory / 'ipv6-dad-inventory-model'
        result = subprocess.run([os.environ.get('CC', 'gcc'), '-std=gnu11', '-O2', '-g',
            '-Wall', '-Wextra', '-Werror', str(ROOT / 'userspace/tests/net/ipv6_dad_inventory_model.c'),
            '-o', str(cls.program)], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
        (cls.directory / 'compile.log').write_text(result.stdout)
        if result.returncode:
            raise AssertionError(result.stdout)

    @classmethod
    def tearDownClass(cls):
        if cls.temporary:
            cls.temporary.cleanup()

    def case(self, name, rejected=False):
        result = subprocess.run([str(self.program), name], stdout=subprocess.PIPE,
                                stderr=subprocess.STDOUT, text=True, timeout=5)
        (self.directory / (name + '.log')).write_text(result.stdout)
        self.assertEqual(result.returncode, 1 if rejected else 0, result.stdout)
        if not rejected:
            self.assertEqual(result.stdout.strip(), 'IPV6_DAD_INVENTORY_PASS')
        else:
            self.assertIn('IPV6_DAD_FAIL ', result.stdout)

    def test_one_new_candidate(self):
        self.case('fresh')

    def test_retiring_failed_record_before_replacement(self):
        self.case('failed-first')

    def test_retiring_failed_record_after_replacement(self):
        self.case('failed-last')

    def test_retiring_tentative_record_before_replacement(self):
        self.case('tentative-first')

    def test_retiring_tentative_record_after_replacement(self):
        self.case('tentative-last')

    def test_final_count_does_not_collapse_handoff(self):
        self.case('final-count')

    def test_previous_identity_is_not_a_replacement(self):
        self.case('previous')

    def test_failed_candidate_is_not_a_replacement(self):
        self.case('failed')

    def test_other_prefix_does_not_supply_a_candidate(self):
        self.case('unrelated')

    def test_other_prefix_does_not_hide_a_candidate(self):
        self.case('unrelated-and-fresh')

    def test_absent_prefix_has_no_candidate(self):
        self.case('absent')

    def test_two_new_candidates_are_rejected(self):
        self.case('two-fresh', rejected=True)

    def test_duplicate_candidate_records_are_rejected(self):
        self.case('duplicate-fresh', rejected=True)

    def test_three_prefix_owners_are_rejected(self):
        self.case('three-owners', rejected=True)


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--directory', type=Path)
    args, remaining = parser.parse_known_args()
    DIRECTORY = args.directory
    unittest.main(argv=[__file__, *remaining])
