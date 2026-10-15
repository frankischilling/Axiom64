#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Require the complete serial record before interrupting a held guest."""
import sys
from pathlib import Path
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from ext2_journal_lifetime_test import armed_records


class JournalLifetimeBoundaryTests(unittest.TestCase):
    def test_every_partial_record_waits(self):
        for ending in ('\n', '\r\n'):
            record = 'JOURNAL_LIFETIME_ARMED file=12 symlink=13 directory=14' + ending
            for offset in range(len(record)):
                with self.subTest(ending=repr(ending), offset=offset):
                    self.assertEqual(armed_records('prior output\n' + record[:offset]), [])
            self.assertEqual(armed_records('prior output\n' + record), [('12', '13', '14')])

    def test_record_remains_complete_with_later_output(self):
        self.assertEqual(armed_records(
            'JOURNAL_LIFETIME_ARMED file=12 symlink=13 directory=14\nnext partial'),
            [('12', '13', '14')])

    def test_malformed_or_embedded_records_do_not_arm(self):
        for record in ('file=12 symlink=13 directory=', 'file=12 symlink=13 directory=14extra',
                       'file=12 symlink=-13 directory=14', 'file=12 symlink=13 directory=14\r\r'):
            self.assertEqual(armed_records('JOURNAL_LIFETIME_ARMED ' + record + '\n'), [])
        self.assertEqual(armed_records('echo JOURNAL_LIFETIME_ARMED file=12 symlink=13 directory=14\n'), [])


if __name__ == '__main__':
    unittest.main()
