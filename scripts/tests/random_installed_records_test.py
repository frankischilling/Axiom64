#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Replay actual ordinary-console records without accepting partial timestamps or echoes."""
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from random_installed_test import seed_records, shell_check


class Records(unittest.TestCase):
    def test_actual_prompt_prefixed_reap(self):
        # This complete line was present in the failed legacy second-boot log.
        actual = '/ # INIT_RANDOM_SEED_REAP pid=3 status=0 monotonic_ms=1240\n'
        self.assertEqual(seed_records(actual, 'REAP'), [('3', '0', '1240')])

    def test_all_complete_and_partial_boundaries(self):
        for prefix in ('', '/ # '):
            for newline in ('\n', '\r\n'):
                for event, middle, expected in (('SPAWN', '', ('13', '13840')),
                    ('REAP', ' status=256', ('13', '256', '13840'))):
                    record = prefix+'INIT_RANDOM_SEED_'+event+' pid=13'+middle+' monotonic_ms=13840'+newline
                    for boundary in range(len(record)):
                        self.assertEqual(seed_records(record[:boundary], event), [], record[:boundary])
                    self.assertEqual(seed_records(record, event), [expected])

    def test_sender_cannot_echo_a_seed_record(self):
        for ready in (True, False):
            self.assertNotIn(b'INIT_RANDOM_SEED_', shell_check(ready))
        self.assertEqual(seed_records("/ # printf 'INIT_RANDOM_SEED_REAP pid=3 status=0 monotonic_ms=1240\\n'\n", 'REAP'), [])


if __name__ == '__main__':
    unittest.main()
