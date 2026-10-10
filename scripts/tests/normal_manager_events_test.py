# SPDX-License-Identifier: GPL-3.0-or-later
"""A serial read may end at any byte of the real init supervision records."""
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from normal_manager_test import events


class CompleteSupervisionRecords(unittest.TestCase):
    def test_captured_restart_never_validates_a_partial_timestamp(self):
        initial = ('INIT_MANAGER_SPAWN pid=2 monotonic_ms=4120\n'
                   'INIT_MANAGER_REAP pid=2 status=9 monotonic_ms=12840\n')
        restart = 'INIT_MANAGER_SPAWN pid=76 monotonic_ms=13840\n'
        for size in range(len(restart)):
            with self.subTest(size=size):
                spawns, reaps, _ = events(initial + restart[:size])
                self.assertEqual(spawns, [(2, 4120)])
                self.assertEqual(reaps, [(2, 9, 12840)])
        spawns, reaps, _ = events(initial + restart)
        self.assertEqual(spawns[1][1] - reaps[0][2], 1000)

    def test_all_event_types_require_a_complete_line(self):
        records = ('INIT_MANAGER_SPAWN pid=76 monotonic_ms=13840',
                   'INIT_MANAGER_REAP pid=2 status=9 monotonic_ms=12840',
                   'INIT_OBSERVER_PASS phase=desktop-before pid=2 monotonic_ms=12580')
        expected = ([(76, 13840)], [(2, 9, 12840)], {'desktop-before': (2, 12580)})
        for index, record in enumerate(records):
            for ending in ('\n', '\r\n'):
                line = record + ending
                for size in range(len(line)):
                    with self.subTest(index=index, ending=ending, size=size):
                        self.assertEqual(events(line[:size]), ([], [], {}))
                self.assertEqual(events(line)[index], expected[index])


if __name__ == '__main__':
    unittest.main()
