#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Parse complete supervision records after actual ordinary Bash prompts."""
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from normal_manager_test import events


class Records(unittest.TestCase):
    def test_actual_bash_prefixed_spawn(self):
        line = '\x1b[?2004hbash-5.2$ INIT_MANAGER_SPAWN pid=28 monotonic_ms=11360\n'
        self.assertEqual(events(line)[0], [(28, 11360)])

    def test_complete_boundaries_and_status(self):
        for prefix in ('', 'bash-5.2$ ', '\x1b[?2004hbash-5.2$ '):
            for ending in ('\n', '\r\n'):
                for event, middle, expected in (('SPAWN', '', [(28, 11360)]),
                                                ('REAP', ' status=9', [(28, 9, 11360)])):
                    line = prefix + 'INIT_MANAGER_' + event + ' pid=28' + middle + ' monotonic_ms=11360' + ending
                    for count in range(len(line)):
                        spawns, reaps, _ = events(line[:count])
                        self.assertEqual(spawns if event == 'SPAWN' else reaps, [])
                    spawns, reaps, _ = events(line)
                    self.assertEqual(spawns if event == 'SPAWN' else reaps, expected)

    def test_echo_and_unrecognized_prefix_are_rejected(self):
        for text in ("bash-5.2$ printf 'INIT_MANAGER_SPAWN pid=28 monotonic_ms=11360\\n'\n",
                     'unrecognized INIT_MANAGER_SPAWN pid=28 monotonic_ms=11360\n'):
            self.assertEqual(events(text)[0], [])


if __name__ == '__main__':
    unittest.main()
