#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Exercise the complete wall client with independent clock-call boundary fixtures."""
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'scripts'))
from clock_wall_test import check


class CalendarBoundaryTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temporary = tempfile.TemporaryDirectory(prefix='axiom64-wall-boundary-')
        cls.addClassCleanup(cls.temporary.cleanup)
        cls.program = Path(cls.temporary.name) / 'clock-wall'
        subprocess.run([
            os.environ.get('CC', 'cc'), '-std=c11', '-O2', '-g', '-Wall', '-Wextra', '-Werror',
            '-fno-builtin', str(ROOT / 'userspace/tests/time/wall.c'),
            str(ROOT / 'scripts/tests/clock_wall_boundary_shim.c'),
            '-Wl,--wrap=puts,--wrap=clock_gettime,--wrap=gettimeofday,--wrap=syscall',
            '-o', str(cls.program)], check=True)

    def exercise(self, mode, passed):
        process = subprocess.run([str(self.program)], capture_output=True, text=True, timeout=3,
                                 env=dict(os.environ, CLOCK_WALL_BOUNDARY_CASE=mode))
        output = process.stdout + process.stderr
        self.assertEqual(process.returncode, 0 if passed else 1, output)
        self.assertIn('CLOCK_WALL_FILESYSTEM_PASS creation=3 write=2', output)
        if passed:
            self.assertIn('CLOCK_WALL_PASS ', output)
            self.assertNotIn('CLOCK_WALL_FAIL ', output)
        else:
            self.assertIn('CLOCK_WALL_FAIL operation=wall interfaces agree', output)
            self.assertNotIn('CLOCK_WALL_PASS ', output)
        return output

    def test_precise_and_coarse_same_second(self):
        self.exercise('same-second', True)

    def test_precise_second_advances_before_coarse_second(self):
        self.exercise('boundary', True)

    def test_coarse_second_advances_during_observation(self):
        self.exercise('coarse-crossing', True)

    def test_changed_return_value_rejected(self):
        self.exercise('bad-return', False)

    def test_seconds_before_coarse_bracket_rejected(self):
        self.exercise('bad-seconds-low', False)

    def test_seconds_after_coarse_bracket_rejected(self):
        self.exercise('bad-seconds-high', False)

    def test_timeval_before_precise_bracket_rejected(self):
        self.exercise('bad-timeval-low', False)

    def test_timeval_after_precise_bracket_rejected(self):
        self.exercise('bad-timeval-high', False)

    def test_invalid_timeval_fraction_rejected(self):
        self.exercise('bad-timeval-fraction', False)

    def test_reversed_coarse_bracket_rejected(self):
        self.exercise('bad-coarse-order', False)

    def test_invalid_coarse_fraction_rejected(self):
        self.exercise('bad-coarse-fraction', False)

    def test_invalid_precise_fraction_rejected(self):
        self.exercise('bad-precise-fraction', False)

    def test_coarse_and_time_shift_rejected_by_independent_calendar(self):
        output = self.exercise('boundary', True)
        check({}, output, 100_000_000_000, 101_500_000_000, None)
        for key in ('coarse_first_s', 'coarse_last_s', 'time_return_s', 'time_store_s'):
            output, count = re.subn(r'\b' + key + r'=(\d+)',
                                    lambda match: key + '=' + str(int(match[1]) + 60), output)
            self.assertEqual(count, 1)
        with self.assertRaisesRegex(RuntimeError, 'coarse calendar'):
            check({}, output, 100_000_000_000, 101_500_000_000, None)


if __name__ == '__main__':
    unittest.main()
