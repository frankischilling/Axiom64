#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Replay actual UEFI RTC writes without widening the calendar tolerance."""
import copy
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from clock_wall_observer import check_hardware
from rtc_calendar_fixture import FIXTURES


class CalendarObserver(unittest.TestCase):
    def check(self, fixture):
        row = fixture['row']
        check_hardware(row, row['host_interval_ns'][0], None, fixture['events'])

    def test_actual_firmware_writes(self):
        for name, fixture in FIXTURES.items():
            with self.subTest(case=name):
                self.check(copy.deepcopy(fixture))

    def test_wrong_firmware_offsets_are_rejected(self):
        for name, fixture in FIXTURES.items():
            if not fixture['events']:
                continue
            with self.subTest(case=name):
                damaged = copy.deepcopy(fixture)
                damaged['events'][-1]['data']['offset'] += 10
                with self.assertRaises(RuntimeError):
                    self.check(damaged)

    def test_incorrect_hardware_and_guest_calendars(self):
        for name, fixture in FIXTURES.items():
            for field in ('initial_hardware_calendar', 'hardware_calendar', 'observed'):
                with self.subTest(case=name, field=field):
                    damaged = copy.deepcopy(fixture)
                    key = 'seconds' if field == 'observed' else 'tm_min' if field == 'initial_hardware_calendar' else 'tm_sec'
                    damaged['row'][field][key] += 1 if key == 'tm_min' else 10
                    with self.assertRaises(RuntimeError):
                        self.check(damaged)

    def test_malformed_unrelated_and_late_changes(self):
        for name, fixture in FIXTURES.items():
            if not fixture['events']:
                continue
            for mutation in ('offset', 'device', 'timestamp', 'unbounded'):
                with self.subTest(case=name, mutation=mutation):
                    damaged = copy.deepcopy(fixture)
                    event = damaged['events'][-1]
                    if mutation == 'offset':
                        event['data']['offset'] = str(event['data']['offset'])
                    elif mutation == 'device':
                        event['data']['qom-path'] = '/machine/unrelated'
                    elif mutation == 'timestamp':
                        event['timestamp']['seconds'] += 100
                    else:
                        event['data']['offset'] -= 100
                    with self.assertRaises(RuntimeError):
                        self.check(damaged)

    def test_wrong_elapsed_clock_and_post_reference_writes(self):
        for name, fixture in FIXTURES.items():
            with self.subTest(case=name, mutation='progress'):
                damaged = copy.deepcopy(fixture)
                damaged['row']['hardware_monotonic_interval_ns'] = [
                    value+10_000_000_000 for value in damaged['row']['hardware_monotonic_interval_ns']]
                with self.assertRaisesRegex(RuntimeError, 'monotonic progress'):
                    self.check(damaged)
            if fixture['events']:
                with self.subTest(case=name, mutation='post-reference-write'):
                    damaged = copy.deepcopy(fixture)
                    damaged['row']['reference_firmware_changes'] = damaged['events'][:-1]
                    with self.assertRaisesRegex(RuntimeError, 'post-firmware'):
                        self.check(damaged)


if __name__ == '__main__':
    unittest.main()
