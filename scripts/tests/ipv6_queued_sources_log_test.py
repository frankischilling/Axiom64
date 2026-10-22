# SPDX-License-Identifier: GPL-3.0-or-later
"""Keep real serial line endings distinct from damaged observation fields."""
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from ipv6_queued_sources_capture import records


class QueuedSerial(unittest.TestCase):
    def observations(self):
        path = Path(__file__).parent / 'fixtures/ipv6-queued-sources-serial.txt'
        return path.read_bytes().decode()

    def test_actual_lf_and_crlf_serial_observations_match(self):
        text = self.observations()
        expected = records(text)
        self.assertEqual(len(expected), 16)
        self.assertEqual(records(text.replace('\n', '\r\n')), expected)

    def test_carriage_return_inside_a_field_stays_invalid(self):
        with self.assertRaises(ValueError):
            records(self.observations().replace('copied=1', 'copied=\r1', 1))

    def test_missing_observation_stays_invalid(self):
        text = self.observations()
        with self.assertRaises(ValueError):
            records('\n'.join(text.splitlines()[1:]) + '\n')

    def test_missing_completion_stays_invalid(self):
        with self.assertRaises(ValueError):
            records(self.observations().replace('IPV6_QUEUED_SOURCE_DONE', 'MISSING'))


if __name__ == '__main__':
    unittest.main()
