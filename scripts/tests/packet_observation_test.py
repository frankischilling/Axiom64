# SPDX-License-Identifier: GPL-3.0-or-later
"""Check receipt boundaries against complete original captured packet bytes."""
import hashlib
import json
from pathlib import Path
import struct
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from packet_observation import PcapObservation


class Observation(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.path = Path(self.directory.name) / 'original.pcap'
        fixture = json.loads((Path(__file__).parent / 'fixtures/ipv6-pmtu-queued-input.json').read_text())
        self.frame = bytes.fromhex(fixture['quoted_error'])

    def tearDown(self):
        self.directory.cleanup()

    def header(self, endian):
        return struct.pack(endian + 'IHHIIII', 0xa1b2c3d4, 2, 4, 0, 0, 65536, 1)

    def packet(self, endian):
        return struct.pack(endian + 'IIII', 123, 456, len(self.frame), len(self.frame)) + self.frame

    def test_only_complete_future_input_starts_observation(self):
        for endian in ('<', '>'):
            with self.subTest(endian=endian):
                old = self.header(endian) + self.packet(endian)
                self.path.write_bytes(old)
                observer = PcapObservation(self.path)
                receipt = observer.watch(self.frame)
                self.assertIsNone(receipt(), 'an older identical packet is not the pending input')
                packet = self.packet(endian)
                for part in (packet[:15], packet[15:40], packet[40:-1]):
                    with self.path.open('ab') as output:
                        output.write(part)
                    self.assertIsNone(receipt(), 'an incomplete actual record cannot start the timer')
                with self.path.open('ab') as output:
                    output.write(packet[-1:])
                expected = self.path.read_bytes()
                with patch('packet_observation.time.monotonic_ns', return_value=100250000000):
                    self.assertEqual(receipt(), 100.25)
                self.assertEqual(receipt(), 100.25)
                self.assertEqual(self.path.read_bytes(), expected)
                proof = json.loads(self.path.with_suffix('.observations.jsonl').read_text().splitlines()[-1])
                self.assertEqual(proof['record'], 1)
                self.assertEqual(proof['pcap_timestamp_us'], 123000456)
                self.assertEqual(proof['sha256'], hashlib.sha256(self.frame).hexdigest())
                self.assertTrue(proof['original_packet_times_not_rescaled'])

    def test_missing_and_partial_header_wait_for_actual_bytes(self):
        observer = PcapObservation(self.path)
        receipt = observer.watch(self.frame)
        self.assertIsNone(receipt())
        self.path.write_bytes(self.header('<')[:20])
        self.assertIsNone(receipt())
        self.path.write_bytes(self.header('<') + self.packet('<'))
        self.assertIsNotNone(receipt())

    def test_changed_and_malformed_capture_are_rejected(self):
        self.path.write_bytes(self.header('<'))
        observer = PcapObservation(self.path)
        receipt = observer.watch(self.frame)
        self.assertIsNone(receipt())
        self.path.write_bytes(self.header('>'))
        with self.assertRaisesRegex(ValueError, 'header changed'):
            receipt()
        self.path.write_bytes(self.header('<') + struct.pack('<IIII', 123, 456, 13, 13))
        with self.assertRaisesRegex(ValueError, 'packet bounds'):
            receipt()

    def test_one_pending_input_per_capture(self):
        observer = PcapObservation(self.path)
        observer.watch(self.frame)
        with self.assertRaisesRegex(ValueError, 'one pending'):
            observer.watch(self.frame)


if __name__ == '__main__':
    unittest.main()
