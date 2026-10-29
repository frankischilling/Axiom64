# SPDX-License-Identifier: GPL-3.0-or-later
"""Reproduce the real cross-adapter ACK race and require complete capture receipts."""
import hashlib
import json
from pathlib import Path
import struct
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from ipv6_device_frames import decode
from ipv6_device_pending_capture import inspect, plan
from ipv6_device_pending_peer import Peer
from ipv6_router_capture import qemu_records
from qemu_capture_delivery import Delivery

FIXTURES = Path(__file__).resolve().parent / 'fixtures/ipv6-device-delivery'


class PhysicalDelivery(unittest.TestCase):
    def fixture(self, label):
        manifest = json.loads((FIXTURES / 'manifest.json').read_text())
        self.assertEqual(manifest['schema'], 1)
        self.assertEqual(len(manifest['cases']), 3)
        row = manifest['cases'][label]
        self.assertTrue(row['diagnostic_only'])
        self.assertFalse(row['full_matrix_acceptance'])
        self.assertTrue(row['original_packet_and_serial_bytes_unchanged'])
        case = FIXTURES / label
        for name, record in row['files'].items():
            self.assertEqual(Path(name).name, name)
            data = (case / name).read_bytes()
            self.assertEqual((len(data), hashlib.sha256(data).hexdigest()),
                             (record['bytes'], record['sha256']))
        return case, row

    def test_original_failure_stays_rejected_and_corrected_traces_pass(self):
        for label in ('before', 'after', 'first-ready'):
            with self.subTest(label=label):
                case, row = self.fixture(label)
                text = (case / 'serial.log').read_text()
                if row['expected_reader_passed']:
                    for subject in range(2):
                        self.assertTrue(inspect(case / f'lane{subject}.pcap', subject, text,
                                                row['action'], row['state'])['passed'])
                else:
                    with self.assertRaisesRegex(ValueError, row['expected_error']):
                        inspect(case / 'lane0.pcap', 0, text, row['action'], row['state'])

    def test_partial_record_gates_the_actual_peer(self):
        case, row = self.fixture('before')
        packets = [list(qemu_records(case / f'lane{lane}.pcap')) for lane in range(2)]
        for subject in range(2):
            with self.subTest(subject=subject), tempfile.TemporaryDirectory() as temporary:
                directory = Path(temporary)
                delivery = Delivery(directory)
                peers = [Peer(lane, row['action'], row['state'], delivery=delivery)
                         for lane in range(2)]
                for peer in peers:
                    peer.bind_peers(peers)
                companion = 1 - subject
                requests = [packet['frame'] for packet in packets[companion] if
                            packet['frame'][12:14] == b'\x88\xc4' and
                            packet['frame'][6:12] == peers[companion].guest]
                probe = next(packet['frame'] for packet in packets[subject] if
                             len(packet['frame']) == 86 and packet['frame'][54] == 135)
                for frame in requests:
                    if (frame[20], frame[23]) == (2, 10):
                        peers[subject].receive(probe)
                    peers[companion].receive(frame)
                    if frame[20] == 12:
                        break
                    peers[companion].outgoing.clear()
                conflict = peers[subject].outgoing.pop()
                self.assertFalse(peers[subject].output)
                self.assertFalse(peers[companion].outgoing)
                data = (case / f'lane{subject}.pcap').read_bytes()
                offset = 24
                while True:
                    size = struct.unpack_from('<I', data, offset + 8)[0]
                    if data[offset + 16:offset + 16 + size] == conflict:
                        break
                    offset += 16 + size
                capture = directory / f'lane{subject}.pcap'
                capture.write_bytes(data[:23])
                peers[companion].tick()
                self.assertFalse(peers[companion].outgoing)
                capture.write_bytes(data[:offset + 7])
                peers[companion].tick()
                self.assertFalse(peers[companion].outgoing)
                capture.write_bytes(data[:offset + 16 + size - 1])
                peers[companion].tick()
                self.assertFalse(peers[companion].outgoing)
                capture.write_bytes(data[:offset + 16 + size])
                peers[companion].tick()
                acknowledgment = next(packet['frame'] for packet in packets[companion] if
                                      packet['frame'][12:14] == b'\x88\xc4' and
                                      packet['frame'][6:12] == peers[companion].control and
                                      packet['frame'][19] == frame[19])
                self.assertEqual(peers[companion].outgoing, [acknowledgment])
                receipt = peers[companion].conflicts[-1]['capture_delivery']
                self.assertEqual(receipt['physical'], subject)
                self.assertEqual(receipt['sha256'], hashlib.sha256(conflict).hexdigest())
                self.assertEqual(receipt['packet_microseconds'], next(
                    packet['stamp'] for packet in packets[subject] if packet['frame'] == conflict))
                peers[companion].outgoing.clear()
                peers[companion].tick()
                self.assertFalse(peers[companion].outgoing)

    def test_actual_first_ready_query_precedes_the_initial_inventory(self):
        case, row = self.fixture('first-ready')
        text = (case / 'serial.log').read_text()
        parsed, _ = decode(case / 'lane0.pcap', text, row['action'],
                           [plan(row['action'], row['state']),
                            plan(row['action'], row['state'], early_ready=True)],
                           allow_conflicts=True)
        for subject in range(2):
            with self.subTest(subject=subject):
                companion = parsed[1 - subject]
                requests = companion['requests']
                link = next(value for value in requests if (value['kind'], value['stage']) == (6, 1))
                ready = [value for value in requests if (value['kind'], value['stage']) == (10, 1)]
                addresses = [value for value in requests if (value['kind'], value['stage']) == (2, 1)]
                self.assertEqual(len(ready), 1)
                self.assertEqual(len(addresses), 1)
                self.assertEqual(ready[0]['target'], addresses[0]['target'])
                self.assertEqual((ready[0]['flags'], addresses[0]['flags']), (0x880, 0x880))
                self.assertLess(ready[0]['phase'], addresses[0]['phase'])
                self.assertGreaterEqual(companion['replies'][link['phase']]['stamp'] -
                                        link['row']['stamp'], 1100000)

    def test_capture_replacement_truncation_and_invalid_framing_fail(self):
        case, _ = self.fixture('before')
        data = (case / 'lane0.pcap').read_bytes()
        frame = next(packet['frame'] for packet in qemu_records(case / 'lane0.pcap') if
                     len(packet['frame']) == 86 and packet['frame'][54] == 136)
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            capture = directory / 'lane0.pcap'
            capture.write_bytes(b'bad!' + data[4:])
            with self.assertRaisesRegex(ValueError, 'original delivery capture magic'):
                Delivery(directory).receipt(0, frame)
            capture.write_bytes(data)
            delivery = Delivery(directory)
            self.assertIsNotNone(delivery.receipt(0, frame))
            capture.write_bytes(data[:24])
            with self.assertRaisesRegex(ValueError, 'delivery capture was truncated'):
                delivery.receipt(0, frame)
            capture.write_bytes(data)
            delivery = Delivery(directory)
            self.assertIsNotNone(delivery.receipt(0, frame))
            capture.rename(directory / 'original.pcap')
            capture.write_bytes(data)
            with self.assertRaisesRegex(ValueError, 'delivery capture was replaced'):
                delivery.receipt(0, frame)

    def test_frame_budget_is_bounded_without_changing_packet_timestamps(self):
        case, _ = self.fixture('before')
        data = (case / 'lane0.pcap').read_bytes()
        size = struct.unpack_from('<I', data, 32)[0]
        record = data[24:40 + size]
        frame = record[16:]
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            capture = directory / 'lane0.pcap'
            capture.write_bytes(data[:24] + record * 4096)
            delivery = Delivery(directory)
            self.assertIsNotNone(delivery.receipt(0, frame))
            with capture.open('ab') as output:
                output.write(record)
            with self.assertRaisesRegex(ValueError, 'bounded physical delivery frame count'):
                delivery.receipt(0, frame)


if __name__ == '__main__':
    unittest.main()
