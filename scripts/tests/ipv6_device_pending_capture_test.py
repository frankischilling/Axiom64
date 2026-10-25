# SPDX-License-Identifier: GPL-3.0-or-later
"""Replay original pending-device diagnostics and serialized corruption controls."""
import argparse
import hashlib
import json
from pathlib import Path
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from ipv6_device_pending_capture import inspect
from ipv6_device_pending_damage import controls
from ipv6_device_pending_peer import Peer
from qemu_capture_delivery import Delivery
from ipv6_router_capture import qemu_records

FIXTURES = Path(__file__).resolve().parent / 'fixtures/ipv6-device-pending'
ARCHIVE = None


class PendingDeviceCaptures(unittest.TestCase):
    def test_selected_conflict_is_sent_before_its_acknowledgment(self):
        for action in ('administrative', 'mtu', 'carrier'):
            for state in ('probing', 'regenerating', 'retrying', 'exhausted'):
                with self.subTest(action=action, state=state):
                    case = FIXTURES / f'axiom-{action}-{state}'
                    packets = [list(qemu_records(case / f'lane{lane}.pcap')) for lane in range(2)]
                    delivery = Delivery(case)
                    peers = [Peer(lane, action, state, delivery=delivery) for lane in range(2)]
                    for peer in peers:
                        peer.bind_peers(peers)
                    requests = [row['frame'] for row in packets[1] if
                                row['frame'][12:14] == b'\x88\xc4' and
                                row['frame'][6:12] == peers[1].guest]
                    probe = next(row['frame'] for row in packets[0] if
                                 len(row['frame']) == 86 and row['frame'][54] == 135)
                    for frame in requests:
                        if frame[20] == 2 and frame[23] == 10:
                            peers[0].receive(probe)
                        peers[1].receive(frame)
                        if frame[20] == 12:
                            break
                        peers[1].outgoing.clear()
                        if state == 'probing' and frame[20] == 2:
                            break
                    self.assertEqual(peers[1].frames,
                                     [hashlib.sha256(frame).hexdigest()
                                      for frame in requests[:4 if state == 'probing' else 5]])
                    if state != 'probing':
                        conflict = next(row['frame'] for row in packets[0] if
                                        len(row['frame']) == 86 and row['frame'][54] == 136)
                        self.assertEqual(peers[0].outgoing, [conflict])
                        peers[1].tick()
                        self.assertEqual(peers[1].outgoing, [])
                        peers[0].output.extend(peers[0].outgoing.pop())
                        peers[1].tick()
                        self.assertEqual(peers[1].outgoing, [])
                        peers[0].output.clear()
                        peers[1].tick()
                        acknowledgment = next(row['frame'] for row in packets[1] if
                                              row['frame'][12:14] == b'\x88\xc4' and
                                              row['frame'][6:12] == peers[1].control and
                                              row['frame'][19] == frame[19])
                        self.assertEqual(peers[1].outgoing, [acknowledgment])
                        self.assertIsNone(peers[1].pending_conflict)
                    peers[1].frames = ['bounded'] * 2048
                    with self.assertRaisesRegex(ValueError, 'bounded pending device traffic'):
                        peers[1].receive(requests[2])

    def test_original_two_kernel_and_guest_captures(self):
        manifest = json.loads((FIXTURES / 'manifest.json').read_text())
        self.assertEqual(manifest['schema'], 1)
        self.assertEqual(len(manifest['cases']), 36)
        for name, row in manifest['cases'].items():
            with self.subTest(case=name):
                self.assertEqual(Path(name).name, name)
                self.assertTrue(row['diagnostic_only'])
                self.assertFalse(row['pending_device_acceptance'])
                self.assertTrue(row['original_packet_and_serial_bytes_unchanged'])
                case = FIXTURES / name
                for filename, record in row['files'].items():
                    self.assertEqual(Path(filename).name, filename)
                    data = (case / filename).read_bytes()
                    self.assertEqual((len(data), hashlib.sha256(data).hexdigest()),
                                     (record['bytes'], record['sha256']))
                statistics = json.loads((case / 'statistics.json').read_text()) if row['native'] else None
                for subject in range(2):
                    result = inspect(case / f'lane{subject}.pcap', subject,
                                     (case / 'serial.log').read_text(), row['action'], row['state'],
                                     native=row['native'], statistics=statistics,
                                     native_kernel_release=row['kernel_release'])
                    self.assertTrue(result['passed'])

    def test_closed_and_reopened_corruption_controls(self):
        manifest = json.loads((FIXTURES / 'manifest.json').read_text())
        total = 0
        with tempfile.TemporaryDirectory(prefix='axiom64-pending-controls-') as temporary:
            for name, row in manifest['cases'].items():
                if row['native']:
                    continue
                with self.subTest(case=name):
                    archive = (ARCHIVE.with_name(ARCHIVE.stem + '-' + name + ARCHIVE.suffix)
                               if ARCHIVE else Path(temporary) / (name + '.zip'))
                    result = controls(FIXTURES / name, row['action'], row['state'], archive)
                    total += len(result)
        self.assertEqual(total, 304)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument('--archive', type=Path)
    arguments, remaining = parser.parse_known_args()
    ARCHIVE = arguments.archive
    unittest.main(argv=[sys.argv[0], *remaining])
