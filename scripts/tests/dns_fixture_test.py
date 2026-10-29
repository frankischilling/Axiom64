# SPDX-License-Identifier: GPL-3.0-or-later
"""Keep strict DNS peer failures and their actual rejected Ethernet bytes."""
import hashlib
import json
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from dns_peer import Peer
from dns_test import observe_frame
from ipv6_router_capture import qemu_records

FIXTURES = Path(__file__).resolve().parent / 'fixtures'


class RejectedControl(unittest.TestCase):
    def solicitations(self):
        metadata = json.loads((FIXTURES / 'normal-init-default-ipv6.json').read_text())
        for capture in metadata['captures']:
            path = FIXTURES / capture['file']
            self.assertEqual(hashlib.sha256(path.read_bytes()).hexdigest(), capture['sha256'])
            frames = [row['frame'] for row in qemu_records(path)
                      if row['frame'][12:14] == b'\x86\xdd' and row['frame'][54] == 133]
            self.assertEqual(len(frames), 1)
            yield capture['lane'], frames[0]

    def test_actual_router_solicitations_stay_rejected_and_are_saved(self):
        for lane, frame in self.solicitations():
            with self.subTest(lane=lane):
                peer, observed = Peer(lane), []
                peer.started = True
                with self.assertRaisesRegex(RuntimeError, 'unexpected traffic after resolver fixture begins'):
                    observe_frame(peer, frame, observed)
                self.assertEqual(len(observed), 1)
                self.assertEqual(bytes.fromhex(observed[0]['frame']), frame)
                self.assertEqual(observed[0]['sha256'], hashlib.sha256(frame).hexdigest())
                self.assertEqual(observed[0]['lane'], lane)
                self.assertTrue(observed[0]['started_before'])
                self.assertGreater(observed[0]['observed_monotonic_ns'], 0)
                self.assertEqual(observed[0]['rejection'], 'unexpected traffic after resolver fixture begins')
                self.assertEqual(peer.frames, [])

    def test_before_configuration_keeps_original_foreign_frame_policy(self):
        for lane, frame in self.solicitations():
            with self.subTest(lane=lane):
                peer, observed = Peer(lane), []
                observe_frame(peer, frame, observed)
                self.assertEqual(peer.foreign, 1)
                self.assertFalse(peer.started)
                self.assertNotIn('rejection', observed[0])
                self.assertEqual(bytes.fromhex(observed[0]['frame']), frame)

    def test_malformed_frame_is_retained_before_length_rejection(self):
        peer, observed = Peer(0), []
        with self.assertRaisesRegex(RuntimeError, 'bounded Ethernet frame'):
            observe_frame(peer, b'bad', observed)
        self.assertEqual(bytes.fromhex(observed[0]['frame']), b'bad')
        self.assertEqual(observed[0]['rejection'], 'bounded Ethernet frame')


if __name__ == '__main__':
    unittest.main()
