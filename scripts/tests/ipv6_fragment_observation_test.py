# SPDX-License-Identifier: GPL-3.0-or-later
"""Keep fragment suppression spacing relative to the first released input."""
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from ipv6_fragments_peer import Peer


class FragmentObservation(unittest.TestCase):
    def test_delayed_first_release_retains_all_original_intervals(self):
        for delay in (0, .020631, .25, 1.5):
            with self.subTest(delay=delay):
                peer = Peer(0, native=True)
                peer.phase = 4
                with patch('ipv6_fragments_peer.time.monotonic', return_value=100):
                    peer.arm_expiry()
                first = 100 + delay
                with patch('ipv6_fragments_peer.time.monotonic', return_value=first):
                    peer.tick()
                self.assertEqual(peer.outgoing, [peer.first])
                peer.outgoing.clear()
                for offset in (1, 2, 3, 30):
                    with patch('ipv6_fragments_peer.time.monotonic', return_value=first + offset - .0001):
                        peer.tick()
                    self.assertEqual(peer.outgoing, [], f'input released before actual first input + {offset}s')
                    with patch('ipv6_fragments_peer.time.monotonic', return_value=first + offset + .02):
                        peer.tick()
                    self.assertEqual(len(peer.outgoing), 1)
                    frame = peer.outgoing.pop()
                    identity = int.from_bytes(frame[58:62], 'big')
                    self.assertEqual(identity, peer.expiry_id + (offset if offset < 4 else 0))
                peer.expiry_seen = True
                with patch('ipv6_fragments_peer.time.monotonic', return_value=first + 70.9999):
                    peer.tick()
                self.assertEqual(peer.outgoing, [], 'complete original 71-second peer observation')
                with patch('ipv6_fragments_peer.time.monotonic', return_value=first + 71.02):
                    peer.tick()
                self.assertEqual(len(peer.outgoing), 1)
                self.assertEqual(peer.complete, [peer.phase])


if __name__ == '__main__':
    unittest.main()
