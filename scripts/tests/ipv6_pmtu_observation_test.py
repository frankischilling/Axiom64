# SPDX-License-Identifier: GPL-3.0-or-later
"""Retain a full PMTU observation after an independently observed input."""
import json
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from ipv6_pmtu_peer import Peer


class Observation(unittest.TestCase):
    def test_delayed_actual_input_preserves_fifty_milliseconds(self):
        fixture = json.loads((Path(__file__).parent / 'fixtures/ipv6-pmtu-queued-input.json').read_text())
        for native in (False, True):
            for delay in (0, .000223, .020631, .25, 1.5):
                with self.subTest(native=native, delay=delay):
                    peer = Peer(0, native=native)
                    peer.sequence = fixture['sequence']
                    original = bytes.fromhex(fixture['original'])
                    peer.active = dict(boundary=bytes.fromhex(fixture['boundary']),
                                       original=original, protocol=17,
                                       local=original[22:38], remote=original[38:54])
                    receipt, watched = [None], []
                    def observe(frame):
                        watched.append(frame)
                        return lambda: receipt[0]
                    peer.observe_input = observe
                    with patch('ipv6_pmtu_peer.time.monotonic', return_value=100):
                        peer.tick()
                    self.assertEqual(peer.outgoing, [bytes.fromhex(fixture['quoted_error'])])
                    peer.outgoing.clear()
                    if delay:
                        with patch('ipv6_pmtu_peer.time.monotonic', return_value=100 + delay - .0000001):
                            peer.tick()
                        self.assertEqual(peer.outgoing, [], 'no acknowledgement before actual input receipt')
                    receipt[0] = 100 + delay
                    with patch('ipv6_pmtu_peer.time.monotonic', return_value=receipt[0] + .049999):
                        peer.tick()
                    self.assertEqual(peer.outgoing, [], 'full original50ms observation follows receipt')
                    with patch('ipv6_pmtu_peer.time.monotonic', return_value=receipt[0] + .050001):
                        peer.tick()
                    self.assertEqual(len(peer.outgoing), 1)
                    self.assertEqual(watched, [bytes.fromhex(fixture['quoted_error'])])


if __name__ == '__main__':
    unittest.main()
