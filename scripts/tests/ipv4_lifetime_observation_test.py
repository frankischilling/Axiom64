# SPDX-License-Identifier: GPL-3.0-or-later
"""Keep the physical TCP absence window complete after delayed client output."""
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from ipv4_lifetimes.wire_peer import Peer


class LifetimeObservation(unittest.TestCase):
    def test_delayed_expiry_receipt_still_gets_two_physical_seconds(self):
        commands = []
        now = 100_000_000_000
        peer = Peer(lambda *args: None, lambda data, case: commands.append((data, case, now)))
        peer.results = [{} for _ in range(8)]
        peer.event(dict(peer.specs[8], phase='begin'))
        commands.clear()
        with patch('ipv4_lifetimes.wire_peer.time.monotonic_ns', side_effect=lambda: now):
            peer.event(dict(case=8, phase='expired', status=64))
            # Original hosted capture: source waited 2.002 seconds, but the
            # expiry marker arrived 65.977 ms late and its successor 0.118 ms late.
            now += 1_936_162_930
            peer.event(dict(case=8, phase='absence-end'))
            self.assertEqual(commands, [])
            peer.poll()
            self.assertEqual(commands, [])
            now = 102_000_000_000
            peer.poll()
            self.assertEqual(commands, [(b'R', 8, now)])
            peer.poll()
            self.assertEqual(len(commands), 1)

    def test_full_physical_wait_also_needs_the_client_end_marker(self):
        commands = []
        now = 100_000_000_000
        peer = Peer(lambda *args: None, lambda *args: commands.append(args))
        peer.results = [{} for _ in range(8)]
        peer.event(dict(peer.specs[8], phase='begin'))
        commands.clear()
        with patch('ipv4_lifetimes.wire_peer.time.monotonic_ns', side_effect=lambda: now):
            peer.event(dict(case=8, phase='expired', status=64))
            now += 2_500_000_000
            peer.poll()
            self.assertEqual(commands, [])
            peer.event(dict(case=8, phase='absence-end'))
            peer.poll()
            self.assertEqual(commands, [(b'R', 8)])


if __name__ == '__main__':
    unittest.main()
