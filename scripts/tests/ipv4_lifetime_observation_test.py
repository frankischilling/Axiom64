# SPDX-License-Identifier: GPL-3.0-or-later
"""Check the original client and peer lifetime observation windows."""
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from ipv4_lifetimes.wire_peer import Peer
from ipv4_lifetimes.reader import DEPRECATED, native_promotion_sample


class NativePromotionObservation(unittest.TestCase):
    def test_expired_primary_then_observed_absence(self):
        # The failing Linux dump retained IFA_F_DEPRECATED with both lifetimes zero.
        expired = dict(flags=DEPRECATED, cache=(0, 0, 0x3065f, 0x3065f))
        native_promotion_sample(expired, 40_000, 1_500_060_000, 1_500_090_000, None)
        native_promotion_sample(None, 40_000, 1_550_090_000, 1_550_100_000, 1_500_090_000)

    def test_live_primary_is_not_pending_removal(self):
        for value in (dict(flags=DEPRECATED, cache=(0, 1)), dict(flags=0, cache=(0, 0))):
            with self.subTest(value=value):
                with self.assertRaisesRegex(ValueError, 'only an expired native primary'):
                    native_promotion_sample(value, 0, 1_500_000_000, 1_500_010_000, None)

    def test_early_and_late_absence_does_not_qualify(self):
        for query, receipt, previous, message in (
            (1_499_999_999, 1_500_010_000, None, 'original sample'),
            (2_499_980_000, 2_500_000_001, None, 'bounded withdrawal'),
            (1_550_089_999, 1_550_100_000, 1_500_090_000, 'actual polling intervals'),
        ):
            with self.subTest(query=query):
                with self.assertRaisesRegex(ValueError, message):
                    native_promotion_sample(None, 0, query, receipt, previous)


class LifetimeObservation(unittest.TestCase):
    def test_delayed_primary_marker_gets_the_full_physical_lifetime_window(self):
        commands = []
        now = 100_000_000_000
        peer = Peer(lambda *args: None, lambda data, case: commands.append((data, case, now)))
        peer.event(dict(peer.specs[0], phase='begin'))
        commands.clear()
        with patch('ipv4_lifetimes.wire_peer.time.monotonic_ns', side_effect=lambda: now):
            peer.event(dict(case=0, phase='lifetime-start'))
            # The original native control waited 1.500 seconds, but the
            # start marker arrived 34.788 ms late and fresh-bind 2.517 ms late.
            now += 1_467_879_015
            peer.event(dict(case=0, phase='withdrawn'))
            peer.poll()
            self.assertEqual(commands, [])
            now = 101_500_000_000
            peer.poll()
            self.assertEqual(commands, [(b'B', 0, now)])
            peer.poll()
            self.assertEqual(len(commands), 1)

    def test_observer_wait_does_not_replace_actual_primary_withdrawal(self):
        commands = []
        now = 100_000_000_000
        peer = Peer(lambda *args: None, lambda *args: commands.append(args))
        peer.event(dict(peer.specs[0], phase='begin'))
        commands.clear()
        with patch('ipv4_lifetimes.wire_peer.time.monotonic_ns', side_effect=lambda: now):
            peer.event(dict(case=0, phase='lifetime-start'))
            now += 1_600_000_000
            peer.poll()
            self.assertEqual(commands, [])
            peer.event(dict(case=0, phase='withdrawn'))
            peer.poll()
            self.assertEqual(commands, [(b'B', 0)])

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
