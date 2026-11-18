# SPDX-License-Identifier: GPL-3.0-or-later
"""Replay a native retry whose six/ten lifetimes aged before the first query."""
from pathlib import Path
import struct
import sys
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from ipv6_owner_peer import Peer
from tcp_capture_clock import raw_records

FIXTURE = Path(__file__).parent / 'fixtures/ipv6-owner-native-retry-aged-lane0.pcap'


class FiniteOwnerRetry(unittest.TestCase):
    def replay(self, mutate=None):
        peer = Peer(0, 'global', native=True)
        # This historical capture predates the case 3 probe barrier. Replay
        # just the finite takeover case with consecutive control phases.
        peer.cases = (4,)
        in_case = False
        found = False
        for row in raw_records(FIXTURE):
            frame = row['frame']
            if frame[6:12] != peer.guest:
                continue
            control = frame[12:14] == b'\x88\xc3'
            if control and frame[20:22] == bytes([1, 4]):
                in_case = True
            if not in_case and not (control and frame[20:22] == bytes([0, 0])):
                continue
            selected = control and frame[20:22] == bytes([9, 4])
            if control:
                frame = bytearray(frame)
                frame[19] = len(peer.controls)
                if selected and mutate:
                    mutate(frame)
                frame = bytes(frame)
            with patch('ipv6_owner_peer.time.monotonic_ns', return_value=row['stamp'] * 1000):
                peer.receive(frame)
            peer.outgoing.clear()
            if selected:
                found = True
                break
        self.assertTrue(found)
        return peer

    def test_original_native_first_query_keeps_aged_five_nine_cache(self):
        peer = self.replay()
        self.assertEqual((peer.samples[4, 9]['preferred'], peer.samples[4, 9]['valid']), (5, 9))

    def test_wrong_raw_flags_are_still_rejected(self):
        with self.assertRaisesRegex(ValueError, 'actual retry'):
            self.replay(lambda frame: struct.pack_into('!I', frame, 24, 0x940))

    def test_unrelated_or_expired_cache_is_rejected(self):
        for preferred, valid in ((30, 60), (0, 4), (5, 10)):
            with self.subTest(preferred=preferred, valid=valid):
                with self.assertRaisesRegex(ValueError, 'actual retry'):
                    self.replay(lambda frame: struct.pack_into('!II', frame, 28, preferred, valid))

    def test_cache_must_match_the_observed_aging_interval(self):
        def late_reset(frame):
            struct.pack_into('!II', frame, 28, 6, 10)
            stamp = int.from_bytes(frame[52:60], 'big') + 100_000_000
            frame[52:60] = stamp.to_bytes(8, 'big')
        with self.assertRaisesRegex(ValueError, 'actual retry'):
            self.replay(late_reset)
        def early_loss(frame):
            stamp = int.from_bytes(frame[52:60], 'big') - 900_000_000
            frame[52:60] = stamp.to_bytes(8, 'big')
        with self.assertRaisesRegex(ValueError, 'actual retry'):
            self.replay(early_loss)


if __name__ == '__main__':
    unittest.main()
