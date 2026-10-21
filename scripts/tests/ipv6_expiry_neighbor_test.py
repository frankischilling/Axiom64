# SPDX-License-Identifier: GPL-3.0-or-later
"""Check real neighbor probes and replies against assigned source ownership."""
import json
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from ipv6_expiry_capture import inspect_neighbor, checksum


def repair(frame):
    frame[56:58] = bytes(2)
    value = checksum(bytes(frame[22:54]) + (32).to_bytes(4, 'big') + bytes([0, 0, 0, 58]) + bytes(frame[54:]))
    frame[56:58] = value.to_bytes(2, 'big')
    return bytes(frame)


class NeighborSource(unittest.TestCase):
    def setUp(self):
        row = json.loads((Path(__file__).parent / 'fixtures/ipv6-expiry-neighbor-source.json').read_text())
        self.request = bytes.fromhex(row['solicitation'])
        self.reply = bytes.fromhex(row['advertisement'])

    def test_actual_link_local_source_and_matching_reply(self):
        pending = {}
        inspect_neighbor(self.request, 0, pending, 1000, 0)
        self.assertEqual(pending[self.request[62:78]], [(self.request[22:38], 1000, 0)])
        inspect_neighbor(self.reply, 0, pending, 2000, 1)
        self.assertEqual(pending, {})

    def test_foreign_source_with_valid_checksum_is_rejected(self):
        changed = bytearray(self.request)
        changed[27] ^= 64
        with self.assertRaisesRegex(ValueError, 'solicitation'):
            inspect_neighbor(repair(changed), 0, {}, 1000, 0)

    def test_reply_must_target_the_actual_solicitation_source(self):
        pending = {}
        inspect_neighbor(self.request, 0, pending, 1000, 0)
        changed = bytearray(self.reply)
        changed[38:54] = bytes.fromhex('20010db8000100000000000000000002')
        with self.assertRaisesRegex(ValueError, 'advertisement'):
            inspect_neighbor(repair(changed), 0, pending, 2000, 1)

    def test_unsolicited_and_wrong_interface_replies_are_rejected(self):
        with self.assertRaisesRegex(ValueError, 'advertisement'):
            inspect_neighbor(self.reply, 0, {}, 2000, 1)
        with self.assertRaisesRegex(ValueError, 'destination'):
            inspect_neighbor(self.request, 1, {}, 1000, 0)


    def test_original_concurrent_neighbor_transactions_keep_their_clocks(self):
        fixture = json.loads((Path(__file__).parent / 'fixtures/ipv6-expiry-concurrent-neighbors.json').read_text())
        pending = {}
        stamps = [r['kernel_realtime_ns'] for r in fixture['records']]
        self.assertTrue(any(b < a for a, b in zip(stamps, stamps[1:])))
        replies = []
        for row in fixture['records']:
            request = inspect_neighbor(bytes.fromhex(row['frame']), fixture['lane'], pending,
                                       row['kernel_realtime_ns'], row['record'])
            if request is not None:
                replies.append((request, row['record']))
        self.assertEqual(replies, [(6, 10), (9, 29)])
        self.assertEqual(pending, {})

    def test_neighbor_reply_cannot_predate_its_actual_request(self):
        pending = {}
        inspect_neighbor(self.request, 0, pending, 1000, 0)
        with self.assertRaisesRegex(ValueError, 'neighbor.*clock'):
            inspect_neighbor(self.reply, 0, pending, 999, 1)

    def test_neighbor_clock_requires_complete_integer_evidence(self):
        for clock in (None, -1, 1.5):
            with self.subTest(clock=clock):
                with self.assertRaisesRegex(ValueError, 'neighbor.*clock'):
                    inspect_neighbor(self.request, 0, {}, clock, 0)


if __name__ == '__main__':
    unittest.main()
