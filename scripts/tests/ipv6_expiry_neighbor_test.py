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
        inspect_neighbor(self.request, 0, pending)
        self.assertEqual(pending[self.request[62:78]], [self.request[22:38]])
        inspect_neighbor(self.reply, 0, pending)
        self.assertEqual(pending, {})

    def test_foreign_source_with_valid_checksum_is_rejected(self):
        changed = bytearray(self.request)
        changed[27] ^= 64
        with self.assertRaisesRegex(ValueError, 'solicitation'):
            inspect_neighbor(repair(changed), 0, {})

    def test_reply_must_target_the_actual_solicitation_source(self):
        pending = {}
        inspect_neighbor(self.request, 0, pending)
        changed = bytearray(self.reply)
        changed[38:54] = bytes.fromhex('20010db8000100000000000000000002')
        with self.assertRaisesRegex(ValueError, 'advertisement'):
            inspect_neighbor(repair(changed), 0, pending)

    def test_unsolicited_and_wrong_interface_replies_are_rejected(self):
        with self.assertRaisesRegex(ValueError, 'advertisement'):
            inspect_neighbor(self.reply, 0, {})
        with self.assertRaisesRegex(ValueError, 'destination'):
            inspect_neighbor(self.request, 1, {})


if __name__ == '__main__':
    unittest.main()
