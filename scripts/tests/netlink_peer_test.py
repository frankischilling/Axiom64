# SPDX-License-Identifier: GPL-3.0-or-later
"""Keep automatic IPv6 traffic visible to the strict IPv4 route peer."""
import json
from pathlib import Path
import struct
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from netlink_peer import Peer, checksum


class CapturedAutoconfiguration(unittest.TestCase):
    def test_original_dad_frame_is_valid_ipv6_and_rejected_by_ipv4_peer(self):
        fixture = Path(__file__).with_name('fixtures') / 'netlink-autoconfiguration-dad.json'
        frame = bytes.fromhex(json.loads(fixture.read_text())['frame_hex'])
        self.assertEqual(frame[12:14], bytes.fromhex('86dd'))
        self.assertEqual(frame[20:22], bytes([58, 255]))
        self.assertEqual(frame[22:38], bytes(16))
        self.assertEqual(frame[54], 135)
        payload = frame[54:]
        self.assertEqual(len(payload), int.from_bytes(frame[18:20], 'big'))
        pseudo = frame[22:54] + struct.pack('!I3xB', len(payload), 58)
        self.assertEqual(checksum(pseudo + payload), 0)
        peer = Peer(0)
        with self.assertRaisesRegex(RuntimeError, 'independently resolved MAC'):
            peer.packet(frame)
        self.assertEqual(peer.resolutions, [0, 0, 0])
        self.assertEqual(peer.packets, [0, 0, 0])


if __name__ == '__main__':
    unittest.main()
