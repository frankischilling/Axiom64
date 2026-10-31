#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Reopen actual Linux and guest kernel replies without weakening raw output checks."""
import json
from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'scripts'))
from ipv4_test import Peer, checksum


class KernelReplyTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.capture = json.loads((ROOT / 'scripts/tests/fixtures/ipv4-kernel-replies/manifest.json').read_text())

    def peer(self):
        peer = Peer(0)
        peer.arp_valid = True
        peer.host_request = bytes.fromhex(self.capture['observations']['echo']['input'])[34:]
        frame = bytes.fromhex(self.capture['observations']['protocol']['input'])
        peer.unknown = frame[14:14 + int.from_bytes(frame[16:18], 'big')]
        return peer

    @staticmethod
    def changed(frame, offset, value):
        packet = bytearray(frame)
        packet[14 + offset:14 + offset + len(value)] = value
        packet[24:26] = bytes(2)
        packet[24:26] = checksum(bytes(packet[14:34])).to_bytes(2, 'big')
        return bytes(packet)

    def test_linux_and_guest_headers_and_payloads_agree(self):
        for kind, values in self.capture['observations'].items():
            native, guest = (bytearray.fromhex(values[name]) for name in ('native', 'guest'))
            for frame in (native, guest):
                self.assertEqual(checksum(frame[14:34]), 0)
                self.assertEqual(checksum(frame[34:]), 0)
                frame[18:20] = bytes(2)  # The independent stacks choose their own IP ID.
                frame[24:26] = bytes(2)
            self.assertEqual(native, guest, kind)

    def test_original_linux_and_guest_replies_are_accepted(self):
        for source in ('native', 'guest'):
            with self.subTest(source=source):
                peer = self.peer()
                for kind in ('echo', 'protocol'):
                    peer.packet(bytes.fromhex(self.capture['observations'][kind][source]))
                self.assertEqual((peer.host_echo, peer.protocol_error), (1, 1))

    def test_checksum_repaired_wrong_kernel_headers_are_rejected(self):
        for kind, values in self.capture['observations'].items():
            for source in ('native', 'guest'):
                frame = bytes.fromhex(values[source])
                for offset, value in ((1, bytes((0xc0 if kind == 'echo' else 0,))),
                                      (6, bytes.fromhex('4000')), (8, bytes((63,))),
                                      (16, bytes((10, 23, 1, 9)))):
                    with self.subTest(kind=kind, source=source, offset=offset):
                        with self.assertRaisesRegex(RuntimeError, 'IPv4 header, route, length, TTL, or checksum differs'):
                            self.peer().packet(self.changed(frame, offset, value))

    def test_original_application_request_keeps_df_and_zero_tos(self):
        peer = self.peer()
        peer.packet(bytes.fromhex(self.capture['application_request']))
        self.assertEqual(peer.echo, 1)

    def test_application_request_cannot_borrow_kernel_header_policy(self):
        frame = bytes.fromhex(self.capture['application_request'])
        for offset, value in ((1, bytes((0xc0,))), (6, bytes(2))):
            with self.subTest(offset=offset):
                with self.assertRaisesRegex(RuntimeError, 'IPv4 header, route, length, TTL, or checksum differs'):
                    self.peer().packet(self.changed(frame, offset, value))


if __name__ == '__main__':
    unittest.main()
