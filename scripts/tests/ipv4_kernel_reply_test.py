#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Reopen actual Linux and guest kernel replies without weakening raw output checks."""
import json
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'scripts'))
from ipv4_test import Peer, checksum
from ipv4_fragments import FragmentPeer


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


    def expiry(self, native):
        expiry = FragmentPeer(0, native=native).expiry
        expiry.start, expiry.duplicate, expiry.stage = 100, 130, 1
        return expiry

    def test_captured_fragment_timeout_has_the_same_kernel_header_policy(self):
        frame = bytes.fromhex(self.capture['fragment_timeout']['native_frame'])
        for native in (False, True):
            with self.subTest(native=native):
                expiry = self.expiry(native)
                self.assertEqual(frame[42:], expiry.first)
                with patch('ipv4_fragments.time.monotonic', return_value=160):
                    self.assertEqual(expiry.receive(frame[14:]), [])
                self.assertEqual(expiry.quote, 160)
                self.assertEqual(expiry.latest_quote_seconds, 66 if native else 61)
                self.assertEqual(expiry.context_gap_seconds, 8 if native else 2)
                self.assertEqual(expiry.quiet_delay_seconds, 69 if native else 63)

    def test_repaired_wrong_fragment_timeout_headers_are_rejected(self):
        frame = bytes.fromhex(self.capture['fragment_timeout']['native_frame'])
        for native in (False, True):
            for offset, value in ((1, bytes(1)), (6, bytes.fromhex('4000'))):
                with self.subTest(native=native, offset=offset):
                    with patch('ipv4_fragments.time.monotonic', return_value=160):
                        with self.assertRaises(ValueError):
                            self.expiry(native).receive(self.changed(frame, offset, value)[14:])


if __name__ == '__main__':
    unittest.main()
