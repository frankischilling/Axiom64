#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Reopen the emitted UDP error that stopped the actual guest wire scenario."""
import json
from pathlib import Path
import struct
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from udp_peer import Peer, checksum


class KernelPortError(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.fixture = json.loads((Path(__file__).parent / 'fixtures/udp-kernel-error.json').read_text())

    def peer(self):
        peer = Peer(0)
        peer.filter_quotes = [bytes.fromhex(self.fixture['input_frame'])[14:]]
        return peer

    @staticmethod
    def changed(frame, offset, value):
        data = bytearray(frame)
        data[14 + offset:14 + offset + len(value)] = value
        data[24:26] = bytes(2)
        struct.pack_into('!H', data, 24, checksum(bytes(data[14:34])))
        return bytes(data)

    def test_actual_kernel_error_keeps_the_exact_trigger_quote(self):
        frame = bytes.fromhex(self.fixture['error_frame'])
        self.assertEqual(frame[42:], bytes.fromhex(self.fixture['input_frame'])[14:])
        self.assertEqual((frame[15], frame[20:22]), (192, bytes(2)))
        self.assertEqual((checksum(frame[14:34]), checksum(frame[34:])), (0, 0))
        native = bytes.fromhex(self.fixture['native_error_frame'])
        for observed in (native, frame):
            self.assertEqual(observed[42:], bytes.fromhex(self.fixture['input_frame'])[14:])
            self.assertEqual((checksum(observed[14:34]), checksum(observed[34:])), (0, 0))
            peer = self.peer()
            peer.packet(observed)
            self.assertEqual(peer.filter_errors, 1)
        native, frame = bytearray(native), bytearray(frame)
        for observed in (native, frame):
            observed[18:20] = bytes(2)
            observed[24:26] = bytes(2)
        self.assertEqual(native, frame)

    def test_repaired_wrong_kernel_headers_still_fail(self):
        frame = bytes.fromhex(self.fixture['error_frame'])
        for offset, value in ((1, bytes(1)), (6, bytes.fromhex('4000')),
                              (8, bytes((63,))), (16, bytes((10, 23, 1, 9)))):
            with self.subTest(offset=offset), self.assertRaisesRegex(RuntimeError, 'Ethernet/IPv4 header'):
                self.peer().packet(self.changed(frame, offset, value))

    def test_actual_application_output_keeps_its_separate_header_policy(self):
        frame = bytes.fromhex(self.fixture['application_frame'])
        peer = Peer(0)
        peer.packet(frame)
        self.assertEqual(peer.frames, 1)
        for offset, value in ((1, bytes((192,))), (6, bytes(2))):
            with self.subTest(offset=offset), self.assertRaisesRegex(RuntimeError, 'Ethernet/IPv4 header'):
                Peer(0).packet(self.changed(frame, offset, value))


if __name__ == '__main__':
    unittest.main()
