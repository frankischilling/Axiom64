# SPDX-License-Identifier: GPL-3.0-or-later
"""Replay native neighbor maintenance observed during the complete lifetime client."""
from pathlib import Path
import struct
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from ipv6_host_peer import Peer, checksum

# Actual unicast NS after the original five host phases, with a link-local source.
PROBE = bytes.fromhex('02495036000152540012341086dd6000000000203aff'
                      'fe80000000000000000000000000000220010db8000100000000000000000001'
                      '870097340000000020010db80001000000000000000000010101525400123410')


class Maintenance(unittest.TestCase):
    def peer(self, native=True):
        peer = Peer(0, native=native)
        peer.ready = True
        peer.phase = 5
        peer.complete = [1, 2, 3, 4, 5]
        peer.duplicate_seen = True
        return peer

    def changed(self, offset):
        frame = bytearray(PROBE)
        frame[offset] ^= 1
        body = frame[54:]
        body[2:4] = bytes(2)
        body[2:4] = struct.pack('!H', checksum(frame[22:54] + struct.pack('!I3xB', len(body), 58) + body))
        frame[54:] = body
        return bytes(frame)

    def test_observed_probe_gets_exact_solicited_response(self):
        peer = self.peer()
        peer.receive(PROBE)
        self.assertEqual(peer.maintenance_probes, 1)
        self.assertEqual(len(peer.outgoing), 1)
        response = peer.outgoing[0]
        self.assertEqual(response[:12], peer.guest + peer.mac)
        self.assertEqual(response[22:54], peer.remote + peer.link)
        self.assertEqual(response[20:22], b'\x3a\xff')
        self.assertEqual(response[54:56], b'\x88\0')
        self.assertEqual(response[58:], b'\x60\0\0\0' + peer.remote + b'\2\1' + peer.mac)
        self.assertEqual(checksum(response[22:54] + struct.pack('!I3xB', 32, 58) + response[54:]), 0)

    def test_invalid_probes_keep_valid_checksums_and_are_rejected(self):
        for offset in (0, 21, 23, 53, 58, 78):
            with self.subTest(offset=offset):
                with self.assertRaises(ValueError): self.peer().receive(self.changed(offset))

    def test_probe_does_not_bypass_original_phases(self):
        peer = self.peer()
        peer.complete = [1, 2, 3, 4]
        with self.assertRaises(ValueError): peer.receive(PROBE)

    def test_non_native_producer_rejects_the_extra_probe(self):
        with self.assertRaises(ValueError): self.peer(native=False).receive(PROBE)

    def test_probe_budget_is_finite(self):
        peer = self.peer()
        for _ in range(9): peer.receive(PROBE)
        with self.assertRaises(ValueError): peer.receive(PROBE)


if __name__ == '__main__':
    unittest.main()
