#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Replay actual TCP source-handshake and scoped maintenance frames."""
from copy import deepcopy
import hashlib
import json
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from tcp6.peer import packet
from tcp6.source_peer import Peer
from tcp_fault_peer import ACK, FIN, SYN

FIXTURE = Path(__file__).parent / 'fixtures/tcp6-source-handshake-data.json'


class SourceHandshakeTest(unittest.TestCase):
    def setUp(self):
        capture = json.loads(FIXTURE.read_text())
        self.frames = [bytes.fromhex(row['frame']) for row in capture['frames']]
        self.assertEqual([hashlib.sha256(frame).hexdigest() for frame in self.frames],
                         [row['sha256'] for row in capture['frames']])
        self.peer = Peer(0)
        self.peer.ready = True
        self.flow = self.peer.flows[0]
        self.flow.receive(packet(self.frames[0]), (64, 0))
        # The real peer must generate the exact captured SYN acknowledgment.
        self.assertEqual(self.peer.frames[-1]['frame'], self.frames[1].hex())
        self.final = packet(self.frames[2])

    def test_captured_payload_completes_handshake_and_produces_echo(self):
        self.flow.receive(self.final, (64, 0))
        self.assertTrue(self.flow.established)
        self.assertEqual(self.flow.tags, [0])
        self.assertEqual(self.flow.guest_next, (self.final['seq'] + 16) & 0xffffffff)
        echo = packet(bytes.fromhex(self.peer.frames[-1]['frame']))
        self.assertEqual(echo['data'], self.final['data'])
        self.assertEqual(echo['ack'], self.flow.guest_next)
        self.assertEqual(echo['seq'], self.final['ack'])

    def test_payload_without_push_also_completes_handshake(self):
        self.final['flags'] = ACK
        self.flow.receive(self.final, (64, 0))
        self.assertTrue(self.flow.established)
        self.assertEqual(self.flow.tags, [0])

    def test_separate_empty_ack_keeps_original_data_path(self):
        empty = dict(self.final, flags=ACK, data=b'')
        self.flow.receive(empty, (64, 0))
        self.assertTrue(self.flow.established)
        self.assertEqual(self.flow.tags, [])
        self.flow.receive(self.final, (64, 0))
        self.assertEqual(self.flow.tags, [0])

    def test_bad_acknowledgment_sequence_flags_tuple_and_bytes_reject(self):
        variants = [dict(ack=(self.final['ack'] + 1) & 0xffffffff),
                    dict(seq=(self.final['seq'] + 1) & 0xffffffff),
                    dict(flags=ACK | FIN), dict(flags=SYN | ACK), dict(flags=8),
                    dict(flags=ACK | 4), dict(source_ip=bytes(16)),
                    dict(data=bytes([self.final['data'][0] ^ 1]) + self.final['data'][1:])]
        for mutation in variants:
            with self.subTest(mutation=mutation):
                peer = Peer(0)
                flow = peer.flows[0]
                flow.receive(packet(self.frames[0]), (64, 0))
                with self.assertRaises(ValueError):
                    flow.receive(dict(deepcopy(self.final), **mutation), (64, 0))

    def test_empty_final_ack_with_wrong_sequence_rejects(self):
        with self.assertRaises(ValueError):
            self.flow.receive(dict(self.final, flags=ACK, data=b'',
                                   seq=(self.final['seq'] + 1) & 0xffffffff), (64, 0))



class ScopedRouterMaintenanceTest(unittest.TestCase):
    # Actual companion-source solicitation observed during source restoration.
    frame=bytes.fromhex('33330000000252540012341086dd6000000000103afffe800000000000000000000000000003ff0200000000000000000000000000028500f5b4000000000101525400123410')

    def test_actual_companion_solicitation_is_valid_for_scoped_fixture(self):
        from tcp6.scoped_source_peer import Peer as ScopedPeer
        peer=ScopedPeer(0);peer.ready=True
        peer.receive(self.frame)
        self.assertEqual(peer.frames[-1]['frame'],self.frame.hex())

    def test_companion_source_is_not_enabled_for_other_workloads(self):
        peer=Peer(0);peer.ready=True
        with self.assertRaises(ValueError):peer.receive(self.frame)

    def test_corrupt_companion_solicitations_reject(self):
        from tcp6.scoped_source_peer import Peer as ScopedPeer
        from tcp_fault_peer import checksum
        import struct
        # Repair checksums after semantic changes so validation reaches each field.
        for field,offset in (('source',36),('destination',53),('hops',21),
                             ('link-owner',11),('option-owner',69),('reserved',61)):
            with self.subTest(field=field):
                changed=bytearray(self.frame);changed[offset]^=1;changed[56:58]=bytes(2)
                changed[56:58]=struct.pack('!H',checksum(changed[22:54]+struct.pack('!I3xB',16,58)+changed[54:]))
                peer=ScopedPeer(0);peer.ready=True
                with self.assertRaises(ValueError):peer.receive(bytes(changed))
        changed=bytearray(self.frame);changed[56]^=1
        peer=ScopedPeer(0);peer.ready=True
        with self.assertRaises(ValueError):peer.receive(bytes(changed))

    def test_companion_solicitation_requires_readiness(self):
        from tcp6.scoped_source_peer import Peer as ScopedPeer
        with self.assertRaises(ValueError):ScopedPeer(0).receive(self.frame)


if __name__ == '__main__':
    unittest.main()
