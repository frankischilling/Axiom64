#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Retain source-restoration handshake replies through an original TCP retry."""
from pathlib import Path
from copy import deepcopy
import hashlib
import json
import struct
import sys
import tempfile
import unittest
import zipfile

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from tcp6.pending_peer import Peer
from tcp6.peer import packet
from tcp_fault_peer import SYN as SYN_FLAG, ACK
from tcp_fault_peer import checksum
from tcp6.pending_capture import verify
from ipv4_expiry_capture import read_capture, encode_capture

# Original native SYN, withdrawn-source retry, restoration barrier and later retry.
SYN = bytes.fromhex(
    '02415854430152540012341186dd600000000028064020010db8000200000000000000000002'
    '20010db8000200000000000000000001c743c7a723e6d0f500000000a002fd2037c10000'
    '020405a00402080a4e6be583000000000103030a')
WITHDRAWN_RETRY = bytes.fromhex(
    '02415854430152540012341186dd600000000028064020010db8000200000000000000000002'
    '20010db8000200000000000000000001c743c7a723e6d0f500000000a002fd2033c20000'
    '020405a00402080a4e6be982000000000103030a')
RESTORATION = bytes.fromhex(
    '02495036010052540012341188ca49503650011400') + bytes(39)
RESTORED_RETRY = bytes.fromhex(
    '02415854430152540012341186dd600000000028064020010db8000200000000000000000002'
    '20010db8000200000000000000000001c743c7a723e6d0f500000000a002fd202fc20000'
    '020405a00402080a4e6bed82000000000103030a')
SYNACK = bytes.fromhex(
    '52540012341102415854430186dd600000000018064020010db8000200000000000000000001'
    '20010db8000200000000000000000002c7a7c7435577110023e6d0f66012200035fa000002040218')


class PendingRetryTest(unittest.TestCase):
    def released_active(self):
        peer = Peer(1, native=True)
        flow = peer.flows[2]
        flow.receive(packet(SYN))
        flow.receive(packet(WITHDRAWN_RETRY))
        self.assertEqual(peer.outgoing, [])
        self.assertEqual(len(RESTORATION), 60)
        peer.waiting = (20, RESTORATION)
        peer.complete_if_ready()
        return peer, flow

    def test_post_restoration_syn_retains_the_original_reply(self):
        peer = Peer(1, native=True)
        flow = peer.flows[2]  # Active pending connection, round one.
        flow.receive(packet(SYN))
        flow.receive(packet(WITHDRAWN_RETRY))
        self.assertEqual(peer.outgoing, [], 'withdrawal still withholds every handshake reply')
        # The caller has received the actual source-restoration barrier.
        peer.waiting = (20, RESTORATION)
        peer.complete_if_ready()
        self.assertEqual(peer.outgoing[0], SYNACK)
        self.assertIsNone(peer.waiting)
        count = len(peer.outgoing)
        flow.receive(packet(RESTORED_RETRY))
        self.assertEqual(peer.outgoing[count:], [SYNACK],
                         'a matching retry must recover a lost released SYNACK')

    def test_passive_retry_recovers_the_released_final_ack(self):
        peer = Peer(1, native=True)
        flow = peer.flows[6]
        value = packet(SYN)
        value.update(source=flow.local, target=flow.remote, seq=0x12345678,
                     ack=flow.remote_next, flags=SYN_FLAG | ACK)
        flow.receive(value)
        flow.receive(value)
        self.assertEqual(peer.outgoing, [])
        restoration = bytearray(RESTORATION)
        restoration[19] = 52
        peer.waiting = (52, bytes(restoration))
        peer.complete_if_ready()
        reply = peer.outgoing[0]
        self.assertEqual(packet(reply)['flags'], ACK)
        count = len(peer.outgoing)
        flow.receive(value)
        self.assertEqual(peer.outgoing[count:], [reply],
                         'a matching SYNACK retry must recover a lost final ACK')

    def test_changed_pending_identity_does_not_receive_a_reply(self):
        peer, flow = self.released_active()
        count = len(peer.outgoing)
        for change in ({'seq': packet(SYN)['seq'] + 1}, {'ack': 1},
                       {'source_ip': flow.address[:-1] + b'\3'},
                       {'flags': SYN_FLAG | ACK}, {'data': b'changed'}):
            with self.subTest(change=change):
                value = packet(RESTORED_RETRY)
                value.update(change)
                with self.assertRaises(ValueError):
                    flow.receive(value)
                self.assertEqual(len(peer.outgoing), count)

    def test_established_active_flow_does_not_restart_its_handshake(self):
        peer, flow = self.released_active()
        value = packet(SYN)
        value.update(seq=flow.guest_next, ack=flow.remote_next, flags=ACK)
        flow.receive(value)
        self.assertTrue(flow.established)
        count = len(peer.outgoing)
        flow.receive(packet(RESTORED_RETRY))
        self.assertEqual(len(peer.outgoing), count)

    def test_fresh_companion_still_replies_before_main_source_restoration(self):
        peer = Peer(1, native=True)
        flow = peer.flows[3]
        value = packet(SYN)
        value.update(source=flow.local, target=flow.remote, source_ip=flow.address)
        flow.receive(value)
        self.assertEqual(packet(peer.outgoing[0])['flags'], SYN_FLAG | ACK)
        self.assertFalse(peer.flows[2].released)


class RecoveryCaptureTest(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix='tcp6-pending-recovery-')
        self.addCleanup(self.temporary.cleanup)
        self.directory = Path(self.temporary.name)
        fixture = Path(__file__).with_name('fixtures') / 'tcp6-pending-recovery.zip'
        with zipfile.ZipFile(fixture) as archive:
            self.assertEqual(set(archive.namelist()),
                             {'lane0.pcap', 'lane1.pcap', 'client.log', 'provenance.json'})
            provenance = json.loads(archive.read('provenance.json'))
            self.assertFalse(provenance['native_clock_qualification'])
            self.assertFalse(provenance['guest_execution'])
            for name, value in provenance['files'].items():
                body = archive.read(name)
                self.assertEqual(hashlib.sha256(body).hexdigest(), value['sha256'])
                (self.directory / name).write_bytes(body)
        self.log = (self.directory / 'client.log').read_text()
        self.path = self.directory / 'lane1.pcap'
        self.rows = read_capture(self.path)

    def tcp(self, source, target, flags):
        result = []
        for index, row in enumerate(self.rows):
            frame = row['frame']
            if len(frame) >= 74 and frame[12:14] == b'\x86\xdd' and frame[20] == 6:
                value = packet(frame)
                if (value['source'], value['target'], value['flags']) == (source, target, flags):
                    result.append(index)
        return result

    def reject(self, rows, message):
        self.path.write_bytes(encode_capture(rows))
        with self.assertRaisesRegex(ValueError, message):
            verify(self.path, 1, self.log)

    def test_both_lost_release_replies_recover_with_owned_retries(self):
        # Offline semantic fixture; live native comparisons retain clock qualification.
        for lane in (1, 0):
            proof = verify(self.directory / f'lane{lane}.pcap', lane, self.log)
            self.assertEqual(proof['actual_flows'], 8)
            self.assertEqual(sum(row['recovery_replies'] for row in proof['observations']),
                             2 if lane else 0)

    def test_orphan_synack_does_not_count_as_recovery(self):
        rows = deepcopy(self.rows)
        index = self.tcp(51111, 51011, SYN_FLAG | ACK)[0]
        rows.insert(index + 1, deepcopy(rows[index]))
        self.reject(rows, 'owned retry')

    def test_orphan_passive_ack_does_not_count_as_recovery(self):
        rows = deepcopy(self.rows)
        index = self.tcp(51131, 51031, ACK)[0]
        rows.insert(index + 1, deepcopy(rows[index]))
        self.reject(rows, 'owned retry')

    def test_recovery_reply_preserves_every_original_byte(self):
        rows = deepcopy(self.rows)
        index = self.tcp(51111, 51011, SYN_FLAG | ACK)[1]
        frame = bytearray(rows[index]['frame'])
        frame[58:62] = ((int.from_bytes(frame[58:62], 'big') + 1) & 0xffffffff).to_bytes(4, 'big')
        frame[70:72] = b'\0\0'
        frame[70:72] = struct.pack('!H', checksum(frame[22:54] +
            struct.pack('!I3xB', len(frame) - 54, 6) + frame[54:]))
        rows[index]['frame'] = bytes(frame)
        self.reject(rows, 'identical released handshake reply')

    def test_all_passive_replies_still_acknowledge_the_actual_original_synack(self):
        rows = deepcopy(self.rows)
        for index in self.tcp(51131, 51031, ACK):
            frame = bytearray(rows[index]['frame'])
            frame[62:66] = ((int.from_bytes(frame[62:66], 'big') + 1) & 0xffffffff).to_bytes(4, 'big')
            frame[70:72] = b'\0\0'
            frame[70:72] = struct.pack('!H', checksum(frame[22:54] +
                struct.pack('!I3xB', len(frame) - 54, 6) + frame[54:]))
            rows[index]['frame'] = bytes(frame)
        self.reject(rows, 'exact initial released handshake')

    def test_recovery_cannot_replace_the_original_restoration_reply(self):
        rows = deepcopy(self.rows)
        rows.pop(self.tcp(51111, 51011, SYN_FLAG | ACK)[0])
        self.reject(rows, 'input follows explicit source restoration')

    def test_natural_withdrawn_retry_keeps_its_original_lower_bound(self):
        rows = deepcopy(self.rows)
        origin = rows[0]['ns']
        for row in rows:
            row['ns'] = origin + (row['ns'] - origin) // 10
        self.reject(rows, '850ms wire lower bound')

    def test_recovery_reply_cannot_arrive_after_application_data(self):
        rows = deepcopy(self.rows)
        reply = self.tcp(51111, 51011, SYN_FLAG | ACK)[1]
        data = self.tcp(51011, 51111, ACK | 8)[0]
        moved = rows.pop(reply)
        rows.insert(data, moved)
        self.reject(rows, 'recovery precedes application data')


if __name__ == '__main__':
    unittest.main()
