# SPDX-License-Identifier: GPL-3.0-or-later
"""Replay real packet shapes at the independent protocol peer boundary."""
import struct
import io
import unittest
from dhcp_peer import checksum
from manager_protocol_peer import BAD_REPLIES, ProtocolPeer, client_packet, fingerprint, tlvs
from manager_protocol_test import Controller


def request(peer, transaction, kind=1, configured=False, destination=None, server=None,
            requested=False, parameters=(121, 1, 3, 6, 15, 51, 58, 59, 119)):
    message = bytearray(240)
    message[:3] = b'\x01\x01\x06'
    message[4:8], message[28:34] = transaction, peer.guest
    message[10:12] = b'\x80\0' if destination is None else bytes(2)
    message[12:16] = peer.address if configured else bytes(4)
    message[236:240] = bytes.fromhex('63825363')
    rows = [(53, bytes([kind])), (61, b'\x01' + peer.guest)]
    if kind not in (4, 7):
        rows.append((55, bytes(parameters)))
    if server:
        rows.append((54, server))
    if requested:
        rows.append((50, peer.address))
    message += tlvs(rows)
    source = peer.address if configured else bytes(4)
    target = destination or b'\xff' * 4
    udp = bytearray(struct.pack('!HHHH', 68, 67, len(message) + 8, 0) + message)
    pseudo = source + target + b'\0\x11' + struct.pack('!H', len(udp))
    struct.pack_into('!H', udp, 6, checksum(pseudo + udp) or 65535)
    ip = bytearray(struct.pack('!BBHHHBBH4s4s', 0x45, 0, len(udp) + 20, 1,
                               0x4000, 64, 17, 0, source, target))
    struct.pack_into('!H', ip, 10, checksum(ip))
    return (peer.mac if destination else b'\xff' * 6) + peer.guest + b'\x08\x00' + ip + udp


def reply_options(frame):
    message = frame[42:]
    values = {}

    def scan(data):
        at = 0
        while at < len(data):
            code = data[at]
            at += 1
            if code == 255:
                return
            if code == 0:
                continue
            size = data[at]
            at += 1
            assert at + size <= len(data)
            values[code] = values.get(code, b'') + data[at:at + size]
            at += size
        raise AssertionError('reply field has no END')
    scan(message[240:])
    if values.get(52, b'\0')[0] & 1:
        scan(message[108:236])
    if values.get(52, b'\0')[0] & 2:
        scan(message[44:108])
    return values


class ProtocolPackets(unittest.TestCase):
    def setUp(self):
        self.peer = ProtocolPeer(0, 'options', 0)
        self.transaction = bytes.fromhex('12345678')

    def test_request_list_rejects_the_previous_complete_but_wrong_order(self):
        client_packet(request(self.peer, self.transaction), self.peer.guest)
        old = request(self.peer, self.transaction, parameters=(1, 3, 6, 15, 51, 58, 59, 119, 121))
        with self.assertRaisesRegex(RuntimeError, 'RFC 3442'):
            client_packet(old, self.peer.guest)

    def test_real_selected_request_rejects_a_competing_server(self):
        peer = self.peer
        peer.packet(request(peer, self.transaction))
        peer.approve()
        with self.assertRaisesRegex(RuntimeError, 'selected server'):
            peer.packet(request(peer, self.transaction, kind=3, requested=True, server=peer.other))
        peer.packet(request(peer, self.transaction, kind=3, requested=True, server=peer.ip))
        peer.approve()
        self.assertEqual(peer.ack_server, peer.ip)
        with self.assertRaisesRegex(RuntimeError, 'RELEASE'):
            peer.packet(request(peer, self.transaction, kind=7, configured=True,
                                destination=peer.other, server=peer.other))

    def test_positive_overload_concatenates_in_main_file_sname_order(self):
        frame = self.peer.reply(5, self.transaction)
        self.assertEqual(checksum(frame[14:34]), 0)
        udp = frame[34:]
        self.assertEqual(checksum(frame[26:34] + b'\0\x11' + struct.pack('!H', len(udp)) + udp), 0)
        values = reply_options(frame)
        self.assertEqual(values[1], bytes.fromhex('ffffff80'))
        self.assertEqual(values[6], bytes([10, 23, 1, 54, 1, 1, 1, 1]))
        self.assertEqual(values[119], b'\x03lab\x07example\0\x03dev\xc0\x04')
        self.assertEqual(values[121], b'\0' + self.peer.other + b'\x10\xac\x10' + bytes(4))
        self.assertEqual(values[3], self.peer.ip)  # Must lose to the different classless default.

    def test_server_nak_has_zero_addresses_and_no_ack_parameters(self):
        peer = ProtocolPeer(0, 'nak-renew', 0)
        frame = peer.reply(6, self.transaction)
        self.assertEqual(frame[54:70], bytes(16))
        self.assertEqual(set(reply_options(frame)), {53, 54, 61})
        self.assertEqual(frame[30:34], b'\xff' * 4)
        self.assertEqual(checksum(frame[14:34]), 0)

    def test_server_ack_echoes_client_flags_and_configured_address(self):
        peer = ProtocolPeer(0, 'renew-ack', 0)
        peer.packet(request(peer, self.transaction))
        peer.approve()
        self.assertEqual(bytes.fromhex(peer.sent[-1]['frame'])[52:54], b'\x80\0')
        peer.packet(request(peer, self.transaction, kind=3, requested=True, server=peer.ip))
        peer.approve()
        renewal = bytes.fromhex('12345679')
        peer.packet(request(peer, renewal, kind=3, configured=True, destination=peer.ip))
        frame = bytes.fromhex(peer.sent[-1]['frame'])
        self.assertEqual(frame[52:54], bytes(2))
        self.assertEqual(frame[54:58], peer.address)
        self.assertEqual(frame[30:34], peer.address)

    def test_every_malformed_variant_is_distinct_and_bounded(self):
        frames = [self.peer.reply(5, self.transaction, variant=variant) for variant in BAD_REPLIES]
        self.assertEqual(len(set(frames)), len(BAD_REPLIES))
        self.assertTrue(all(282 <= len(frame) <= 1518 for frame in frames))
        for variant, frame in zip(BAD_REPLIES, frames):
            with self.subTest(variant=variant):
                self.assertEqual(checksum(frame[14:34]) == 0, variant != 'ip-checksum')

    def test_injection_waits_for_correct_driver_receipt_before_next_packet(self):
        peer = ProtocolPeer(1, 'reply-rejection', 1)
        peer.packet(request(peer, self.transaction))
        peer.tick(False)
        self.assertFalse(peer.sent)
        peer.tick(True)
        self.assertEqual(len(peer.sent), 1)
        row = peer.sent[0]
        peer.tick(True)
        self.assertEqual(len(peer.sent), 1)
        peer.receipt(row['length'] + 1, row['hash'], 100, 1)
        peer.receipt(row['length'], '0' * 16, 100, 1)
        peer.receipt(row['length'], row['hash'], 100, 4)
        peer.tick(True)
        self.assertEqual(len(peer.sent), 1)
        peer.receipt(row['length'], row['hash'], 101, 1)
        peer.tick(True)
        self.assertEqual(len(peer.sent), 2)
        self.assertEqual(peer.sent[0]['guest_ms'], 101)

    def test_outbound_clock_receipt_can_arrive_before_the_tcp_packet(self):
        frame = request(self.peer, self.transaction)
        self.peer.receipt(len(frame), fingerprint(frame), 123, 4)
        self.peer.packet(frame)
        self.assertEqual(self.peer.received[0]['guest_ms'], 123)
        self.assertFalse(self.peer.unmatched)

    def test_capture_rejects_unmatched_driver_observations(self):
        peer = self.peer
        peer.packet(request(peer, self.transaction))
        peer.approve()
        peer.packet(request(peer, self.transaction, kind=3, requested=True, server=peer.ip))
        peer.approve()
        for source in (bytes(4),) * 3 + (peer.address,) * 2:
            arp = bytes.fromhex('0001080006040001') + peer.guest + source + bytes(6) + peer.address
            peer.packet((b'\xff' * 6 + peer.guest + b'\x08\x06' + arp).ljust(60, b'\0'))
        peer.packet(request(peer, self.transaction, kind=7, configured=True,
                            destination=peer.ip, server=peer.ip))
        for record in peer.received:
            peer.receipt(record['length'], record['hash'], record['sequence'], 4)
        for record in peer.sent:
            peer.receipt(record['length'], record['hash'], record['sequence'], 1)
        peer.verify()
        peer.receipt(60, '0' * 16, 100, 1)
        with self.assertRaisesRegex(RuntimeError, 'unmatched driver'):
            peer.verify()

    def test_controller_waits_for_new_request_ack_and_announcements_after_revocation(self):
        peers = [ProtocolPeer(lane, 'nak-renew', 0) for lane in (0, 1)]
        target, healthy = peers
        process = type('Serial', (), {'stdin': io.BytesIO()})()
        controller = Controller(process, peers, 0)
        controller.ready = True

        def announce(peer):
            arp = bytes.fromhex('0001080006040001') + peer.guest + peer.address + bytes(6) + peer.address
            peer.packet((b'\xff' * 6 + peer.guest + b'\x08\x06' + arp).ljust(60, b'\0'))

        def receipts():
            for peer in peers:
                for row in peer.sent:
                    if not row['delivered']:
                        peer.receipt(row['length'], row['hash'], 1, 1)

        announce(healthy)
        announce(healthy)
        target.packet(request(target, self.transaction))
        controller.drive()
        target.packet(request(target, self.transaction, kind=3, requested=True, server=target.ip))
        controller.drive()
        announce(target)
        announce(target)
        controller.drive()
        controller.line('MANAGER_PROTOCOL_PASS stage=bound affected=0 monotonic_ms=20000')
        renewing = bytes.fromhex('12345679')
        target.packet(request(target, renewing, kind=3, configured=True, destination=target.ip))
        for _ in range(3):
            controller.drive()
            receipts()
        controller.drive()
        controller.line('MANAGER_PROTOCOL_PASS stage=bound affected=0 monotonic_ms=28000')
        receipts()
        fresh = bytes.fromhex('1234567a')
        target.packet(request(target, fresh))
        controller.drive()
        controller.line('MANAGER_PROTOCOL_PASS stage=withdrawn affected=0 monotonic_ms=35000')
        controller.drive()
        self.assertIsNone(controller.pending, 'old announcements cannot complete a new acquisition')
        target.packet(request(target, fresh, kind=3, requested=True, server=target.other))
        controller.drive()
        self.assertEqual(target.acks, 2)
        self.assertIsNone(controller.pending, 'a new ACK still needs its actual announcements')
        announce(target)
        controller.drive()
        self.assertIsNone(controller.pending)
        announce(target)
        controller.drive()
        self.assertEqual(controller.pending[0], 'recovered')


if __name__ == '__main__':
    unittest.main(verbosity=2)
