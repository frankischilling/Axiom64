"""Check real client packet replay while a supervision ACK is deliberately held."""
import unittest
from manager_peer_test import acquired, frame
from normal_manager_test import SupervisionPeer


class HeldRestartAck(unittest.TestCase):
    def test_firmware_traffic_is_counted_before_manager_and_rejected_after(self):
        peer = SupervisionPeer(0, True)
        header = bytes.fromhex('3333ff12341052540012341086dd6000000000200001'
                               '00000000000000000000000000000000ff0200000000000000000001ff123410')
        firmware = header + bytes(86 - len(header))
        peer.deliver(firmware, False)
        self.assertEqual(peer.before_manager, {'86dd': 1})
        self.assertFalse(peer.discovers)
        with self.assertRaisesRegex(RuntimeError, 'protocol=86dd'):
            peer.deliver(firmware, True)
        discover = frame(peer, bytes.fromhex('12345678'), 1)
        peer.deliver(discover, True)
        self.assertEqual(peer.discovers, 1)
        self.assertEqual(peer.before_manager, {'86dd': 1})

    def test_missing_peer_requires_a_new_process_discovery(self):
        peer = SupervisionPeer(1, False)
        old, new = bytes.fromhex('12345678'), bytes.fromhex('87654321')
        peer.packet(frame(peer, old, 1))
        peer.verify_initial()
        peer.packet(frame(peer, old, 1))
        self.assertFalse(peer.restart_discover_transaction)
        peer.packet(frame(peer, new, 1))
        self.assertEqual(peer.restart_discover_transaction, new)
        self.assertEqual(peer.discover_transactions, [old.hex(), old.hex(), new.hex()])
        self.assertFalse(peer.output)

    def test_same_transaction_retries_remain_pending(self):
        peer = SupervisionPeer(0, True)
        old, new = bytes.fromhex('12345678'), bytes.fromhex('87654321')
        acquired(peer, old)
        peer.output.clear()
        peer.packet(frame(peer, new, 3, requested=True))
        peer.packet(frame(peer, new, 3, requested=True))
        self.assertEqual(peer.pending, new)
        self.assertEqual(peer.restart_transaction, new)
        self.assertEqual(peer.initial_transaction, old)
        self.assertFalse(peer.output)
        peer.approve()
        self.assertIsNone(peer.pending)
        self.assertEqual(peer.ack_server, peer.other)
        self.assertTrue(peer.output)
        peer.output.clear()
        peer.packet(frame(peer, new, 3, requested=True))
        self.assertIsNone(peer.pending)
        self.assertEqual(peer.restart_transaction, new)
        self.assertEqual(peer.ack_server, peer.other)
        self.assertTrue(peer.output)
        peer.output.clear()
        peer.packet(frame(peer, new, 7, configured=True, destination=peer.other, server=peer.other))
        peer.packet(frame(peer, bytes.fromhex('aabbccdd'), 1))
        self.assertFalse(peer.output)

    def test_different_pending_transaction_is_rejected(self):
        peer = SupervisionPeer(1, True)
        peer.packet(frame(peer, bytes.fromhex('12345678'), 3, requested=True))
        with self.assertRaises(RuntimeError):
            peer.packet(frame(peer, bytes.fromhex('87654321'), 3, requested=True))



class AutomaticIpv6(unittest.TestCase):
    @staticmethod
    def captured(lane):
        from pathlib import Path
        import hashlib
        import json
        from ipv6_router_capture import qemu_records
        fixtures = Path(__file__).resolve().parent / 'tests/fixtures'
        metadata = json.loads((fixtures / 'normal-init-default-ipv6.json').read_text())
        row = metadata['captures'][lane]
        data = (fixtures / row['file']).read_bytes()
        if hashlib.sha256(data).hexdigest() != row['sha256']:
            raise ValueError('changed original normal-init automatic IPv6 capture')
        return [row['frame'] for row in qemu_records(fixtures / row['file'])
                if len(row['frame']) >= 54 and row['frame'][12:14] == b'\x86\xdd']

    def test_actual_default_controls_keep_ipv4_counters_unchanged(self):
        for lane in range(2):
            peer = SupervisionPeer(lane, False)
            packets = self.captured(lane)
            self.assertEqual({frame[54] for frame in packets}, {133, 135})
            for frame in packets:
                with self.subTest(lane=lane, type=frame[54]):
                    peer.deliver(frame, True)
            self.assertEqual([bytes.fromhex(row['frame']) for row in peer.ipv6_control.records], packets)
            self.assertFalse(peer.discovers)
            self.assertFalse(peer.output)

    def test_checksum_valid_field_damage_and_unknown_ipv6_remain_rejected(self):
        import struct
        from ipv6_host_peer import checksum
        original = next(frame for frame in self.captured(0) if frame[54] == 133)
        # Recompute checksums after semantic damage so each contract is tested.
        for field, offset, value in (('Ethernet destination', 5, 1), ('Ethernet source', 11, 17),
                                     ('version', 14, 0x50), ('length', 19, 15),
                                     ('next header', 20, 17), ('hop limit', 21, 254),
                                     ('source', 37, 17), ('destination', 53, 1),
                                     ('type', 54, 129), ('code', 55, 1), ('reserved', 58, 1),
                                     ('SLLA type', 62, 2), ('SLLA length', 63, 0),
                                     ('SLLA address', 69, 17)):
            frame = bytearray(original)
            frame[offset] = value
            frame[56:58] = bytes(2)
            struct.pack_into('!H', frame, 56, checksum(bytes(frame[22:54]) +
                struct.pack('!I3xB', len(frame) - 54, 58) + bytes(frame[54:])))
            peer = SupervisionPeer(0, False)
            with self.subTest(field=field), self.assertRaisesRegex(RuntimeError, 'protocol=86dd'):
                peer.deliver(bytes(frame), True)
        for frame in (original[:65], original + b'\0',
                      original[:56] + bytes([original[56] ^ 1]) + original[57:]):
            with self.assertRaisesRegex(RuntimeError, 'protocol=86dd'):
                SupervisionPeer(0, False).deliver(frame, True)

    def test_control_capture_is_bounded(self):
        peer = SupervisionPeer(0, False)
        packet = next(frame for frame in self.captured(0) if frame[54] == 133)
        for _ in range(64):
            peer.deliver(packet, True)
        with self.assertRaisesRegex(RuntimeError, 'bounded'):
            peer.deliver(packet, True)

    def test_checksum_valid_dad_target_source_and_nonce_damage(self):
        import struct
        from ipv6_host_peer import checksum
        original = next(frame for frame in self.captured(0) if frame[54] == 135)
        self.assertEqual(len(original), 86)
        for field, offset, value in (('source', 37, 1), ('destination', 53, 17),
                                     ('target', 77, 17), ('nonce type', 78, 1),
                                     ('nonce length', 79, 0), ('type', 54, 136)):
            frame = bytearray(original)
            frame[offset] = value
            frame[56:58] = bytes(2)
            struct.pack_into('!H', frame, 56, checksum(bytes(frame[22:54]) +
                struct.pack('!I3xB', len(frame) - 54, 58) + bytes(frame[54:])))
            with self.subTest(field=field), self.assertRaisesRegex(RuntimeError, 'protocol=86dd'):
                SupervisionPeer(0, False).deliver(bytes(frame), True)


if __name__ == '__main__':
    unittest.main(verbosity=2)
