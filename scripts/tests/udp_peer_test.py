# SPDX-License-Identifier: GPL-3.0-or-later
"""Keep UDP peer header checks tied to the path's observed hint history."""
from pathlib import Path
import json
import struct
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from udp_peer import Peer, checksum, ipv4, payload, udp


def frame(peer, phase, source_port, destination_port, *, flags=0x4000,
          destination=None, mac=None, length=31, sequence=0):
    destination = destination or peer.ip
    data = payload(length, peer.lane, phase, sequence)
    packet = bytearray(ipv4(peer.guest_ip, destination,
                           udp(peer.guest_ip, destination, source_port, destination_port, data)))
    struct.pack_into('!H', packet, 6, flags)
    packet[8] = 64
    packet[10:12] = b'\0\0'
    struct.pack_into('!H', packet, 10, checksum(bytes(packet[:20])))
    return ((mac or peer.mac) + peer.guest + b'\x08\0' + packet).ljust(60, b'\0')


def learned(lane):
    peer = Peer(lane)
    peer.frames, peer.zero = 4, 1
    peer.packet(frame(peer, 'I', 41000 + lane, 9000))
    # The three actual broadcast requests precede the first unicast reply from
    # the other socket. Their distinct destination still requires DF.
    for sequence in range(3):
        peer.packet(frame(peer, 'B', 41000 + lane, 9000, sequence=sequence,
                          destination=b'\xff' * 4, mac=b'\xff' * 6))
    return peer


class UdpPeerTest(unittest.TestCase):
    def test_actual_administrative_restoration_retires_the_locked_path(self):
        value = json.loads((Path(__file__).parent / 'fixtures/udp-route-retirement.json').read_text())
        peer = learned(value['lane'])
        peer.packet(bytes.fromhex(value['frames']['L']))
        peer.packet(bytes.fromhex(value['frames']['R']))
        self.assertFalse(peer.path_locked)

    def test_restored_route_rejects_the_retired_path_flags(self):
        value = json.loads((Path(__file__).parent / 'fixtures/udp-route-retirement.json').read_text())
        peer = learned(value['lane'])
        peer.packet(bytes.fromhex(value['frames']['L']))
        packet = bytearray.fromhex(value['frames']['R'])
        packet[20:22] = b'\0\0'
        packet[24:26] = b'\0\0'
        struct.pack_into('!H', packet, 24, checksum(bytes(packet[14:34])))
        with self.assertRaisesRegex(RuntimeError, 'Ethernet/IPv4 header'):
            peer.packet(bytes(packet))

    def test_shared_locked_path_from_another_socket(self):
        for lane in range(2):
            with self.subTest(lane=lane):
                peer = learned(lane)
                peer.packet(frame(peer, 'K', 44000 + lane, 9003, flags=0))
                self.assertEqual(peer.broadcast_ack, 1)

    def test_locked_path_requires_df_clear(self):
        for lane in range(2):
            with self.subTest(lane=lane):
                peer = learned(lane)
                with self.assertRaisesRegex(RuntimeError, 'Ethernet/IPv4 header'):
                    peer.packet(frame(peer, 'K', 44000 + lane, 9003))

    def test_fresh_path_requires_df(self):
        peer = Peer(0)
        peer.broadcast_ingress = 1
        with self.assertRaisesRegex(RuntimeError, 'Ethernet/IPv4 header'):
            peer.packet(frame(peer, 'K', 44000, 9003, flags=0))

    def test_other_destination_keeps_its_df_policy(self):
        for lane in range(2):
            for flags in [0x4000, 0]:
                with self.subTest(lane=lane, flags=flags):
                    peer = learned(lane)
                    peer.pressure_released = True
                    packet = frame(peer, 'P', 45000 + lane, 9000, flags=flags,
                                   destination=peer.pressure_ip, mac=peer.pressure_mac, length=129)
                    if flags:
                        peer.packet(packet)
                        self.assertEqual(peer.pressure_frames, 1)
                    else:
                        with self.assertRaisesRegex(RuntimeError, 'Ethernet/IPv4 header'):
                            peer.packet(packet)

    def test_locked_path_still_checks_headers_and_payload(self):
        for kind in ['checksum', 'ttl', 'fragment', 'payload']:
            with self.subTest(kind=kind):
                peer = learned(0)
                packet = bytearray(frame(peer, 'K', 44000, 9003, flags=0))
                offset = {'checksum': 24, 'ttl': 22, 'fragment': 21, 'payload': 50}[kind]
                packet[offset] ^= 1
                if kind in ['ttl', 'fragment']:
                    packet[24:26] = b'\0\0'
                    struct.pack_into('!H', packet, 24, checksum(bytes(packet[14:34])))
                with self.assertRaises(RuntimeError):
                    peer.packet(bytes(packet))


if __name__ == '__main__':
    unittest.main()
