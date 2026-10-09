"""Replay independent client packets across two lease lifetimes in one peer."""
import struct
import unittest
from dhcp_peer import Peer, checksum
from manager_peer import ManagerPeer


def frame(peer, transaction, kind, configured=False, destination=None, server=None, requested=False):
    message = bytearray(240)
    message[:3] = bytes([1, 1, 6])
    message[4:8] = transaction
    broadcast = destination is None
    message[10:12] = b'\x80\x00' if broadcast else bytes(2)
    message[12:16] = peer.address if configured else bytes(4)
    message[28:34] = peer.guest
    message[236:240] = bytes.fromhex('63825363')
    options = [(53, bytes([kind])), (61, b'\x01' + peer.guest)]
    if kind == 1:
        options.append((55, bytes([1, 3, 6, 15, 51, 58, 59, 119, 121])))
    if server:
        options.append((54, server))
    if requested:
        options.append((50, peer.address))
    for code, value in options:
        message += bytes([code, len(value)]) + value
    message += b'\xff'
    source = peer.address if configured else bytes(4)
    destination = destination or bytes([255]) * 4
    udp = bytearray(struct.pack('!HHHH', 68, 67, len(message) + 8, 0) + message)
    pseudo = source + destination + bytes([0, 17]) + struct.pack('!H', len(udp))
    struct.pack_into('!H', udp, 6, checksum(pseudo + udp) or 65535)
    ip = bytearray(struct.pack('!BBHHHBBH4s4s', 0x45, 0, len(udp) + 20, 1, 0x4000,
                               64, 17, 0, source, destination))
    struct.pack_into('!H', ip, 10, checksum(ip))
    return (bytes([255]) * 6 if broadcast else peer.mac) + peer.guest + bytes.fromhex('0800') + ip + udp


def acquired(peer, transaction):
    peer.packet(frame(peer, transaction, 1))
    if peer.discovers == 1:
        peer.packet(frame(peer, transaction, 1))
    peer.packet(frame(peer, transaction, 3, server=peer.ip, requested=True))


class LeaseLifetime(unittest.TestCase):
    def test_release_after_second_selecting_ack(self):
        peer = Peer(0)
        old, new = bytes.fromhex('12345678'), bytes.fromhex('87654321')
        acquired(peer, old)
        peer.packet(frame(peer, old, 3, configured=True))  # First lease rebinds to .2.
        acquired(peer, new)  # A replacement process obtains a new ACK from .1.
        peer.packet(frame(peer, new, 7, configured=True, destination=peer.ip, server=peer.ip))
        self.assertEqual((peer.selecting, peer.rebindings, peer.releases), (2, 1, 1))

    def test_release_after_second_reboot_ack(self):
        peer = ManagerPeer(1, 'restart')
        old, new = bytes.fromhex('12345678'), bytes.fromhex('87654321')
        acquired(peer, old)
        peer.packet(frame(peer, old, 3, configured=True))
        peer.packet(frame(peer, new, 3, requested=True))
        peer.packet(frame(peer, new, 7, configured=True, destination=peer.ip, server=peer.ip))
        self.assertEqual((peer.reboots, peer.rebindings, peer.releases), (1, 1, 1))

    def test_previous_server_is_rejected_after_new_ack(self):
        peer = Peer(0)
        old, new = bytes.fromhex('12345678'), bytes.fromhex('87654321')
        acquired(peer, old)
        peer.packet(frame(peer, old, 3, configured=True))
        acquired(peer, new)
        with self.assertRaisesRegex(RuntimeError, 'RELEASE fields'):
            peer.packet(frame(peer, new, 7, configured=True, destination=peer.other, server=peer.other))

    def test_standard_rebound_release_remains_checked(self):
        peer = Peer(0)
        transaction = bytes.fromhex('12345678')
        acquired(peer, transaction)
        peer.packet(frame(peer, transaction, 3, configured=True))
        peer.packet(frame(peer, transaction, 7, configured=True, destination=peer.other, server=peer.other))
        self.assertEqual(peer.releases, 1)


if __name__ == '__main__':
    unittest.main(verbosity=2)
