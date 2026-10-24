# SPDX-License-Identifier: GPL-3.0-or-later
"""Reject damaged alias wire controls before advancing the live peer."""
from pathlib import Path
import struct
import sys
import unittest
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from ipv4_aliases import AliasPeer, checksum


def control():
    peer = AliasPeer(0)
    body = bytearray([8, 0, 0, 0, ord('A'), ord('L'), 0, 0])
    body.extend((n * 17) & 255 for n in range(8, 64))
    struct.pack_into('!H', body, 2, checksum(bytes(body)))
    packet = bytearray(struct.pack('!BBHHHBBH4s4s', 0x45, 0, 84, 7, 0x4000,
                                   64, 1, 0, peer.alias, peer.primary[:3] + b'\x09'))
    struct.pack_into('!H', packet, 10, checksum(bytes(packet)))
    return bytearray(peer.mac + peer.guest + b'\x08\0' + packet + body)


def header_checksum(frame):
    frame[24:26] = b'\0\0'
    struct.pack_into('!H', frame, 24, checksum(bytes(frame[14:34])))


class AliasControls(unittest.TestCase):
    def test_original_control(self):
        peer = AliasPeer(0)
        self.assertEqual(len(peer.receive(bytes(control()))), 2)
        self.assertEqual(peer.cases, 1)

    def test_damaged_controls(self):
        for mutation in ('oversized-total', 'short-total', 'truncated', 'ip-checksum',
                         'icmp-checksum', 'source', 'destination', 'mac', 'ttl',
                         'fragment', 'case', 'payload', 'padding'):
            with self.subTest(mutation=mutation):
                frame = control()
                if mutation in ('oversized-total', 'short-total'):
                    struct.pack_into('!H', frame, 16, 100 if mutation == 'oversized-total' else 83)
                    header_checksum(frame)
                elif mutation == 'truncated':
                    frame = frame[:-1]
                elif mutation == 'ip-checksum':
                    frame[24] ^= 1
                elif mutation == 'icmp-checksum':
                    frame[36] ^= 1
                elif mutation in ('source', 'destination'):
                    frame[29 if mutation == 'source' else 33] ^= 1
                    header_checksum(frame)
                elif mutation == 'mac':
                    frame[0] ^= 2
                elif mutation == 'ttl':
                    frame[22] = 63
                    header_checksum(frame)
                elif mutation == 'fragment':
                    frame[20:22] = b'\x20\0'
                    header_checksum(frame)
                elif mutation in ('case', 'payload'):
                    frame[40 if mutation == 'case' else 50] ^= 1
                    frame[36:38] = b'\0\0'
                    struct.pack_into('!H', frame, 36, checksum(bytes(frame[34:])))
                else:
                    frame += b'\x01'
                peer = AliasPeer(0)
                with self.assertRaises(ValueError):
                    peer.receive(bytes(frame))
                self.assertEqual(peer.cases, 0)


if __name__ == '__main__':
    unittest.main()
