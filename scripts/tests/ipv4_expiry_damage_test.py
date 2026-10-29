# SPDX-License-Identifier: GPL-3.0-or-later
"""Keep expiry mutations on their owned packets when IPv4 IDs collide."""
import copy
from pathlib import Path
import struct
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from ipv4_expiry_capture import checksum, damages


def packet(identity, source, destination, flags=0x2000, protocol=1, payload=b'P' * 24,
           broadcast=False):
    header = bytearray(struct.pack('!BBHHHBBH4s4s', 0x45, 0, 20 + len(payload), identity,
                                   flags, 51, protocol, 0, source, destination))
    struct.pack_into('!H', header, 10, checksum(header))
    return ((b'\xff' * 6 if broadcast else bytes.fromhex('525400123410')) +
            bytes.fromhex('024158495000') + b'\x08\0' + header + payload)


def cohort():
    remote, local = bytes([10, 23, 1, 1]), bytes([10, 23, 1, 2])
    first = packet(0x7a10, remote, local)
    quote = packet(0x1234, local, remote, flags=0,
                   payload=b'\x0b\x01' + b'\0' * 6 + first[14:42])
    return [dict(ns=at * 1000000000, frame=frame) for at, frame in [
        (0, first), (8, first),
        (1, packet(0x7a11, remote, local, flags=3)),
        (2, packet(0x7a12, remote, local)),
        (3, packet(0x7a13, remote, local, broadcast=True)),
        (61, quote), (70, first)]]


class ExpiryDamageOwnershipTest(unittest.TestCase):
    def test_broadcast_damage_ignores_later_udp_with_the_same_id(self):
        rows = cohort()
        noise = dict(ns=71 * 1000000000,
                     frame=packet(0x7a12, bytes([10, 23, 1, 2]), bytes([10, 23, 1, 193]),
                                  flags=0x4000, protocol=17, payload=b'U' * 40))
        rows.append(noise)
        original = copy.deepcopy(rows)
        changed = dict(damages(rows, 0, native=True))['unicast-broadcast-case']
        self.assertEqual(changed[-1], noise)
        self.assertEqual(changed[4]['frame'][:6], bytes.fromhex('525400123410'))
        self.assertEqual(rows, original)

    def test_foreign_first_fragment_does_not_change_the_seed(self):
        rows = cohort()
        rows.append(dict(ns=72 * 1000000000,
                         frame=packet(0x7a10, bytes([10, 23, 1, 2]), bytes([10, 23, 1, 193]),
                                      protocol=17)))
        self.assertEqual(len(list(damages(rows, 0, native=True))), 10)

    def test_foreign_quote_does_not_change_the_seed(self):
        rows = cohort()
        quoted = rows[0]['frame'][14:42]
        rows.append(dict(ns=73 * 1000000000,
                         frame=packet(0x4321, bytes([10, 99, 0, 1]), bytes([10, 99, 0, 2]),
                                      flags=0, payload=b'\x0b\x01' + b'\0' * 6 + quoted)))
        self.assertEqual(len(list(damages(rows, 0, native=True))), 10)

    def test_udp_quote_with_the_same_addresses_and_id_does_not_change_the_seed(self):
        rows = cohort()
        remote, local = bytes([10, 23, 1, 1]), bytes([10, 23, 1, 2])
        quoted = packet(0x7a10, remote, local, protocol=17)[14:42]
        noise = dict(ns=74 * 1000000000,
                     frame=packet(0x4321, local, remote, flags=0,
                                  payload=b'\x0b\x01' + b'\0' * 6 + quoted))
        rows.append(noise)
        original = copy.deepcopy(rows)
        changes = list(damages(rows, 0, native=True))
        self.assertEqual(len(changes), 10)
        self.assertTrue(all(changed[-1] == noise for _, changed in changes))
        self.assertEqual(rows, original)


if __name__ == '__main__':
    unittest.main()
