# SPDX-License-Identifier: GPL-3.0-or-later
"""Inject source-distinct UDP packets after each actual delivery barrier."""
import struct

from ipv4_multicast.source_peer import SourcePeer
from ipv4_multicast_peer import checksum, packet

GROUP = bytes.fromhex('ef7f2a01')
GROUP_MAC = bytes.fromhex('01005e7f2a01')


class DeliveryPeer(SourcePeer):
    def __init__(self, lane):
        super().__init__(lane)
        self.scenario = 'delivery'
        self.count = 8
        self.injected = 0

    def query(self, stage):
        frames = []
        for which in range(2):
            source = bytes([10, 67, self.lane + 1, 1 + which * 2])
            payload = b'AXSI' + bytes([self.lane, stage, which, 0x7e])
            udp = bytearray(struct.pack('!HHHH', 41002, 39901, 16, 0) + payload)
            pseudo = source + GROUP + b'\0\x11' + struct.pack('!H', len(udp))
            struct.pack_into('!H', udp, 6, checksum(pseudo + udp) or 65535)
            frames.append((GROUP_MAC + self.mac + b'\x08\x00' +
                           packet(source, GROUP, bytes(udp), 17)).ljust(60, b'\0'))
        self.injected += len(frames)
        return frames

    def result(self):
        return dict(super().result(), data_packets_injected=self.injected)
