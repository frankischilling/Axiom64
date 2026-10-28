# SPDX-License-Identifier: GPL-3.0-or-later
"""Inject complete source queries at the socket and Ethernet query limits."""
import struct

from ipv4_multicast.source_peer import SourcePeer
from ipv4_multicast_peer import checksum, packet


class QueryBoundsPeer(SourcePeer):
    def __init__(self, lane):
        super().__init__(lane)
        self.scenario = 'query-bounds'
        self.count = 8

    def query(self, stage):
        if stage not in (2, 3, 4, 6, 7):
            return []
        first = 0xc0000201
        if stage in (2, 6):
            sources = [first + 100 + n for n in range(65)]
        elif stage == 7:
            sources = [first + 100 + n for n in range(366)]
        else:
            sources = [first] * (65 if stage == 4 else 1)
        group = bytes.fromhex('ef7f2a01')
        body = bytearray(b'\x11\x0a\0\0' + group + b'\x02\x7d' + struct.pack('!H', len(sources)))
        body.extend(b''.join(struct.pack('!I', source) for source in sources))
        if stage == 3:
            body.extend(b'\0\0\0\xa7')
        struct.pack_into('!H', body, 2, checksum(bytes(body)))
        frame = (bytes.fromhex('01005e7f2a01') + self.mac + b'\x08\x00' +
                 packet(self.ip, group, bytes(body), 2, options=b'\x94\x04\0\0'))
        self.query_count += 1
        return [frame.ljust(60, b'\0')]
