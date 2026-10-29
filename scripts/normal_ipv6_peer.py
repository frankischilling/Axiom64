# SPDX-License-Identifier: GPL-3.0-or-later
"""Check default link-local DAD and router solicitations during normal boot."""
import hashlib
import struct
import time

from ipv6_host_peer import checksum


def require(condition, message):
    if not condition:
        raise RuntimeError('unexpected Ethernet protocol=86dd: ' + message)


class AutomaticIpv6Control:
    def __init__(self, guest):
        self.guest = guest
        identifier = bytes([guest[0] ^ 2]) + guest[1:3] + b'\xff\xfe' + guest[3:]
        self.link = b'\xfe\x80' + bytes(6) + identifier
        self.records = []

    def receive(self, frame):
        if frame[12:14] != b'\x86\xdd':
            return False
        require(len(self.records) < 64, 'bounded automatic control capture')
        require(len(frame) >= 62 and frame[6:12] == self.guest,
                'complete control frame from the expected guest')
        length, protocol, hops = struct.unpack_from('!HBB', frame, 18)
        require(frame[14:18] == b'\x60\0\0\0' and len(frame) == 54 + length and
                protocol == 58 and hops == 255, 'exact IPv6 length, header and hop limit')
        source, destination, body = frame[22:38], frame[38:54], frame[54:]
        require(not body[1] and not any(body[4:8]) and not checksum(source + destination +
                struct.pack('!I3xB', length, 58) + body), 'ICMPv6 code, reserved bytes and checksum')
        if body[0] == 133:
            require(source == self.link and destination == b'\xff\x02' + bytes(13) + b'\x02' and
                    frame[:6] == b'\x33\x33\0\0\0\x02' and
                    body[8:] == b'\x01\x01' + self.guest,
                    'router solicitation addresses and complete source-link-layer option')
            kind = 'RS'
        elif body[0] == 135:
            solicited = b'\xff\x02' + bytes(9) + b'\x01\xff' + self.link[-3:]
            require(source == bytes(16) and destination == solicited and
                    frame[:6] == b'\x33\x33\xff' + self.link[-3:] and
                    len(body) in (24, 32) and body[8:24] == self.link,
                    'link-local DAD source, target and solicited-node destination')
            require(len(body) == 24 or body[24:26] == b'\x0e\x01',
                    'complete optional six-byte enhanced DAD nonce')
            kind = 'DAD'
        else:
            require(False, 'only default link-local DAD and router solicitations are expected')
        self.records.append(dict(type=kind, frame=frame.hex(),
                                 sha256=hashlib.sha256(frame).hexdigest(),
                                 observed_monotonic_ns=time.monotonic_ns()))
        return True

    def evidence(self):
        return dict(guest=self.guest.hex(), records=[row.copy() for row in self.records],
                    DAD=sum(row['type'] == 'DAD' for row in self.records),
                    RS=sum(row['type'] == 'RS' for row in self.records),
                    packet_clock_qualified=False)
