# SPDX-License-Identifier: GPL-3.0-or-later
"""Controlled next hops for actual IPv4 gateway and direct-output checks."""
import hashlib
import struct
from ipv4_expiry_capture import checksum


def require(value, reason):
    if not value:
        raise ValueError(reason)


def payload(lane, kind, phase):
    length = 1100 if phase == 0 else 32
    value = bytearray((n * 31 + phase * 17 + lane * 13) & 255 for n in range(length))
    if kind:
        value[:8] = bytes([8, 0, 0, 0, ord('G'), ord('W'), kind, phase])
        struct.pack_into('!H', value, 2, checksum(value))
    else:
        value[:8] = bytes([ord('G'), ord('W'), lane, kind, phase, 0, 0, 0])
    return bytes(value)


class GatewayPeer:
    def __init__(self, lane):
        self.lane = lane
        self.guest = bytes([0x52, 0x54, 0, 0x12, 0x34, 0x10 + lane])
        self.mac = bytes([2, 0x41, 0x58, 0x49, 0x50, lane])
        self.primary = bytes([10, 23, lane + 1, 2])
        self.alias = self.primary[:3] + b'\x03'
        self.remote = self.primary[:3] + b'\x01'
        self.gateways = [self.primary[:3] + bytes([250 + n]) for n in range(2)]
        self.targets = [bytes([192, 0, lane + 2, 10 + n]) for n in range(2)]
        self.kind = self.phase = 0
        self.pending = None
        self.received = False
        self.active = False
        self.arp_requests = []
        self.datagrams = []
        self.controls = []

    def next_hop_mac(self, phase):
        return bytes([2, 0x47, 0x57, 0x42 if phase == 1 else 0x44 if phase == 3 else 0x41,
                      self.lane, 1])

    def packet(self, source, destination, body, mac):
        header = bytearray(struct.pack('!BBHHHBBH4s4s', 0x45, 0, 20 + len(body),
                                       0x4757, 0, 51, 1, 0, source, destination))
        struct.pack_into('!H', header, 10, checksum(header))
        return self.guest + mac + b'\x08\0' + header + body

    def release(self):
        if self.pending is None or (self.phase not in (5, 7) and not self.received):
            return []
        body = bytearray(self.pending)
        body[:4] = b'\0' * 4
        struct.pack_into('!H', body, 2, checksum(body))
        response = self.packet(self.remote, self.primary, body, self.mac)
        self.controls.append(dict(kind=self.kind, phase=self.phase))
        self.phase += 1
        if self.phase == 8:
            self.kind += 1
            self.phase = 0
        self.pending = None
        self.received = False
        return [response]

    def receive(self, frame):
        if len(frame) < 34:
            return None
        if frame[12:14] == b'\x08\x06' and len(frame) >= 42:
            target = frame[38:42]
            if target not in self.gateways + self.targets and not (self.active and target == self.remote):
                return None
            self.active = True
            require(frame[:6] == b'\xff' * 6 and frame[6:12] == self.guest and
                    frame[14:22] == b'\0\1\x08\0\x06\x04\0\1' and
                    frame[22:28] == self.guest and frame[32:38] == b'\0' * 6 and
                    not any(frame[42:]), 'gateway ARP request ownership or wire shape differs')
            source = self.primary if target == self.remote else self.alias
            require(frame[28:32] == source, 'gateway ARP preserves its explicit local source')
            mac = (self.mac if target == self.remote else
                   self.next_hop_mac(1 if target == self.gateways[1] else
                                     3 if target in self.targets else 0))
            self.arp_requests.append(dict(source=source.hex(), target=target.hex(), mac=mac.hex()))
            return [(self.guest + mac + b'\x08\x06' +
                     struct.pack('!HHBBH', 1, 0x800, 6, 4, 2) + mac + target +
                     self.guest + source).ljust(60, b'\0')]
        if frame[12:14] != b'\x08\0':
            return None
        total = int.from_bytes(frame[16:18], 'big')
        ip = frame[14:14 + total]
        control = (len(ip) == 52 and ip[9] == 1 and ip[12:20] == self.primary + self.remote and
                   ip[24:26] == b'GW')
        if not control and (len(ip) < 28 or ip[16:20] not in self.targets):
            return None
        require(total == len(ip) and ip[:2] == b'\x45\0' and not checksum(ip[:20]) and
                ip[6:9] == b'\x40\0\x40' and frame[6:12] == self.guest and
                not any(frame[14 + total:]), 'gateway IPv4 header or Ethernet source differs')
        require(self.kind < 2, 'gateway workload is already complete')
        if control:
            body = ip[20:]
            expected = bytearray([8, 0, 0, 0, ord('G'), ord('W'), self.kind, self.phase, self.lane])
            expected.extend((n * 17 + self.lane * 31) & 255 for n in range(9, 32))
            struct.pack_into('!H', expected, 2, checksum(expected))
            require(frame[:6] == self.mac and body == bytes(expected) and self.pending is None,
                    'gateway control bytes, sequence or next hop differ')
            self.pending = body
            return self.release()
        require(self.phase in (0, 1, 2, 3, 4, 6) and not self.received and
                ip[12:20] == self.alias + self.targets[self.kind] and
                frame[:6] == self.next_hop_mac(self.phase),
                'gateway datagram tuple, source, next-hop MAC or sequence differs')
        body = ip[20:]
        if not self.kind:
            require(ip[9] == 17 and len(body) >= 8 and
                    struct.unpack('!HHH', body[:6]) ==
                    (49100 + self.lane * 4, 48009, len(body)) and
                    not checksum(self.alias + self.targets[0] +
                                 struct.pack('!BBH', 0, 17, len(body)) + body),
                    'gateway UDP tuple, length or checksum differs')
            body = body[8:]
        else:
            require(ip[9] == 1 and not checksum(body), 'gateway ICMP checksum or protocol differs')
        require(body == payload(self.lane, self.kind, self.phase), 'gateway application bytes differ')
        self.received = True
        self.datagrams.append(dict(kind=self.kind, phase=self.phase, bytes=len(body),
                                   sha256=hashlib.sha256(frame).hexdigest(),
                                   next_hop_mac=frame[:6].hex()))
        responses = []
        if self.phase == 0:
            hint = bytearray(struct.pack('!BBHHH', 3, 4, 0, 0, 900) + ip[:28])
            struct.pack_into('!H', hint, 2, checksum(hint))
            responses.append(self.packet(self.gateways[0], self.alias, hint, self.next_hop_mac(0)))
        return responses + self.release()

    @property
    def passed(self):
        return self.kind == 2 and self.phase == 0 and self.pending is None and len(self.datagrams) == 12

    def report(self):
        return dict(passed=self.passed, lane=self.lane, datagrams=self.datagrams,
                    controls=self.controls, arp_requests=self.arp_requests)
