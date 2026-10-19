# SPDX-License-Identifier: GPL-3.0-or-later
"""Ethernet observations for bound IPv4 output without a configured address."""
import struct
from ipv4_expiry_capture import checksum
from ipv4_retained import RetainedPeer


def require(value, reason):
    if not value:
        raise ValueError(reason)


class UnconfiguredPeer:
    def __init__(self, lane, query_model='release', native_cache=False):
        self.retained = RetainedPeer(lane, query_model, native_cache)
        self.lane = lane
        self.guest = bytes([0x52, 0x54, 0, 0x12, 0x34, 0x10 + lane])
        self.control = bytes([2, 0x55, 0x4e, 0x43, lane, 0])
        self.phase = self.kind = 0
        self.pending = None
        self.data = False
        self.arp = set()
        self.datagrams = []

    def release(self):
        if not self.data or self.pending is None:
            return []
        reply = bytearray(self.pending)
        reply[:12] = self.guest + self.control
        reply[21] = 1
        self.kind += 1
        if self.kind == 2:
            self.phase += 1
            self.kind = 0
        self.data = False
        self.pending = None
        return [bytes(reply)]

    def receive(self, frame):
        retained = self.retained.receive(frame)
        if retained is not None:
            return retained
        if len(frame) < 14:
            return None
        control = frame[12:14] == b'\x88\xb5'
        arp = frame[12:14] == b'\x08\x06' and len(frame) >= 42
        ip = frame[12:14] == b'\x08\0' and len(frame) >= 34
        prefix = bytes([198, 18, self.lane + 1])
        if not (control or arp and frame[38:41] == prefix or ip and frame[30:33] == prefix):
            return None
        require(self.phase < 7, 'unconfigured workload already complete')
        target = prefix + bytes([10 + self.phase * 2 + self.kind])
        mac = bytes([2, 0x55, 0x4e, 0x43, self.lane, 1 + self.phase * 2 + self.kind])
        own = bytes([10, 23, self.lane + 1, 2])
        other = bytes([10, 23, 2 - self.lane, 2])
        source = b'\0' * 4 if self.phase == 0 else own if self.phase == 3 else other
        if control:
            expected = bytearray(self.control + self.guest + b'\x88\xb5UNC1' +
                                 bytes([self.lane, self.phase, self.kind, 0]))
            expected.extend((n * 19 + self.phase * 7 + self.kind * 31 + self.lane) & 255
                            for n in range(22, 60))
            require(frame == bytes(expected) and self.pending is None,
                    'unconfigured Ethernet control bytes or order differ')
            self.pending = frame
            return self.release()
        if arp:
            require(frame[:14] == b'\xff' * 6 + self.guest + b'\x08\x06' and
                    frame[14:42] == b'\0\1\x08\0\x06\x04\0\1' + self.guest + source +
                    b'\0' * 6 + target and not any(frame[42:]),
                    'unconfigured ARP preserves pending output source and destination')
            self.arp.add((self.phase, self.kind))
            return [(self.guest + mac + b'\x08\x06\0\1\x08\0\x06\x04\0\2' +
                     mac + target + self.guest + source).ljust(60, b'\0')]
        total = int.from_bytes(frame[16:18], 'big')
        packet = frame[14:14 + total]
        require(len(packet) == total and packet[:2] == b'\x45\0' and
                packet[6:10] == b'\x40\0\x40' + bytes([1 if self.kind else 17]) and
                packet[12:20] == source + target and not checksum(packet[:20]) and
                frame[:12] == mac + self.guest and not any(frame[14 + total:]) and
                (self.phase, self.kind) in self.arp and not self.data,
                'unconfigured original datagram ownership, header or ARP differs')
        body = packet[20:]
        if not self.kind:
            require(len(body) == 40 and struct.unpack('!HHH', body[:6]) ==
                    (49200 + self.lane * 32 + self.phase, 48010, 40) and
                    not checksum(source + target + b'\0\x11\0\x28' + body),
                    'unconfigured UDP ports, length or checksum differ')
            body = body[8:]
        expected = bytearray((n * 23 + self.phase * 17 + self.kind * 11 + self.lane) & 255
                             for n in range(32))
        if self.kind:
            expected[:8] = bytes([8, 0, 0, 0, 0x55, 0x43, self.lane, self.phase])
            struct.pack_into('!H', expected, 2, checksum(expected))
        else:
            expected[:8] = bytes([0x55, 0x43, self.lane, self.phase, self.kind, 0, 0, 0])
        require(body == bytes(expected), 'unconfigured original application bytes differ')
        self.datagrams.append(dict(phase=self.phase, kind=self.kind, source=source.hex()))
        self.data = True
        return self.release()

    @property
    def passed(self):
        return (self.phase == 7 and self.kind == 0 and len(self.datagrams) == len(self.arp) == 14 and
                self.retained.passed)

    def report(self):
        return dict(passed=self.passed, lane=self.lane, datagrams=self.datagrams,
                    arp_exchanges=len(self.arp), retained=self.retained.report())
