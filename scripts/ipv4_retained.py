# SPDX-License-Identifier: GPL-3.0-or-later
"""Observe retained zero-source descriptions across actual output syscalls."""
import struct
from ipv4_expiry_capture import checksum


def require(value, reason):
    if not value:
        raise ValueError(reason)


class RetainedPeer:
    def __init__(self, lane, query_model='release'):
        self.lane = lane
        require(query_model in ('release', 'read-only'), 'known retained query model')
        self.query_model = query_model
        self.guest = bytes([0x52, 0x54, 0, 0x12, 0x34, 0x10 + lane])
        self.control = bytes([2, ord('R'), ord('S'), ord('C'), lane, 0])
        self.prefix = bytes([198, 18, 31 + lane])
        self.cases = []
        for phase in range(6):
            self.cases += [(phase, 2, 8), (phase, 2, 9)]
            self.cases += [(phase, k, m) for k in range(2) for m in range(8)]
        self.cases += [(6, 0, 0), (7, 0, 0), (7, 0, 7)]
        self.position = 0
        self.pending = None
        self.data = False
        self.resolved = set()
        self.datagrams = []

    def release(self):
        if self.pending is None or (self.cases[self.position][0] != 6 and not self.data):
            return []
        frame = bytearray(self.pending)
        frame[:12] = self.guest + self.control
        frame[22] = 1
        self.position += 1
        self.data = False
        self.pending = None
        return [bytes(frame)]

    def receive(self, frame):
        if len(frame) < 14:
            return None
        control = frame[12:14] == b'\x88\xb6'
        arp = frame[12:14] == b'\x08\x06' and len(frame) >= 42
        ip = frame[12:14] == b'\x08\0' and len(frame) >= 34
        if not (control or arp and frame[38:41] == self.prefix or
                ip and frame[30:33] == self.prefix):
            return None
        require(self.position < len(self.cases), 'retained workload already complete')
        phase, kind, method = self.cases[self.position]
        target = self.prefix + bytes([12 if phase == 7 else 13 if kind == 2 else
                                      (20 if method == 6 else 10) + kind])
        mac = self.control[:5] + target[3:]
        preferred = (b'\0' * 4 if phase in (0, 4) else
                     bytes([10, 23, self.lane + 1 if phase == 2 else 2 - self.lane, 2]))
        source = (bytes([10, 23, 2 - self.lane, 2]) if phase == 7 else
                  preferred if kind or method in (4, 5, 6) else b'\0' * 4)
        if kind == 2:
            source = preferred if method == 8 else b'\0' * 4
        elif phase < 6 and not kind and method == 0 and self.query_model == 'read-only':
            source = preferred
        if control:
            expected = self.control + self.guest + b'\x88\xb6RSC1' + bytes([
                self.lane, phase, kind, method, 0]) + bytes(
                    (n * 13 + phase * 7 + kind * 31 + method * 17 + self.lane) & 255
                    for n in range(23, 60))
            require(frame == expected and self.pending is None,
                    'retained Ethernet barrier bytes or order differ')
            self.pending = frame
            return self.release()
        require(phase != 6, 'removed source must not emit an IP or ARP packet')
        if arp:
            announced = source if any(source) else preferred
            require(frame[:14] == b'\xff' * 6 + self.guest + b'\x08\x06' and
                    frame[14:42] == b'\0\1\x08\0\x06\x04\0\1' + self.guest + announced +
                    b'\0' * 6 + target and not any(frame[42:]),
                    'retained ARP source or pending destination differs')
            self.resolved.add(target)
            return [(self.guest + mac + b'\x08\x06\0\1\x08\0\x06\x04\0\2' +
                     mac + target + self.guest + announced).ljust(60, b'\0')]
        total = int.from_bytes(frame[16:18], 'big')
        packet = frame[14:14 + total]
        raw = kind == 1
        require(len(packet) == total == (52 if raw else 60) and
                frame[:12] == mac + self.guest and packet[:2] == b'\x45\0' and
                packet[6:10] == b'\x40\0\x40' + bytes([1 if raw else 17]) and
                packet[12:20] == source + target and not checksum(packet[:20]) and
                not any(frame[14 + total:]) and target in self.resolved and not self.data,
                'retained original source, destination, checksum or ownership differs')
        body = packet[20:]
        if not raw:
            require(struct.unpack('!HHH', body[:6]) ==
                    (49300 + self.lane * 32 + (2 if kind == 2 else phase == 7), 48010, 40) and
                    not checksum(source + target + b'\0\x11\0\x28' + body),
                    'retained UDP ports, length or pseudoheader differ')
            body = body[8:]
        expected = bytearray((n * 23 + phase * 17 + kind * 11 + method * 7 + self.lane) & 255
                             for n in range(32))
        if raw:
            expected[:8] = bytes([8, 0, 0, 0, ord('R'), ord('S'), phase, method])
            struct.pack_into('!H', expected, 2, checksum(expected))
        else:
            expected[:8] = bytes([ord('R'), ord('S'), self.lane, phase, kind, method, 0, 0])
        require(body == bytes(expected), 'retained actual application bytes differ')
        self.datagrams.append(dict(phase=phase, kind=kind, method=method, source=source.hex()))
        self.data = True
        return self.release()

    @property
    def passed(self):
        return self.position == 111 and len(self.datagrams) == 110

    def report(self):
        return dict(passed=self.passed, datagrams=self.datagrams, barriers=self.position)
