# SPDX-License-Identifier: GPL-3.0-or-later
"""Observe the unchanged ten-minute path limit through actual UDP datagrams."""
import struct
import time


def require(condition, message):
    if not condition:
        raise ValueError('path MTU lifetime: ' + message)


def checksum(data):
    data += b'\0' * (len(data) % 2)
    total = sum(struct.unpack('!' + 'H' * (len(data) // 2), data))
    while total >> 16:
        total = (total & 65535) + (total >> 16)
    return (~total) & 65535


class PathMtuLifetimePeer:
    def __init__(self, lane, *, native=False):
        self.lane, self.native = lane, native
        self.local = bytes([10, 23, lane + 1, 2])
        self.remote = bytes([10, 23, lane + 1, 1])
        self.target = bytes([10, 23, lane + 1, 210])
        self.guest = bytes([0x52, 0x54, 0, 0x12, 0x34, 0x10 + lane])
        self.mac = bytes([2, 0x41, 0x58, 0x49, 0x50, lane])
        self.stage, self.next_sample = 'idle', 0
        self.quote = self.pending = self.started = self.finished = None
        self.after_ports = set()
        self.passed = False

    def accepts(self, packet):
        return (len(packet) >= 20 and (packet[16:20] == self.target or
                (len(packet) == 52 and packet[9] == 1 and packet[16:20] == self.remote and
                 packet[24:26] == b'PL')))

    def arp_reply(self, frame):
        if len(frame) < 42 or frame[12:14] != b'\x08\x06' or frame[38:42] != self.target:
            return None
        require(self.stage not in ('idle', 'done'), 'ARP belongs to an active path')
        expected = (b'\xff' * 6 + self.guest + b'\x08\x06' +
                    struct.pack('!HHBBH', 1, 0x800, 6, 4, 1) + self.guest + self.local +
                    b'\0' * 6 + self.target)
        require(frame[:42] == expected and len(frame) == (42 if self.native else 60) and
                not any(frame[42:]), 'exact route-owned ARP request')
        return (self.guest + self.mac + b'\x08\x06' +
                struct.pack('!HHBBH', 1, 0x800, 6, 4, 2) + self.mac + self.target +
                self.guest + self.local).ljust(60, b'\0')

    def packet(self, source, body):
        header = bytearray(struct.pack('!BBHHHBBH4s4s', 0x45, 0, 20 + len(body),
                                      0x706e, 0, 51, 1, 0, source, self.local))
        struct.pack_into('!H', header, 10, checksum(bytes(header)))
        return bytes(header) + body

    def hint(self, damaged=False):
        body = bytearray(struct.pack('!BBHHH', 3, 4, 0, 0, 900) + self.quote)
        struct.pack_into('!H', body, 2, checksum(bytes(body)))
        if damaged:
            body[2] ^= 1
        return self.packet(self.target, bytes(body))

    def data(self, packet):
        require(len(packet) == 1128 and packet[6:10] == b'\x40\0\x40\x11' and
                packet[16:20] == self.target, 'whole DO datagram, route, TTL and flags')
        segment = packet[20:]
        source, destination, length, wire_sum = struct.unpack('!HHHH', segment[:8])
        pseudo = self.local + self.target + struct.pack('!BBH', 0, 17, len(segment))
        require(destination == 48100 and length == 1108 and wire_sum and
                not checksum(pseudo + segment) and segment[8:] ==
                bytes((n * 31 + self.lane * 47 + 0x51) & 255 for n in range(1100)),
                'actual UDP tuple, checksum and every application byte')
        responses = []
        if self.stage == 'initial':
            require(self.quote is None and source == 49300 + self.lane,
                    'one original owned quote')
            self.quote = packet[:28]
            responses.append(self.hint(damaged=True))
        else:
            require(self.stage == 'waiting' and self.next_sample == 21 and
                    600 <= time.monotonic() - self.started <= 610 and
                    source in (49300 + self.lane, 49500 + self.lane) and
                    source not in self.after_ports, 'both descriptions emit only after real expiry')
            self.after_ports.add(source)
        if self.pending is not None and (self.stage == 'initial' or len(self.after_ports) == 2):
            pending, self.pending = self.pending, None
            responses.extend(self.control(pending))
        return responses

    def control(self, packet):
        require(len(packet) == 52 and packet[6:10] == b'\x40\0\x40\x01' and
                packet[16:20] == self.remote, 'control route, policy and size')
        body = packet[20:]
        sample, phase = body[6:8]
        require(body[:2] == b'\x08\0' and body[4:6] == b'PL' and not checksum(body) and
                body[8:10] == bytes([0, self.lane]) and body[10:] ==
                bytes((n * 17 + self.lane * 31) & 255 for n in range(10, 32)),
                'exact ordered control bytes')
        needs_data = (phase == 1 and self.stage == 'initial' and self.quote is None or
                      phase == 3 and sample == 21 and self.stage == 'waiting' and
                      self.next_sample == 21 and len(self.after_ports) != 2)
        if needs_data:
            require(self.pending is None, 'one deferred barrier owns queued data')
            self.pending = bytes(packet)
            return []
        responses = []
        if phase == 0:
            require(sample == 0 and self.stage == 'idle', 'one fresh lifetime path')
            self.stage = 'initial'
        elif phase == 1:
            require(sample == 0 and self.stage == 'initial' and self.quote is not None,
                    'corrupted hint follows an actual datagram')
            self.stage = 'bad-observed'
        elif phase == 2:
            require(sample == 0 and self.stage == 'bad-observed', 'valid hint follows rejection')
            self.started = time.monotonic()
            responses.append(self.hint())
            self.stage = 'waiting'
        elif phase == 3:
            require(self.stage == 'waiting' and sample == self.next_sample and sample < 22,
                    'every lookup sample appears once and in order')
            elapsed = time.monotonic() - self.started
            scheduled = sample * 30 if sample < 20 else 590 if sample == 20 else 605
            require(scheduled - 1 <= elapsed <= scheduled + 5,
                    'unchanged real interval between route lookups')
            require((sample == 21 and len(self.after_ports) == 2 and elapsed >= 600) or
                    (sample < 21 and elapsed < 600 and not self.after_ports),
                    'DO silence precedes both post-expiry datagrams')
            self.next_sample += 1
        elif phase == 4:
            require(sample == 22 and self.stage == 'waiting' and self.next_sample == 22 and
                    len(self.after_ports) == 2, 'final acknowledgement owns all complete evidence')
            self.finished = time.monotonic()
            self.stage, self.passed = 'done', True
        else:
            raise ValueError('path MTU lifetime: unknown control phase')
        reply = bytearray(body)
        reply[0] = 0
        reply[2:4] = b'\0\0'
        struct.pack_into('!H', reply, 2, checksum(bytes(reply)))
        responses.append(self.packet(self.remote, bytes(reply)))
        return responses

    def receive(self, packet):
        require(len(packet) >= 20 and packet[:2] == b'\x45\0' and
                int.from_bytes(packet[2:4], 'big') == len(packet) and
                not checksum(packet[:20]) and packet[12:16] == self.local,
                'validated original IPv4 bounds, source and checksum')
        return self.control(packet) if packet[24:26] == b'PL' else self.data(packet)

    def report(self):
        return dict(passed=self.passed, stage=self.stage, samples=self.next_sample,
                    seconds=None if self.finished is None else self.finished - self.started,
                    post_expiry_descriptions=len(self.after_ports), unchanged_lifetime_seconds=600)
