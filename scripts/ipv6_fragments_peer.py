# SPDX-License-Identifier: GPL-3.0-or-later
"""Paced original IPv6 fragments and full real-time reassembly expiry."""
from collections import deque
import hashlib
import ipaddress
import struct
import time
from ipv6_host_peer import Peer as HostPeer, checksum, require


def pattern(lane, case, length):
    return bytes((at * 17 + lane * 31 + (8 if case == 9 and at >= 8 else case) * 7) & 255
                 for at in range(length))


def fragment(frame, offset, length, more, identifier, prefix=0):
    body = frame[54:54 + int.from_bytes(frame[18:20], 'big')]
    result = bytearray(frame[:54])
    result[18:20] = (prefix + 8 + length).to_bytes(2, 'big')
    result[20] = 60 if prefix else 44
    if prefix:
        options = bytes([0x1e, 10]) + bytes(10) + bytes(2) if prefix == 16 else bytes(prefix - 2)
        result += bytes([44, prefix // 8 - 1]) + options
    return bytes(result) + struct.pack('!BBHI', frame[20], 0, offset | int(more), identifier) + body[offset:offset + length]


class Peer:
    def __init__(self, lane, native=False):
        self.wire = HostPeer(lane, native)
        self.__dict__.update({name: getattr(self.wire, name) for name in
            ('guest', 'mac', 'control', 'local', 'remote', 'link', 'all_nodes')})
        self.remote_link = bytes.fromhex('fe800000000000000000000000000001')
        self.lane, self.native = lane, native
        self.outgoing, self.output, self.flows = [], bytearray(), []
        self.pending = deque()
        self.ready, self.phase, self.next_release = False, -1, 0
        self.inputs, self.outputs, self.firmware_frames = [], [], []
        self.expected_errors, self.errors = [], []
        self.advertisements, self.warm = 0, 0
        self.expiry_began, self.expiry_seen, self.waiting = None, False, None
        self.first_sent, self.complete = None, []

    def packet(self, source, destination, payload, hop=64, protocol=58):
        return self.wire.packet(source, destination, payload, hop, protocol)

    def udp(self, case, size, link=False):
        source, destination = (self.remote_link, self.link) if link else (self.remote, self.local)
        ports = (58011, 58010) if link else (57000 + self.lane, 56000 + self.lane)
        body = bytearray(struct.pack('!HHHH', *ports, size + 8, 0) + pattern(self.lane, case, size))
        value = checksum(source + destination + struct.pack('!I3xB', len(body), 17) + body)
        struct.pack_into('!H', body, 6, value or 65535)
        return self.packet(source, destination, body, protocol=17)

    def queue(self, frame, delay=0):
        self.pending.append((time.monotonic() + delay, frame))

    def ack(self):
        self.queue(self.guest + self.control + b'\x88\xb7IP6F' +
                   bytes([self.lane, self.phase, 1]) + bytes(39))
        self.complete.append(self.phase)
        self.waiting = None

    def parts(self, frame, pieces, identifier):
        return [fragment(frame, offset, length, more, identifier, prefix)
                for offset, length, more, prefix in pieces]

    def basic(self):
        base = 0x66000000 + self.lane * 256
        raw = self.packet(self.remote, self.local, b'\x81\0\0\0' + pattern(self.lane, 1, 15))
        packets = self.parts(raw, [(8, 11, False, 0), (0, 8, True, 8)], base + 1)
        udp = self.udp(2, 57)
        pieces = [(48, 17, False, 0), (0, 24, True, 8), (0, 24, True, 8), (24, 24, True, 16)]
        packets += self.parts(udp, pieces, base + 2)
        maximum = self.udp(3, 65527)
        pieces = [(at, min(1448, 65535 - at), at + 1448 < 65535, 0)
                  for at in range(0, 65535, 1448)]
        packets += self.parts(maximum, list(reversed(pieces)), base + 3)
        # Both links retain identical scoped identities before either gets its tail.
        self.scoped_tail = fragment(self.udp(4, 41, True), 24, 25, False, 0x66009900)
        packets.append(fragment(self.udp(4, 41, True), 0, 24, True, 0x66009900))
        self.atomic = [fragment(self.udp(6, 41), 0, 16, True, base + 5),
                       fragment(self.udp(5, 9), 0, 17, False, base + 5),
                       fragment(self.udp(6, 41), 16, 33, False, base + 5)]
        packets += self.parts(self.udp(7, 41),
            [(0, 16, True, 0), (8, 16, True, 0), (24, 25, False, 0)], base + 7)
        packets += self.parts(self.udp(7, 49),
            [(0, 16, True, 0), (32, 17, False, 0), (40, 17, False, 0)], base + 8)
        bad = bytearray(self.udp(7, 41)); bad[-1] ^= 1
        packets += self.parts(bytes(bad), [(0, 16, True, 0), (16, 33, False, 0)], base + 9)
        ns = self.packet(self.remote, self.local,
            b'\x87\0\0\0' + bytes(4) + self.local + b'\1\1' + self.mac, 255)
        packets += self.parts(ns, [(0, 24, True, 0), (24, 8, False, 0)], base + 10)
        packets.append(fragment(ns, 0, 32, False, base + 11))
        packets.append(self.packet(self.remote, self.local, b'\x87\0\0\0' + bytes(4) + self.local, 255))
        foreign = bytearray(fragment(self.udp(7, 41), 0, 16, True, base + 12))
        foreign[53] = 0x77
        packets.append(bytes(foreign))
        foreign[38:54] = ipaddress.IPv6Address('ff02::1234:5678').packed
        foreign[:6] = b'\x33\x33' + foreign[50:54]
        packets.append(bytes(foreign))
        for frame in packets:
            self.queue(frame)
        malformed = fragment(self.udp(7, 41), 0, 15, True, base + 13)
        overflow = bytearray(fragment(self.udp(7, 41), 0, 16, False, base + 14))
        overflow[56:58] = (65528).to_bytes(2, 'big')
        tcp = self.packet(self.remote, self.local, bytes(16), protocol=6)
        truncated = fragment(tcp, 0, 16, True, base + 15)
        for delay, frame, code, pointer in [(1, malformed, 0, 4), (3, bytes(overflow), 0, 42), (5, truncated, 3, 0)]:
            self.expected_errors.append((4, code, pointer, frame[14:]))
            self.queue(frame, delay)
        self.ack()

    def arm_expiry(self):
        self.expiry_began = time.monotonic()
        base = 0x66008000 + self.lane * 256
        self.expiry_id = base
        self.first = fragment(self.udp(8, 41), 0, 16, True, base)
        self.queue(self.first)
        self.queue(fragment(self.udp(8, 41), 16, 33, False, base + 1), 1)
        error = self.packet(self.remote, self.local, b'\1\4' + bytes(14))
        self.queue(fragment(error, 0, 16, True, base + 2), 2)
        multicast = bytearray(fragment(self.udp(8, 41), 0, 16, True, base + 3))
        multicast[38:54] = self.all_nodes
        multicast[:6] = b'\x33\x33\0\0\0\1'
        self.queue(bytes(multicast), 3)
        self.queue(self.first, 30)
        self.waiting = 'expiry'

    def tick(self):
        clock = time.monotonic()
        if self.waiting == 'basic' and len(self.errors) == 3 and self.advertisements == 1:
            self.ack()
        # Observe an extra second so the independent client and capture clocks
        # both retain the complete required seventy-second quiet interval.
        if self.waiting == 'expiry' and clock - self.expiry_began >= 71:
            require(self.expiry_seen, 'eligible first fragment expires at its original 60-second deadline')
            self.ack()
        if clock < self.next_release:
            return
        for _ in range(4):
            if not self.pending or self.pending[0][0] > clock:
                break
            _, frame = self.pending.popleft()
            if self.expiry_began is not None and frame == self.first and self.first_sent is None:
                self.first_sent = time.monotonic()
            self.inputs.append(frame.hex())
            self.outgoing.append(frame)
        self.next_release = clock + .005

    def receive(self, frame):
        require(len(frame) >= 14 and frame[6:12] == self.guest, 'actual fragment client source MAC')
        if frame[12:14] == b'\x88\xb7':
            require(len(frame) == 60 and frame[:6] == self.control and
                    frame[14:19] == b'IP6F' + bytes([self.lane]) and not any(frame[20:]), 'exact fragment barrier')
            require(frame[19] == self.phase + 1 and frame[19] < 8, 'ordered fragment barriers')
            self.phase = frame[19]
            self.ready = True
            if self.phase == 1:
                self.basic()
            elif self.phase == 2:
                self.queue(self.scoped_tail)
                # The client has consumed its maximum datagrams before this
                # barrier; unrelated receive-buffer pressure cannot drop these.
                for packet in self.atomic:
                    self.queue(packet)
                self.ack()
            elif self.phase == 3:
                self.waiting = 'basic'
            elif self.phase == 4:
                self.arm_expiry()
            elif self.phase == 5:
                self.queue(fragment(self.udp(8, 41), 16, 33, False, self.expiry_id)); self.ack()
            elif self.phase == 6:
                self.queue(fragment(self.udp(9, 41), 0, 16, True, self.expiry_id)); self.ack()
            else:
                self.ack()
            return
        if not self.ready and not self.native:
            require(len(self.firmware_frames) < 256, 'bounded fragment firmware prelude')
            self.firmware_frames.append(hashlib.sha256(frame).hexdigest())
            return
        if frame[12:14] != b'\x86\xdd':
            return
        if self.native and len(frame) >= 78 and frame[20] == 0:
            self.wire.receive(frame)
            return
        require(len(frame) >= 54 and frame[14:18] == b'\x60\0\0\0', 'fixed fragment client IPv6 header')
        length, protocol, hop = struct.unpack('!HBB', frame[18:22])
        source, destination, body = frame[22:38], frame[38:54], frame[54:54 + length]
        require(len(body) == length and not checksum(source + destination +
            struct.pack('!I3xB', length, protocol) + body), 'original fragment client transport checksum')
        self.outputs.append(frame[:54 + length].hex())
        if protocol == 17:
            require((source, destination, hop) == (self.local, self.remote, 64) and
                body[:6] == struct.pack('!HHH', 56000 + self.lane, 57000 + self.lane, 8) and len(body) == 8,
                'only zero-byte UDP neighbor warmup')
            self.warm += 1
            require(self.warm == 1, 'one original neighbor warmup')
            return
        require(protocol == 58 and len(body) >= 8, 'ICMPv6 diagnostic or neighbor output')
        if body[0] == 135:
            require(hop == 255 and source in (self.local, self.link) and
                    destination in (self.remote, self.wire.multicast(self.remote)) and
                    body[:2] + bytes(2) + body[4:8] == b'\x87\0' + bytes(6) and
                    body[8:24] == self.remote and body[24:] == b'\1\1' + self.guest,
                    'actual neighbor request')
            self.outgoing.append(self.wire.na(self.remote, source))
        elif body[0] == 136:
            require((source, destination, hop) == (self.local, self.remote, 255) and
                    body[:2] + bytes(2) + body[4:] == b'\x88\0' + bytes(2) + b'\x40\0\0\0' + self.local,
                    'only unfragmented ND produces an advertisement')
            self.advertisements += 1
            require(self.advertisements == 1, 'fragmented and atomic ND stay suppressed')
        else:
            require((source, destination, hop) == (self.local, self.remote, 64), 'diagnostic source and target')
            key = (body[0], body[1], int.from_bytes(body[4:8], 'big'), body[8:])
            if body[0] == 3:
                require(key == (3, 1, 0, self.first[14:]) and not self.expiry_seen,
                        'only eligible original first fragment produces expiry diagnostic')
                age = time.monotonic() - self.first_sent
                require(59.98 <= age <= (66 if self.native else 61), 'real 60-second fixed fragment lifetime')
                self.expiry_seen = True
            else:
                require(key in self.expected_errors and key not in self.errors, 'exact original malformed-fragment quote')
                self.errors.append(key)

    @property
    def passed(self):
        return self.complete == list(range(8)) and self.expiry_seen and len(self.errors) == 3 and self.advertisements == 1 and self.warm == 1

    def result(self):
        return dict(passed=self.passed, lane=self.lane, phases=self.complete, errors=len(self.errors),
                    expiry=self.expiry_seen, inputs=self.inputs, outputs=self.outputs,
                    firmware_sha256=self.firmware_frames, native_MLD_reports=self.wire.mld_reports)
