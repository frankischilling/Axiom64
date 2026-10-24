# SPDX-License-Identifier: GPL-3.0-or-later
"""Deliver controlled IPv6 headers to actual raw/UDP receive queues."""
import struct
from ipv6_host_peer import Peer as HostPeer, checksum, require


class Peer(HostPeer):
    def __init__(self, lane, native=False):
        super().__init__(lane, native)
        self.remote_link = bytes.fromhex('fe800000000000000000000000000001')
        self.inputs = []

    def ack(self):
        if self.phase:
            self.complete.append(self.phase)
        self.outgoing.append(self.guest + self.control + b'\x88\xbdIP6C' +
                             bytes([self.lane, self.phase, 1]) + bytes(39))

    def deliver(self, sequence):
        scoped, raw = sequence // 20 % 2, sequence >= 40
        source, destination = ((self.remote_link, self.link) if scoped
                               else (self.remote, self.local))
        payload = bytes((sequence * 7 + self.lane * 13 + n * 19) & 255 for n in range(32))
        protocol = 58 if raw else 17
        if raw:
            body = b'\x81\0\0\0\x6c\x44' + sequence.to_bytes(2, 'big') + payload[8:]
        else:
            body = bytearray(struct.pack('!HHHH', 42000 + sequence, 41000 + sequence, 40, 0) + payload)
            value = checksum(source + destination + struct.pack('!I3xB', len(body), protocol) + body)
            struct.pack_into('!H', body, 6, value or 65535)
        hop = 7 + sequence * 11 % 248
        traffic_class = (sequence * 37 + self.lane * 59) % 256
        frame = bytearray(self.packet(source, destination, body, hop, protocol))
        frame[14:18] = ((6 << 28) | (traffic_class << 20)).to_bytes(4, 'big')
        bad = bytearray(frame)
        bad[-1] ^= 1
        self.outgoing += [bytes(bad), bytes(frame)]
        self.inputs.append(dict(sequence=sequence, protocol=protocol, hop=hop,
                                traffic_class=traffic_class, scope=scoped))

    def receive(self, frame):
        require(len(frame) >= 14 and frame[6:12] == self.guest,
                'metadata output belongs to actual adapter')
        if frame[12:14] == b'\x88\xbd':
            require(len(frame) == 60 and frame[:6] == self.control and
                    frame[14:19] == b'IP6C' + bytes([self.lane]) and not any(frame[20:]),
                    'complete metadata Ethernet barrier')
            phase = frame[19]
            if not self.ready:
                require(phase == 0, 'metadata readiness before address assignment')
                self.ready = True
            else:
                require(phase == self.phase + 1 and phase <= 160,
                        'ordered metadata input and completion barriers')
            self.phase = phase
            if phase % 2:
                self.deliver((phase - 1) // 2)
            self.ack()
            return
        if not self.ready and not self.native:
            import hashlib
            require(len(self.firmware_frames) < 256, 'bounded metadata firmware prelude')
            self.firmware_frames.append(hashlib.sha256(frame).hexdigest())
            return
        if self.native and len(frame) >= 78 and frame[12:14] == b'\x86\xdd' and frame[20] == 0:
            super().receive(frame)
            return
        require(frame[12:14] != b'\x86\xdd', 'metadata receives produce no extra IPv6 traffic')

    @property
    def passed(self):
        return self.ready and self.complete == list(range(1, 161)) and len(self.inputs) == 80

    def result(self):
        return dict(passed=self.passed, lane=self.lane, phases=self.complete,
                    inputs=self.inputs, firmware_frames=len(self.firmware_frames),
                    firmware_sha256=self.firmware_frames, native_MLD_reports=self.mld_reports)
