# SPDX-License-Identifier: GPL-3.0-or-later
"""Quote actual datagrams and observe unchanged ten-minute IPv6 PMTU lifetimes."""
import hashlib
import struct
import time
from ipv6_host_peer import Peer as HostPeer, checksum, require


def application(lane, number, stage, length):
    data = bytearray((n * 29 + number * 7 + stage * 11 + lane) & 255 for n in range(length))
    offset = 0 if number < 8 else 4
    if offset:
        data[:4] = b'\x81\0\0\0'
    data[offset:offset + 8] = b'P6EX' + bytes([number, stage, lane, 0])
    return bytes(data)


class Peer(HostPeer):
    barrier_protocol = b'\x88\xbc'
    barrier_magic = b'IP6X'

    def __init__(self, lane, native=False):
        super().__init__(lane, native)
        self.frames = {}
        self.hints = []
        self.pending = None
        self.awaiting_datagrams = None
        self.heartbeat_counts = [0] * 16

    def reply(self, frame):
        reply = bytearray(frame)
        reply[:6], reply[6:12], reply[20] = self.guest, self.control, 1
        self.outgoing.append(bytes(reply))

    def tick(self):
        if self.awaiting_datagrams is not None:
            stage = 0 if self.phase == 2 else 2
            if all((number, stage) in self.frames for number in range(16)):
                for number in range(16):
                    role = number % 4
                    values = (([1400] if role < 2 else []) if self.phase == 2 else
                              [1400, 1450, 1279] if role == 0 else [1280] if role < 3 else [])
                    original = self.frames[number, stage]
                    for mtu in values:
                        router = bytearray(original[38:54])
                        router[-1] = 250
                        body = b'\x02\0\0\0' + struct.pack('!I', mtu) + original[14:62]
                        self.outgoing.append(self.packet(bytes(router), original[22:38], body, 64))
                        self.hints.append(dict(case=number, phase=self.phase, mtu=mtu))
                self.pending = time.monotonic() + .1, self.awaiting_datagrams
                self.awaiting_datagrams = None
        if self.pending and time.monotonic() >= self.pending[0]:
            self.reply(self.pending[1])
            self.pending = None

    def receive(self, frame):
        require(len(frame) >= 14 and frame[6:12] == self.guest, 'expiry source MAC ownership')
        if frame[12:14] == self.barrier_protocol:
            require(len(frame) == 60 and frame[:6] == self.control and
                    frame[14:19] == self.barrier_magic + bytes([self.lane]) and not any(frame[20:]),
                    'exact expiry barrier request')
            phase = frame[19]
            if not self.ready:
                require(phase == 0, 'expiry readiness before configuration')
                self.ready = True
                self.reply(frame)
                return
            require(self.pending is None and self.awaiting_datagrams is None and
                    phase == self.phase + 1 and phase <= 6,
                    'ordered expiry stages')
            self.phase = phase
            if phase in (2, 3):
                # AF_PACKET barriers can overtake packets still queued for ND.
                # Quote every actual datagram before acknowledging this phase.
                self.awaiting_datagrams = frame
            else:
                self.reply(frame)
            return
        if not self.ready and not self.native:
            require(len(self.firmware_frames) < 256, 'bounded expiry firmware prelude')
            self.firmware_frames.append(hashlib.sha256(frame).hexdigest())
            return
        if self.native and frame[12:14] == b'\x86\xdd' and len(frame) >= 78 and frame[20] == 0:
            super().receive(frame)
            return
        require(self.ready and frame[12:14] == b'\x86\xdd' and len(frame) >= 54 and
                frame[14:18] == b'\x60\0\0\0', 'expiry IPv6 envelope')
        size, protocol, hop = struct.unpack_from('!HBB', frame, 18)
        require(len(frame) >= size + 54, 'complete expiry packet')
        source, destination, body = frame[22:38], frame[38:54], frame[54:54 + size]
        if protocol == 58 and body[:1] == b'\x87':
            targets = {(self.link if n % 8 >= 4 else self.remote)[:-1] + bytes([32 + n])
                       for n in range(16)}
            require(source in (self.local, self.link) and body[8:24] in targets and
                    hop == 255 and len(body) == 32 and body[24:] == b'\x01\x01' + self.guest and
                    destination in (body[8:24], self.multicast(body[8:24])) and
                    not checksum(source + destination + struct.pack('!I3xB', size, 58) + body),
                    'expiry multicast or unicast neighbor resolution')
            self.outgoing.append(self.na(body[8:24], source))
            return
        require(frame[:6] == self.mac and hop == 64 and protocol in (17, 58) and
                not checksum(source + destination + struct.pack('!I3xB', size, protocol) + body),
                'expiry route and transport checksum')
        data = body[8:] if protocol == 17 else body
        offset = 0 if protocol == 17 else 4
        require(len(data) >= 16 and data[offset:offset + 4] == b'P6EX', 'tagged expiry payload')
        number, stage, lane, reserved = data[offset + 4:offset + 8]
        require(number < 16 and lane == self.lane and not reserved and
                protocol == (17 if number < 8 else 58), 'expiry flow ownership')
        scoped = number % 8 >= 4
        remote = (self.link if scoped else self.remote)[:-1] + bytes([32 + number])
        require(source == (self.link if scoped else self.local) and destination == remote,
                'expiry source, destination and scope')
        if protocol == 17:
            require(struct.unpack_from('!HHH', body) == (49000 + number, 50000 + number, len(body)),
                    'expiry UDP ports and size')
        expected = application(lane, number, stage, len(data))
        require(data == expected if protocol == 17 else data[:2] == expected[:2] and data[4:] == expected[4:],
                'complete actual expiry application bytes')
        if stage == 250:
            require(number % 4 != 0 and len(data) == 16, 'ordinary traffic on retained path')
            self.heartbeat_counts[number] += 1
            return
        role = number % 4
        allowed = stage in (0, 2, 6) or role == 3 or stage == 1 and role == 2 or stage == 5 and role < 2
        require(stage <= 6 and allowed and len(data) == 1440 and (number, stage) not in self.frames,
                'only successful sends emit an expiry datagram')
        self.frames[number, stage] = frame

    @property
    def passed(self):
        expected = {(n, s) for n in range(16) for s in range(7)
                    if s in (0, 2, 6) or n % 4 == 3 or s == 1 and n % 4 == 2 or s == 5 and n % 4 < 2}
        return self.ready and self.phase == 6 and set(self.frames) == expected and len(self.hints) == 28

    def result(self):
        return dict(passed=self.passed, lane=self.lane, datagrams=len(self.frames),
                    hints=self.hints, heartbeats=self.heartbeat_counts,
                    firmware_sha256=self.firmware_frames, native_MLD_reports=self.mld_reports)
