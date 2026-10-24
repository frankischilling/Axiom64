# SPDX-License-Identifier: GPL-3.0-or-later
"""Strict Ethernet peers for actual IPv6 raw and UDP socket traffic."""
import struct
from ipv6_host_peer import Peer as HostPeer, checksum, require


class Peer(HostPeer):
    def __init__(self, lane, native=False):
        super().__init__(lane, native)
        self.stage = 0
        self.remote_link = bytes.fromhex('fe800000000000000000000000000001')

    def ack(self):
        if self.phase:
            self.complete.append(self.phase)
        self.outgoing.append(self.guest + self.control + b'\x88\xb7IP6S' +
                             bytes([self.lane, self.phase, 1]) + bytes(39))

    def udp(self, source, destination, sport, dport, payload):
        body = bytearray(struct.pack('!HHHH', sport, dport, len(payload) + 8, 0) + payload)
        value = checksum(source + destination + struct.pack('!I3xB', len(body), 17) + body)
        struct.pack_into('!H', body, 6, value or 65535)
        return self.packet(source, destination, body, 64, 17)

    def receive(self, frame):
        require(len(frame) >= 14 and frame[6:12] == self.guest, 'actual IPv6 socket source MAC')
        if frame[12:14] == b'\x88\xb7':
            require(len(frame) == 60 and frame[:6] == self.control and
                    frame[14:19] == b'IP6S' + bytes([self.lane]) and not any(frame[20:]),
                    'exact socket barrier')
            phase = frame[19]
            if not self.ready:
                require(phase == 0, 'socket readiness precedes configuration')
                self.ready = True
            else:
                require(phase == self.phase + 1 and phase in (1, 2), 'ordered socket barriers')
                require(self.stage == (0 if phase == 1 else 7), 'complete original socket workload')
            self.phase = phase
            self.ack()
            return
        if not self.ready and not self.native:
            require(len(self.firmware_frames) < 256, 'bounded socket firmware prelude')
            import hashlib
            self.firmware_frames.append(hashlib.sha256(frame).hexdigest())
            return
        if frame[12:14] != b'\x86\xdd':
            return
        if self.native and len(frame) >= 78 and frame[20] == 0:
            super().receive(frame)
            return
        require(self.phase == 1 and len(frame) >= 54 and frame[14:18] == b'\x60\0\0\0',
                'socket IPv6 fixed header and active phase')
        length, protocol, hop = struct.unpack('!HBB', frame[18:22])
        require(54 + length <= len(frame), 'complete socket IPv6 payload')
        source, destination, body = frame[22:38], frame[38:54], frame[54:54 + length]
        require(not checksum(source + destination + struct.pack('!I3xB', length, protocol) + body),
                'actual socket pseudo-header checksum')
        self.records.append(dict(stage=self.stage, protocol=protocol,
                                 source=source.hex(), destination=destination.hex(), length=length))
        if self.stage in (0, 5):
            link = self.stage == 5
            target, local = (self.remote_link, self.link) if link else (self.remote, self.local)
            require(protocol == 58 and hop == 255 and source == local and
                    destination == self.multicast(target) and frame[:6] == b'\x33\x33' + destination[-4:] and
                    body[:2] + bytes(2) + body[4:8] == b'\x87\0' + bytes(6) and body[8:24] == target and
                    body[24:] == b'\1\1' + self.guest, 'socket owns exact neighbor resolution')
            self.outgoing.append(self.na(target, local))
        elif self.stage == 1:
            expected = bytes([128, 0, 0, 0, 0x6a, 0x10 + self.lane, 0x27, 1]) + bytes(
                (n * 7 + self.lane) & 255 for n in range(8, 19))
            require(protocol == 58 and hop == 37 and source == self.local and destination == self.remote and
                    frame[:6] == self.mac and body[:2] + bytes(2) + body[4:] == expected,
                    'original application raw ICMPv6 message')
            reply = bytearray(body)
            reply[0] = 129
            valid = self.packet(self.remote, self.local, reply, 61)
            bad = bytearray(valid)
            bad[-1] ^= 0x80
            self.outgoing += [bytes(bad), valid]
        else:
            require(protocol == 17 and hop == 64 and frame[:6] == self.mac and len(body) >= 8,
                    'actual UDP socket Ethernet output')
            sport, dport, size, check = struct.unpack('!HHHH', body[:8])
            require(size == length and check, 'complete mandatory UDP length and checksum')
            payload = body[8:]
            if self.stage == 2:
                require(source == self.local and destination == self.remote and
                        (sport, dport, payload) == (41000 + self.lane, 42000 + self.lane, b''),
                        'zero-length UDP output')
                bad = bytearray(self.udp(self.remote, self.local, dport, sport, b'\xe0'))
                bad[-1] ^= 1
                zero = bytearray(self.udp(self.remote, self.local, dport, sport, b'\xe1'))
                zero[60:62] = bytes(2)
                size_bad = bytearray(self.udp(self.remote, self.local, dport, sport, b'\xe2'))
                size_bad[58:60] = (11).to_bytes(2, 'big')
                self.outgoing += [bytes(bad), bytes(zero), bytes(size_bad),
                                  self.udp(self.remote, self.local, dport, sport, b'')]
            elif self.stage == 3:
                expected = bytes((n * 13 + self.lane) & 255 for n in range(41))
                require(source == self.local and destination == self.remote and
                        (sport, dport, payload) == (41000 + self.lane, 42000 + self.lane, expected),
                        'exact vectored UDP application bytes')
                self.outgoing.append(self.udp(self.remote, self.local, dport, sport,
                                              bytes(value ^ 0x5a for value in payload)))
            elif self.stage == 4:
                expected = bytes((n * 3 + self.lane) & 255 for n in range(13))
                require(source == self.local and destination == self.remote and
                        (sport, dport, payload) == (41010 + self.lane, 43000 + self.lane, expected),
                        'owned UDP quote input')
                self.outgoing.append(self.packet(self.remote, self.local,
                    b'\1\4' + bytes(6) + frame[14:54 + length], 64))
            elif self.stage == 6:
                expected = bytes((n * 9 + self.lane) & 255 for n in range(7))
                require(source == self.link and destination == self.remote_link and
                        (sport, dport, payload) == (41020 + self.lane, 44000 + self.lane, expected),
                        'original link-local UDP source and payload')
                self.outgoing.append(self.udp(self.remote_link, self.link, dport, sport, payload))
            else:
                raise ValueError('unexpected socket output stage')
        self.stage += 1

    @property
    def passed(self):
        return self.ready and self.complete == [1, 2] and self.stage == 7

    def result(self):
        return dict(passed=self.passed, lane=self.lane, stages=self.stage, phases=self.complete,
                    packets=self.records, firmware_frames=len(self.firmware_frames),
                    firmware_sha256=self.firmware_frames, native_MLD_reports=self.mld_reports)
