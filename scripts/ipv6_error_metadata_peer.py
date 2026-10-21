# SPDX-License-Identifier: GPL-3.0-or-later
"""Quote actual emitted datagrams with independently varied IPv6 error headers."""
import struct
from ipv6_host_peer import Peer as HostPeer, checksum, require


class Peer(HostPeer):
    def __init__(self, lane, native=False):
        super().__init__(lane, native)
        self.datagrams = {}
        self.quotes = []
        self.pending = None

    def ack(self, request):
        reply = bytearray(request)
        reply[:6], reply[6:12] = self.guest, self.control
        reply[20] = 1
        self.outgoing.append(bytes(reply))
        if self.phase:
            self.complete.append(self.phase)

    def release_quote(self):
        sequence = (self.phase - 1) // 2
        if self.pending is None or sequence not in self.datagrams:
            return
        frame = self.datagrams[sequence]
        source = bytearray(frame[38:54])
        source[-1] = 250
        body = b'\x01\x04\0\0' + bytes(4) + frame[14:]
        hop, traffic_class = 7 + sequence * 11 % 248, (sequence * 37 + self.lane * 59) % 256
        packet = bytearray(self.packet(bytes(source), frame[22:38], body, hop))
        packet[14:18] = ((6 << 28) | (traffic_class << 20)).to_bytes(4, 'big')
        bad = bytearray(packet)
        # A checksum-invalid code also has a different pending error if wrongly
        # accepted, even when the later receive has a protected payload buffer.
        bad[55] ^= 1
        self.outgoing.extend([bytes(bad), bytes(packet)])
        self.quotes.append(sequence)
        self.ack(self.pending)
        self.pending = None

    def receive(self, frame):
        require(len(frame) >= 14 and frame[6:12] == self.guest, 'error metadata adapter ownership')
        if frame[12:14] == b'\x88\xbe':
            require(len(frame) == 60 and frame[:6] == self.control and
                    frame[14:19] == b'IP6M' + bytes([self.lane]) and not any(frame[20:]),
                    'complete error metadata barrier')
            phase = frame[19]
            if not self.ready:
                require(phase == 0, 'error metadata begins with readiness')
                self.ready = True
            else:
                require(phase == self.phase + 1 and phase <= 160 and self.pending is None,
                        'ordered error metadata transactions')
            self.phase = phase
            if phase % 2:
                self.pending = frame
                self.release_quote()
            else:
                self.ack(frame)
            return
        require(self.ready and frame[12:14] == b'\x86\xdd' and len(frame) >= 54,
                'defined error metadata protocol after readiness')
        if self.native and frame[20] == 0:
            super().receive(frame)
            return
        length, protocol, hop = struct.unpack('!HBB', frame[18:22])
        require(frame[14:18] == b'\x60\0\0\0' and len(frame) >= 54 + length,
                'complete original error metadata IPv6 output')
        source, destination = frame[22:38], frame[38:54]
        body = frame[54:54 + length]
        if protocol == 58 and body[:1] == b'\x87':
            target = body[8:24]
            require(length == 32 and hop == 255 and source in (self.local, self.link) and
                    target[-1] in range(128, 208) and
                    target[:-1] in (self.local[:-1], self.link[:-1]) and
                    destination == self.multicast(target) and
                    frame[:6] == b'\x33\x33' + destination[-4:] and
                    body[:8] == b'\x87\0' + body[2:4] + bytes(4) and
                    body[24:] == b'\1\1' + self.guest and not checksum(
                        source + destination + struct.pack('!I3xB', length, 58) + body),
                    'owned metadata neighbor resolution')
            self.outgoing.append(self.na(target, source))
            return
        sequence = destination[-1] - 128
        require(sequence in range(80) and sequence not in self.datagrams and
                self.phase in (2 * sequence, 2 * sequence + 1), 'one original metadata datagram')
        scoped, raw = sequence // 20 % 2, sequence >= 40
        local = self.link if scoped else self.local
        remote = bytearray(local)
        remote[-1] = 128 + sequence
        require(frame[:6] == self.mac and source == local and destination == bytes(remote) and
                protocol == (58 if raw else 17) and hop == 33 + sequence and not checksum(
                    source + destination + struct.pack('!I3xB', length, protocol) + body),
                'actual original metadata source, route, protocol, hop and checksum')
        payload = bytes((sequence * 7 + self.lane * 13 + n * 19) & 255 for n in range(32))
        if raw:
            require(length == 32 and body[:2] + bytes(2) + body[4:] ==
                    b'\x81\0\0\0\x6d\x45' + sequence.to_bytes(2, 'big') + payload[8:],
                    'complete original raw metadata payload')
        else:
            require(length == 40 and body[:6] == struct.pack('!HHH', 46000 + sequence,
                    48000 + sequence, 40) and body[8:] == payload,
                    'complete original UDP metadata payload')
        self.datagrams[sequence] = frame[:54 + length]
        if self.pending is not None:
            self.release_quote()

    @property
    def passed(self):
        return self.ready and self.pending is None and self.complete == list(range(1, 161)) and \
            set(self.datagrams) == set(range(80)) and self.quotes == list(range(80))

    def result(self):
        return dict(passed=self.passed, cases=len(self.datagrams), quotes=len(self.quotes),
                    native_MLD_reports=self.mld_reports)
