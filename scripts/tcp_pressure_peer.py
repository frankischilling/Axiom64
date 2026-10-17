# SPDX-License-Identifier: GPL-3.0-or-later
"""Keep real TCP companions and UDP exchanges alive across TIME-WAIT pressure."""
import re
import struct
from tcp_fault_peer import Peer as EthernetPeer, checksum, check, MASK, SYN, ACK, FIN, RST


def pattern(lane, step, direction):
    return bytes(((at * 29) ^ (lane * 53) ^ (step * 97) ^ (direction * 41)) & 255
                 for at in range(16))


def ip(source, destination, protocol, body):
    header = bytearray(struct.pack('!BBHHHBBH4s4s', 0x45, 0, 20 + len(body), 0, 0x4000,
                                   64, protocol, 0, source, destination))
    header[10:12] = checksum(header).to_bytes(2, 'big')
    return header + body


class Flow:
    def __init__(self, peer, role):
        self.peer, self.role = peer, role
        self.local_port = 46000 + peer.lane
        self.guest_port = self.guest_origin = None
        self.initial, self.origin = 0xfffffff0, 0xfffffff1
        self.received = bytearray()
        self.sent = self.acknowledged = 0
        self.fin_received = self.fin_sent = self.done = self.aborted = False

    def send(self, flags=ACK, data=b'', sequence=None):
        if sequence is None:
            sequence = self.origin + self.sent
        options = bytes.fromhex('020405b4') if flags & SYN else b''
        acknowledgment = self.guest_origin + len(self.received) + int(self.fin_received)
        tcp = bytearray(struct.pack('!HHIIHHHH', self.local_port, self.guest_port,
            sequence & MASK, acknowledgment & MASK, ((20 + len(options)) // 4) << 12 | flags,
            8192, 0, 0) + options + data)
        tcp[16:18] = checksum(self.peer.ip + self.peer.address +
                              struct.pack('!BBH', 0, 6, len(tcp)) + tcp).to_bytes(2, 'big')
        self.peer.send(self.peer.guest + self.peer.mac + b'\x08\x00' +
                       ip(self.peer.ip, self.peer.address, 6, tcp))

    def input(self, segment, record):
        flags = segment['flags']
        check(not flags & RST, 'live TCP companion cannot be reset by unrelated pressure')
        if flags & SYN:
            check(not flags & ACK and not segment['data'], 'active companion SYN')
            self.guest_port = segment['source']
            origin = (segment['seq'] + 1) & MASK
            check(self.guest_origin is None or self.guest_origin == origin, 'stable companion identity')
            self.guest_origin = origin
            self.send(SYN | ACK, sequence=self.initial)
            return
        check(self.guest_origin is not None and flags & ACK, 'established live companion')
        acknowledgment = (segment['ack'] - self.origin) & MASK
        check(acknowledgment <= self.sent + int(self.fin_sent), 'ACK owns transmitted companion bytes')
        self.acknowledged = max(self.acknowledged, min(acknowledgment, self.sent))
        expected = b''.join(pattern(self.peer.lane, step, 0) for step in range(self.peer.steps))
        data = segment['data']
        if data:
            offset = (segment['seq'] - self.guest_origin) & MASK
            check(offset <= len(self.received) and offset + len(data) <= len(expected) and
                  data == expected[offset:offset + len(data)], 'exact companion request through table pressure')
            self.received.extend(data[max(0, len(self.received) - offset):])
        if flags & FIN:
            offset = ((segment['seq'] - self.guest_origin) & MASK) + len(data)
            check(offset == len(expected) == len(self.received), 'companion FIN follows every observed phase')
            self.fin_received = True
        if data or flags & FIN:
            self.send()
        while self.sent + 16 <= len(self.received):
            self.send(data=pattern(self.peer.lane, self.sent // 16, 1))
            self.sent += 16
        if self.fin_received and self.acknowledged == self.sent and not self.fin_sent:
            self.send(FIN | ACK)
            self.fin_sent = True
        if self.fin_sent and acknowledgment == self.sent + 1:
            self.done = True

    def result(self):
        check(self.done and self.fin_received and self.fin_sent and
              len(self.received) == self.sent == self.acknowledged == self.peer.steps * 16,
              'all companion phases and both acknowledged closes')
        return dict(role=0, done=True, steps=self.peer.steps, bytes_each=self.sent, sequence_wrap=True)


class Peer(EthernetPeer):
    flow_type = Flow

    def __init__(self, lane, minimum_fin_ms=0):
        self.steps, self.phases = 3, 2
        self.datagrams = set()
        super().__init__(lane, minimum_fin_ms)
        self.flows = self.flows[:1]

    def line(self, line):
        mode = re.fullmatch(rb'TCP_PRESSURE_MODE native=[01] expiry=([01]) external=1\r?', line)
        if mode:
            self.phases = 2 if mode[1] == b'1' else 1
            self.steps = self.phases + 1

    def receive(self, frame):
        frame = bytes(frame)
        if len(frame) < 34 or frame[12:14] != b'\x08\x00' or frame[23] != 17:
            super().receive(frame)
            return
        import time
        self.frames.append(dict(direction='receive', ms=(time.monotonic() - self.began) * 1000,
                                frame=frame.hex()))
        check(frame[:12] == self.mac + self.guest, 'actual independent UDP Ethernet tuple')
        packet = frame[14:]
        total = int.from_bytes(packet[2:4], 'big')
        check(packet[0] == 0x45 and total == 44 and len(packet) >= total and
              checksum(packet[:20]) == 0 and not int.from_bytes(packet[6:8], 'big') & 0xbfff and
              packet[12:20] == self.address + self.ip, 'complete pressure UDP IPv4 packet')
        udp = packet[20:total]
        source, target, length, _ = struct.unpack_from('!HHHH', udp)
        check(length == 24 and checksum(self.address + self.ip + struct.pack('!BBH', 0, 17, length) + udp) == 0,
              'actual UDP length and pseudo-header checksum')
        index = target - 47000 - self.lane * 100
        body = udp[8:]
        check(0 <= index < 32 and index % 2 == self.lane and body[:1] == b'U' and
              body[2:4] == bytes([index, self.lane]), 'owned UDP phase and index')
        phase = body[1]
        expected = bytes([ord('U'), phase, index, self.lane]) + bytes(
            ((at * 29) ^ (phase * 53) ^ (index * 97) ^ (self.lane * 41)) & 255 for at in range(4, 16))
        check(phase < self.phases and body == expected and (phase, index) not in self.datagrams,
              'one exact UDP request per pressure phase')
        self.datagrams.add((phase, index))
        answer = bytearray(struct.pack('!HHHH', target, source, 24, 0) + bytes(value ^ 0x80 for value in body))
        value = checksum(self.ip + self.address + struct.pack('!BBH', 0, 17, 24) + answer)
        answer[6:8] = (value or 0xffff).to_bytes(2, 'big')
        self.send(self.guest + self.mac + b'\x08\x00' + ip(self.ip, self.address, 17, answer))

    def result(self):
        check(self.datagrams == {(phase, index) for phase in range(self.phases)
                                 for index in range(self.lane, 32, 2)}, 'all fresh UDP sockets survive every phase')
        return dict(lane=self.lane, flows=[self.flows[0].result()],
                    datagrams=len(self.datagrams), phases=self.phases, frames=self.frames)
