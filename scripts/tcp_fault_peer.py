# SPDX-License-Identifier: GPL-3.0-or-later
"""Independent Ethernet/TCP endpoint that discards actual guest transmissions."""
import struct
import time

BYTES = 65536
MASK = (1 << 32) - 1
FIN, SYN, RST, ACK = 1, 2, 4, 16


def check(value, reason):
    if not value:
        raise ValueError(reason)


def checksum(data):
    if len(data) & 1:
        data += b'\0'
    total = sum(int.from_bytes(data[at:at + 2], 'big') for at in range(0, len(data), 2))
    while total > 65535:
        total = (total & 65535) + (total >> 16)
    return total ^ 65535


def payload(lane, role, direction):
    return bytes(((at * 29) ^ (at >> 7) ^ (lane * 53) ^ (role * 97) ^ (direction * 41)) & 255
                 for at in range(BYTES))


def packet(frame):
    check(len(frame) >= 54 and frame[12:14] == b'\x08\x00', 'complete Ethernet IPv4/TCP packet')
    ip = frame[14:]
    header, total = (ip[0] & 15) * 4, int.from_bytes(ip[2:4], 'big')
    check(ip[0] >> 4 == 4 and header >= 20 and header + 20 <= total <= len(ip) and
          ip[9] == 6 and checksum(ip[:header]) == 0 and
          not int.from_bytes(ip[6:8], 'big') & 0x3fff, 'TCP peer IPv4 bounds/checksum/fragmentation')
    tcp = ip[header:total]
    source, target, sequence, acknowledgment, bits, window, _, urgent = struct.unpack_from('!HHIIHHHH', tcp)
    length = (bits >> 12) * 4
    check(20 <= length <= len(tcp) and not bits & 0x0e00 and not urgent and
          checksum(ip[12:20] + struct.pack('!BBH', 0, 6, len(tcp)) + tcp) == 0,
          'TCP peer header bounds/reserved/checksum')
    at = 20
    while at < length:
        kind = tcp[at]
        if kind == 0:
            break
        if kind == 1:
            at += 1
            continue
        check(at + 2 <= length and tcp[at + 1] >= 2 and at + tcp[at + 1] <= length,
              'TCP peer option bounds')
        at += tcp[at + 1]
    return dict(source=source, target=target, seq=sequence, ack=acknowledgment, flags=bits & 0x1ff,
                window=window, data=tcp[length:], source_ip=ip[12:16], target_ip=ip[16:20])


class Flow:
    def __init__(self, peer, role):
        self.peer, self.role = peer, role
        self.local_port = (45000 if role else 44000) + peer.lane
        self.guest_port = 44010 + peer.lane if role else None
        self.initial = 0xfffffff0
        self.origin = (self.initial + 1) & MASK
        self.guest_initial = self.guest_origin = None
        self.handshakes = []
        self.lost_data = self.lost_fin = None
        self.data_retry_ms = self.fin_retry_ms = None
        self.established = self.fin_received = self.fin_sent = self.done = False
        self.received = bytearray()
        self.sent = self.acknowledged = 0
        self.window = 0
        self.expected = payload(peer.lane, role, 0)
        self.reply = payload(peer.lane, role, 1)

    @property
    def guest_next(self):
        return (self.guest_origin + len(self.received) + int(self.fin_received)) & MASK

    def send(self, flags=ACK, sequence=None, data=b'', window=8192):
        options = bytes.fromhex('02040218') if flags & SYN else b''
        sequence = self.origin + self.sent + int(self.fin_sent) if sequence is None else sequence
        acknowledgment = 0 if self.guest_origin is None else self.guest_next
        if flags == SYN:
            acknowledgment = 0
        tcp = bytearray(struct.pack('!HHIIHHHH', self.local_port, self.guest_port, sequence & MASK,
                                    acknowledgment, ((20 + len(options)) // 4) << 12 | flags,
                                    window, 0, 0) + options + data)
        pseudo = self.peer.ip + self.peer.address + struct.pack('!BBH', 0, 6, len(tcp))
        tcp[16:18] = struct.pack('!H', checksum(pseudo + tcp))
        ip = bytearray(struct.pack('!BBHHHBBH4s4s', 0x45, 0, 20 + len(tcp), 0, 0x4000, 64, 6, 0,
                                  self.peer.ip, self.peer.address))
        ip[10:12] = struct.pack('!H', checksum(ip))
        self.peer.send(self.peer.guest + self.peer.mac + b'\x08\x00' + ip + tcp)

    def start(self):
        check(self.role and not self.handshakes, 'one independent active peer SYN')
        self.send(SYN, self.initial, window=536)

    def input(self, segment, record):
        flags, sequence, data = segment['flags'], segment['seq'], segment['data']
        check(not flags & RST, 'guest did not reset the controlled loss stream')
        if flags & SYN:
            check(not data and not flags & FIN and bool(flags & ACK) == bool(self.role),
                  'actual active/passive guest handshake shape')
            if self.guest_initial is None:
                self.guest_initial = sequence
                self.guest_origin = (sequence + 1) & MASK
                self.guest_port = segment['source']
            check(sequence == self.guest_initial and
                  (not self.role or segment['ack'] == self.origin), 'stable retransmitted guest handshake')
            self.handshakes.append(record['ms'])
            if len(self.handshakes) == 1:
                record['drop'] = 'handshake'
                return
            check(self.handshakes[1] - self.handshakes[0] >= 850,
                  'handshake retransmission waits on an actual elapsed timer')
            if self.role:
                self.established = True
                self.send(window=536)
            else:
                self.send(SYN | ACK, self.initial, window=536)
            return
        check(flags & ACK and self.guest_origin is not None, 'established TCP acknowledgment')
        acknowledged = (segment['ack'] - self.origin) & MASK
        check(acknowledged <= self.sent + int(self.fin_sent), 'guest ACK covers only transmitted peer bytes')
        self.window = segment['window']
        if not self.established:
            check(not self.role and acknowledged == 0, 'active guest completes the real handshake')
            self.established = True
        if data:
            offset = (sequence - self.guest_origin) & MASK
            check(offset <= len(self.received) and offset + len(data) <= BYTES and
                  data == self.expected[offset:offset + len(data)], 'guest sends only exact controlled payload bytes')
            if self.lost_data is None:
                check(offset == 0 and len(data) <= 536, 'one initial data segment within the advertised window')
                self.lost_data = dict(sequence=sequence, data=data, ms=record['ms'])
                record['drop'] = 'data'
                return
            if self.data_retry_ms is None:
                check(sequence == self.lost_data['sequence'] and data == self.lost_data['data'],
                      'lost data sequence and bytes are actually retransmitted')
                self.data_retry_ms = record['ms'] - self.lost_data['ms']
                check(self.data_retry_ms >= 2850, 'data RTO resets to three seconds after handshake loss')
            self.received.extend(data[max(0, len(self.received) - offset):])
            if not flags & FIN:
                self.send()
        if flags & FIN:
            check(len(self.received) == BYTES and (sequence + len(data)) & MASK ==
                  (self.guest_origin + BYTES) & MASK, 'guest FIN follows all exact data')
            if self.lost_fin is None:
                self.lost_fin = record['ms']
                record['drop'] = 'fin'
                return
            if not self.fin_received:
                self.fin_retry_ms = record['ms'] - self.lost_fin
                check(self.fin_retry_ms >= self.peer.minimum_fin_ms, 'FIN retransmission uses an actual timer')
                self.fin_received = True
            self.send()
        if acknowledged > self.acknowledged:
            self.acknowledged = acknowledged
        if self.fin_sent and acknowledged == BYTES + 1:
            self.done = True
        self.pump()

    def pump(self):
        if not self.fin_received:
            return
        end = min(BYTES, self.acknowledged + min(self.window, 8192))
        while self.sent < end:
            size = min(536, end - self.sent)
            self.send(sequence=self.origin + self.sent, data=self.reply[self.sent:self.sent + size])
            self.sent += size
        if self.acknowledged == BYTES and not self.fin_sent:
            self.send(ACK | FIN, self.origin + BYTES)
            self.fin_sent = True

    def result(self):
        check(self.done and self.received == self.expected and self.sent == BYTES and
              len(self.handshakes) >= 2 and self.data_retry_ms is not None and self.fin_retry_ms is not None,
              'complete controlled handshake/data/FIN loss recovery and both exact streams')
        return dict(role=self.role, received=len(self.received), sent=self.sent, sequence_wrap=True,
                    handshake_retry_ms=round(self.handshakes[1] - self.handshakes[0], 3),
                    data_retry_ms=round(self.data_retry_ms, 3), fin_retry_ms=round(self.fin_retry_ms, 3), passed=True)


class Peer:
    def __init__(self, lane, minimum_fin_ms=850):
        self.lane = lane
        self.minimum_fin_ms = minimum_fin_ms
        self.guest = bytes([0x52, 0x54, 0, 0x12, 0x34, 0x10 + lane])
        self.mac = bytes([2, 0x41, 0x58, 0x54, 0x43, lane])
        self.ip, self.address = bytes([10, 23, lane + 1, 1]), bytes([10, 23, lane + 1, 2])
        self.input, self.output = bytearray(), bytearray()
        self.frames, self.outgoing = [], []
        self.began = time.monotonic()
        self.flows = [Flow(self, role) for role in range(2)]

    def send(self, frame):
        frame = bytes(frame)
        self.outgoing.append(frame)
        self.frames.append(dict(direction='send', ms=(time.monotonic() - self.began) * 1000, frame=frame.hex()))

    def receive(self, frame):
        frame = bytes(frame)
        record = dict(direction='receive', ms=(time.monotonic() - self.began) * 1000, frame=frame.hex())
        self.frames.append(record)
        check(len(frame) >= 14 and frame[6:12] == self.guest, 'real configured guest Ethernet source')
        if frame[12:14] == b'\x08\x06':
            arp = frame[14:42]
            check(len(arp) == 28 and arp[:6] == bytes.fromhex('000108000604'), 'complete Ethernet/IPv4 ARP')
            if arp[6:8] == b'\0\1' and arp[24:28] == self.ip:
                answer = struct.pack('!HHBBH', 1, 0x800, 6, 4, 2) + self.mac + self.ip + self.guest + arp[14:18]
                self.send(self.guest + self.mac + b'\x08\x06' + answer)
            return
        if frame[12:14] != b'\x08\x00' or len(frame) < 34 or frame[23] != 6:
            return
        segment = packet(frame)
        check(frame[:6] == self.mac and segment['source_ip'] == self.address and segment['target_ip'] == self.ip,
              'real configured controlled TCP tuple')
        flow = next((flow for flow in self.flows if segment['target'] == flow.local_port), None)
        check(flow is not None and (flow.guest_port is None or segment['source'] == flow.guest_port),
              'controlled TCP flow port ownership')
        record['role'] = flow.role
        flow.input(segment, record)

    def result(self):
        return dict(lane=self.lane, flows=[flow.result() for flow in self.flows], frames=self.frames)
