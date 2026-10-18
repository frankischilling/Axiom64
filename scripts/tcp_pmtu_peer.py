# SPDX-License-Identifier: GPL-3.0-or-later
"""Independent PMTU endpoint with active/passive and repeated-reduction streams."""
import re
import struct
import time
from tcp_fault_peer import Peer as EthernetPeer, checksum, check, MASK, SYN, ACK, FIN, RST

BYTES = 4096
MTU = 576
def pattern(lane, role, direction):
    return bytes(((at * 29) ^ (at >> 7) ^ (lane * 53) ^ (role * 97) ^ (direction * 41)) & 255
                 for at in range(BYTES))

class Flow:
    def __init__(self, peer, role):
        self.peer, self.role = peer, role
        self.local_port = 44000 + role * 20 + peer.lane
        self.guest_port = 45000 + role * 20 + peer.lane if role & 1 else None
        self.guest_origin = None
        self.ip_address = bytes([10, 23, peer.lane + 1, 10 + role])
        self.mtu = 1400 if role == 3 else MTU
        self.reductions = set()
        self.initial, self.origin = 0xfffffff0, 0xfffffff1
        self.received = bytearray()
        self.expected, self.reply = pattern(peer.lane, role, 0), pattern(peer.lane, role, 1)
        self.sent = self.acknowledged = 0
        self.window = 0
        self.fin_position = None
        self.fin_received = self.fin_sent = self.done = self.aborted = False
        self.quoted = self.reduced_packets = self.oversized_packets = 0
        self.pending_quote = None
        self.invalid_at = self.valid_at = None
        self.accepted_damaged = False

    def send(self, flags=ACK, data=b'', sequence=None):
        if sequence is None:
            sequence = self.origin + self.sent
        options = bytes.fromhex('020405b4') if flags & SYN else b''
        acknowledgment = ((self.guest_origin or 0) + len(self.received) + int(self.fin_received)
                          if flags & ACK else 0)
        tcp = bytearray(struct.pack('!HHIIHHHH', self.local_port, self.guest_port,
            sequence & MASK, acknowledgment & MASK,
            ((20 + len(options)) // 4) << 12 | flags, 8192, 0, 0) + options + data)
        tcp[16:18] = checksum(self.ip_address + self.peer.address +
                             struct.pack('!BBH', 0, 6, len(tcp)) + tcp).to_bytes(2, 'big')
        self.peer.send(self.peer.guest + self.peer.mac + b'\x08\x00' + self.ip(6, tcp))

    def ip(self, protocol, data):
        header = bytearray(struct.pack('!BBHHHBBH4s4s', 0x45, 0, 20 + len(data), 0,
                                      0x4000, 64, protocol, 0, self.ip_address, self.peer.address))
        header[10:12] = checksum(header).to_bytes(2, 'big')
        return header + data

    def quote(self, frame, damaged=False):
        header = (frame[14] & 15) * 4
        quote = bytearray(frame[14:14 + header + 8])
        mtu = 0 if self.role == 2 else self.mtu
        if damaged:
            if self.role == 5:
                quote[10] ^= 1
            elif self.role in (6, 7):
                sequence = self.guest_origin + (BYTES + 2 if self.role == 6 else -1)
                quote[24:28] = (sequence & MASK).to_bytes(4, 'big')
            elif self.role == 8:
                quote[21] ^= 1
            elif self.role == 9:
                quote[23] ^= 1
            elif self.role == 10:
                quote[9] = 17
                quote[10:12] = b'\0\0'
                quote[10:12] = checksum(quote[:header]).to_bytes(2, 'big')
            elif self.role == 11:
                mtu = 65535
        body = bytearray(struct.pack('!BBHHH', 3, 4, 0, 0, mtu) + quote)
        body[2:4] = checksum(body).to_bytes(2, 'big')
        if damaged and self.role == 4:
            body[2] ^= 1
        self.peer.send(self.peer.guest + self.peer.mac + b'\x08\x00' + self.ip(1, body))
        if damaged:
            self.invalid_at = time.monotonic()
        else:
            self.quoted += 1
            self.reductions.add(self.mtu)
            if self.valid_at is None:
                self.valid_at = time.monotonic()

    def tick(self):
        if self.role == 5 and self.peer.native:
            return
        if self.pending_quote is not None and time.monotonic() - self.invalid_at >= .05:
            frame, self.pending_quote = self.pending_quote, None
            self.quote(frame)

    def start(self):
        check(self.role & 1 and self.guest_origin is None, 'one passive-open trigger')
        self.send(SYN, sequence=self.initial)

    def input(self, segment, record):
        flags = segment['flags']
        frame = bytes.fromhex(record['frame'])
        if flags & RST:
            self.aborted = True
            return
        if flags & SYN:
            check(bool(flags & ACK) == bool(self.role & 1) and not segment['data'],
                  'active or passive handshake identity')
            self.guest_port = segment['source']
            origin = (segment['seq'] + 1) & MASK
            check(self.guest_origin is None or self.guest_origin == origin, 'stable handshake identity')
            self.guest_origin = origin
            if self.role & 1:
                check(segment['ack'] == self.origin, 'passive SYN acknowledges exact peer sequence')
                self.send()
            else:
                self.send(SYN | ACK, sequence=self.initial)
            return
        check(self.guest_origin is not None and flags & ACK, 'established controlled stream')
        total = int.from_bytes(frame[16:18], 'big')
        if self.role == 3 and 576 < total <= 1400 and self.quoted:
            self.mtu = MTU
        if segment['data'] and total > self.mtu:
            self.oversized_packets += 1
            if self.role >= 4 and self.valid_at is None:
                if self.invalid_at is None:
                    self.pending_quote = frame
                    self.quote(frame, damaged=True)
                return
            self.quote(frame)
            return
        if self.pending_quote is not None and segment['data']:
            if self.role == 5 and self.peer.native and segment['seq'] == self.guest_origin:
                self.accepted_damaged = True
                self.pending_quote = None
            else:
                check(segment['seq'] != self.guest_origin,
                      'damaged or unowned quote cannot resize the first outstanding segment')
        self.window = segment['window']
        acknowledgment = (segment['ack'] - self.origin) & MASK
        check(acknowledgment <= self.sent + int(self.fin_sent), 'no ACK for untransmitted peer bytes')
        self.acknowledged = max(self.acknowledged, min(acknowledgment, BYTES))
        if segment['data']:
            position = (segment['seq'] - self.guest_origin) & MASK
            data = segment['data']
            check(position + len(data) <= BYTES and data == self.expected[position:position + len(data)],
                  'exact independently generated guest bytes')
            if position <= len(self.received):
                self.received.extend(data[max(0, len(self.received) - position):])
            self.reduced_packets += 1
        if flags & FIN:
            position = ((segment['seq'] - self.guest_origin) & MASK) + len(segment['data'])
            check(position == BYTES, 'FIN belongs after the exact guest stream')
            self.fin_position = position
        self.fin_received = self.fin_position == len(self.received) == BYTES
        if segment['data'] or flags & FIN:
            self.send()
        if len(self.received) == BYTES:
            while self.sent < BYTES and self.sent - self.acknowledged < min(8192, self.window):
                length = min(536, BYTES - self.sent,
                             min(8192, self.window) - (self.sent - self.acknowledged))
                if not length:
                    break
                self.send(data=self.reply[self.sent:self.sent + length])
                self.sent += length
            if self.fin_received and self.acknowledged == BYTES and not self.fin_sent:
                self.send(FIN | ACK)
                self.fin_sent = True
        if self.fin_sent and acknowledgment == BYTES + 1:
            self.done = True

    def result(self):
        check(self.done and not self.aborted and self.received == self.expected and
              self.acknowledged == BYTES and (self.quoted > 0 or self.accepted_damaged) and
              self.reduced_packets > 0,
              'complete exact PMTU-recovered bidirectional stream and acknowledged close')
        if self.role == 5 and self.peer.native:
            check(self.accepted_damaged and self.quoted == 0 and self.valid_at is None,
                  'measured Linux accepts the damaged inner header without a later valid hint')
        elif self.role >= 4:
            check(self.pending_quote is None and self.invalid_at is not None and
                  self.valid_at - self.invalid_at >= .05,
                  'damaged quote observation completes before a valid reduction')
        if self.role == 3:
            check(self.reductions == {576, 1400}, 'both consecutive path reductions exercised')
        return dict(done=self.done, bytes_received=len(self.received), bytes_acked=self.acknowledged,
                    quoted=self.quoted, oversized_packets=self.oversized_packets,
                    reduced_packets=self.reduced_packets, mtu=self.mtu, role=self.role,
                    reductions=sorted(self.reductions), peer_address=self.ip_address.hex(),
                    rejected_quote=self.role - 4 if self.role >= 4 else None,
                    native_accepts_inner_checksum=self.accepted_damaged,
                    observation_ms=(self.valid_at - self.invalid_at) * 1000
                    if self.invalid_at is not None and self.valid_at is not None else None)

class Peer(EthernetPeer):
    flow_type = Flow
    def __init__(self, lane, minimum_fin_ms=0):
        super().__init__(lane, minimum_fin_ms)
        self.native = False
        self.flows = [self.flow_type(self, role) for role in range(12)]

    def native_profile(self):
        self.native = True

    def tick(self):
        for flow in self.flows:
            flow.tick()

    def line(self, line):
        match = re.fullmatch(rb'TCP_PMTU_LISTEN lane=(\d+) case=(\d+)\r?', line)
        if match and int(match[1]) == self.lane:
            role = int(match[2])
            check(0 <= role < len(self.flows), 'bounded passive-open case')
            self.flows[role].start()

    def receive(self, frame):
        # Each case has its own destination so Linux's shared route cache
        # cannot supply a PMTU learned by an earlier connection.
        if frame[12:14] == b'\x08\x06' and len(frame) >= 42:
            target = frame[38:42]
            if target not in {flow.ip_address for flow in self.flows}:
                super().receive(frame)
                return
        elif frame[12:14] == b'\x08\x00' and len(frame) >= 34 and frame[23] == 6:
            target = frame[30:34]
        else:
            super().receive(frame)
            return
        check(target in {flow.ip_address for flow in self.flows}, 'owned independent path')
        self.ip = target
        super().receive(frame)
