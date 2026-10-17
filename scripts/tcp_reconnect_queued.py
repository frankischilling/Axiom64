# SPDX-License-Identifier: GPL-3.0-or-later
"""Observe successor bytes independently while old transmit copies remain pending."""
import struct
from tcp_fault_peer import check, checksum, MASK, SYN, ACK, FIN, RST


def pattern(lane, phase, direction, at, size):
    return bytes(((position * 29) ^ (position >> 7) ^ (lane * 53) ^ (4 * 97) ^ (phase * 71) ^
                  (direction * 41)) & 255 for position in range(at, at + size))


class QueuedPhase:
    def __init__(self, flow, initial, ordinal):
        self.flow, self.initial, self.ordinal = flow, initial, ordinal
        self.origin = (initial + 1) & MASK
        self.peer_initial = (0xfffffff0 + ordinal * 0x100000) & MASK
        self.peer_origin = (self.peer_initial + 1) & MASK
        self.received = bytearray()
        self.app_sent = self.wire_sent = self.acked = 0
        self.fin_received = self.fin_sent = self.closed = False

    def send(self, flags=ACK, data=b'', sequence=None):
        flow, peer = self.flow, self.flow.peer
        options = bytes.fromhex('020405b4') if flags & SYN else b''
        if sequence is None:
            sequence = self.peer_origin + self.wire_sent + int(self.fin_sent)
        acknowledgment = self.origin + len(self.received) + int(self.fin_received)
        body = bytearray(struct.pack('!HHIIHHHH', flow.local_port, flow.guest_port, sequence & MASK,
            acknowledgment & MASK, ((20 + len(options)) // 4) << 12 | flags, 65535, 0, 0) + options + data)
        body[16:18] = checksum(peer.ip + peer.address + struct.pack('!BBH', 0, 6, len(body)) + body).to_bytes(2, 'big')
        ip = bytearray(struct.pack('!BBHHHBBH4s4s', 0x45, 0, 20 + len(body), 0, 0x4000, 64, 6, 0,
                                   peer.ip, peer.address))
        ip[10:12] = checksum(ip).to_bytes(2, 'big')
        peer.send(peer.guest + peer.mac + b'\x08\x00' + ip + body)

    def control(self):
        check(self.ordinal == 0 and self.wire_sent == self.app_sent, 'one old-phase queue barrier')
        self.send(data=b'Q')
        self.wire_sent += 1

    def input(self, segment):
        flags, data = segment['flags'], segment['data']
        if flags & SYN:
            check(segment['seq'] == self.initial and not flags & ACK and not data, 'stable active owned handshake')
            self.send(SYN | ACK, sequence=self.peer_initial)
            return
        if flags & RST:
            check(self.ordinal == 0 and self.flow.old_prefix is not None and
                  segment['seq'] == (self.origin + self.flow.old_prefix + 512) & MASK,
                  'explicit disconnect reset owns only its old queued sequence')
            self.flow.old_reset = True
            self.closed = True
            return
        check(flags & ACK, 'owned synchronized queued-reconnect packet')
        acknowledgment = (segment['ack'] - self.peer_origin) & MASK
        check(acknowledgment <= self.wire_sent + int(self.fin_sent), 'ACK owns only emitted peer bytes')
        self.acked = max(self.acked, acknowledgment)
        if data:
            position = (segment['seq'] - self.origin) & MASK
            check(position + len(data) < 4096 and data == pattern(self.flow.peer.lane, self.ordinal, 0,
                  position, len(data)), 'exact independently generated old/new application bytes')
            if position <= len(self.received):
                self.received.extend(data[max(0, len(self.received) - position):])
        if flags & FIN:
            check(self.ordinal == 1 and (segment['seq'] - self.origin) & MASK == len(self.received),
                  'successor FIN follows its complete exact stream')
            self.fin_received = True
        if data or flags & FIN:
            self.send()
        self.flow.flush()
        if self.fin_sent and acknowledgment == self.wire_sent + 1:
            self.closed = True


class QueuedFlow:
    def __init__(self, peer, role):
        check(role == 4, 'queued-copy case has its independent tuple')
        self.peer, self.role = peer, role
        self.local_port, self.guest_port = 49080 + peer.lane, 48080 + peer.lane
        self.phases = []
        self.old_prefix = None
        self.future = self.old_reset = False
        self.late_bytes = {}
        self.delta = None

    @property
    def done(self):
        return len(self.phases) == 2 and self.phases[-1].closed

    def input(self, segment, record):
        if segment['flags'] & SYN:
            if not self.phases:
                self.phases.append(QueuedPhase(self, segment['seq'], 0))
            elif self.future and len(self.phases) == 1:
                old_end = (self.phases[0].origin + self.old_prefix + 512) & MASK
                self.delta = (segment['seq'] - old_end) & MASK
                check(65537 <= self.delta < 0x80000000, 'successor excludes the entire old queued sequence window')
                self.phases.append(QueuedPhase(self, segment['seq'], 1))
        check(self.phases, 'actual first handshake precedes queued reconnect data')
        if len(self.phases) == 2 and not segment['flags'] & SYN:
            old = self.phases[0]
            position = (segment['seq'] - old.origin) & MASK
            if position <= self.old_prefix + 512:
                data = segment['data']
                check(not segment['flags'] & FIN, 'old cancellation does not create a late FIN')
                if data:
                    check(self.old_prefix <= position and position + len(data) <= self.old_prefix + 512 and
                          data == pattern(self.peer.lane, 0, 0, position, len(data)),
                          'late old native copy retains its exact original payload')
                    self.late_bytes.update({position + at: byte for at, byte in enumerate(data)})
                if segment['flags'] & RST:
                    check(position == self.old_prefix + 512, 'late old reset owns only its abandoned stream')
                    self.old_reset = True
                    old.closed = True
                record['old_queued_copy'] = True
                self.phases[-1].send()
                return
        self.phases[-1].input(segment)

    def flush(self):
        if not self.phases:
            return
        phase = self.phases[-1]
        limit = len(phase.received)
        if self.peer.queued_copy is not None:
            limit = self.peer.queued_copy.limit(self.peer.lane, limit)
        while phase.app_sent < limit:
            size = min(512, limit - phase.app_sent)
            phase.send(data=pattern(self.peer.lane, phase.ordinal, 1, phase.app_sent, size))
            phase.app_sent += size
            phase.wire_sent += size
        if phase.fin_received and phase.acked == phase.wire_sent and not phase.fin_sent:
            phase.send(FIN | ACK)
            phase.fin_sent = True

    def result(self):
        check(self.done and self.old_reset and len(self.phases[1].received) == (576 if self.peer.lane == 0 else 528),
              'exact successor and live companion bytes complete with both FINs')
        return dict(role=self.role, done=True, old_prefix=self.old_prefix, old_reset=self.old_reset,
                    late_old_bytes=len(self.late_bytes), successor_delta=self.delta,
                    phases=[dict(initial=p.initial, received=len(p.received), sent=p.wire_sent,
                                 acknowledged=p.acked, closed=p.closed) for p in self.phases])
