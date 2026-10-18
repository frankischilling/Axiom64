# SPDX-License-Identifier: GPL-3.0-or-later
"""Observe description reuse, completed tuples and old/new sequence separation."""
import struct
from tcp_fault_peer import Peer as EthernetPeer, checksum, check, packet, MASK, SYN, ACK, FIN, RST
from tcp_reconnect_queued import QueuedFlow


def pattern(lane, role, phase, direction, size):
    return bytes(((at * 29) ^ (at >> 7) ^ (lane * 53) ^ (role * 97) ^
                  (phase * 71) ^ (direction * 41)) & 255 for at in range(size))


class Phase:
    def __init__(self, owner, ordinal, initial):
        self.owner, self.ordinal, self.initial = owner, ordinal, initial
        self.origin = (initial + 1) & MASK
        self.peer_initial = (0xfffffff0 + ordinal * 0x100000) & MASK
        self.local_port = owner.local_port + int(ordinal == 1 and owner.role >= 2)
        self.peer_origin = (self.peer_initial + 1) & MASK
        self.received = bytearray()
        self.reply_sent = self.reply_acked = 0
        self.fin_received = self.fin_sent = self.closed = self.reset = False
        self.size = (262144, 16, 512)[ordinal] if owner.role == 5 else owner.size
        self.expected = pattern(owner.peer.lane, owner.role, ordinal, 0, self.size)
        self.reply = pattern(owner.peer.lane, owner.role, ordinal, 1, 16)

    @property
    def end(self):
        return (self.origin + len(self.received) + int(self.fin_received)) & MASK

    def send(self, flags=ACK, data=b'', sequence=None):
        owner, peer = self.owner, self.owner.peer
        options = bytes.fromhex('020405b4') if flags & SYN else b''
        if sequence is None:
            sequence = self.peer_origin + self.reply_sent + int(self.fin_sent)
        body = bytearray(struct.pack('!HHIIHHHH', self.local_port, owner.guest_port,
            sequence & MASK, self.end, ((20 + len(options)) // 4) << 12 | flags,
            owner.window, 0, 0) + options + data)
        body[16:18] = checksum(peer.ip + peer.address + struct.pack('!BBH', 0, 6, len(body)) + body).to_bytes(2, 'big')
        ip = bytearray(struct.pack('!BBHHHBBH4s4s', 0x45, 0, 20 + len(body), 0, 0x4000,
                                   64, 6, 0, peer.ip, peer.address))
        ip[10:12] = checksum(ip).to_bytes(2, 'big')
        peer.send(peer.guest + peer.mac + b'\x08\x00' + ip + body)

    def input(self, segment):
        flags = segment['flags']
        check(segment['target'] == self.local_port, 'owned old or successor destination port')
        if flags & SYN:
            check(segment['seq'] == self.initial and not flags & ACK and not segment['data'],
                  'stable active reconnect handshake')
            self.send(SYN | ACK, sequence=self.peer_initial)
            return
        if flags & RST:
            check(((self.ordinal == 0 and self.owner.role < 2) or
                   (self.owner.role == 5 and self.ordinal < 2)) and len(self.received) == self.size and
                  self.reply_acked == 16 and segment['seq'] == self.end and not segment['data'],
                  'explicit reset owns the complete acknowledged old stream')
            self.closed = self.reset = True
            return
        check(flags & ACK and not self.reset, 'established owned reconnect phase')
        acknowledgment = (segment['ack'] - self.peer_origin) & MASK
        check(acknowledgment <= self.reply_sent + int(self.fin_sent), 'reconnect ACK owns only emitted peer bytes')
        self.reply_acked = max(self.reply_acked, min(16, acknowledgment))
        data = segment['data']
        if data:
            position = (segment['seq'] - self.origin) & MASK
            check(position + len(data) <= self.size and
                  data == self.expected[position:position + len(data)], 'exact independent reconnect bytes')
            if position <= len(self.received):
                self.received.extend(data[max(0, len(self.received) - position):])
        if flags & FIN:
            check(((segment['seq'] - self.origin) & MASK) + len(data) == self.size and
                  len(self.received) == self.size, 'reconnect FIN follows its complete byte stream')
            self.fin_received = True
        if data or flags & FIN:
            self.send()
        if len(self.received) == self.size and not self.reply_sent:
            self.send(data=self.reply)
            self.reply_sent = 16
        if self.fin_received and self.reply_acked == 16 and not self.fin_sent:
            self.send(FIN | ACK)
            self.fin_sent = True
        if self.fin_sent and acknowledgment == 17:
            self.closed = True

    def result(self):
        check(self.closed and self.received == self.expected and self.reply_acked == 16,
              'complete actual reconnect phase and acknowledged reply')
        return dict(phase=self.ordinal, initial=self.initial, old_end=self.end, closed=self.closed,
                    reset=self.reset, bytes_received=len(self.received), reply_acked=self.reply_acked,
                    fin_received=self.fin_received, fin_sent=self.fin_sent)


class Flow:
    def __init__(self, peer, role):
        self.peer, self.role = peer, role
        self.local_port = 49000 + role * 20 + peer.lane
        self.guest_port = 48000 + role * 20 + peer.lane
        self.size = 32768 if role < 2 else 4096
        self.window = 65535 if role == 5 or not role & 1 else 8192
        self.phase_count = 3 if role == 5 else 2
        self.phases = []
        self.reuse_delta = None

    @property
    def done(self):
        return len(self.phases) == self.phase_count and all(phase.closed for phase in self.phases)

    def input(self, segment, record):
        if segment['flags'] & SYN and (not self.phases or self.phases[-1].closed):
            check(len(self.phases) < self.phase_count, 'exact controlled opens per description')
            if self.phases:
                old = self.phases[0]
                self.reuse_delta = (segment['seq'] - old.end) & MASK
                if self.role < 2 or self.role == 5:
                    check(self.window + 2 <= self.reuse_delta < 0x80000000,
                          'successor SYN starts beyond the old transmitted sequence window')
                if self.role == 5:
                    step = (segment['seq'] - self.phases[-1].end) & MASK
                    check(self.window + 2 <= step < 0x80000000,
                          'each intervening reconnect advances the description sequence')
            self.phases.append(Phase(self, len(self.phases), segment['seq']))
        check(self.phases, 'a reconnect phase begins with an actual SYN')
        self.phases[-1].input(segment)

    def result(self):
        check(len(self.phases) == self.phase_count, 'all actual opens use the same bound source')
        return dict(role=self.role, window=self.window, size=self.size, done=True,
                    reuse_delta=self.reuse_delta, phases=[phase.result() for phase in self.phases])


class Peer(EthernetPeer):
    flow_type = Flow

    def __init__(self, lane, minimum_fin_ms=0):
        super().__init__(lane, minimum_fin_ms)
        self.flows = [Flow(self, role) for role in (*range(4), 5)] + [QueuedFlow(self, 4)]
        self.queued_copy = None

    def line(self, line):
        if self.lane == 0:
            check(self.queued_copy is not None, 'actual queued-copy controller is attached')
            self.queued_copy.line(line)

    def result(self):
        result = super().result()
        check(self.queued_copy is not None, 'both old-copy ownership observations have their controller')
        result['queued_copy'] = self.queued_copy.result()
        return result

    def close(self):
        if self.queued_copy is not None:
            self.queued_copy.close()

    def receive(self, frame):
        if frame[12:14] != b'\x08\x00' or len(frame) < 34 or frame[23] != 6:
            return super().receive(frame)
        frame = bytes(frame)
        segment = packet(frame)
        check(frame[:12] == self.mac + self.guest and segment['source_ip'] == self.address and
              segment['target_ip'] == self.ip, 'actual reconnect NIC and IPv4 identities')
        owner = next((flow for flow in self.flows if segment['source'] == flow.guest_port and
                      segment['target'] in (flow.local_port, flow.local_port + int(2 <= flow.role < 4 or flow.role == 5))), None)
        check(owner is not None, 'actual reconnect old or successor tuple')
        record = dict(direction='receive', ms=0, frame=frame.hex(), role=owner.role)
        # The packet order and original bytes are retained in the producer record.
        import time
        record['ms'] = (time.monotonic() - self.began) * 1000
        self.frames.append(record)
        if owner.role == 4 and segment['flags'] & SYN and owner.future and len(owner.phases) == 1:
            check(self.queued_copy is not None, 'actual queued successor has its shared controller')
            self.queued_copy.successor(self.lane, frame)
        owner.input(segment, record)
