# SPDX-License-Identifier: GPL-3.0-or-later
"""Deliver real malformed checksums/options and preserve exact stream recovery."""
import struct
import time
from tcp_fault_peer import Peer as EthernetPeer, ACK, SYN, FIN, RST, MASK, check, checksum, payload

CASES = [('checksum', b''), ('length-zero', bytes.fromhex('fe000000')),
         ('length-one', bytes.fromhex('fe010000')), ('length-overrun', bytes.fromhex('fe050000')),
         ('MSS-length', bytes.fromhex('02030000')), ('scale-length', bytes.fromhex('03040100')),
         ('unknown-valid', bytes.fromhex('fe040000'))]


class Flow:
    role = 0

    def __init__(self, peer):
        self.peer = peer
        self.local_port, self.guest_port = 49550 + peer.lane, 48550 + peer.lane
        self.initial, self.origin = 0xfffffff0, 0xfffffff1
        self.guest_initial = self.guest_origin = None
        self.request, self.reply = payload(peer.lane, 0, 0)[:16], payload(peer.lane, 0, 1)[:16 * len(CASES)]
        self.received = bytearray()
        self.sent = self.acknowledged = 0
        self.case, self.stage, self.injected_at = 0, 'ready', None
        self.observations = []
        self.fin_received = self.fin_sent = self.done = False

    def send(self, flags=ACK, data=b'', options=b'', sequence=None, corrupt=False):
        sequence = self.origin + self.sent + int(self.fin_sent) if sequence is None else sequence
        body = bytearray(struct.pack('!HHIIHHHH', self.local_port, self.guest_port, sequence & MASK,
            (self.guest_origin + len(self.received) + int(self.fin_received)) & MASK,
            ((20 + len(options)) // 4) << 12 | flags, 65535, 0, 0) + options + data)
        body[16:18] = checksum(self.peer.ip + self.peer.address + struct.pack('!BBH', 0, 6, len(body)) + body).to_bytes(2, 'big')
        if corrupt:
            body[16] ^= 1
        ip = bytearray(struct.pack('!BBHHHBBH4s4s', 0x45, 0, len(body) + 20, 0, 0x4000,
                                   64, 6, 0, self.peer.ip, self.peer.address))
        ip[10:12] = checksum(ip).to_bytes(2, 'big')
        self.peer.send(self.peer.guest + self.peer.mac + b'\x08\x00' + ip + body)

    def inject(self):
        name, options = CASES[self.case]
        data = self.reply[self.sent:self.sent + 16]
        if self.case == 0:
            data = bytes(value ^ 0x80 for value in data)
        self.stage, self.injected_at = 'holding', time.monotonic()
        self.send(ACK | 8, data=data, options=options, corrupt=self.case == 0)
        self.peer.frames[-1].update(injection=name, offset=self.sent, intended_end=self.sent + 16)
        self.observations.append(dict(name=name, offset=self.sent, acknowledged_before_valid=False))

    def input(self, segment, record):
        flags, data = segment['flags'], segment['data']
        check(not flags & RST, 'malformed-input comparison remains a live exact stream')
        if flags & SYN:
            check(not flags & ACK and not data, 'one actual active malformed-input handshake')
            if self.guest_initial is None:
                self.guest_initial, self.guest_origin = segment['seq'], (segment['seq'] + 1) & MASK
            check(segment['seq'] == self.guest_initial, 'stable malformed-input tuple sequence')
            self.send(SYN | ACK, options=bytes.fromhex('020405b4'), sequence=self.initial)
            return
        check(flags & ACK and self.guest_origin is not None, 'established malformed-input stream')
        acknowledgment = (segment['ack'] - self.origin) & MASK
        allowed = self.sent + int(self.fin_sent)
        if self.stage == 'holding' and self.case != 0:
            allowed += 16
        check(acknowledgment <= allowed, 'invalid checksum cannot acknowledge or deliver poisoned bytes')
        if self.stage == 'holding' and acknowledgment > self.sent:
            check(acknowledgment == self.sent + 16, 'option-bearing data advances exactly its real payload')
            self.observations[-1]['acknowledged_before_valid'] = True
        self.acknowledged = max(self.acknowledged, acknowledgment)
        if data:
            offset = (segment['seq'] - self.guest_origin) & MASK
            check(offset <= len(self.received) and offset + len(data) <= 16 and
                  data == self.request[offset:offset + len(data)], 'exact request survives malformed input')
            self.received.extend(data[max(0, len(self.received) - offset):])
            self.send()
        if flags & FIN:
            check(len(self.received) == 16 and self.case == len(CASES) - 1 and
                  self.acknowledged >= len(self.reply) and
                  ((segment['seq'] + len(data) - self.guest_origin) & MASK) == 16,
                  'guest closes only after every exact malformed-input recovery byte')
            self.fin_received = True
            if self.stage == 'complete':
                self.send()
        if self.fin_sent and acknowledgment == len(self.reply) + 1:
            self.done = True
        self.pump()

    def pump(self):
        if self.done or len(self.received) != 16:
            return
        if self.stage == 'ready':
            self.inject()
        elif self.stage == 'holding' and time.monotonic() - self.injected_at >= .1:
            self.send(ACK | 8, data=self.reply[self.sent:self.sent + 16])
            self.peer.frames[-1].update(valid_recovery=CASES[self.case][0], offset=self.sent)
            self.sent += 16
            self.stage = 'waiting'
        if self.stage == 'waiting' and self.acknowledged >= self.sent:
            if self.case + 1 < len(CASES):
                self.case += 1
                self.stage = 'ready'
                self.inject()
            else:
                self.stage = 'complete'
        if self.stage == 'complete' and self.fin_received and not self.fin_sent:
            self.send()
            self.send(FIN | ACK)
            self.fin_sent = True

    def result(self):
        check(self.done and self.received == self.request and self.sent == len(self.reply) and
              len(self.observations) == len(CASES) and not self.observations[0]['acknowledged_before_valid'],
              'all actual malformed-input cases recover exact bytes and both closes')
        return dict(done=True, cases=self.observations, exact_request=16, exact_reply=len(self.reply),
                    exact_stream_recovered=True)


class Peer(EthernetPeer):
    def __init__(self, lane, minimum_fin_ms=0):
        super().__init__(lane, minimum_fin_ms)
        self.flows = [Flow(self)]

    def tick(self):
        self.flows[0].pump()
