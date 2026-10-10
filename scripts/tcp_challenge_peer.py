# SPDX-License-Identifier: GPL-3.0-or-later
"""Burst invalid control segments, observe real silence, then recover original streams."""
import time
from tcp_fault_peer import Flow as LossFlow, Peer as LossPeer, ACK, FIN, SYN, RST, MASK, check

KINDS = 8
WAIT_MS = 650


class Flow(LossFlow):
    def __init__(self, peer, role):
        super().__init__(peer, role)
        self.round = 0
        self.phase = 'ready'
        self.reply_at = None
        self.waves = 0
        self.barriers = []

    def inject(self, kind, wave):
        flags, sequence, acknowledgment, data = ACK | FIN, self.origin, self.guest_next, b'bad'
        if kind == 0:
            acknowledgment = (self.guest_next - 8193) & MASK
        elif kind == 1:
            acknowledgment = (self.guest_next + 1) & MASK
        elif kind in (2, 3, 6):
            flags = SYN | ACK
            if kind == 3:
                sequence = (self.origin + 0x40000000) & MASK
            if kind == 6:
                data = b''
        elif kind in (4, 7):
            flags, sequence = RST, (self.origin + 1) & MASK
            if kind == 7:
                data = b''
        elif kind == 5:
            flags, sequence, data = ACK, (self.origin + 0x40000000) & MASK, b''
        self.send(flags, sequence, data, 65535, acknowledgment)
        self.peer.frames[-1].update(role=self.role, attack=self.round, kind=kind, wave=wave)

    def input(self, segment, record):
        if self.phase == 'response':
            check(segment['flags'] == ACK and not segment['data'] and
                  segment['seq'] == self.guest_next and segment['ack'] == self.origin,
                  'first actual challenge preserves both sequence edges')
            record['challenge'] = self.round
            self.reply_at = record['ms']
            self.phase = 'silence'
            self.waves = 0
            self.barriers.append(self.reply_at)
        elif self.phase == 'silence':
            raise ValueError('extra actual guest reply inside the challenge interval')
        super().input(segment, record)

    def pump(self):
        if not self.fin_received or not all(flow.fin_received for flow in self.peer.flows):
            return
        now = (time.monotonic() - self.peer.began) * 1000
        if self.phase == 'silence':
            # Send a complete mixed burst immediately, then another after 100 ms.
            if self.waves < 2 and now >= self.reply_at + self.waves * 100:
                for kind in range(KINDS):
                    self.inject(kind, self.waves + 1)
                self.waves += 1
            if self.waves < 2 or now < self.reply_at + WAIT_MS:
                return
            self.phase = 'ready'
        if self.phase == 'ready' and self.round < KINDS:
            self.round += 1
            self.phase = 'response'
            self.inject(self.round - 1, 0)
            return
        if self.phase == 'ready':
            self.phase = 'complete'
        if self.phase == 'complete':
            super().pump()

    def result(self):
        result = super().result()
        check(self.phase == 'complete' and self.round == len(self.barriers) == KINDS,
              'all actual challenge bursts, silence barriers and exact recovery complete')
        return dict(result, challenge_rounds=KINDS, burst_injections=KINDS * 17,
                    challenge_ms=self.barriers, silence_ms=WAIT_MS)


class Peer(LossPeer):
    flow_type = Flow

    def tick(self):
        for flow in self.flows:
            flow.pump()
