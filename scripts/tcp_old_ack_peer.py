# SPDX-License-Identifier: GPL-3.0-or-later
"""Inject in-window payload/FIN with an ACK outside the learned send-window bound."""
import time
from tcp_fault_peer import Flow as LossFlow, Peer as LossPeer, ACK, FIN, MASK, check

WINDOW = 8192
POISON = b'bad'
SHAPES = ((ACK, POISON), (ACK | FIN, b''), (ACK | FIN, POISON))


class Flow(LossFlow):
    def __init__(self, peer, role):
        super().__init__(peer, role)
        self.attacks = []
        self.challenges = []
        self.pending = None
        self.next_attack_ms = 0

    def input(self, segment, record):
        if self.pending is not None:
            check(segment['flags'] == ACK and not segment['data'] and
                  segment['seq'] == self.guest_next and segment['ack'] == self.origin,
                  'actual challenge ACK preserves receive sequence and rejects poisoned data/FIN')
            check(record['ms'] >= self.pending, 'actual challenge follows its injection')
            record['challenge'] = len(self.attacks)
            self.challenges.append(record['ms'])
            self.pending = None
            self.next_attack_ms = record['ms'] + 1200
        super().input(segment, record)

    def pump(self):
        if not self.fin_received:
            return
        if len(self.challenges) < len(SHAPES):
            now = (time.monotonic() - self.peer.began) * 1000
            if self.pending is not None or now < self.next_attack_ms:
                return
            check(self.sent == self.acknowledged == 0 and len(self.attacks) == len(self.challenges),
                  'no legitimate peer data before each rejected attack response')
            flags, data = SHAPES[len(self.attacks)]
            self.send(flags, self.origin, data, 65535,
                      acknowledgment=(self.guest_next - WINDOW - 1) & MASK)
            record = self.peer.frames[-1]
            record['attack'], record['role'] = len(self.attacks) + 1, self.role
            self.attacks.append(record['ms'])
            self.pending = record['ms']
            return
        super().pump()

    def result(self):
        result = super().result()
        check(len(self.attacks) == len(self.challenges) == len(SHAPES) and self.pending is None,
              'three actual rejected payload/FIN injections recover both original streams')
        intervals = [now - then for then, now in zip(self.challenges, self.attacks[1:])]
        check(all(interval >= 1200 for interval in intervals),
              'independent injections wait between actual challenge responses')
        return dict(result, old_ack_attacks=3, challenge_acks=3, maximum_peer_window=WINDOW,
                    invalid_ack_delta=WINDOW + 1, attack_ms=self.attacks,
                    challenge_ms=self.challenges, intervals_ms=intervals)


class Peer(LossPeer):
    flow_type = Flow

    def tick(self):
        for flow in self.flows:
            flow.pump()
