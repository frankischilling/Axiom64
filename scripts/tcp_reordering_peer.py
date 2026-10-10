# SPDX-License-Identifier: GPL-3.0-or-later
"""Add consistently valued receive reordering to the independent loss peer."""
from tcp_fault_peer import Flow as LossFlow, Peer as LossPeer, MASK, check


class Flow(LossFlow):
    def __init__(self, peer, role):
        super().__init__(peer, role)
        self.receive_stage = 0
        self.hole_acknowledgements = 0

    def send_range(self, offset, length):
        self.send(sequence=(self.origin + offset) & MASK,
                  data=self.reply[offset:offset + length])
        self.sent = max(self.sent, offset + length)

    def pump(self):
        if not self.fin_received:
            return
        if self.receive_stage == 0:
            self.send_range(536, 536)
            self.receive_stage = 1
            return
        if self.receive_stage in (1, 2):
            check(self.acknowledged == 0, 'receive hole stays cumulatively unacknowledged')
            self.hole_acknowledgements += 1
            if self.receive_stage == 1:
                self.send_range(536, 536)
                self.send_range(804, 536)
                self.receive_stage = 2
            else:
                self.send_range(0, 804)
                self.receive_stage = 3
            return
        if self.receive_stage == 3:
            if self.acknowledged == 0:
                return
            check(self.acknowledged == 1340, 'actual gap fill promotes queued overlapping ranges')
            self.receive_stage = 4
        super().pump()

    def result(self):
        result = super().result()
        check(self.receive_stage == 4 and self.hole_acknowledgements == 2,
              'actual reordering, duplicate, overlap and hole acknowledgements')
        return dict(result, receive_reordering=True,
                    hole_acknowledgements=self.hole_acknowledgements)


class Peer(LossPeer):
    flow_type = Flow
