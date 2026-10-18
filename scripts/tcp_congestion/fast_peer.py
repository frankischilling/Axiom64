# SPDX-License-Identifier: GPL-3.0-or-later
"""Observe real duplicate-ACK fast retransmit, inflation, deflation and rwnd bounds."""
import time
from tcp_fault_peer import check, MASK
from tcp_congestion.window_peer import Flow as WindowFlow, Peer as WindowPeer


class Flow(WindowFlow):
    def __init__(self, peer):
        super().__init__(peer)
        self.fast_retries = []

    def input(self, segment, record):
        data = segment['data']
        if data and self.origin is not None and self.stage in ('fast', 'extra'):
            position = (segment['seq'] - self.origin) & MASK
            if position == self.acked and all(self.present[position:position + len(data)]):
                self.fast_retries.append(dict(monotonic_ns=time.monotonic_ns(), offset=position, size=len(data)))
        super().input(segment, record)

    def pump(self):
        if self.stage_at is None or self.done:
            return
        now = time.monotonic()
        elapsed = now - self.stage_at
        if self.stage == 'opening' and elapsed >= .1:
            check(self.prefix >= 2920, 'fast-recovery fixture observes a real opening burst')
            self.snapshot()
            self.acked = 1460
            self.stage, self.stage_at = 'growth', now
            self.send()
        elif self.stage == 'growth' and elapsed >= .1:
            self.snapshot()
            self.stage, self.stage_at = 'fast', now
            for ordinal in range(1, 4):
                self.send()
                self.peer.frames[-1]['duplicate_ack'] = ordinal
        elif self.stage == 'fast' and self.fast_retries and elapsed >= .05:
            self.snapshot()
            self.stage, self.stage_at = 'extra', now
            self.send()
            self.peer.frames[-1]['duplicate_ack'] = 4
        elif self.stage == 'extra' and elapsed >= .05:
            self.snapshot()
            self.acked = self.prefix
            self.stage, self.stage_at = 'recovery', now
            self.send()
        elif self.stage == 'recovery' and elapsed >= .1:
            self.snapshot()
            self.acked, self.window = self.prefix, 1024
            self.stage, self.stage_at = 'receiver', now
            self.send()
        elif self.stage == 'receiver' and elapsed >= .35:
            self.snapshot()
            self.acked, self.window = self.prefix, 65535
            self.stage, self.stage_at = 'complete', now
            self.send()

    def result(self):
        check(self.done and self.received == self.expected and len(self.fast_retries) == 1 and len(self.measurements) == 6,
              'actual duplicate-ACK fast recovery completes one retry, every stage and exact close')
        return dict(done=True, role=0, initial=self.initial, measurements=self.measurements,
                    fast_retries=self.fast_retries, exact_bytes=65536,
                    exact_stream_recovered=True)


class Peer(WindowPeer):
    def __init__(self, lane, minimum_fin_ms=0):
        super().__init__(lane, minimum_fin_ms)
        self.flows = [Flow(self)]
