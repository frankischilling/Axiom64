# SPDX-License-Identifier: GPL-3.0-or-later
"""Stop an independent receiver, answer persist probes, then reopen its window."""
from tcp_reordering_peer import Flow as ReorderingFlow
from tcp_fault_peer import Peer as LossPeer, ACK, SYN, FIN, RST, MASK, check


class Flow(ReorderingFlow):
    def __init__(self, peer, role):
        super().__init__(peer, role)
        self.zero_closed = False
        self.closed_at = None
        self.probe_ms = []
        self.reopened_at = None

    def send(self, flags=ACK, sequence=None, data=b'', window=8192):
        if self.zero_closed:
            window = 0
        elif self.closed_at is None:
            window = 536
        super().send(flags, sequence, data, window)

    def input(self, segment, record):
        data, sequence, flags = segment['data'], segment['seq'], segment['flags']
        if self.zero_closed:
            check(flags & ACK and not flags & (SYN | FIN | RST), 'closed receiver stays connected')
            check(segment['ack'] == self.origin, 'no reply data before sender finishes')
            if not data and sequence == self.guest_next:
                self.send()
                return
            check((not data and sequence == (self.guest_next - 1) & MASK) or
                  (len(data) == 1 and sequence == self.guest_next and
                   data == self.expected[len(self.received):len(self.received) + 1]),
                  'only actual empty or one-byte probes while window is zero')
            self.probe_ms.append(record['ms'])
            record['probe'] = len(self.probe_ms)
            if len(self.probe_ms) == 3:
                self.zero_closed = False
                self.reopened_at = record['ms']
            self.send()
            return
        if data and self.closed_at is None and self.data_retry_ms is not None:
            # Keep one segment in flight until a clean RTT sample follows the
            # recovered loss. Otherwise native Linux can inherit a long RTO.
            check(len(self.received) == 536 and sequence == self.guest_next and len(data) == 536,
                  'one clean acknowledged segment precedes zero window')
            self.zero_closed = True
            self.closed_at = record['ms']
        super().input(segment, record)

    def result(self):
        result = super().result()
        check(len(self.probe_ms) == 3 and self.reopened_at is not None,
              'three actual persist probes followed by exact recovery')
        previous = [self.closed_at, *self.probe_ms[:-1]]
        intervals = [now - then for then, now in zip(previous, self.probe_ms)]
        check(intervals[0] >= self.peer.minimum_fin_ms and
              all(now + 100 >= then * 1.6 for then, now in zip(intervals, intervals[1:])),
              'actual first persist wait and exponential backoff')
        return dict(result, zero_window=True, closed_at=self.closed_at,
                    probe_ms=self.probe_ms, reopened_at=self.reopened_at,
                    intervals_ms=[round(value, 3) for value in intervals])


class Peer(LossPeer):
    flow_type = Flow
