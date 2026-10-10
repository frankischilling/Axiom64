# SPDX-License-Identifier: GPL-3.0-or-later
"""Answer a stopped receiver's probes through timeout and disabled-timeout control."""
import re
import time
from tcp_fault_peer import Flow as LossFlow, Peer as LossPeer, ACK, SYN, FIN, RST, MASK, check


class Flow(LossFlow):
    def __init__(self, peer, index):
        self.control, role = divmod(index, 2)
        super().__init__(peer, role)
        self.local_port += self.control * 20
        if self.guest_port is not None:
            self.guest_port += self.control * 20
        self.expected = bytes(((at * 29) ^ (at >> 7) ^ (peer.lane * 53) ^
                               (role * 97) ^ (self.control * 41)) & 255 for at in range(2048))
        self.closed_at = self.reopened_at = None
        self.probe_ms = []
        self.zero_closed = False
        self.application = None
        self.fin_acknowledged = False

    def send(self, flags=ACK, sequence=None, data=b'', window=536):
        super().send(flags, sequence, data, 0 if self.zero_closed else window)

    def input(self, segment, record):
        record['control'] = self.control
        flags, sequence, data = segment['flags'], segment['seq'], segment['data']
        if flags & SYN:
            check(not self.established and not data, 'one timeout fixture handshake')
            self.guest_initial = sequence
            self.guest_origin = (sequence + 1) & MASK
            self.guest_port = segment['source']
            self.handshakes.append(record['ms'])
            if self.role:
                check(flags == SYN | ACK and segment['ack'] == self.origin, 'passive SYN-ACK tuple')
                self.established = True
                self.send()
            else:
                check(flags == SYN, 'active SYN tuple')
                self.send(SYN | ACK, self.initial)
            return
        check(self.guest_origin is not None, 'timeout fixture established tuple')
        if flags & RST:
            check(not self.control and self.closed_at is not None and
                  record['ms'] - self.closed_at >= 2300, 'only configured timeout may reset')
            return
        check(flags & ACK and segment['ack'] in (self.origin, (self.origin + 2) & MASK),
              'timeout fixture peer ACK')
        self.established = True
        if self.zero_closed:
            check(not flags & FIN, 'no FIN accepted through a closed receiver')
            if not data and sequence == self.guest_next:
                self.send()
                return
            check((not data and sequence == (self.guest_next - 1) & MASK) or
                  (len(data) == 1 and sequence == self.guest_next and
                   data == self.expected[len(self.received):len(self.received) + 1]),
                  'actual empty or one-byte timeout probe')
            self.probe_ms.append(record['ms'])
            record['probe'] = len(self.probe_ms)
            self.send()
            return
        if data:
            check(sequence == self.guest_next and len(self.received) + len(data) <= 2048 and
                  data == self.expected[len(self.received):len(self.received) + len(data)],
                  'exact clean timeout fixture payload')
            self.received.extend(data)
            if self.closed_at is None and len(self.received) >= 1072:
                check(len(self.received) == 1072, 'two clean MSS segments precede the closed window')
                self.closed_at = record['ms']
                self.zero_closed = True
            self.send(window=8192 if self.reopened_at is not None else 536)
            if len(self.received) == 2048:
                check(self.control and self.reopened_at is not None, 'only the recovered control delivers all bytes')
                self.send(ACK | FIN, self.origin, b'K', window=8192)
                self.sent, self.fin_sent = 1, True
        if flags & FIN:
            check(self.control and len(self.received) == 2048 and
                  sequence + len(data) & MASK == self.guest_next, 'control FIN follows exact data')
            self.fin_received = True
            self.send(window=8192)
        if self.fin_sent and segment['ack'] == (self.origin + 2) & MASK:
            self.fin_acknowledged = True
        self.done = bool(self.application and (not self.control or
                                              self.fin_received and self.fin_acknowledged))

    def tick(self):
        if self.control and self.zero_closed and self.peer.elapsed() - self.closed_at >= 4000:
            self.zero_closed = False
            self.reopened_at = self.peer.elapsed()
            self.send(window=8192)

    def result(self):
        check(self.done and self.application and self.closed_at is not None and self.probe_ms,
              'actual timeout/control application and packet completion')
        check((not self.control and len(self.received) == 1072 and self.reopened_at is None) or
              (self.control and self.received == self.expected and self.reopened_at - self.closed_at >= 4000),
              'timeout retains undelivered bytes and control fully recovers')
        return dict(role=self.role, control=self.control, closed_at=self.closed_at,
                    probe_ms=self.probe_ms, reopened_at=self.reopened_at,
                    received=len(self.received), application=self.application)


class Peer(LossPeer):
    def __init__(self, lane, minimum_fin_ms=850):
        super().__init__(lane, minimum_fin_ms)
        self.flows = [Flow(self, index) for index in range(4)]

    def elapsed(self):
        return (time.monotonic() - self.began) * 1000

    def tick(self):
        for flow in self.flows:
            flow.tick()

    def line(self, line):
        ready = re.fullmatch(rb'TCP_TIMEOUT_READY lane=(\d) role=1 control=(\d)\r?', line)
        if ready and int(ready[1]) == self.lane:
            self.flows[int(ready[2]) * 2 + 1].start()
        passed = re.fullmatch(rb'TCP_TIMEOUT_FLOW_PASS lane=(\d) role=(\d) control=(\d) '
                             rb'option_ms=(\d+) queued=2048 elapsed_ms=(\d+) error=(\d+) '
                             rb'consumed=(recv|SO_ERROR|none)\r?', line)
        if passed and int(passed[1]) == self.lane:
            role, control = int(passed[2]), int(passed[3])
            flow = self.flows[control * 2 + role]
            check(flow.application is None, 'one actual application completion per timeout tuple')
            flow.application = dict(ms=self.elapsed(), option_ms=int(passed[4]),
                                    elapsed_ms=int(passed[5]), error=int(passed[6]),
                                    consumed=passed[7].decode())
            flow.done = not control or flow.fin_received and flow.fin_acknowledged
