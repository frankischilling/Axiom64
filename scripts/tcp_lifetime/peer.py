# SPDX-License-Identifier: GPL-3.0-or-later
"""Own independent endpoints throughout real, unshortened default TCP lifetimes."""
import re
import time
from tcp_fault_peer import Flow as BaseFlow, Peer as BasePeer, ACK, SYN, FIN, RST, MASK, check

DEFAULT_MS, LONGER_MS, CASES, RECOVERY_BYTES = 924600, 984600, 6, 2048


class Flow(BaseFlow):
    def __init__(self, peer, index):
        self.kind, role = divmod(index, 2)
        super().__init__(peer, role)
        self.local_port += self.kind * 20
        if self.guest_port is not None:
            self.guest_port += self.kind * 20
        self.expected = bytes(((at * 29) ^ (at >> 7) ^ (peer.lane * 53) ^
                               (role * 97) ^ (self.kind * 41)) & 255 for at in range(RECOVERY_BYTES))
        self.reply = bytes(value ^ 0xa5 for value in self.expected)
        self.attempts = []
        self.reopened_at = self.application = self.started = None
        self.fin_acknowledged = False

    def window_value(self):
        return 0 if self.kind in (2, 3, 5) and self.reopened_at is None else 8192

    def start(self):
        check(self.role and not self.handshakes, 'one actual passive lifetime SYN')
        self.send(SYN, self.initial, window=self.window_value())

    def input(self, segment, record):
        record['kind'] = self.kind
        flags, sequence, data = segment['flags'], segment['seq'], segment['data']
        if flags & SYN:
            check(not data and not self.handshakes and flags == (SYN | ACK if self.role else SYN),
                  'one successful active/passive lifetime handshake')
            self.guest_initial, self.guest_origin = sequence, (sequence + 1) & MASK
            self.guest_port = segment['source']
            self.handshakes.append(record['ms'])
            if self.role:
                check(segment['ack'] == self.origin, 'lifetime SYN-ACK acknowledges owned SYN')
                self.established = True
                self.send(window=self.window_value())
            else:
                self.send(SYN | ACK, self.initial, window=self.window_value())
            return
        check(self.guest_origin is not None and flags & ACK and
              (segment['ack'] - self.origin) & MASK <= self.sent + int(self.fin_sent),
              'lifetime packet belongs to the established peer sequence')
        self.established = True
        if flags & RST:
            minimum = 2300 if self.kind == 5 else (LONGER_MS if self.kind == 4 else DEFAULT_MS - 100)
            check(self.kind != 3 and self.attempts and record['ms'] - self.attempts[0] >= minimum - 1000,
                  'no early reset substitutes for transport expiry')
            return
        if self.kind == 3 and self.reopened_at is not None:
            if data:
                offset = (sequence - self.guest_origin) & MASK
                check(offset <= len(self.received) and offset + len(data) <= RECOVERY_BYTES and
                      data == self.expected[offset:offset + len(data)], 'exact recovered lifetime bytes')
                self.received.extend(data[max(0, len(self.received) - offset):])
                self.send(window=8192)
                if len(self.received) == RECOVERY_BYTES and not self.fin_sent:
                    for at in range(0, RECOVERY_BYTES, 536):
                        block = self.reply[at:at + 536]
                        self.send(ACK | (FIN if at + len(block) == RECOVERY_BYTES else 0),
                                  self.origin + at, block, window=8192)
                    self.sent, self.fin_sent = RECOVERY_BYTES, True
            if flags & FIN:
                check(len(self.received) == RECOVERY_BYTES and
                      (sequence + len(data)) & MASK == (self.guest_origin + RECOVERY_BYTES) & MASK,
                      'recovered FIN follows all owned bytes')
                self.fin_received = True
                self.send(window=8192)
            if self.fin_sent and segment['ack'] == (self.origin + RECOVERY_BYTES + 1) & MASK:
                self.fin_acknowledged = True
            self.done = bool(self.application and self.fin_received and self.fin_acknowledged)
            return
        if self.kind in (0, 4):
            if not data:
                check(flags == ACK and sequence == self.guest_origin, 'ordinary lifetime synchronization ACK')
                return
            check(data == self.expected[:1] and sequence == self.guest_origin and not flags & FIN,
                  'only the original unanswered byte is retransmitted')
        elif self.kind == 1:
            check(not data and sequence in (self.guest_origin, (self.guest_origin + 1) & MASK),
                  'only pure FIN sequence is outstanding')
            if not flags & FIN:
                return
            check(sequence == self.guest_origin, 'pure FIN keeps its original sequence')
        else:
            check(not flags & FIN, 'closed-window probe does not deliver a FIN')
            if not data and sequence == self.guest_origin:
                return
            check((not data and sequence == (self.guest_origin - 1) & MASK) or
                  (self.kind != 5 and data == self.expected[:1] and sequence == self.guest_origin),
                  'actual empty/native or one-byte/guest unanswered probe')
        self.attempts.append(record['ms'])
        record['attempt'] = len(self.attempts)
        if self.kind == 3:
            self.send(window=0)  # Responsive but deliberately no delivery progress.
        # Every other case receives no post-handshake acknowledgment or window event.

    def tick(self):
        if (self.kind == 3 and self.attempts and self.reopened_at is None and
                self.peer.elapsed() - self.attempts[0] >= LONGER_MS):
            self.reopened_at = self.peer.elapsed()
            self.send(window=8192)

    def result(self):
        check(self.done and self.application and self.started and self.attempts,
              'complete real lifetime application and packet observation')
        check(self.kind != 3 or (self.received == self.expected and self.fin_received and
                                self.fin_acknowledged and self.reopened_at - self.attempts[0] >= LONGER_MS),
              'responsive default persists beyond its complete deadline and recovers exactly')
        return dict(role=self.role, kind=self.kind, attempts_ms=self.attempts, reopened_at=self.reopened_at,
                    received=len(self.received), sent=self.sent, started=self.started,
                    application=self.application, passed=True)


class Peer(BasePeer):
    def __init__(self, lane, minimum_fin_ms=850):
        super().__init__(lane, minimum_fin_ms)
        self.flows = [Flow(self, index) for index in range(CASES * 2)]

    def elapsed(self):
        return (time.monotonic() - self.began) * 1000

    def tick(self):
        for flow in self.flows:
            flow.tick()

    def line(self, line):
        ready = re.fullmatch(rb'TCP_LIFETIME_READY lane=(\d) role=1 kind=(\d)\r?', line)
        if ready and int(ready[1]) == self.lane:
            self.flows[int(ready[2]) * 2 + 1].start()
        started = re.fullmatch(rb'TCP_LIFETIME_STARTED lane=(\d) role=(\d) kind=(\d) option_ms=(\d+)\r?', line)
        if started and int(started[1]) == self.lane:
            flow = self.flows[int(started[3]) * 2 + int(started[2])]
            check(flow.started is None, 'one actual lifetime application start')
            flow.started = dict(ms=self.elapsed(), option_ms=int(started[4]))
        passed = re.fullmatch(rb'TCP_LIFETIME_FLOW_PASS lane=(\d) role=(\d) kind=(\d) option_ms=(\d+) '
                             rb'elapsed_ms=(\d+) error=(\d+) consumed=(recv|SO_ERROR|none) reclaimed=(\d+)\r?', line)
        if passed and int(passed[1]) == self.lane:
            role, kind = int(passed[2]), int(passed[3])
            flow = self.flows[kind * 2 + role]
            check(flow.application is None, 'one actual lifetime application completion')
            flow.application = dict(ms=self.elapsed(), option_ms=int(passed[4]), elapsed_ms=int(passed[5]),
                                    error=int(passed[6]), consumed=passed[7].decode(), reclaimed=int(passed[8]))
            flow.done = kind != 3 or flow.fin_received and flow.fin_acknowledged
