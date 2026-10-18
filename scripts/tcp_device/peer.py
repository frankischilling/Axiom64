# SPDX-License-Identifier: GPL-3.0-or-later
"""Keep one real TCP tuple pending while another remains active across removal."""
from tcp_fault_peer import Peer as EthernetPeer, Flow as BaseFlow, ACK, FIN, SYN, RST, MASK, check, payload


class Flow(BaseFlow):
    def __init__(self, peer):
        super().__init__(peer, 0)
        self.local_port, self.guest_port = 49600 + peer.lane, 48600 + peer.lane
        self.received = bytearray()
        self.fin_received = self.fin_sent = self.done = False

    def input(self, segment, record):
        flags, data = segment['flags'], segment['data']
        check(not flags & RST, 'the healthy device stream never resets')
        if flags & SYN:
            check(not flags & ACK and not data, 'real active device-comparison handshake')
            if self.guest_initial is None:
                self.guest_initial, self.guest_origin = segment['seq'], (segment['seq'] + 1) & MASK
            check(segment['seq'] == self.guest_initial, 'stable device-comparison sequence')
            self.send(SYN | ACK, self.initial, window=65535)
            return
        check(flags & ACK and self.guest_origin is not None, 'established device-comparison stream')
        acknowledged = (segment['ack'] - self.origin) & MASK
        check(acknowledged <= self.sent + int(self.fin_sent), 'device-comparison ACK owns emitted bytes')
        self.acknowledged = max(self.acknowledged, acknowledged)
        if data:
            offset = (segment['seq'] - self.guest_origin) & MASK
            check(offset <= len(self.received) and offset + len(data) <= len(self.expected) and
                  data == self.expected[offset:offset + len(data)], 'exact independent device-comparison request')
            self.received.extend(data[max(0, len(self.received) - offset):])
            self.send(window=65535)
            if self.sent < len(self.received):
                self.send(data=self.reply[self.sent:len(self.received)], window=65535)
                self.sent = len(self.received)
        if flags & FIN:
            check(self.peer.lane != self.peer.controller.affected and
                  ((segment['seq'] + len(data) - self.guest_origin) & MASK) == len(self.received),
                  'healthy FIN follows the exact surviving stream')
            self.fin_received = True
            self.send(window=65535)
            if not self.fin_sent:
                self.send(FIN | ACK, self.origin + self.sent, window=65535)
                self.fin_sent = True
        if self.fin_sent and acknowledged == self.sent + 1:
            self.done = True

    def gate(self):
        check(len(self.received) == self.sent == 16, 'warm selected tuple precedes the held copy')
        self.send(data=self.reply[16:17], window=65535)
        self.sent = 17

    def result(self):
        failed = self.peer.lane == self.peer.controller.affected
        check(self.done and (len(self.received) == 16 if failed else self.fin_received and self.fin_sent and self.sent >= 112),
              'selected aborted tuple and healthy exact stream complete')
        return dict(done=True, failed=failed, received=len(self.received), sent=self.sent,
                    exact_stream_recovered=True)


class Peer(EthernetPeer):
    def __init__(self, lane, controller):
        super().__init__(lane, 0)
        self.controller = controller
        self.flows = [Flow(self)]

    def line(self, line):
        if self.lane == 0:
            self.controller.line(line)
