# SPDX-License-Identifier: GPL-3.0-or-later
"""Inject ordinary ICMPv6 errors quoting actual active, passive and data packets."""
import re
import struct
import time
from tcp6.peer import Flow as WireFlow, Peer as EthernetPeer
from tcp_fault_peer import check, SYN, ACK, FIN, RST, MASK

CLASSES = [(1, n) for n in range(7)] + [(1, 99), (3, 0), (3, 1), (4, 0), (4, 1), (4, 2)]
FATAL = {1, 4, 5, 6, 7, 10, 11, 12}
CASES = 62


class Flow(WireFlow):
    def __init__(self, peer, scenario):
        self.peer, self.scenario = peer, scenario
        self.mode, self.kind = divmod(scenario, 13)
        self.role = int(self.mode == 1)
        self.local_port = 44000 + scenario * 20 + peer.lane
        self.guest_port = 45000 + scenario * 20 + peer.lane
        self.ip = peer.ip[:-1] + bytes([10 + scenario])
        self.initial, self.origin = 0xfffffff0, 0xfffffff1
        self.guest_initial = self.guest_origin = None
        self.received = bytearray()
        self.sent = self.acknowledged = 0
        self.fin_sent = self.fin_received = self.done = False
        self.notices, self.resets = [], []
        self.observation = self.injected = self.pending = None
        self.handshake = False
        self.replacement = False
        self.maximum_segment = 1440

    @property
    def guest_next(self):
        return (self.guest_origin + len(self.received) + int(self.fin_received)) & MASK

    def send(self, *args, **kwargs):
        self.peer.ip = self.ip
        super().send(*args, **kwargs)

    def start(self):
        check(self.role and self.guest_origin is None, 'one initial passive error SYN')
        self.send(SYN, sequence=self.initial)

    def notify(self, frame):
        check(not self.notices and self.peer.observe_input is not None, 'one independently observed error')
        quoted = bytearray(frame[14:62])
        type_, code = CLASSES[self.kind] if self.mode != 4 else (1, 4)
        if self.mode == 4:
            if self.kind in (1, 2):
                value = int.from_bytes(quoted[44:48], 'big')
                quoted[44:48] = ((value + (-1 if self.kind == 1 else 2)) & MASK).to_bytes(4, 'big')
            elif self.kind in (3, 4, 5, 6):
                quoted[{3: 9, 4: 25, 5: 40, 6: 42}[self.kind]] ^= 64 if self.kind in (3, 4) else 1
            elif self.kind == 7:
                quoted = quoted[:47]
            elif self.kind == 8:
                quoted[6] = 17
            elif self.kind == 9:
                quoted[0] = 0x50
        body = bytes([type_, code, 0, 0]) + bytes(4) + quoted
        frame = bytearray(self.peer.envelope(self.ip[:-1] + b'\xfa', self.peer.address, body))
        if self.mode == 4 and self.kind == 0:
            frame[56] ^= 1
        self.observation = self.peer.observe_input(bytes(frame))
        self.peer.send(frame)
        self.notices.append(dict(type=type_, code=code, quote=bytes(quoted).hex()))

    def tick(self):
        if self.observation is not None:
            observed = self.observation()
            if observed is None:
                return
            self.injected = observed
            self.observation = None
        if self.injected is None or time.monotonic() - self.injected < .1:
            return
        if self.mode == 0 or self.peer.native and self.scenario == 61:
            self.done = True
        elif self.mode == 1 and self.pending is None:
            self.send()
            self.handshake = self.kind not in FATAL
            self.pending = time.monotonic() + .1
        elif self.mode == 1 and self.kind in FATAL and not self.replacement and time.monotonic() >= self.pending:
            self.replacement = True
            self.local_port += 2
            self.initial, self.origin = 0xffffffe0, 0xffffffe1
            self.guest_initial = self.guest_origin = None
            self.send(SYN, sequence=self.initial)
        elif self.mode == 4 and self.pending is not None and not self.handshake and time.monotonic() >= self.pending:
            self.handshake = True
            self.send(SYN | ACK, sequence=self.initial)

    def input(self, segment, record):
        flags, data = segment['flags'], segment['data']
        frame = bytes.fromhex(record['frame'])
        if flags & RST:
            check(self.role and self.kind in FATAL and not data, 'reset only retires the hard-error request')
            self.resets.append(record['ms'])
            return
        if flags & SYN:
            check(not data and bool(flags & ACK) == bool(self.role) and not flags & FIN,
                  'real error active/passive handshake')
            if self.guest_origin is None:
                self.guest_initial = segment['seq']
                self.guest_origin = (segment['seq'] + 1) & MASK
            check(self.guest_initial == segment['seq'] and (not self.role or segment['ack'] == self.origin),
                  'owned actual error SYN sequence')
            if self.replacement:
                self.send()
                self.handshake = True
            elif self.mode in (0, 1, 4):
                if not self.notices:
                    self.notify(frame)
            else:
                self.handshake = True
                self.send(SYN | ACK, sequence=self.initial)
            return
        check(flags & ACK and self.guest_origin is not None, 'owned error stream ACK')
        acknowledged = (segment['ack'] - self.origin) & MASK
        check(acknowledged <= self.sent + int(self.fin_sent), 'error stream ACK covers actual reply')
        self.acknowledged = max(self.acknowledged, acknowledged)
        if self.fin_sent and self.acknowledged == 2:
            self.done = True
        if data:
            start = (segment['seq'] - self.guest_origin) & MASK
            wanted = b'onetwo' if self.mode in (2, 3) else b'one'
            check(start <= len(self.received) and data == wanted[start:start + len(data)],
                  'exact error-surviving stream bytes')
            self.received.extend(data[max(0, len(self.received) - start):])
            if self.mode in (2, 3) and not self.notices:
                check(self.received == b'one', 'error quotes first outstanding data')
                self.notify(frame)
            if self.received == wanted:
                self.send()
                if not self.sent:
                    self.sent = 1
                    self.send(sequence=self.origin, data=b'K')
        if flags & FIN:
            check(self.received == (b'onetwo' if self.mode in (2, 3) else b'one') and
                  (segment['seq'] + len(data)) & MASK == (self.guest_origin + len(self.received)) & MASK,
                  'FIN follows complete surviving stream')
            self.fin_received = True
            self.send()
            if not self.fin_sent:
                self.fin_sent = True
                self.send(ACK | FIN, sequence=self.origin + self.sent)

    def result(self):
        aborted = self.mode == 0 or self.peer.native and self.scenario == 61
        check(self.done and len(self.notices) == 1 and (aborted or self.fin_received),
              'complete quoted error and surviving or aborted stream')
        return dict(case=self.scenario, mode=self.mode, notices=self.notices,
                    replacement=self.replacement, resets=len(self.resets), done=True)


class Peer(EthernetPeer):
    barrier_protocol = b'\x88\xc3'
    barrier_magic = b'IP6E'

    def __init__(self, lane, minimum_fin_ms=0, native=False):
        super().__init__(lane, minimum_fin_ms, native)
        self.flows = [Flow(self, scenario) for scenario in range(CASES)]
        self.phase, self.boundary = 0, None
        self.observe_input = None

    def tick(self):
        for flow in self.flows:
            flow.tick()
        if self.boundary is None:
            return
        scenario, part = divmod(self.phase - 1, 3)
        flow = self.flows[scenario]
        if part == 1 and (flow.injected is None or time.monotonic() - flow.injected < .1 or
                          flow.mode == 1 and not flow.handshake):
            return
        if part == 2 and not flow.done:
            return
        frame, self.boundary = bytearray(self.boundary), None
        frame[:12] = self.guest + frame[:6]
        frame[20] = 1
        self.send(frame)
        if part == 1 and flow.mode == 4 and not (self.native and scenario == 61):
            flow.pending = time.monotonic() + .15

    def line(self, line):
        match = re.fullmatch(rb'TCP6_ERRORS_LISTEN lane=(\d+) case=(\d+)\r?', line)
        if match and int(match[1]) == self.lane:
            self.flows[int(match[2])].start()

    def receive(self, frame):
        if frame[12:14] == self.barrier_protocol and frame[19] != 0:
            check(len(frame) == 60 and frame[14:19] == self.barrier_magic + bytes([self.lane]) and
                  frame[19] == self.phase + 1 and frame[20:] == bytes(40) and self.boundary is None,
                  'ordered complete error barrier')
            self.phase, self.boundary = frame[19], frame
            self.frames.append(dict(direction='receive', ms=(time.monotonic() - self.began) * 1000, frame=frame.hex()))
            self.tick()
            return
        if len(frame) >= 78 and frame[12:14] == b'\x86\xdd':
            target = frame[38:54] if frame[20] == 6 else frame[62:78] if frame[20] == 58 and frame[54] == 135 else None
            if target in {flow.ip for flow in self.flows}:
                self.ip = target
        # Passive hard errors replace the peer port while preserving the original
        # listener. The base lookup uses that current full flow identity.
        super().receive(frame)
