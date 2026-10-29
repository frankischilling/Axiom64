# SPDX-License-Identifier: GPL-3.0-or-later
"""Quote actual TCP6 transmissions and retain invalid-hint observations."""
import re
import struct
import time
from tcp6.peer import Flow as WireFlow, Peer as EthernetPeer
from tcp_fault_peer import check, SYN, ACK, FIN, RST, MASK

SIZE = 4096
CASES = 22


def pattern(lane, scenario, direction):
    return bytes(((n * 29) ^ (n >> 7) ^ (lane * 53) ^ (scenario * 97) ^ (direction * 41)) & 255
                 for n in range(SIZE))


class Flow(WireFlow):
    def __init__(self, peer, scenario):
        self.peer, self.scenario = peer, scenario
        self.role = int(scenario in (1, 3, 5))
        self.local_port = 44000 + scenario * 20 + peer.lane
        self.guest_port = 45000 + scenario * 20 + peer.lane if self.role else None
        self.ip = peer.ip[:-1] + bytes([10 + scenario])
        self.initial, self.origin = 0xfffffff0, 0xfffffff1
        self.guest_origin = None
        self.maximum_segment = {4: 536, 5: 536, 6: 1200, 7: 1220, 8: 1280}.get(scenario, 1440)
        self.received = bytearray(SIZE)
        self.seen = bytearray(SIZE)
        self.prefix = self.sent = self.acknowledged = 0
        self.fin_received = self.fin_sent = self.done = False
        self.observation = self.last_injected = None
        self.pending_valid = self.handshake_pending = None
        self.small_pending = []
        self.small_released = False
        self.first = None
        self.window = 8192
        self.notices = []
        self.next_reduction = None
        self.idle_quoted = False

    @property
    def guest_next(self):
        return (self.guest_origin + self.prefix + int(self.fin_received)) & MASK

    def send(self, *args, **kwargs):
        self.peer.ip = self.ip
        super().send(*args, **kwargs)

    def start(self):
        check(self.role and self.guest_origin is None, 'one passive PMTU SYN')
        self.send(SYN, sequence=self.initial)

    def notify(self, frame, mtu, damaged=False):
        check(self.observation is None and self.peer.observe_input is not None,
              'one independently observed PTB at a time')
        quoted = bytearray(frame[14:62])
        scenario = self.scenario
        if damaged:
            if scenario == 11:
                quoted[44:48] = ((self.guest_origin - 1) & MASK).to_bytes(4, 'big')
            elif scenario == 12:
                quoted[44:48] = ((self.guest_origin + SIZE + 1) & MASK).to_bytes(4, 'big')
            elif scenario == 13:
                quoted[9] ^= 64
            elif scenario == 14:
                quoted[25] ^= 64
            elif scenario in (15, 16):
                quoted[40 if scenario == 15 else 42] ^= 1
            elif scenario == 17:
                mtu = 1279
            elif scenario == 18:
                quoted = quoted[:47]
            elif scenario == 19:
                quoted[6] = 17
        router = self.ip[:-1] + b'\xfa'
        body = b'\2\0\0\0' + struct.pack('!I', mtu) + quoted
        packet = bytearray(self.peer.envelope(router, self.peer.address, body))
        if damaged and scenario == 10:
            packet[56] ^= 1
        self.observation = self.peer.observe_input(bytes(packet))
        self.peer.send(packet)
        self.notices.append(dict(mtu=mtu, damaged=damaged, quote=bytes(quoted).hex()))

    def tick(self):
        if self.observation is not None:
            observed = self.observation()
            if observed is None:
                return
            self.last_injected = observed
            self.notices[-1]['observed_monotonic_seconds'] = observed
            self.observation = None
        # Two fifty-ms budgets retain a full fifty-ms lower bound even when
        # the independent monitor's arrival bracket is at its maximum width.
        quiet = self.last_injected is not None and time.monotonic() - self.last_injected >= .1
        if self.pending_valid is not None and quiet:
            original, self.pending_valid = self.pending_valid, None
            self.notify(original, 1280)
            return
        if self.handshake_pending is not None and quiet:
            self.handshake_pending = None
            if self.role:
                self.send()
            else:
                self.send(SYN | ACK, sequence=self.initial)
        if self.small_pending and quiet:
            queued, self.small_pending = self.small_pending, []
            self.small_released = True
            for segment in queued:
                self.accept(segment)
        if self.next_reduction is not None and self.observation is None:
            original, self.next_reduction = self.next_reduction, None
            self.notify(original, 1280)

    def accept(self, segment):
        data, sequence, flags = segment['data'], segment['seq'], segment['flags']
        if data:
            start = (sequence - self.guest_origin) & MASK
            check(start + len(data) <= SIZE and data == pattern(self.peer.lane, self.scenario, 0)[start:start + len(data)],
                  'exact PMTU guest sequence and copied bytes')
            self.received[start:start + len(data)] = data
            self.seen[start:start + len(data)] = b'\1' * len(data)
            while self.prefix < SIZE and self.seen[self.prefix]:
                self.prefix += 1
        if flags & FIN:
            check(self.prefix == SIZE and ((sequence + len(data) - self.guest_origin) & MASK) == SIZE,
                  'PMTU FIN follows all recovered bytes')
            self.fin_received = True
        if data or flags & FIN:
            self.send()
        self.pump()

    def pump(self):
        if self.prefix != SIZE:
            return
        reply = pattern(self.peer.lane, self.scenario, 1)
        while self.sent < SIZE and self.sent < self.acknowledged + min(self.window, 8192):
            count = min(536, SIZE - self.sent, self.acknowledged + min(self.window, 8192) - self.sent)
            self.send(data=reply[self.sent:self.sent + count], sequence=self.origin + self.sent)
            self.sent += count
        if self.fin_received and self.acknowledged == SIZE and not self.fin_sent:
            self.send(ACK | FIN, sequence=self.origin + SIZE)
            self.fin_sent = True

    def input(self, segment, record):
        flags, data = segment['flags'], segment['data']
        check(not flags & RST, 'PMTU does not reset the stream')
        frame = bytes.fromhex(record['frame'])
        if flags & SYN:
            check(not data and bool(flags & ACK) == bool(self.role), 'owned PMTU handshake')
            self.guest_port = segment['source']
            origin = (segment['seq'] + 1) & MASK
            check(self.guest_origin is None or self.guest_origin == origin, 'stable PMTU ISN')
            self.guest_origin = origin
            if self.scenario in (2, 3) and not self.notices:
                self.notify(frame, 1280)
                self.handshake_pending = True
            elif self.role:
                self.send()
            else:
                self.send(SYN | ACK, sequence=self.initial)
            return
        check(flags & ACK and self.guest_origin is not None, 'established PMTU stream')
        self.window = segment['window']
        acknowledged = (segment['ack'] - self.origin) & MASK
        check(acknowledged <= self.sent + int(self.fin_sent), 'ACK covers only transmitted reply')
        self.acknowledged = max(self.acknowledged, min(acknowledged, SIZE))
        if self.fin_sent and acknowledged == SIZE + 1:
            self.done = True
        if self.scenario in (20, 21) or self.scenario == 9 and len(self.notices) >= 2:
            if self.acknowledged == SIZE and not self.idle_quoted and not data and not flags & FIN:
                self.idle_quoted = True
                self.notify(self.first if self.scenario == 20 else frame, 1500 if self.scenario == 9 else 1280)
        if data:
            if self.first is None:
                self.first = frame
            if self.scenario in (4, 5, 6, 7) and not self.small_released:
                if not self.notices:
                    self.notify(frame, 1280)
                self.small_pending.append(segment)
                return
            if self.scenario not in (2, 3, 20, 21):
                mtu = 1400 if self.scenario == 9 and not self.notices else 1280
                if len(frame) - 14 > mtu:
                    if not self.notices:
                        self.notify(frame, mtu, damaged=self.scenario >= 10)
                        if self.scenario >= 10:
                            self.pending_valid = frame
                    elif self.scenario == 9 and len(self.notices) == 1:
                        self.next_reduction = frame
                    return
        self.accept(segment)

    def result(self):
        check(self.done and self.prefix == SIZE and self.acknowledged == SIZE and self.notices,
              'complete exact PMTU stream and observed quoted notification')
        return dict(case=self.scenario, role=self.role, done=self.done, notices=self.notices,
                    received=self.prefix, reply_acked=self.acknowledged)


class Peer(EthernetPeer):
    barrier_protocol = b'\x88\xc2'
    barrier_magic = b'IP6M'

    def __init__(self, lane, minimum_fin_ms=0, native=False):
        super().__init__(lane, minimum_fin_ms, native)
        self.flows = [Flow(self, scenario) for scenario in range(CASES)]
        self.phase, self.boundary = 0, None
        self.observe_input = None

    def reply(self, frame):
        answer = bytearray(frame)
        answer[:12] = self.guest + frame[:6]
        answer[20] = 1
        self.send(answer)

    def tick(self):
        for flow in self.flows:
            flow.tick()
        if self.boundary is not None:
            scenario, part = (self.phase - 1) // 3, (self.phase - 1) % 3
            flow = self.flows[scenario]
            if part == 1 and (flow.acknowledged != SIZE or flow.observation is not None or
                flow.last_injected is None or time.monotonic() - flow.last_injected < .05):
                return
            if part == 2 and not flow.done:
                return
            frame, self.boundary = self.boundary, None
            self.reply(frame)

    def line(self, line):
        match = re.fullmatch(rb'TCP6_PMTU_LISTEN lane=(\d+) case=(\d+)\r?', line)
        if match and int(match[1]) == self.lane:
            self.flows[int(match[2])].start()

    def receive(self, frame):
        if frame[12:14] == self.barrier_protocol and frame[19] != 0:
            check(len(frame) == 60 and frame[14:19] == self.barrier_magic + bytes([self.lane]) and
                  frame[19] == self.phase + 1 and frame[20:] == bytes(40) and self.boundary is None,
                  'ordered complete PMTU barrier')
            self.phase = frame[19]
            self.boundary = frame
            self.frames.append(dict(direction='receive', ms=(time.monotonic() - self.began) * 1000, frame=frame.hex()))
            self.tick()
            return
        if len(frame) >= 78 and frame[12:14] == b'\x86\xdd':
            target = frame[38:54] if frame[20] == 6 else frame[62:78] if frame[20] == 58 and frame[54] == 135 else None
            if target in {flow.ip for flow in self.flows}:
                self.ip = target
        super().receive(frame)
