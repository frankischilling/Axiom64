# SPDX-License-Identifier: GPL-3.0-or-later
"""Quote real TCP transmissions in independently constructed ICMP frames."""
import re
import struct
import time
from fetch import ROOT
from tcp_fault_peer import Peer as EthernetPeer, packet, checksum, MASK, SYN, ACK, FIN, RST, check

CASE_SOURCE = ROOT / 'userspace/tests/net/tcp_icmp_cases.h'
CASES = [dict(name=name, type=int(kind), code=int(code), mutation=mutation, mode=mode,
              error=int(error)) for name, kind, code, mutation, mode, error in re.findall(
    r'\{"([a-z-]+)",\s*(\d+),\s*(\d+),\s*"([a-z-]+)",\s*ICMP_([A-Z_]+),\s*(\d+)\}',
    CASE_SOURCE.read_text())]
check(len(CASES) == 57, 'complete literal ICMP acceptance contract')


def ip(source, destination, protocol, payload):
    header = bytearray(struct.pack('!BBHHHBBH4s4s', 0x45, 0, 20 + len(payload), 1, 0,
                                   64, protocol, 0, source, destination))
    header[10:12] = checksum(header).to_bytes(2, 'big')
    return bytes(header) + payload


class Flow:
    def __init__(self, peer, ordinal, port, guest_port, generation=0, cycle=None):
        self.peer, self.ordinal, self.port, self.guest_port = peer, ordinal, port, guest_port
        self.generation, self.cycle = generation, cycle
        self.case = CASES[ordinal] if cycle is None else dict(name='cycle', type=3, code=3,
                                                            mutation='valid', mode='PENDING')
        self.passive = self.case['mode'].startswith('PASSIVE')
        self.done = self.quoted = self.established = self.finished = False
        self.initial = (MASK - 2 - ordinal * 4096 - generation * 128) & MASK
        self.next = self.initial if self.passive else (self.initial + 1) & MASK
        self.guest_initial = self.guest_next = None
        self.data = b''
        self.syn_frame = None
        self.events = []

    def send(self, flags=ACK, data=b'', sequence=None, acknowledgment=None):
        sequence = self.next if sequence is None else sequence
        acknowledgment = self.guest_next if acknowledgment is None else acknowledgment
        options = bytes.fromhex('02040218') if flags & SYN else b''
        body = bytearray(struct.pack('!HHIIHHHH', self.port, self.guest_port, sequence & MASK,
                                    (acknowledgment or 0) & MASK,
                                    ((20 + len(options)) // 4) << 12 | flags, 8192, 0, 0) + options + data)
        body[16:18] = checksum(self.peer.ip + self.peer.address +
                              struct.pack('!BBH', 0, 6, len(body)) + body).to_bytes(2, 'big')
        self.peer.send(self.peer.guest + self.peer.mac + b'\x08\x00' + ip(self.peer.ip, self.peer.address, 6, body))
        self.peer.frames[-1].update(case=self.ordinal, generation=self.generation, cycle=self.cycle)

    def later(self, delay, function):
        self.peer.pending.append((time.monotonic() + delay, self, function))

    def quote(self, frame, override=None):
        case = override or self.case
        quote = bytearray(frame[14:42])
        mutation = case['mutation']
        if mutation == 'options':
            quote[0] = 0x46
            quote[2:4] = (int.from_bytes(quote[2:4], 'big') + 4).to_bytes(2, 'big')
            quote[20:20] = bytes([1, 1, 0, 0])
        if mutation == 'short-original': quote[2:4] = (28).to_bytes(2, 'big')
        if mutation == 'version': quote[0] = 0x65
        if mutation == 'ihl': quote[0] = 0x44
        if mutation in ('fragment', 'more-fragments', 'reserved'):
            quote[6:8] = {'fragment': b'\0\1', 'more-fragments': b'\x20\0', 'reserved': b'\x80\0'}[mutation]
        if mutation == 'protocol': quote[9] = 17
        if mutation == 'local': quote[15] ^= 64
        if mutation == 'peer': quote[19] ^= 64
        if mutation == 'source-port': quote[21] ^= 1
        if mutation == 'target-port': quote[23] ^= 1
        if mutation in ('old-sequence', 'future-sequence', 'upper-edge', 'half-range'):
            sequence = int.from_bytes(quote[24:28], 'big')
            change = {'old-sequence': -1, 'future-sequence': 2, 'upper-edge': 1, 'half-range': 0x80000000}[mutation]
            quote[24:28] = ((sequence + change) & MASK).to_bytes(4, 'big')
        header = 24 if mutation == 'options' else 20
        quote[10:12] = bytes(2)
        quote[10:12] = checksum(quote[:header]).to_bytes(2, 'big')
        if mutation == 'quote-checksum': quote[10] ^= 1
        if mutation == 'truncated': quote = quote[:-1]
        body = bytearray(bytes([case['type'], case['code'], 0, 0, 0, 0, 4, 0]) + quote)
        body[2:4] = checksum(bytes(body)).to_bytes(2, 'big')
        if mutation == 'icmp-checksum': body[2] ^= 1
        delivery = self.peer.others[1 - self.peer.lane] if mutation.startswith('other-') else self.peer
        delivery.send(delivery.guest + delivery.mac + b'\x08\x00' + ip(delivery.ip, self.peer.address, 1, body))
        delivery.frames[-1].update(case=self.ordinal, owner_lane=self.peer.lane,
                                   generation=self.generation, cycle=self.cycle, mutation=mutation)
        self.events.append(dict(event='icmp', ms=self.peer.ms(), type=case['type'], code=case['code'],
                                mutation=mutation, receiving_lane=delivery.lane))

    def synack(self):
        self.send(SYN | ACK, sequence=self.initial)

    def start(self):
        check(self.passive, 'peer initiates only a passive-open case')
        self.send(SYN, sequence=self.initial, acknowledgment=0)

    def input(self, segment, frame):
        flags = segment['flags']
        if flags & RST:
            self.events.append(dict(event='reset', ms=self.peer.ms()))
            return
        if flags & SYN:
            if self.passive:
                check(flags & ACK and segment['ack'] == (self.initial + 1) & MASK,
                      'real passive SYN-ACK owns the independent peer SYN')
                self.guest_initial = segment['seq']
                self.guest_next = (segment['seq'] + 1) & MASK
                self.next = (self.initial + 1) & MASK
                if self.generation:
                    self.send()
                    self.established = True
                elif not self.quoted:
                    self.quoted = True
                    self.later(.025, lambda: self.quote(frame))
                    self.later(.2, self.send)
                    if self.case['mode'] == 'PASSIVE_DROP':
                        self.later(.3, lambda: self.peer.replace(self))
                return
            self.guest_initial = segment['seq']
            self.guest_next = (segment['seq'] + 1) & MASK
            if self.quoted:
                return
            self.quoted = True
            self.syn_frame = bytes(frame)
            if self.cycle is not None:
                previous = [flow for flow in self.peer.flows if flow is not self and flow.cycle is not None]
                if previous:
                    stale = previous[-1].syn_frame
                    check(stale is not None and stale[34:38] == frame[34:38] and
                          stale[38:42] != frame[38:42], 'same tuple has a fresh sequence owner')
                    self.later(.025, lambda: self.quote(stale))
                self.later(.15, lambda: self.quote(frame))
                return
            if self.generation or self.case['mode'] in ('SOFT', 'RECOVER', 'CONSUME', 'TIME_WAIT'):
                self.synack()
            else:
                self.later(.35 if self.case['mutation'] == 'delayed' else .025, lambda: self.quote(frame))
                if self.case['mode'] == 'IGNORE': self.later(.4, self.synack)
            return
        if not self.established and flags & ACK:
            self.established = True
        data = segment['data']
        if data and self.case['mode'] in ('SOFT', 'RECOVER', 'CONSUME'):
            if self.data:
                if data == b'two' and self.case['mode'] == 'RECOVER':
                    self.events.append(dict(event='unacknowledged-second', ms=self.peer.ms()))
                return
            check(data == b'one' and segment['seq'] == self.guest_next,
                  'actual owned outstanding application bytes')
            self.data = data
            self.later(.025, lambda: self.quote(frame))
            if self.case['mutation'] == 'last-error':
                self.later(.08, lambda: self.quote(frame, dict(type=12, code=0, mutation='valid')))
            if self.case['mode'] == 'RECOVER':
                def recover():
                    self.guest_next = (self.guest_next + 3) & MASK
                    self.send(data=b'K')
                    self.next = (self.next + 1) & MASK
                    self.events.append(dict(event='progress', ms=self.peer.ms()))
                self.later(.5, recover)
            return
        if data:
            self.guest_next = (segment['seq'] + len(data)) & MASK
            self.send()
        if flags & FIN:
            self.guest_next = (segment['seq'] + len(data) + 1) & MASK
            self.send()
            if not self.finished:
                self.send(ACK | FIN)
                self.next = (self.next + 1) & MASK
                self.finished = True
                if self.case['mode'] == 'TIME_WAIT':
                    self.later(.15, lambda: self.quote(frame))

    def result(self):
        check(self.done, 'every observed TCP generation completes its actual client case')
        return dict(case=self.ordinal, cycle=self.cycle, generation=self.generation,
                    guest_port=self.guest_port, peer_port=self.port, initial=self.guest_initial,
                    events=self.events, passed=True)


class Companion(Flow):
    def __init__(self, peer, port, guest_port, role):
        super().__init__(peer, -1, port, guest_port)
        self.role, self.checkpoints = role, 0
        self.case = dict(mode='COMPANION')
        self.passive = role == 1
        self.initial = MASK - 2
        self.next = self.initial if self.passive else (self.initial + 1) & MASK

    def input(self, segment, frame):
        flags = segment['flags']
        if flags & SYN:
            self.guest_initial = segment['seq']
            self.guest_next = (segment['seq'] + 1) & MASK
            if self.passive:
                check(flags == SYN | ACK and segment['ack'] == (self.initial + 1) & MASK,
                      'unrelated accepted stream acknowledges its real peer SYN')
                self.next = (self.initial + 1) & MASK
                self.send()
            else:
                self.synack()
            return
        if segment['data']:
            check(segment['data'] == b'S' and segment['seq'] == self.guest_next,
                  'unrelated connection keeps exact application-byte ownership')
            self.guest_next = (self.guest_next + 1) & MASK
            self.send(data=b'Q')
            self.next = (self.next + 1) & MASK
            self.checkpoints += 1
            return
        if flags & FIN:
            self.guest_next = (segment['seq'] + 1) & MASK
            self.send(ACK | FIN)
            self.next = (self.next + 1) & MASK

    def result(self):
        check(self.done and self.checkpoints == len(CASES) + 10,
              'unrelated active and accepted streams stay usable through all errors and reclamation')
        return dict(companion=True, role=self.role, checkpoints=self.checkpoints, passed=True)


class Peer(EthernetPeer):
    def __init__(self, lane, minimum_fin_ms=0):
        super().__init__(lane, minimum_fin_ms)
        self.flows, self.pending, self.completed, self.cycles, self.others = [], [], set(), set(), None

    def ms(self):
        return (time.monotonic() - self.began) * 1000

    def bind_peers(self, peers):
        self.others = peers

    def replace(self, flow):
        replacement = Flow(self, flow.ordinal, flow.port + 1, flow.guest_port, 1)
        self.flows.append(replacement)
        replacement.start()

    def line(self, line):
        companion = re.search(rb'ICMP_COMPANION_LISTEN_READY lane=(\d+)', line)
        if companion and int(companion[1]) == self.lane:
            flow = Companion(self, 57000 + self.lane * 1000, 39000 + self.lane * 1000, 1)
            self.flows.append(flow)
            flow.start()
        companion = re.search(rb'ICMP_COMPANION_PASS lane=(\d+) role=(\d+) checkpoints=(\d+)', line)
        if companion and int(companion[1]) == self.lane:
            flow = next(flow for flow in self.flows if isinstance(flow, Companion) and flow.role == int(companion[2]))
            check(int(companion[3]) == flow.checkpoints == len(CASES) + 10, 'actual unaffected companion completion')
            flow.done = True
        ready = re.search(rb'ICMP_LISTEN_READY lane=(\d+) case=(\d+)', line)
        if ready and int(ready[1]) == self.lane:
            ordinal = int(ready[2])
            flow = Flow(self, ordinal, 56000 + self.lane * 1000 + ordinal * 2,
                        40000 + self.lane * 1000 + ordinal)
            self.flows.append(flow)
            flow.start()
        passed = re.search(rb'ICMP_CASE_PASS lane=(\d+) case=(\d+)', line)
        if passed and int(passed[1]) == self.lane:
            ordinal = int(passed[2])
            check(ordinal not in self.completed, 'one actual pass per socket case')
            self.completed.add(ordinal)
            for flow in self.flows:
                if flow.ordinal == ordinal and flow.cycle is None: flow.done = True
        cycle = re.search(rb'ICMP_CYCLE_PASS cycle=(\d+) lane=(\d+)', line)
        if cycle and int(cycle[2]) == self.lane:
            number = int(cycle[1])
            check(number not in self.cycles, 'one actual descriptor reclamation per cycle')
            self.cycles.add(number)
            for flow in self.flows:
                if flow.cycle == number: flow.done = True

    def receive(self, frame):
        if frame[12:14] == b'\x08\x06':
            return super().receive(frame)
        self.frames.append(dict(direction='receive', ms=self.ms(), frame=bytes(frame).hex()))
        if len(frame) < 54 or frame[12:14] != b'\x08\x00' or frame[23] != 6:
            return
        segment = packet(frame)
        check(frame[:6] == self.mac and frame[6:12] == self.guest and
              segment['source_ip'] == self.address and segment['target_ip'] == self.ip,
              'real configured TCP addresses and independently verified packet checksums')
        flow = next((flow for flow in reversed(self.flows)
                     if flow.port == segment['target'] and flow.guest_port == segment['source']), None)
        if segment['flags'] == SYN:
            if segment['target'] == 47000 + self.lane * 1000:
                if flow is None:
                    flow = Companion(self, segment['target'], segment['source'], 0)
                    self.flows.append(flow)
                flow.input(segment, frame)
                return
            ordinal = segment['target'] - (48000 + self.lane * 1000)
            cycle_port = 49000 + self.lane * 1000
            if not 0 <= ordinal < len(CASES):
                check(segment['target'] == cycle_port, 'owned descriptor-cycle destination')
                if flow is not None and flow.guest_initial == segment['seq']:
                    cycle = flow.cycle
                else:
                    cycle = 2 * sum(row.cycle is not None for row in self.flows) + self.lane
                check(cycle < 128, 'bounded same-tuple descriptor generations')
                ordinal = 0
            else:
                cycle = None
            if flow is None or flow.guest_initial != segment['seq']:
                generation = sum(row.ordinal == ordinal and row.cycle == cycle for row in self.flows)
                flow = Flow(self, ordinal, segment['target'], segment['source'], generation, cycle)
                self.flows.append(flow)
        check(flow is not None, 'each TCP segment has an independently observed connection owner')
        self.frames[-1].update(case=flow.ordinal, generation=flow.generation, cycle=flow.cycle)
        flow.input(segment, frame)

    def tick(self):
        for due, flow, function in list(self.pending):
            if time.monotonic() >= due:
                if not flow.done: function()
                self.pending.remove((due, flow, function))

    def result(self):
        check(self.completed == set(range(len(CASES))) and self.cycles == set(range(self.lane, 128, 2)),
              'all socket cases and descriptor cycles actually complete on each NIC')
        return dict(lane=self.lane, cases=len(self.completed), cycles=len(self.cycles),
                    flows=[flow.result() for flow in self.flows], frames=self.frames)
