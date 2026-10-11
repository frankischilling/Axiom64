# SPDX-License-Identifier: GPL-3.0-or-later
"""A controlled DNS server implemented directly over captured Ethernet bytes."""
from collections import Counter
import struct
import time
from dns_peer import check, question, response
from tcp_fault_peer import packet, checksum, MASK, SYN, FIN, RST, ACK
from udp_peer import ipv4, udp


def dns_answer(query, case, address):
    count = 40 if case in ('large', 'split', 'oversized-valid') else 1
    if case.startswith('parallel'):
        address += int(case[8:])
    if case == 'cycle-success':
        address += 64
    poisoned = case not in ('valid', 'large', 'split', 'selection', 'cycle-success', 'casefold', 'oversized-valid') and not case.startswith('parallel')
    addresses = [tuple((0x0a17ff01 + i if poisoned else address + i).to_bytes(4, 'big'))
                 for i in range(count)]
    reply = bytearray(response(query, addresses))
    if case in ('wrong-id', 'wrong-id-valid', 'cycle-failure', 'oversized-wrong-id-valid'):
        reply[1] ^= 1
    if case == 'wrong-name':
        reply[13] ^= 1
    if case == 'wrong-type':
        reply[len(query) - 3] = 28
    if case == 'wrong-class':
        reply[len(query) - 1] = 3
    if case == 'query-bit':
        reply[2] &= ~0x80
    if case == 'opcode':
        reply[2] |= 8
    if case == 'refused':
        reply[3] |= 5
    if case == 'casefold':
        reply[12:len(query)] = reply[12:len(query)].upper()
    if case == 'compression-loop':
        reply[12:len(query)] = b'\xc0\x0c\0\1\0\1'
    if case == 'questionless-negative':
        reply = query[:2] + bytes.fromhex('81830000000000000000')
    if case.startswith('oversized'):
        reply += bytes(4096 - len(reply))
    framed = len(reply).to_bytes(2, 'big') + reply
    if case in ('wrong-id-valid', 'oversized-wrong-id-valid'):
        valid = response(query, (tuple(address.to_bytes(4, 'big')),))
        framed += len(valid).to_bytes(2, 'big') + valid
    if case == 'short-prefix':
        framed = framed[:1]
    if case == 'short-body':
        framed = framed[:15]
    if case == 'short-frame':
        framed = b'\0\x0c' + reply[:12]
    return bytes(framed)


class Flow:
    def __init__(self, peer, segment, ordinal):
        self.peer = peer
        self.port = segment['source']
        self.initial = (0xfffffff0 - ordinal * 4096) & MASK
        self.origin = (self.initial + 1) & MASK
        self.guest_initial = segment['seq']
        self.guest_origin = (segment['seq'] + 1) & MASK
        self.received = bytearray()
        self.sent = bytearray()
        self.acknowledged = 0
        self.pending = []
        self.case = self.query = None
        self.started = self.guest_fin = self.fin_sent = self.fin_acked = self.reset = False
        self.refused = False
        self.events = []

    @property
    def guest_next(self):
        return (self.guest_origin + len(self.received) + int(self.guest_fin)) & MASK

    @property
    def done(self):
        return self.refused or self.reset or self.guest_fin and self.fin_acked

    def send(self, flags=ACK, data=b'', sequence=None):
        if sequence is None:
            sequence = self.origin + len(self.sent) + int(self.fin_sent)
        options = bytes.fromhex('02040218') if flags & SYN else b''
        body = bytearray(struct.pack('!HHIIHHHH', 53, self.port, sequence & MASK,
                                    self.guest_next, ((20 + len(options)) // 4) << 12 | flags,
                                    8192, 0, 0) + options + data)
        body[16:18] = struct.pack('!H', checksum(self.peer.ip + self.peer.guest_ip +
            struct.pack('!BBH', 0, 6, len(body)) + body))
        header = bytearray(struct.pack('!BBHHHBBH4s4s', 0x45, 0, 20 + len(body),
                                       0, 0x4000, 64, 6, 0, self.peer.ip, self.peer.guest_ip))
        header[10:12] = struct.pack('!H', checksum(header))
        self.peer.send((self.peer.guest + self.peer.mac + b'\x08\x00' + header + body).ljust(60, b'\0'))

    def start_answer(self, delay=0):
        check(not self.started and self.case, 'one owned answer schedule')
        self.started = True
        if self.case == 'silent':
            return
        payload = dns_answer(self.query, self.case, 0x0a174001 + (self.peer.lane << 8))
        chunks = ([payload[:1], payload[1:2], payload[2:19], payload[19:401], payload[401:]]
                  if self.case == 'split' else
                  [payload[at:at + 536] for at in range(0, len(payload), 536)])
        # A measured server delay keeps the bounded driver observer below its
        # 32-frame burst capacity while preserving concurrent open queries.
        self.pending = [(time.monotonic() + .025 + delay + (i * .025 if self.case == 'split' else 0), chunk)
                        for i, chunk in enumerate(chunks)]

    def input(self, segment):
        self.events.append(dict(ms=self.peer.ms(), seq=segment['seq'], ack=segment['ack'],
                                flags=segment['flags'], data=segment['data'].hex()))
        flags, data = segment['flags'], segment['data']
        if flags & RST:
            self.reset = True
            self.pending.clear()
            return
        if flags & SYN:
            check(segment['seq'] == self.guest_initial and not data and not flags & (ACK | FIN),
                  'ordinary stable active DNS TCP handshake')
            refused = [row for row in self.peer.transactions if not row['claimed'] and
                       row['name'] == 'connect-refused.tcp.fixture']
            if refused:
                check(len(refused) == 1, 'one serial connection-refusal control')
                refused[0]['claimed'] = True
                self.case = 'connect-refused'
                self.refused = True
                self.send(RST | ACK, sequence=0)
            else:
                self.send(SYN | ACK, sequence=self.initial)
            return
        check(flags & ACK and not self.refused, 'established owned TCP segment')
        acknowledged = (segment['ack'] - self.origin) & MASK
        check(acknowledged <= len(self.sent) + int(self.fin_sent), 'client acknowledges only delivered DNS bytes')
        self.acknowledged = max(self.acknowledged, acknowledged)
        if self.fin_sent and acknowledged == len(self.sent) + 1:
            self.fin_acked = True
        offset = (segment['seq'] - self.guest_origin) & MASK
        if data:
            check(offset <= len(self.received), 'DNS TCP query without a receive hole')
            overlap = min(len(data), len(self.received) - offset)
            check(self.received[offset:offset + overlap] == data[:overlap], 'consistent retransmitted DNS query')
            self.received.extend(data[overlap:])
            self.send()
            if self.query is None and len(self.received) >= 2:
                size = int.from_bytes(self.received[:2], 'big')
                check(17 <= size <= 280 and len(self.received) <= size + 2, 'one bounded framed query')
                if len(self.received) == size + 2:
                    query = bytes(self.received[2:])
                    name = question(query)
                    candidates = [row for row in self.peer.transactions if not row['claimed'] and
                                  row['query'] == query.hex() and row['tc_sent']]
                    check(len(candidates) == 1, 'TCP query exactly owns a previous truncated UDP answer')
                    candidates[0]['claimed'] = True
                    self.query, self.case = query, name.removesuffix('.tcp.fixture')
                    if self.case.startswith('parallel'):
                        self.peer.parallel.append(self)
                        if len(self.peer.parallel) == 8:
                            check({flow.case for flow in self.peer.parallel} ==
                                  {f'parallel{i}' for i in range(8)}, 'all eight independent TCP queries')
                            for i, flow in enumerate(reversed(self.peer.parallel)):
                                flow.start_answer(i * .015)
                    else:
                        self.start_answer()
        if flags & FIN:
            check(offset + len(data) == len(self.received), 'FIN follows the complete owned query')
            self.guest_fin = True
            self.send()

    def tick(self):
        for due, payload in list(self.pending):
            if time.monotonic() >= due:
                self.send(data=payload)
                self.sent.extend(payload)
                self.pending.remove((due, payload))
        if self.case and self.case != 'silent' and self.started and not self.pending and not self.reset:
            if self.acknowledged == len(self.sent) and not self.fin_sent:
                self.send(FIN | ACK)
                self.fin_sent = True
        if self.case == 'silent' and self.guest_fin and not self.fin_sent:
            self.send(FIN | ACK)
            self.fin_sent = True

    def result(self):
        check(self.case and self.done, f'completed/reclaimed DNS TCP flow: {self.case}')
        return dict(port=self.port, case=self.case, query=self.query.hex() if self.query else None,
                    received=self.received.hex(), sent=self.sent.hex(), refused=self.refused,
                    reset=self.reset, guest_fin=self.guest_fin, fin_acked=self.fin_acked,
                    initial=self.initial, guest_initial=self.guest_initial, events=self.events)


class Peer:
    def __init__(self, lane):
        self.lane = lane
        self.guest = bytes([0x52, 0x54, 0, 0x12, 0x34, 0x10 + lane])
        self.mac = bytes([2, 0x41, 0x58, 0x44, 0x4e, lane])
        self.guest_ip, self.ip = bytes([10, 23, lane + 1, 2]), bytes([10, 23, lane + 1, 1])
        self.began = time.monotonic()
        self.output = bytearray()
        self.outgoing, self.frames, self.transactions, self.flows, self.parallel = [], [], [], [], []
        self.ports = {}
        self.pending_tc = []
        self.counts = Counter()
        self.foreign = 0

    def ms(self):
        return (time.monotonic() - self.began) * 1000

    def send(self, frame):
        frame = bytes(frame)
        self.frames.append(dict(direction='reply', ms=self.ms(), frame=frame.hex()))
        self.outgoing.append(frame)

    def receive(self, frame):
        frame = bytes(frame)
        if len(frame) < 34 or frame[6:12] != self.guest:
            self.foreign += 1
            return
        if frame[12:14] == b'\x08\x06':
            arp = frame[14:42]
            if len(arp) == 28 and arp[:8] == bytes.fromhex('0001080006040001') and arp[24:28] == self.ip:
                check(arp[8:14] == self.guest and arp[14:18] == self.guest_ip, 'ARP query from configured DNS interface')
                self.frames.append(dict(direction='query', ms=self.ms(), frame=frame.hex()))
                answer = struct.pack('!HHBBH', 1, 0x800, 6, 4, 2) + self.mac + self.ip + self.guest + self.guest_ip
                self.send((self.guest + self.mac + b'\x08\x06' + answer).ljust(60, b'\0'))
            return
        if frame[12:14] != b'\x08\x00' or frame[26:30] != self.guest_ip:
            self.foreign += 1
            return
        check(frame[:12] == self.mac + self.guest and frame[30:34] == self.ip, 'selected DNS server Ethernet/IP tuple')
        self.frames.append(dict(direction='query', ms=self.ms(), frame=frame.hex()))
        if frame[23] == 17:
            ip = frame[14:]
            size = int.from_bytes(ip[2:4], 'big')
            check(ip[0] == 0x45 and checksum(ip[:20]) == 0 and 28 <= size <= len(ip), 'UDP DNS IPv4 bounds/checksum')
            body = ip[20:size]
            source, target, length, value = struct.unpack('!HHHH', body[:8])
            check(source and target == 53 and length == len(body) and value and
                  checksum(self.guest_ip + self.ip + struct.pack('!BBH', 0, 17, len(body)) + body) == 0,
                  'UDP DNS ports, lengths and pseudoheader checksum')
            query = body[8:]
            name = question(query)
            self.counts[name] += 1
            prior = [row for row in self.transactions if row['source'] == source and row['query'] == query.hex()]
            if prior:
                check(len(prior) == 1, 'one retransmitted UDP query owner')
                row = prior[0]
                row['attempts'].append(self.ms())
            else:
                row = dict(source=source, query=query.hex(), name=name, attempts=[self.ms()],
                           claimed=False, tc_sent=False)
                self.transactions.append(row)
            if name == 'selection.tcp.fixture' and self.lane == 0:
                return
            tc = query[:2] + struct.pack('!HHHHH', 0x8380, 1, 0, 0, 0) + query[12:]
            frame = (self.guest + self.mac + b'\x08\x00' +
                     ipv4(self.ip, self.guest_ip, udp(self.ip, self.guest_ip, 53, source, tc))).ljust(60, b'\0')
            if name.startswith('parallel'):
                # Queries remain concurrent. Stagger server TC arrivals so
                # ordinary handshakes fit the observer's bounded burst queue.
                delay = .025 + int(name[8]) * .015
                self.pending_tc.append((time.monotonic() + delay, frame, row))
            else:
                self.send(frame)
                row['tc_sent'] = True
            return
        check(frame[23] == 6, 'only UDP and TCP in the resolver fixture')
        segment = packet(frame)
        check(segment['target'] == 53, 'TCP fallback uses selected nameserver port 53')
        flow = self.ports.get(segment['source'])
        if segment['flags'] & SYN and (flow is None or flow.done and segment['seq'] != flow.guest_initial):
            flow = Flow(self, segment, len(self.flows))
            self.flows.append(flow)
            self.ports[segment['source']] = flow
        check(flow is not None, 'TCP segment has an observed SYN owner')
        flow.input(segment)

    def tick(self):
        for due, frame, row in list(self.pending_tc):
            if time.monotonic() >= due:
                self.send(frame)
                row['tc_sent'] = True
                self.pending_tc.remove((due, frame, row))
        for flow in self.flows:
            if not flow.done:
                flow.tick()

    def result(self):
        return dict(lane=self.lane, counts=dict(self.counts), transactions=self.transactions,
                    flows=[flow.result() for flow in self.flows], frames=self.frames,
                    foreign=self.foreign)
