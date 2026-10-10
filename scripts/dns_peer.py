# SPDX-License-Identifier: GPL-3.0-or-later
"""Controlled DNS answers and independent Ethernet/IP/UDP query validation."""
from collections import Counter
import struct
import time
from udp_peer import checksum, ipv4, udp


def check(condition, message):
    if not condition:
        raise RuntimeError(message)


def encode_name(name):
    labels = name.split('.')
    check(all(0 < len(label) <= 63 for label in labels), 'bounded DNS labels')
    return b''.join(bytes([len(label)]) + label.encode('ascii') for label in labels) + b'\0'


def question(data):
    check(len(data) >= 17, 'complete DNS query header and question')
    _, flags, questions, answers, authority, additional = struct.unpack('!6H', data[:12])
    check((flags, questions, answers, authority, additional) == (0x100, 1, 0, 0, 0),
          'ordinary recursive A query')
    at, labels = 12, []
    while at < len(data) and data[at]:
        length = data[at]
        at += 1
        check(0 < length <= 63 and at + length < len(data), 'uncompressed bounded query label')
        labels.append(data[at:at + length].decode('ascii'))
        at += length
    check(labels and at + 5 == len(data) and data[at:] == b'\0\0\1\0\1',
          'one complete IN A question without trailing bytes')
    return '.'.join(labels)


def response(query, addresses=(), rcode=0, canonical=None):
    question(query)
    answer = bytearray(query)
    struct.pack_into('!H', answer, 2, 0x8180 | rcode)
    struct.pack_into('!H', answer, 6, len(addresses) + bool(canonical))
    owner = b'\xc0\x0c'
    if canonical:
        encoded = encode_name(canonical)
        position = len(answer) + 12
        answer += owner + struct.pack('!HHIH', 5, 1, 30, len(encoded)) + encoded
        owner = struct.pack('!H', 0xc000 | position)
    for address in addresses:
        answer += owner + struct.pack('!HHIH', 1, 1, 30, 4) + bytes(address)
    return bytes(answer)


class Answers:
    cold_wire_retry = False

    def __init__(self, lane):
        self.lane = lane
        self.counts = Counter()
        self.transactions = {}
        self.original_queries = {}
        self.queries, self.replies = [], []
        self.pending = []

    def receive(self, data, sender):
        name = question(data)
        self.counts[name] += 1
        key = (sender, data[:2], name)
        now = time.monotonic()
        previous = self.transactions.setdefault(key, [])
        check(self.original_queries.setdefault(key, data) == data, 'identical bytes across retransmissions')
        previous.append(now)
        self.queries.append(dict(name=name, query=data.hex(), sender=list(sender),
                                 milliseconds=round(now * 1000), attempt=len(previous)))
        positive = {
            'wire.linux-abi.fixture': (10, 23, 48, self.lane + 1),
            'short.linux-abi.fixture': (10, 23, 48, 32),
            'bare': (10, 23, 48, 33),
            'absolute': (10, 23, 48, 34),
            'dot.name.linux-abi.fixture': (10, 23, 48, 35),
            'filtered.linux-abi.fixture': (10, 23, 48, 48),
            'retry.linux-abi.fixture': (10, 23, 48, 49),
            'failover.linux-abi.fixture': (10, 23, 48, 50),
            'cycles.linux-abi.fixture': (10, 23, 48, 51),
        }
        if name.startswith('parallel') and name.endswith('.linux-abi.fixture'):
            index = name.split('.')[0][8:]
            check(index.isdigit() and int(index) < 8, 'bounded concurrent lookup index')
            positive[name] = (10, 23, 64, int(index) + 1)
        if name == 'alias.linux-abi.fixture':
            self.send(sender, response(data, ((10, 23, 48, 16), (10, 23, 48, 17)),
                                       canonical='canonical.linux-abi.fixture'))
        elif name == 'empty.linux-abi.fixture':
            self.send(sender, response(data))
        elif name == 'timeout.linux-abi.fixture' or name == 'failover.linux-abi.fixture' and self.lane == 0:
            pass
        elif name in ('refused.linux-abi.fixture', 'servfail.linux-abi.fixture'):
            self.send(sender, response(data, rcode=5 if name.startswith('refused') else 2))
        elif name == 'retry.linux-abi.fixture' and len(previous) == 1:
            pass
        elif name == 'filtered.linux-abi.fixture':
            check(len(previous) == 1, 'filter scenario succeeds before retry')
            poisoned = bytearray(response(data, ((10, 23, 99, 99),)))
            poisoned[0] ^= 0x80
            self.send(sender, bytes(poisoned), kind='wrong-id')
            self.send(sender, response(data, ((10, 23, 99, 99),)), kind='wrong-source')
            self.send(sender, response(data, ((10, 23, 99, 99),)), kind='wrong-port')
            self.send(sender, data[:3], kind='short')
            self.pending.append((now + .12, sender, response(data, (positive[name],))))
        elif name in positive:
            self.send(sender, response(data, (positive[name],)))
        elif name in ('short.missing.fixture', 'bare.missing.fixture', 'bare.linux-abi.fixture',
                       'dot.name.missing.fixture', 'absent.linux-abi.fixture'):
            self.send(sender, response(data, rcode=3))
        else:
            raise RuntimeError('unexpected query or search order: ' + name)

    def tick(self):
        now = time.monotonic()
        remaining = []
        for deadline, sender, answer in self.pending:
            if deadline <= now:
                self.send(sender, answer)
            else:
                remaining.append((deadline, sender, answer))
        self.pending = remaining

    def validate(self):
        expected = Counter({'wire.linux-abi.fixture': 2, 'failover.linux-abi.fixture': 2})
        wire = [clocks for (_, _, name), clocks in self.transactions.items() if name == 'wire.linux-abi.fixture']
        check(len(wire) == 2, 'one separate wire transaction per musl linkage')
        check(all(1 <= len(clocks) <= (2 if self.cold_wire_retry else 1) for clocks in wire),
              'bounded first-lookup retransmissions while cold ARP resolves')
        expected['wire.linux-abi.fixture'] = sum(map(len, wire))
        if self.lane == 0:
            expected.update({name: 2 for name in (
                'alias.linux-abi.fixture', 'short.missing.fixture', 'short.linux-abi.fixture',
                'bare.missing.fixture', 'bare.linux-abi.fixture', 'bare', 'absolute',
                'dot.name.missing.fixture', 'dot.name.linux-abi.fixture', 'absent.linux-abi.fixture',
                'empty.linux-abi.fixture', 'filtered.linux-abi.fixture')})
            expected.update({'retry.linux-abi.fixture': 4, 'timeout.linux-abi.fixture': 4,
                             'refused.linux-abi.fixture': 4, 'servfail.linux-abi.fixture': 12})
        else:
            expected.update({'cycles.linux-abi.fixture': 256})
            expected.update({f'parallel{i}.linux-abi.fixture': 2 for i in range(8)})
        check(self.counts == expected, f'lane {self.lane} exact query inventory: {dict(self.counts)}')
        ordered = [query['name'] for query in self.queries
                   if query['name'] != 'wire.linux-abi.fixture' or query['attempt'] == 1]
        if self.lane == 0:
            sequence = ['wire.linux-abi.fixture', 'alias.linux-abi.fixture',
                        'short.missing.fixture', 'short.linux-abi.fixture',
                        'bare.missing.fixture', 'bare.linux-abi.fixture', 'bare', 'absolute',
                        'dot.name.missing.fixture', 'dot.name.linux-abi.fixture',
                        'absent.linux-abi.fixture', 'empty.linux-abi.fixture', 'filtered.linux-abi.fixture']
            for name, count in (('retry', 2), ('timeout', 2), ('refused', 2), ('servfail', 6), ('failover', 1)):
                sequence += [name + '.linux-abi.fixture'] * count
            check(ordered == sequence * 2, 'exact search order, fallback and error/retry sequence for both linkages')
        else:
            check(len(ordered) == 276, 'complete second-adapter lookup inventory')
            for start in (0, 138):
                block = ordered[start:start + 138]
                check(block[:2] == ['wire.linux-abi.fixture', 'failover.linux-abi.fixture'],
                      'wire lookup precedes the parallel-nameserver case')
                check(sorted(block[2:10]) == [f'parallel{i}.linux-abi.fixture' for i in range(8)],
                      'all eight concurrent queries precede reclamation')
                check(block[10:] == ['cycles.linux-abi.fixture'] * 128, 'exact reclamation lookup sequence')
        check(not self.pending, 'all delayed answers delivered')
        for (_, _, name), clocks in self.transactions.items():
            if name in ('retry.linux-abi.fixture', 'timeout.linux-abi.fixture', 'refused.linux-abi.fixture'):
                check(len(clocks) == 2 and .43 <= clocks[1] - clocks[0] <= .85,
                      'one retransmission at the configured half-second interval')
            elif name == 'servfail.linux-abi.fixture':
                check(len(clocks) == 6 and .43 <= clocks[3] - clocks[0] <= .85,
                      'bounded immediate SERVFAIL retries across two transmission rounds')
        return dict(lane=self.lane, counts=dict(self.counts), queries=self.queries, replies=self.replies)


class Peer(Answers):
    cold_wire_retry = True

    def __init__(self, lane):
        super().__init__(lane)
        self.guest = bytes([0x52, 0x54, 0, 0x12, 0x34, 0x10 + lane])
        self.mac = bytes([2, 0x41, 0x58, 0x44, 0x4e, lane])
        self.guest_ip, self.ip = bytes([10, 23, lane + 1, 2]), bytes([10, 23, lane + 1, 1])
        self.connection = None
        self.input, self.output = bytearray(), bytearray()
        self.arp = self.foreign = 0
        self.frames = []
        self.started = False

    def queue(self, frame):
        self.frames.append(dict(direction='reply', frame=frame.hex()))
        self.output.extend(struct.pack('!I', len(frame)) + frame)

    def send(self, sender, data, kind='answer'):
        source = self.ip if kind != 'wrong-source' else self.ip[:3] + b'\x09'
        port = 54 if kind == 'wrong-port' else 53
        packet = ipv4(source, self.guest_ip, udp(source, self.guest_ip, port, sender[1], data))
        self.queue((self.guest + self.mac + b'\x08\x00' + packet).ljust(60, b'\0'))
        self.replies.append(dict(kind=kind, data=data.hex(), sender=list(sender)))

    def packet(self, frame):
        check(14 <= len(frame) <= 1514, 'bounded Ethernet frame')
        if frame[12:14] == b'\x08\x06':
            body = frame[14:42]
            if body[:8] != struct.pack('!HHBBH', 1, 0x800, 6, 4, 1) or body[14:18] != self.guest_ip:
                check(not self.started, 'only firmware traffic precedes stack configuration')
                self.foreign += 1
                return
            check(frame[6:12] == self.guest and body[8:14] == self.guest and body[24:28] == self.ip,
                  'ARP for the configured nameserver on the actual interface')
            self.started = True
            self.arp += 1
            self.queue((self.guest + self.mac + b'\x08\x06' + struct.pack('!HHBBH', 1, 0x800, 6, 4, 2)
                        + self.mac + self.ip + self.guest + self.guest_ip).ljust(60, b'\0'))
            return
        if frame[12:14] != b'\x08\x00' or len(frame) < 42 or frame[26:30] != self.guest_ip:
            check(not self.started, 'unexpected traffic after resolver fixture begins')
            self.foreign += 1
            return
        self.started = True
        check(frame[:12] == self.mac + self.guest, 'interface-specific DNS Ethernet addresses')
        header = frame[14:34]
        check(header[0] == 0x45 and header[8] and header[9] == 17 and checksum(header) == 0,
              'IPv4 header, protocol and checksum')
        check(header[6:8] in (b'\0\0', b'\x40\0') and header[12:20] == self.guest_ip + self.ip,
              'unfragmented query addressed to this nameserver')
        end = 14 + int.from_bytes(header[2:4], 'big')
        check(42 <= end <= len(frame), 'IPv4 payload bounds')
        segment = frame[34:end]
        source, destination, length, value = struct.unpack('!4H', segment[:8])
        check(source and destination == 53 and length == len(segment) and value,
              'ephemeral DNS query to port 53 with nonzero checksum')
        check(checksum(self.guest_ip + self.ip + struct.pack('!BBH', 0, 17, length) + segment) == 0,
              'UDP pseudoheader and complete query checksum')
        self.frames.append(dict(direction='query', frame=frame.hex()))
        self.receive(segment[8:], ('.'.join(map(str, self.guest_ip)), source))

    def validate(self):
        result = super().validate()
        check(self.arp == 2, 'one nameserver ARP after each linkage configures the adapter')
        return dict(**result, arp=self.arp, foreign=self.foreign, frames=self.frames)
