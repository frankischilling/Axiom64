# SPDX-License-Identifier: GPL-3.0-or-later
"""Controlled peers retain pending ARP and validate actual transport traffic."""
import time

from ipv4_lifetimes.reader import require
from ipv4_lifetimes.wire_packets import arp_reply, definitions, hardware, ipv4, packet, payload, tcp


class Peer:
    def __init__(self, send, command):
        self.send = send
        self.command = command
        self.specs = definitions()
        self.active = None
        self.pending = {}
        self.guards = {}
        self.datagrams = {}
        self.connections = {}
        self.window = None
        self.tcp_absence_end = False
        self.results = []

    def event(self, value):
        phase = value['phase']
        if phase == 'begin':
            number = value['case']
            require(self.active is None and number == len(self.results), 'ordered complete wire cases')
            spec = self.specs[number]
            require(all(value[key] == spec[key] for key in ('case', 'lane', 'transport', 'survival', 'source', 'peer', 'guard')),
                    'client uses fixed independent wire-case inputs')
            self.active = dict(spec, phase='starting')
            self.tcp_absence_end = False
            self.guards[number] = []
            self.datagrams[number] = []
            self.command(b'S', number)
        elif self.active is not None and value['case'] == self.active['case']:
            spec = self.active
            if phase == 'expired':
                spec['phase'] = 'absent'
                if spec['transport'] != 2:
                    require(value['status'] == -101 and spec['case'] in self.pending,
                            'expired datagram owns an original held ARP request')
                    self.send(spec['lane'], arp_reply(spec['lane'], self.pending[spec['case']]))
                    self.window = time.monotonic_ns() + 500_000_000
                else:
                    require(value['status'] == 64, 'TCP accepted copied bytes while its source is absent')
                    self.window = time.monotonic_ns() + 2_000_000_000
            elif phase == 'absence-end':
                require(spec['transport'] == 2 and spec['phase'] == 'absent' and not self.tcp_absence_end,
                        'complete actual TCP absence interval')
                self.tcp_absence_end = True
            elif phase == 'restored':
                spec['phase'] = 'restored'
            elif phase == 'end':
                number = spec['case']
                require(self.guards[number] == [1, 3], 'successful physical guards before and after each case')
                if spec['transport'] == 2:
                    connection = self.connections[number]
                    require(connection['records'] == [4, 5], 'exact before/after TCP records reached the peer')
                else:
                    require(len(self.datagrams[number]) == int(spec['retained']), 'held datagram retention or last-source retirement')
                self.results.append(dict(case=number, transport=spec['transport'], survival=spec['survival'],
                                         retained_datagrams=len(self.datagrams[number]), guard_tags=self.guards[number]))
                self.active = None

    def poll(self):
        if self.window is not None and time.monotonic_ns() >= self.window:
            spec = self.active
            require(spec is not None and spec['phase'] == 'absent', 'owned transport observation window')
            if spec['transport'] == 2:
                if not self.tcp_absence_end:
                    return
            else:
                require(len(self.datagrams[spec['case']]) == int(spec['retained']), 'actual held output after expiry and ARP reply')
            self.window = None
            spec['phase'] = 'restoring'
            self.command(b'R', spec['case'])

    def receive(self, lane, frame):
        require(len(frame) >= 14, 'complete observed Ethernet frame')
        if frame[12:14] == b'\x86\xdd':
            return
        spec = self.active
        if frame[12:14] == b'\x08\x06':
            require(spec is not None and spec['lane'] == lane, 'ARP belongs to the active adapter')
            target = int.from_bytes(frame[38:42], 'big')
            if target == spec['guard'] or spec['transport'] == 2:
                self.send(lane, arp_reply(lane, frame))
            else:
                require(target == spec['peer'], 'actual retained next-hop request')
                self.pending.setdefault(spec['case'], bytes(frame))
            return
        require(frame[12:14] == b'\x08\x00', 'known observed lifetime Ethernet protocol')
        value = ipv4(frame)
        require(frame[6:12] == hardware(lane) and frame[:6] == hardware(lane, True), 'actual wire device and peer hardware')
        if value['protocol'] == 6:
            number = (value['source_port'] - 39000) // 2
            require(0 <= number < len(self.specs) and self.specs[number]['port'] == value['source_port'], 'owned TCP source port')
            target = self.specs[number]
            require(target['lane'] == lane and target['transport'] == 2 and value['source'] == target['source'] and
                    value['destination'] == target['peer'] and value['destination_port'] == 44732, 'complete TCP tuple')
            self.tcp(target, value)
            return
        require(spec is not None and spec['lane'] == lane and value['source'] == spec['source'], 'assigned case source and adapter')
        if value['protocol'] == 254:
            data = value['payload']
            require(value['destination'] == spec['guard'] and len(data) == 64 and data[8] == spec['case'] and
                    data[9] in (1, 3) and data == payload(spec['case'], data[9]), 'complete physical guard payload')
            self.guards[spec['case']].append(data[9])
            self.send(lane, packet(lane, spec['guard'], spec['source'], 254, data))
        else:
            require(value['protocol'] == (17 if spec['transport'] == 0 else 253) and
                    value['destination'] == spec['peer'] and value['payload'] == payload(spec['case'], 2),
                    'exact immutable copied datagram bytes')
            if spec['transport'] == 0:
                require(value['source_port'] == spec['port'] and value['destination_port'] == 44732, 'complete retained UDP tuple')
            require(spec['phase'] == 'absent' and spec['retained'], 'only surviving-address datagrams leave after actual expiry')
            self.datagrams[spec['case']].append(bytes(frame))

    def tcp(self, spec, value):
        number, flags = spec['case'], value['flags']
        if flags & 4:
            return
        if flags & 2:
            require(not value['payload'] and not flags & 16, 'original active TCP SYN')
            if number not in self.connections:
                self.connections[number] = dict(client_next=(value['sequence'] + 1) & 0xffffffff,
                    server_next=(0x23450000 + number * 0x1000 + 1) & 0xffffffff, records=[],
                    syn=value['sequence'], record_buffer=b'', segments={}, fin_reply=None)
            connection = self.connections[number]
            require(value['sequence'] == connection['syn'], 'SYN retries retain their sequence')
            self.send(spec['lane'], tcp(spec, connection['server_next'] - 1, connection['client_next'], 0x12, syn=True))
            return
        require(number in self.connections and flags & 16, 'established TCP sequence context')
        connection = self.connections[number]
        require(value['acknowledgement'] <= connection['server_next'], 'TCP acknowledges only peer-owned sequence space')
        data = value['payload']
        if data:
            key = (value['sequence'], bytes(data))
            if key in connection['segments']:
                self.send(spec['lane'], connection['segments'][key])
                return
            tag = 4 if not connection['records'] else 5
            offset = len(connection['record_buffer'])
            require(len(connection['records']) < 2 and value['sequence'] == connection['client_next'] and
                    0 < len(data) <= 64 - offset and data == payload(number, tag)[offset:offset + len(data)],
                    'exact stream prefix bytes and contiguous sequence ownership')
            if tag == 5:
                require(self.active is not None and self.active['case'] == number and
                        self.active['phase'] in ('restoring', 'restored'), 'no TCP payload while the source is absent')
            connection['client_next'] = (connection['client_next'] + len(data)) & 0xffffffff
            connection['record_buffer'] += data
            if len(connection['record_buffer']) == 64:
                response = tcp(spec, connection['server_next'], connection['client_next'], 0x18,
                               connection['record_buffer'])
                connection['server_next'] = (connection['server_next'] + 64) & 0xffffffff
                connection['records'].append(tag)
                connection['record_buffer'] = b''
            else:
                response = tcp(spec, connection['server_next'], connection['client_next'], 0x10)
            connection['segments'][key] = response
            self.send(spec['lane'], response)
        if flags & 1:
            if connection['fin_reply'] is None:
                require((value['sequence'] + len(data)) & 0xffffffff == connection['client_next'], 'contiguous TCP close sequence')
                connection['client_next'] = (connection['client_next'] + 1) & 0xffffffff
                connection['fin_reply'] = tcp(spec, connection['server_next'], connection['client_next'], 0x11)
                connection['server_next'] = (connection['server_next'] + 1) & 0xffffffff
            self.send(spec['lane'], connection['fin_reply'])
