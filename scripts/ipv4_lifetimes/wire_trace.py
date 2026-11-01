# SPDX-License-Identifier: GPL-3.0-or-later
"""Independently check captured packet bytes, barriers and complete observation windows."""
from collections import Counter
import struct

from ipv4_lifetimes.reader import CLOCK_BOUND_NS, require
from ipv4_lifetimes.wire_log import integer, records, samples, verify as client_log
from ipv4_lifetimes.wire_packets import arp_reply, checksum, hardware, ipv4, packet, payload, tcp

PRECISION_NS = 20_000_000
OBSERVER_NS = 1_000_000_000


def clock(values, label):
    require(values and all(a[0] <= b[0] for a, b in zip(values, values[1:])), 'ordered ' + label + ' clocks')
    offsets = [integer(realtime) - integer(monotonic) for monotonic, realtime in values]
    require(max(offsets) - min(offsets) <= CLOCK_BOUND_NS, 'unchanged 100ms ' + label + ' clock-jump bound')


def background(frame, lane):
    require(len(frame) >= 62 and frame[6:12] == hardware(lane) and frame[12:14] == b'\x86\xdd' and
            frame[14] >> 4 == 6 and int.from_bytes(frame[18:20], 'big') == len(frame) - 54 and
            frame[:6] == b'\x33\x33' + frame[50:54], 'complete bounded multicast IPv6 background packet')
    kind, start = frame[20], 54
    if kind == 0:
        require(start + 8 <= len(frame), 'complete background hop-by-hop header')
        kind, start = frame[start], start + (frame[start + 1] + 1) * 8
    require(kind == 58 and start + 8 <= len(frame), 'background neighbor or multicast ICMPv6')
    body = frame[start:]
    pseudo = frame[22:54] + len(body).to_bytes(4, 'big') + bytes((0, 0, 0, 58))
    require(body[0] in (130, 131, 132, 133, 135, 143) and checksum(pseudo + body) == 0,
            'complete independent background ICMPv6 checksum')


def auxiliary(value):
    controls = value['ancillary']
    require(type(controls) is list and len(controls) == 2, 'original packet auxiliary and kernel timestamp controls')
    kinds = {}
    for item in controls:
        require(set(item) == {'level', 'kind', 'data'} and (item['level'], item['kind']) not in kinds,
                'unique original ancillary field')
        kinds[item['level'], item['kind']] = bytes.fromhex(item['data'])
    require(set(kinds) == {(263, 8), (1, 35)} and len(kinds[263, 8]) == 20 and len(kinds[1, 35]) == 16,
            'actual Linux packet metadata structures')
    status, original, captured, mac, network, vlan, vlan_type = struct.unpack('<IIIHHHH', kinds[263, 8])
    frame = bytes.fromhex(value['frame'])
    require(not status & 8 and original == captured == len(frame) and mac == 0 and network == 14 and
            vlan == vlan_type == 0, 'complete untruncated software-checksummed packet before comparison')
    seconds, nanos = struct.unpack('<qq', kinds[1, 35])
    require(seconds >= 0 and 0 <= nanos < 1_000_000_000 and
            abs(seconds * 1_000_000_000 + nanos - value['realtime_ns']) <= OBSERVER_NS,
            'independent original kernel packet timestamp within observer bound')


def receipt(value, native, ingress=False):
    require(set(value) == {'index', 'direction', 'frame', 'monotonic_ns', 'realtime_ns', 'packet_type', 'flags', 'ancillary'} and
            type(value['index']) is int and value['index'] in (0, 1) and
            value['direction'] in (('ingress',) if ingress else ('input', 'output')) and
            isinstance(value['frame'], str) and len(value['frame']) % 2 == 0 and
            14 <= len(bytes.fromhex(value['frame'])) <= 9014 and type(value['flags']) is int and value['flags'] == 0,
            'complete bounded original Ethernet receipt')
    integer(value['monotonic_ns'])
    integer(value['realtime_ns'])
    if value['direction'] == 'input' or not native:
        require(value['packet_type'] is None and value['ancillary'] == [], 'socket-backend or peer injection metadata')
    else:
        require(type(value['packet_type']) is int and 0 <= value['packet_type'] <= 4, 'actual native packet-socket type')
        auxiliary(value)


def streams(spec, output, inputs, absence, restore):
    require(output and inputs, 'actual complete TCP exchange')
    first = output[0][1]
    require(first['flags'] == 2 and not first['payload'], 'original active open on the wire')
    initial = first['sequence']
    server = 0x23450000 + spec['case'] * 0x1000
    next_client, seen, data = (initial + 1) & 0xffffffff, {}, bytearray()
    fin = False
    for row, value in output:
        require(not absence <= row['monotonic_ns'] < restore, 'no obsolete TCP output while its source is absent')
        require(value['flags'] in (2, 16, 24, 17) and
                value['source'] == spec['source'] and value['destination'] == spec['peer'] and
                value['source_port'] == spec['port'] and value['destination_port'] == 44732,
                'complete owned TCP tuple without reset or unknown flags')
        if value['flags'] == 2:
            require(value['sequence'] == initial and not value['payload'], 'stable active-open sequence')
            continue
        require(server < value['acknowledgement'] <= server + 130, 'ACK stays inside peer-owned sequence space')
        body = value['payload']
        if body:
            key = (value['sequence'], body)
            if key in seen:
                continue
            require(not fin and value['sequence'] == next_client and len(data) + len(body) <= 128,
                    'contiguous original TCP sequence and byte ownership')
            expected = payload(spec['case'], 4) + payload(spec['case'], 5)
            require(body == expected[len(data):len(data) + len(body)], 'exact original stream bytes across segment boundaries')
            if len(data) >= 64 or len(data) + len(body) > 64:
                require(row['monotonic_ns'] >= restore, 'no obsolete TCP payload during source absence')
            data.extend(body)
            seen[key] = True
            next_client = (next_client + len(body)) & 0xffffffff
        if value['flags'] & 1:
            require(len(data) == 128 and value['sequence'] == next_client, 'complete stream before contiguous FIN')
            fin = True
        elif not body:
            require(value['sequence'] == (next_client + int(fin)) & 0xffffffff, 'contiguous pure TCP acknowledgement sequence')
    require(bytes(data) == payload(spec['case'], 4) + payload(spec['case'], 5) and fin, 'complete physical TCP recovery and close')
    echoed = []
    for row, value in inputs:
        if value['flags'] == 18:
            expected = tcp(spec, server, initial + 1, 18, syn=True)
        elif value['flags'] == 24:
            tag = 4 if value['sequence'] == server + 1 else 5
            require(tag != 5 or row['monotonic_ns'] >= restore, 'recovery echo follows the original restore request')
            require(value['sequence'] == server + 1 + (64 if tag == 5 else 0) and
                    value['acknowledgement'] == (initial + 1 + (128 if tag == 5 else 64)) & 0xffffffff,
                    'original echo sequence and acknowledgement')
            expected = tcp(spec, value['sequence'], value['acknowledgement'], 24, payload(spec['case'], tag))
            echoed.append(tag)
        elif value['flags'] == 16:
            require(value['sequence'] == server + 65 and not value['payload'] and
                    64 < ((value['acknowledgement'] - initial - 1) & 0xffffffff) < 128,
                    'partial recovered stream acknowledgement')
            expected = tcp(spec, value['sequence'], value['acknowledgement'], 16)
        else:
            require(value['flags'] == 17, 'original bounded peer close')
            expected = tcp(spec, server + 129, initial + 130, 17)
        require(bytes.fromhex(row['frame']) == expected, 'every exact original controlled TCP input')
    require(set(echoed) == {4, 5}, 'both complete original stream echoes')


def protocol(text, wire, ingress, events, commands, native):
    cases = client_log(text)
    original = [value for kind, value in records(text) if kind == 'EVENT']
    require(all(set(row) == set(source) | {'receipt_monotonic_ns', 'receipt_realtime_ns'} and
                integer(row['receipt_monotonic_ns']) >= 0 and integer(row['receipt_realtime_ns']) >= 0
                for row, source in zip(events, original)), 'complete actual event receipt metadata')
    require(all(a['receipt_monotonic_ns'] <= b['receipt_monotonic_ns'] for a, b in zip(events, events[1:])),
            'ordered actual event receipt clocks')
    require([{key: value for key, value in row.items() if not key.startswith('receipt_')} for row in events] == original,
            'every original client event has its independent observer receipt')
    require(len(commands) == 48, 'all original single-byte S/R barriers')
    require(all(a['after_ns'] <= b['before_ns'] for a, b in zip(commands, commands[1:])), 'ordered actual control-byte writes')
    for values in (wire, ingress):
        require(all(a['monotonic_ns'] <= b['monotonic_ns'] for a, b in zip(values, values[1:])), 'ordered physical packet receipts')
    for row in wire:
        receipt(row, native)
    for row in ingress:
        require(native, 'only native captures have independent AF_PACKET ingress taps')
        receipt(row, native, True)
    injection = [row for row in wire if row['direction'] == 'input']
    if native:
        taps = [row for row in ingress if row['packet_type'] != 4 and bytes.fromhex(row['frame'])[6:12] == hardware(row['index'], True)]
        require(Counter((row['index'], row['frame']) for row in taps) ==
                Counter((row['index'], row['frame']) for row in injection), 'every peer injection reached the actual client-side tap')
    decoded = []
    arp_requests = []
    for row in wire:
        frame, lane = bytes.fromhex(row['frame']), row['index']
        if native and row['direction'] == 'output' and row['packet_type'] == 4:
            require(frame[6:12] == hardware(lane, True), 'owned peer outgoing mirror')
            continue
        if frame[12:14] == b'\x86\xdd':
            require(row['direction'] == 'output', 'no injected background substitution')
            background(frame, lane)
        elif frame[12:14] == b'\x08\x00':
            value = ipv4(frame)
            require(frame[6:12] == hardware(lane, row['direction'] == 'input') and
                    frame[:6] == hardware(lane, row['direction'] == 'output'), 'actual Ethernet ingress and egress ownership')
            decoded.append((row, value))
        else:
            require(frame[12:14] == b'\x08\x06', 'known complete Ethernet protocol')
            if row['direction'] == 'output':
                arp_reply(lane, frame)
                source = 0xc6124002 + lane * 0x1000
                target = int.from_bytes(frame[38:42], 'big')
                require(int.from_bytes(frame[28:32], 'big') == source and
                        target in [((source & 0xffffff00) | value) for value in (*range(16, 28), 254)] and
                        frame[:6] in (bytes.fromhex('ffffffffffff'), hardware(lane, True)),
                        'owned original ARP source, target and physical destination')
                arp_requests.append((lane, frame))
            else:
                require(any(index == lane and frame == arp_reply(lane, request) for index, request in arp_requests),
                        'every injected ARP reply owns a preceding actual request')
    consumed = set()
    for number, case in enumerate(cases):
        spec = case['spec']
        selected = [row for row in events if row['case'] == number and row['phase'] not in ('policy-read', 'policy-write')]
        by_phase = {row['phase']: row for row in selected}
        start, restore = commands[number * 2:number * 2 + 2]
        source_commands = [row for row in selected if row['phase'] == 'command']
        for command, byte, source in zip((start, restore), ('53', '52'), source_commands):
            require(set(command) == {'case', 'bytes', 'before_ns', 'after_ns', 'realtime_ns'} and
                    command['case'] == number and command['bytes'] == byte and
                    integer(command['before_ns']) <= integer(command['after_ns']) <= source['receipt_monotonic_ns'] and
                    source['receipt_monotonic_ns'] - command['before_ns'] <= OBSERVER_NS,
                    'original control byte and prompt independent source receipt')
        require(by_phase['begin']['receipt_monotonic_ns'] <= start['before_ns'] < restore['before_ns'] <=
                by_phase['restored']['receipt_monotonic_ns'], 'actual case start and restoration causality')
        for first, last, minimum in (('lifetime-start', 'fresh-bind', 1_500_000_000),):
            require(by_phase[last]['receipt_monotonic_ns'] - by_phase[first]['receipt_monotonic_ns'] >= minimum - PRECISION_NS,
                    'physical lifetime interval retains the source timer precision')
        if spec['transport'] == 2:
            require(by_phase['absence-end']['receipt_monotonic_ns'] - by_phase['expired']['receipt_monotonic_ns'] >=
                    2_000_000_000 - PRECISION_NS and by_phase['absence-end']['receipt_monotonic_ns'] <= restore['before_ns'],
                    'full physical TCP absence before restoration request')
        outputs, inputs = [], []
        guards = {1: [], 3: []}
        datagrams = []
        for at, (row, value) in enumerate(decoded):
            if row['index'] != spec['lane']:
                continue
            if value['protocol'] == 6:
                owned = (value.get('source_port') if row['direction'] == 'output' else value.get('destination_port')) == spec['port']
            elif value['protocol'] == 254:
                owned = len(value['payload']) >= 10 and value['payload'][8] == number
            else:
                owned = value['protocol'] in (17, 253) and value['destination'] == spec['peer']
            if not owned:
                continue
            consumed.add(at)
            if value['protocol'] == 6:
                (outputs if row['direction'] == 'output' else inputs).append((row, value))
            elif value['protocol'] == 254:
                tag = value['payload'][9]
                require(tag in guards and value['payload'] == payload(number, tag) and value['source'] ==
                        (spec['guard'] if row['direction'] == 'input' else spec['source']) and value['destination'] ==
                        (spec['source'] if row['direction'] == 'input' else spec['guard']), 'exact physical guard tuple and bytes')
                guards[tag].append(row['direction'])
            else:
                require(row['direction'] == 'output' and spec['transport'] != 2 and spec['retained'] and
                        value['protocol'] == (17 if spec['transport'] == 0 else 253) and value['source'] == spec['source'] and
                        value['payload'] == payload(number, 2) and by_phase['expired']['receipt_monotonic_ns'] <=
                        row['monotonic_ns'] <= restore['before_ns'], 'only exact retained datagrams leave after actual expiry')
                if spec['transport'] == 0:
                    require(value['source_port'] == spec['port'] and value['destination_port'] == 44732, 'complete held UDP tuple')
                datagrams.append(row)
        require(guards == {1: ['output', 'input'], 3: ['output', 'input']}, 'both physical guards traversed the actual adapter')
        if spec['transport'] == 2:
            streams(spec, outputs, inputs, by_phase['expired']['receipt_monotonic_ns'], restore['before_ns'])
        else:
            require(len(datagrams) == int(spec['retained']), 'actual datagram survival or last-address retirement')
            arps = [row for row in wire if row['direction'] == 'output' and row['index'] == spec['lane'] and
                    bytes.fromhex(row['frame'])[12:14] == b'\x08\x06' and
                    int.from_bytes(bytes.fromhex(row['frame'])[38:42], 'big') == spec['peer']]
            replies = [row for row in injection if row['index'] == spec['lane'] and
                       bytes.fromhex(row['frame'])[12:14] == b'\x08\x06' and
                       int.from_bytes(bytes.fromhex(row['frame'])[28:32], 'big') == spec['peer']]
            require(arps and len(replies) == 1 and bytes.fromhex(replies[0]['frame']) ==
                    arp_reply(spec['lane'], bytes.fromhex(arps[0]['frame'])) and
                    by_phase['expired']['receipt_monotonic_ns'] <= replies[0]['monotonic_ns'] and
                    restore['before_ns'] - replies[0]['monotonic_ns'] >= 500_000_000,
                    'original held ARP reply and complete physical datagram observation')
            require(all(row['monotonic_ns'] >= replies[0]['monotonic_ns'] for row in datagrams),
                    'held datagram reaches the wire only after its original peer reply')
    require(len(consumed) == len(decoded), 'no omitted unknown or surplus IPv4 packet')
    return dict(cases=24, adapters=2, datagram_cases=16, tcp_cases=8, guards=48, original_receives=True)


def clocks(text, wire, ingress, events, commands):
    clock(samples(records(text)), 'source')
    values = [(row['monotonic_ns'], row['realtime_ns']) for row in wire + ingress]
    values += [(row['receipt_monotonic_ns'], row['receipt_realtime_ns']) for row in events]
    values += [(row['after_ns'], row['realtime_ns']) for row in commands]
    clock(sorted(values), 'observer')
