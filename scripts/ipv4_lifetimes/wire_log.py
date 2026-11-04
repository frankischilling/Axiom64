# SPDX-License-Identifier: GPL-3.0-or-later
"""Decode original syscall, receive, address-inventory and source-clock records."""
import struct

from ipv4_lifetimes.reader import attributes, decode, messages, require
from ipv4_lifetimes.wire_packets import definitions, hardware, ipv4, payload

PREFIX = 'LIFETIME_WIRE_'
PASS = PREFIX + 'PASS cases=24 interfaces=2 transports=3 survival_states=4'


def integer(value, minimum=0):
    require(type(value) is int and minimum <= value < 1 << 63, 'bounded original integer')
    return value


def records(text):
    result = []
    lines = text.replace('\r\n', '\n').splitlines()
    require(lines.count(PASS) == 1 and not any(marker in text for marker in
            ('LIFETIME_WIRE_FAIL', 'PANIC:', 'FAULT pid=')), 'one actual complete successful wire client')
    for line in lines:
        if not line.startswith(PREFIX) or line in (PASS, PREFIX + 'RUNTIME_READY'):
            continue
        kind, separator, body = line[len(PREFIX):].partition(' ')
        require(separator and kind in ('EVENT', 'CONTROL', 'IFCONF', 'RECEIVE'), 'known complete client record')
        value = decode(body)
        keys = {'EVENT': {'case', 'lane', 'index', 'transport', 'survival', 'source', 'peer', 'guard',
                          'phase', 'status', 'monotonic_ns', 'realtime_ns'},
                'CONTROL': {'case', 'before_ns', 'after_ns', 'realtime_before_ns', 'realtime_after_ns', 'request', 'reply'},
                'IFCONF': {'case', 'monotonic_ns', 'realtime_ns', 'bytes'},
                'RECEIVE': {'case', 'tag', 'before_ns', 'after_ns', 'realtime_before_ns', 'realtime_after_ns', 'bytes'}}
        require(type(value) is dict and set(value) == keys[kind], 'complete original record fields')
        integer(value['case'])
        if kind == 'EVENT':
            require(type(value['phase']) is str and type(value['status']) is int and
                    -(1 << 63) <= value['status'] < 1 << 63, 'original named event and signed integer outcome')
            for key in ('lane', 'index', 'transport', 'survival', 'source', 'peer', 'guard'):
                integer(value[key])
        elif kind == 'RECEIVE':
            integer(value['tag'], 1)
        for key in ('request', 'reply') if kind == 'CONTROL' else (() if kind == 'EVENT' else ('bytes',)):
            require(type(value[key]) is str and bytes.fromhex(value[key]).hex() == value[key], 'canonical original hexadecimal bytes')
        if kind in ('CONTROL', 'RECEIVE'):
            fields = ('before_ns', 'after_ns', 'realtime_before_ns', 'realtime_after_ns')
            require(all(integer(value[key]) >= 0 for key in fields) and value['before_ns'] <= value['after_ns'],
                    'ordered actual syscall clock brackets')
        else:
            integer(value['monotonic_ns'])
            integer(value['realtime_ns'])
        result.append((kind, value))
    require(result, 'original client records exist')
    return result


def samples(rows):
    result = []
    for kind, value in rows:
        if kind in ('CONTROL', 'RECEIVE'):
            result += [(value['before_ns'], value['realtime_before_ns']),
                       (value['after_ns'], value['realtime_after_ns'])]
        else:
            result.append((value['monotonic_ns'], value['realtime_ns']))
    require(all(a[0] <= b[0] for a, b in zip(result, result[1:])), 'ordered original source monotonic clocks')
    return result


def control(value, sequence):
    request, reply = bytes.fromhex(value['request']), bytes.fromhex(value['reply'])
    sent, received = messages(request), messages(reply)
    require(len(sent) == len(received) == 1, 'one complete request and acknowledgement')
    sent, received = sent[0], received[0]
    require(sent['sequence'] == received['sequence'] == sequence and sent['port'] == 0 and
            received['port'] > 0 and received['kind'] == 2 and received['flags'] == 0x100 and
            received['body'] == bytes(4) + request[:16], 'matching successful original kernel acknowledgement')
    return sent


def address(message, index, number, kind, flags, lifetime=None):
    require(message['kind'] == kind and message['flags'] == flags and
            message['body'][:8] == struct.pack('<BBBBI', 2, 24, 0, 0, index),
            'exact address operation and interface')
    fields = attributes(message['body'][8:])
    expected = {1: struct.pack('!I', number), 2: struct.pack('!I', number)}
    if lifetime is not None:
        expected[6] = struct.pack('<IIII', lifetime, lifetime, 0x12345678, 0x87654321)
    require(fields == expected, 'complete original address and supplied cache bytes')


def inventory(value, expected):
    data = bytes.fromhex(value['bytes'])
    require(len(data) % 40 == 0, 'complete Linux x86-64 interface inventory')
    actual, loopback = [], 0
    for at in range(0, len(data), 40):
        entry = data[at:at + 40]
        name = entry[:16].split(b'\0', 1)[0]
        if name == b'lo':
            require(entry[16:18] == b'\2\0' and entry[20:24] == bytes((127, 0, 0, 1)), 'fixed independent loopback inventory')
            loopback += 1
            continue
        require(name in (b'eth0', b'eth1') and entry[16:18] == b'\2\0', 'actual selected IPv4 inventory entry')
        actual.append((name.decode(), int.from_bytes(entry[20:24], 'big')))
    require(loopback <= 1 and sorted(actual) == sorted(expected), 'actual primary withdrawal and surviving or cascading address')
    return loopback


def verify(text):
    rows = records(text)
    samples(rows)
    events = [value for kind, value in rows if kind == 'EVENT']
    policies = [value for value in events if value['phase'] in ('policy-read', 'policy-write')]
    require(len(policies) == 31, 'all original global and per-device promotion policy operations')
    expected = [('policy-read', policies[0]['status']), ('policy-write', 0)]
    at = 2
    for lane in (0, 1):
        original = policies[at]['status']
        require(type(original) is int and -(1 << 31) <= original < 1 << 31, 'original signed device policy')
        expected += [('policy-read', original)]
        expected += [('policy-write', int(survival == 3)) for _ in range(3) for survival in range(4)]
        expected += [('policy-write', original)]
        at += 14
    expected += [('policy-write', policies[0]['status'])]
    require([(value['phase'], value['status']) for value in policies] == expected,
            'promotion policy transitions and restoration of every original value')
    sequence = 0
    for kind, value in rows:
        if kind == 'CONTROL':
            sequence += 1
            control(value, sequence)
    result, loopbacks = [], []
    position = 0
    for spec in definitions():
        while position < len(rows) and not (rows[position][0] == 'EVENT' and rows[position][1]['phase'] == 'begin'):
            require(rows[position][0] == 'EVENT' and rows[position][1]['phase'] in ('policy-read', 'policy-write'),
                    'only setup or restore policy operations between cases')
            position += 1
        begin = position
        while position < len(rows) and not (rows[position][0] == 'EVENT' and rows[position][1]['phase'] == 'end'):
            position += 1
        require(position < len(rows), 'every original complete case has its end')
        selected = rows[begin:position + 1]
        position += 1
        require(all(value['case'] == spec['case'] for _, value in selected), 'every syscall belongs to its active case')
        phases = [value for kind, value in selected if kind == 'EVENT']
        for value in phases:
            require(all(value[key] == spec[key] for key in
                        ('case', 'lane', 'transport', 'survival', 'source', 'peer', 'guard')) and
                    integer(value['index'], 1) == phases[0]['index'], 'fixed actual source, peer, adapter and case')
        expected = [('begin', 0), ('command', 83), ('policy-write', int(spec['survival'] == 3)), ('guard-before', 84)]
        if spec['transport'] == 2:
            expected += [('stream-before', 64)]
        expected += [('lifetime-start', 1)]
        if spec['transport'] != 2:
            expected += [('queued', 64)]
        expected += [('withdrawn', 0), ('fresh-bind', -99), ('expired', 64 if spec['transport'] == 2 else -101)]
        if spec['transport'] == 2:
            expected += [('absence-end', 0)]
        expected += [('command', 82), ('restored', 0)]
        if spec['transport'] == 2:
            expected += [('stream-after', 64)]
        expected += [('guard-after', 84), ('end', 0)]
        require([(value['phase'], value['status']) for value in phases] == expected, 'complete ordered syscall outcomes')
        by_phase = {value['phase']: value for value in phases}
        require(1_500_000_000 <= by_phase['withdrawn']['monotonic_ns'] - by_phase['lifetime-start']['monotonic_ns'] <= 2_500_000_000,
                'unchanged minimum primary lifetime wait and bounded actual withdrawal')
        if spec['transport'] == 2:
            require(by_phase['absence-end']['monotonic_ns'] - by_phase['expired']['monotonic_ns'] >= 2_000_000_000,
                    'unchanged actual TCP absence observation')
        calls = [messages(bytes.fromhex(value['request']))[0] for kind, value in selected if kind == 'CONTROL']
        index, other = phases[0]['index'], spec['source'] + (256 if spec['survival'] == 1 else 1)
        address(calls.pop(0), index, spec['source'], 20, 0x605, 0xffffffff)
        if spec['survival']:
            address(calls.pop(0), index, other, 20, 0x605, 0xffffffff)
        route = calls.pop(0)
        require(route['kind'] == 24 and route['flags'] == 0x605 and route['body'][:12] ==
                bytes.fromhex('02200000fe03fd0100000000') and attributes(route['body'][12:]) ==
                {1: struct.pack('!I', spec['peer']), 4: struct.pack('<I', index), 6: struct.pack('<I', 10)},
                'original explicit direct route and metric')
        address(calls.pop(0), index, spec['source'], 20, 0x105, 1)
        address(calls.pop(0), index, spec['source'], 20, 0x605, 0xffffffff)
        address(calls.pop(0), index, spec['source'], 21, 5)
        if spec['retained']:
            address(calls.pop(0), index, other, 21, 5)
        require(not calls, 'no extra address or route mutations')
        snapshots = [value for kind, value in selected if kind == 'IFCONF']
        require(len(snapshots) >= 3, 'actual primary withdrawal, survivor and cleanup inventories')
        name = 'eth' + str(spec['lane'])
        for value in snapshots[:-3]:
            expected = [(name, spec['source'])] + ([(name, other)] if spec['survival'] else [])
            loopbacks.append(inventory(value, expected))
            require(by_phase['lifetime-start']['monotonic_ns'] + 1_500_000_000 <= value['monotonic_ns'] <=
                    by_phase['withdrawn']['monotonic_ns'], 'original primary polling after the complete minimum wait')
        for value in snapshots[-3:]:
            loopbacks.append(inventory(value, [(name, other)] if spec['retained'] else []))
        require(by_phase['lifetime-start']['monotonic_ns'] + 1_500_000_000 <= snapshots[-3]['monotonic_ns'] <=
                by_phase['withdrawn']['monotonic_ns'] <= snapshots[-2]['monotonic_ns'],
                'observed primary absence precedes the independent survivor query')
        receives = [value for kind, value in selected if kind == 'RECEIVE']
        for tag in (1, 3):
            values = [value for value in receives if value['tag'] == tag]
            require(len(values) == 1, 'one original guard receive')
            frame = hardware(spec['lane']) + hardware(spec['lane'], True) + b'\x08\x00' + bytes.fromhex(values[0]['bytes'])
            packet = ipv4(frame)
            require(packet['source'] == spec['guard'] and packet['destination'] == spec['source'] and
                    packet['protocol'] == 254 and packet['payload'] == payload(spec['case'], tag), 'actual raw guard receive bytes')
        for tag in (4, 5):
            values = [value for value in receives if value['tag'] == tag]
            data = b''.join(bytes.fromhex(value['bytes']) for value in values)
            require(data == (payload(spec['case'], tag) if spec['transport'] == 2 else b''),
                    'actual complete stream receives preserve original bytes across arbitrary read boundaries')
        require(all(value['tag'] in (1, 3, 4, 5) for value in receives), 'no extra or unknown receive records')
        result.append(dict(spec=spec, events=phases, receives=receives, inventories=snapshots))
    require(all(kind == 'EVENT' and value['phase'] == 'policy-write' for kind, value in rows[position:]),
            'only final policy restoration follows the campaign')
    require(len(set(loopbacks)) == 1, 'independent loopback inventory remains fixed throughout the campaign')
    return result
