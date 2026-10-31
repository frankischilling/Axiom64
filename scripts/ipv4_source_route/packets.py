# SPDX-License-Identifier: GPL-3.0-or-later
"""Read complete shared-client raw records and independently validate wire bytes."""
import re

from ipv4_source_route.controls import require
from ipv4_source_route.corpus import checksum, option_fields

DAY_MS = 86400000
CLOCK_BOUND_NS = 1000000000


def clocks(text, case, total):
    result = {}
    for line in text.replace('\r\n', '\n').splitlines():
        if not line.startswith('IPV4_SOURCE_WIRE_CLOCK '):
            continue
        match = re.fullmatch(r'IPV4_SOURCE_WIRE_CLOCK case=(\d+) phase=(before|after) realtime_ns=(\d+) '
                             r'monotonic_before_ns=(\d+) monotonic_after_ns=(\d+)', line)
        require(match and int(match[1]) < total, 'complete known source-clock observation')
        if int(match[1]) != case:
            continue
        phase = match[2]
        real, before, after = map(int, match.groups()[2:])
        require(phase not in result and 0 <= real < 1 << 63 and
                0 <= before <= after < 1 << 63 and after - before <= CLOCK_BOUND_NS,
                'unique actual clock sample within unchanged one-second sampling bound')
        result[phase] = dict(realtime_ns=real, monotonic_before_ns=before, monotonic_after_ns=after)
    return result


def raw_packets(text, case, total):
    require(type(total) is int and type(case) is int and 0 <= case < total <= 1000,
            'bounded expected raw case matrix')
    headers, chunks = {}, {}
    completed = []
    for line in text.replace('\r\n', '\n').splitlines():
        if line.startswith('IPV4_SOURCE_WIRE_RAW '):
            match = re.fullmatch(r'IPV4_SOURCE_WIRE_RAW case=(\d+) packet=(\d+) bytes=(\d+) source=([0-9a-f]{8})', line)
            require(match, 'complete raw packet record')
            owner, number, length = map(int, match.groups()[:3])
            require(owner < total, 'known raw packet case')
            if owner != case:
                continue
            require(number not in headers and 20 <= length <= 65535, 'unique bounded raw packet')
            headers[number] = (length, int(match[4], 16))
        elif line.startswith('IPV4_SOURCE_WIRE_RAW_BYTES '):
            match = re.fullmatch(r'IPV4_SOURCE_WIRE_RAW_BYTES case=(\d+) packet=(\d+) offset=(\d+) data=([0-9a-f]+)', line)
            require(match, 'complete raw packet chunk')
            owner, number, offset = map(int, match.groups()[:3])
            require(owner < total, 'known raw chunk case')
            if owner != case:
                continue
            data = bytes.fromhex(match[4])
            require(number in headers and 0 < len(data) <= 64 and
                    offset == len(chunks.get(number, b'')), 'ordered complete raw packet chunks')
            chunks[number] = chunks.get(number, b'') + data
        elif line.startswith('IPV4_SOURCE_WIRE_OBSERVED '):
            match = re.fullmatch(r'IPV4_SOURCE_WIRE_OBSERVED case=(\d+) packets=(\d+)', line)
            require(match, 'complete observed packet count')
            require(int(match[1]) < total, 'known observed case')
            if int(match[1]) == case:
                completed.append(int(match[2]))
    require(len(completed) == 1 and set(headers) == set(range(completed[0])) and
            set(chunks) == set(headers), 'all raw packets and one complete case observation')
    result = []
    for number in range(completed[0]):
        data = chunks[number]
        length, source = headers[number]
        require(len(data) == length and data[0] >> 4 == 4 and
                int.from_bytes(data[2:4], 'big') == length and
                int.from_bytes(data[12:16], 'big') == source, 'actual raw datagram and sockaddr source')
        # Processed unfragmented raw headers may deliberately retain a stale
        # checksum. Equality with the independent native bytes checks that field.
        result.append(data.hex())
    return result


def client_trace(text, cases, native):
    count = len(cases)
    require(type(native) is bool and 0 < count <= 1000 and
            [row['case'] for row in cases] == list(range(count)), 'complete ordered expected case definitions')
    current, phase, kernels, passes, mutations, clocked = 0, 'kernel', 0, 0, set(), set()
    for line in text.replace('\r\n', '\n').splitlines():
        if not line.startswith('IPV4_SOURCE_WIRE_'):
            continue
        if line.startswith('IPV4_SOURCE_WIRE_KERNEL '):
            match = re.fullmatch(r'IPV4_SOURCE_WIRE_KERNEL version=2 sysname=(Linux|Axiom64) release=(\S+) cases=(\d+)', line)
            require(match and phase == 'kernel' and match[1] == ('Linux' if native else 'Axiom64') and
                    int(match[3]) == count, 'one actual kernel and complete declared case matrix')
            kernels += 1
            phase = 'ready'
        elif line.startswith('IPV4_SOURCE_WIRE_CLOCK '):
            match = re.match(r'IPV4_SOURCE_WIRE_CLOCK case=(\d+) phase=(before|after) ', line)
            require(match and int(match[1]) == current < count, 'clock belongs to its ordered active case')
            if match[2] == 'before':
                require(phase == 'ready', 'one source-clock origin before case readiness')
                phase = 'clocked'
            else:
                require(phase == 'active' and cases[current]['clocked'] and current not in clocked,
                        'one prompt source-clock observation for a timestamp case')
                clocked.add(current)
        elif line.startswith('IPV4_SOURCE_WIRE_READY '):
            match = re.fullmatch(r'IPV4_SOURCE_WIRE_READY case=(\d+)', line)
            require(match and phase == 'clocked' and int(match[1]) == current < count,
                    'ordered complete case readiness')
            phase = 'active'
        elif line.startswith('IPV4_SOURCE_WIRE_MUTATED '):
            match = re.fullmatch(r'IPV4_SOURCE_WIRE_MUTATED case=(\d+) action=([a-z-]+)', line)
            require(match and phase == 'active' and int(match[1]) == current and current not in mutations and
                    cases[current]['kind'] == 'held' and match[2] == cases[current]['mutation'],
                    'one exact held-packet mutation')
            mutations.add(current)
        elif line.startswith('IPV4_SOURCE_WIRE_RAW ') or line.startswith('IPV4_SOURCE_WIRE_RAW_BYTES '):
            match = re.match(r'IPV4_SOURCE_WIRE_RAW(?:_BYTES)? case=(\d+) ', line)
            require(match and phase == 'active' and int(match[1]) == current,
                    'raw records belong to their active case')
        elif line.startswith('IPV4_SOURCE_WIRE_OBSERVED '):
            match = re.fullmatch(r'IPV4_SOURCE_WIRE_OBSERVED case=(\d+) packets=(\d+)', line)
            require(match and phase == 'active' and int(match[1]) == current and
                    (current in mutations) == (cases[current]['kind'] == 'held') and
                    (current in clocked) == cases[current]['clocked'],
                    'ordered observation and required mutation')
            current += 1
            phase = 'ready'
        elif line.startswith('IPV4_SOURCE_WIRE_PASS '):
            match = re.fullmatch(r'IPV4_SOURCE_WIRE_PASS cases=(\d+)', line)
            require(match and phase == 'ready' and current == count and int(match[1]) == count,
                    'complete successful shared process')
            passes += 1
            phase = 'complete'
        else:
            raise ValueError('unknown or failed source-route client record')
    require(kernels == passes == 1 and phase == 'complete' and current == count,
            'complete kernel, cases and process completion')
    for number, row in enumerate(cases):
        values = clocks(text, number, count)
        require(set(values) == ({'before', 'after'} if row['clocked'] else {'before'}),
                'complete actual source-clock set')
        if row['clocked']:
            require(values['after']['monotonic_before_ns'] >= values['before']['monotonic_after_ns'],
                    'ordered actual source-clock observations')
    return [raw_packets(text, number, count) for number in range(count)]


def normalized(frame, *, reference=False, source_before_ms=None, source_after_ms=None):
    value = bytes.fromhex(frame) if isinstance(frame, str) else frame
    require(len(value) >= 34 and value[12:14] == b'\x08\x00', 'complete Ethernet IPv4 output')
    size = int.from_bytes(value[16:18], 'big')
    require(20 <= size <= len(value) - 14 and
            (len(value) == size + 14 or
             (len(value) == 60 and size + 14 < 60 and not any(value[size + 14:]))),
            'exact IPv4 length and only minimum zero Ethernet padding')
    packet = bytearray(value[14:14 + size])
    header = (packet[0] & 15) * 4
    require(packet[0] >> 4 == 4 and 20 <= header <= len(packet) and
            checksum(bytes(packet[:header])) == 0, 'actual IPv4 header checksum')
    if packet[12:16] != bytes((10, 0, 0, 2)):
        packet[4:6] = bytes(2)
        packet[10:12] = bytes(2)
    for at, kind, length in option_fields(packet):
        if kind == 68:
            require(length >= 4 and packet[at + 3] & 15 == 1, 'fixed address/timestamp corpus mode')
            stamp = at + packet[at + 2] - 5
            require(at + 8 <= stamp and stamp + 4 <= at + length, 'complete recorded timestamp slot')
            timestamp = int.from_bytes(packet[stamp:stamp + 4], 'big')
            require(timestamp < DAY_MS, 'actual UTC timestamp range')
            if not reference:
                require(type(source_before_ms) is int and type(source_after_ms) is int and
                        0 <= source_after_ms - source_before_ms < 5000,
                        'bounded actual guest/native source-clock interval')
                delta = (timestamp - source_before_ms % DAY_MS + DAY_MS + 20) % DAY_MS
                require(delta <= source_after_ms - source_before_ms + 40,
                        'wire timestamp belongs to the actual source interval with original 20ms precision')
            packet[stamp:stamp + 4] = bytes(4)
            packet[10:12] = bytes(2)
    return value[:14], bytes(packet)
