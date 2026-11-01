# SPDX-License-Identifier: GPL-3.0-or-later
"""Decode original address-control bytes and real lifetime observations offline."""
import argparse
from collections import Counter
import json
from pathlib import Path
import re
import struct

INFINITE = 0xffffffff
SECONDARY, DEPRECATED, PERMANENT = 1, 0x20, 0x80
CLOCK_BOUND_NS = 100_000_000


def require(condition, message):
    if not condition:
        raise ValueError(message)


def decode(text):
    def unique(pairs):
        result = {}
        for key, value in pairs:
            require(key not in result, 'unique JSON keys')
            result[key] = value
        return result
    return json.loads(text, object_pairs_hook=unique)


def attributes(data):
    result = {}
    at = 0
    while at < len(data):
        require(len(data) - at >= 4, 'complete attribute header')
        length, kind = struct.unpack_from('<HH', data, at)
        require(4 <= length <= len(data) - at and kind not in result, 'unique bounded attribute')
        result[kind] = data[at + 4:at + length]
        at += (length + 3) & ~3
        require(at <= len(data), 'aligned attribute bytes')
    return result


def messages(data):
    result = []
    at = 0
    while at < len(data):
        require(len(data) - at >= 16, 'complete netlink header')
        length, kind, flags, sequence, port = struct.unpack_from('<IHHII', data, at)
        require(16 <= length <= len(data) - at, 'bounded netlink message')
        result.append(dict(kind=kind, flags=flags, sequence=sequence, port=port,
                           body=data[at + 16:at + length]))
        at += (length + 3) & ~3
        require(at <= len(data), 'aligned netlink message')
    return result


def specifications():
    result = []

    def change(phase, address, flags, cache=None, label=None, error=0, remove=False):
        result.append(dict(phase=phase, kind=21 if remove else 20, address=address, flags=flags | 5,
                           cache=cache, label=label, error=error))

    def dump(phase, address):
        result.append(dict(phase=phase, kind=22, address=address, flags=0x301))

    change('finite-create', 'first', 0x600, (1, 3, 16))
    dump('finite-create', 'first')
    change('secondary-create', 'alias', 0)
    change('permanent-finite-preferred', 'permanent', 0x100, (1, INFINITE, 16))
    change('permanent-deprecated', 'deprecated', 0x400, (0, INFINITE, 16))
    change('invalid-zero', 'first', 0x100, (0, 0, 16), error=-22)
    change('invalid-order', 'first', 0x100, (4, 3, 16), error=-22)
    change('invalid-short', 'first', 0x100, (1, 3, 12), error=-34)
    change('exclusive-existing', 'first', 0x300, (1, 3, 16), error=-17)
    for name in ('first', 'permanent', 'deprecated'):
        dump('finite-deprecated', name)
    change('finite-renew', 'first', 0x100, (2, 4, 20), 'ignored')
    dump('finite-renew', 'first')
    dump('renewed-deprecated', 'first')
    for name in ('first', 'alias', 'permanent', 'deprecated'):
        dump('finite-expired', name)
    for scope in ('device', 'global'):
        phase = scope + '-promote-create'
        change(phase, 'first', 0x600, (0, 1, 16))
        change(phase, 'alias', 0x600)
        dump(phase, 'alias')
        phase = scope + '-promoted'
        dump(phase, 'first')
        dump(phase, 'alias')
        change(phase, 'alias', 0, remove=True)
    for name in ('permanent', 'deprecated'):
        change('cleanup', name, 0, remove=True)
    require(len(result) == 33, 'complete fixed control inventory')
    return result


def request(message, spec, lane, index):
    require(message['kind'] == spec['kind'] and message['flags'] == spec['flags'] and
            message['port'] == 0 and len(message['body']) >= 8, 'original request kind flags and port')
    family, prefix, flags, scope, device = struct.unpack_from('<BBBBI', message['body'])
    require(family == 2, 'actual IPv4 request')
    if spec['kind'] == 22:
        require(message['body'] == b'\2' + bytes(7), 'complete unfiltered IPv4 inventory request')
        return index
    require(prefix == 24 and flags == 0xa1 and scope == 0 and device > 0,
            'actual address scope prefix flags and interface')
    require(index is None or index == device, 'one selected interface per lane')
    first = 0xc6122002 + lane * 0x1000
    values = dict(first=first, alias=first + 1, permanent=first + 256, deprecated=first + 512)
    fields = attributes(message['body'][8:])
    expected = {1: struct.pack('>I', values[spec['address']]), 2: struct.pack('>I', values[spec['address']]),
                4: bytes(4), 8: struct.pack('<I', 0xa1)}
    if spec['label'] is not None:
        expected[3] = spec['label'].encode() + b'\0'
    if spec['cache']:
        preferred, valid, size = spec['cache']
        expected[6] = (struct.pack('<IIII', preferred, valid, 0x12345678, 0x87654321) + b'\xa5' * 4)[:size]
    require(fields == expected, 'every original mutation attribute and caller-owned stamp byte')
    return device


def selected_address(replies, index, address):
    selected = []
    for reply in replies:
        require(reply['kind'] in (20, 3) and reply['flags'] & 2 and not reply['flags'] & 0x10,
                'uninterrupted multipart address response')
        if reply['kind'] == 3:
            require(reply['body'] == bytes(4), 'complete successful dump status')
            continue
        require(len(reply['body']) >= 8, 'complete address response header')
        family, prefix, header_flags, scope, device = struct.unpack_from('<BBBBI', reply['body'])
        fields = attributes(reply['body'][8:])
        require(family == 2 and 1 in fields and 2 in fields and fields[1] == fields[2] and
                len(fields[2]) == 4 and len(fields.get(6, b'')) == 16 and len(fields.get(8, b'')) == 4,
                'complete IPv4 address local peer flags and cache fields')
        flags = struct.unpack('<I', fields[8])[0]
        require(header_flags == flags & 255, 'header and extended flags agree')
        if device == index and fields[2] == struct.pack('>I', address):
            label = fields.get(3, b'')
            require(prefix == 24 and scope == 0 and 1 <= len(label) <= 16 and label[-1] == 0 and
                    b'\0' not in label[:-1] and len(fields.get(4, bytes(4))) == 4,
                    'selected prefix scope label and broadcast')
            selected.append(dict(flags=flags, cache=struct.unpack('<IIII', fields[6]), label=label,
                                 broadcast=fields.get(4, bytes(4))))
    require(len(selected) <= 1 and replies[-1]['kind'] == 3 and
            sum(reply['kind'] == 3 for reply in replies) == 1, 'one terminal completion and selected identity')
    return selected[0] if selected else None


def verify(path, *, stamp_epoch=(0, 0)):
    require(type(stamp_epoch) is tuple and len(stamp_epoch) == 2 and
            all(type(value) is int for value in stamp_epoch) and
            0 <= stamp_epoch[1] - stamp_epoch[0] <= 3, 'bounded independently observed stamp-clock relation')
    text = Path(path).read_text().replace('\r\n', '\n')
    require('IPV4_LIFETIME_FAIL' not in text and text.splitlines().count(
            'IPV4_LIFETIME_PASS interfaces=2 finite permanent renew cacheinfo cascade promote fresh_bind') == 1,
            'one completed original client without failure')
    records = []
    fields = {'lane', 'phase', 'direction', 'monotonic_before_ns', 'monotonic_after_ns',
              'realtime_before_ns', 'realtime_after_ns', 'bytes'}
    offsets = []
    previous = 0
    for line in text.splitlines():
        if not line.startswith('IPV4_LIFETIME_RECORD'):
            continue
        require(line.startswith('IPV4_LIFETIME_RECORD '), 'complete record prefix')
        value = decode(line.partition(' ')[2])
        require(set(value) == fields and type(value['lane']) is int and value['lane'] in (0, 1) and
                value['direction'] in ('request', 'reply') and type(value['phase']) is str,
                'exact original observation schema')
        for clock in ('monotonic', 'realtime'):
            before, after = (value[clock + suffix] for suffix in ('_before_ns', '_after_ns'))
            require(type(before) is int and type(after) is int and 0 <= before <= after < 1 << 63,
                    'actual ordered clock brackets')
            require(after - before <= CLOCK_BOUND_NS, 'bounded original syscall clock bracket')
        require(value['monotonic_before_ns'] >= previous, 'ordered actual monotonic observations')
        previous = value['monotonic_after_ns']
        for suffix in ('_before_ns', '_after_ns'):
            offsets.append(value['realtime' + suffix] - value['monotonic' + suffix])
        require(type(value['bytes']) is str and re.fullmatch(r'(?:[0-9a-f]{2})+', value['bytes']),
                'complete original canonical message bytes')
        value['messages'] = messages(bytes.fromhex(value['bytes']))
        records.append(value)
    require(offsets and max(offsets) - min(offsets) <= CLOCK_BOUND_NS,
            'native or guest realtime and monotonic observations have no clock jump')
    specs = specifications()
    at = 0
    observations = []
    for lane in (0, 1):
        index = None
        saved = {}
        first = 0xc6122002 + lane * 0x1000
        addresses = dict(first=first, alias=first + 1, permanent=first + 256, deprecated=first + 512)
        for number, spec in enumerate(specs):
            require(at < len(records), 'every required request remains present')
            row = records[at]
            require((row['lane'], row['phase'], row['direction']) == (lane, spec['phase'], 'request') and
                    len(row['messages']) == 1, 'fixed original request order')
            message = row['messages'][0]
            sequence = lane * len(specs) + number + 1
            require(message['sequence'] == sequence, 'original consecutive request identity')
            index = request(message, spec, lane, index)
            at += 1
            replies, receipt = [], None
            while at < len(records) and records[at]['direction'] == 'reply':
                receipt = records[at]
                require((receipt['lane'], receipt['phase']) == (lane, spec['phase']), 'matching reply campaign')
                replies.extend(receipt['messages'])
                at += 1
            require(replies and len({reply['port'] for reply in replies}) == 1 and replies[0]['port'] > 0 and
                    all(reply['sequence'] == sequence for reply in replies), 'matching authoritative reply ownership')
            if spec['kind'] != 22:
                require(len(replies) == 1 and replies[0]['kind'] == 2 and len(replies[0]['body']) >= 20 and
                        struct.unpack_from('<i', replies[0]['body'])[0] == spec['error'] and
                        replies[0]['body'][4:20] == bytes.fromhex(row['bytes'])[:16],
                        'actual mutation result and exact echoed original header')
                saved.setdefault((spec['phase'], 'request'), row)
                continue
            selected = selected_address(replies, index, addresses[spec['address']])
            key = spec['phase'], spec['address']
            saved[key] = dict(value=selected, request=row, receipt=receipt)
        observations.append(check_lifetimes(saved, lane, stamp_epoch))
    require(at == len(records), 'no omitted or surplus original control records')
    check_transport(text)
    check_policy(text)
    return dict(passed=True, lanes=2, requests=66, observations=observations,
                clock_offset_range_ns=max(offsets) - min(offsets), real_clock_qualification=True,
                policy_operations=20,
                stamp_epoch_range_cs=list(stamp_epoch),
                ethernet_or_guest_product_acceptance=False)


def check_lifetimes(saved, lane, stamp_epoch):
    def value(phase, name='first'):
        row = saved[(phase, name)]
        require(row['value'] is not None, 'required address is present')
        return row['value']

    initial = value('finite-create')
    require(initial['flags'] == 0 and initial['cache'][:2] == (1, 3), 'initial finite lifetime and flags')
    created = saved[('finite-create', 'request')]
    updated = saved[('finite-renew', 'request')]
    require(initial['cache'][2] == initial['cache'][3], 'initial creation and update stamps agree')

    def stamp_owned(stamp, begin, end):
        lower = begin['monotonic_before_ns'] // 10_000_000 + stamp_epoch[0]
        upper = end['monotonic_after_ns'] // 10_000_000 + stamp_epoch[1]
        require(((stamp - (lower - 3)) & INFINITE) <= upper - lower + 6,
                'kernel-owned centisecond stamp is bracketed by actual monotonic observations')

    stamp_owned(initial['cache'][2], created, saved[('finite-create', 'first')]['receipt'])
    for phase, begin, delay in (('finite-deprecated', created, 1_500_000_000),
                               ('renewed-deprecated', updated, 2_500_000_000),
                               ('finite-expired', updated, 4_500_000_000)):
        row = saved[(phase, 'first')]
        require(row['request']['monotonic_before_ns'] - begin['monotonic_after_ns'] >= delay,
                'original real elapsed deadline is preserved')
        if phase == 'finite-expired':
            require(row['value'] is None and saved[(phase, 'alias')]['value'] is None,
                    'valid expiry removes only the primary and matching secondary')
        else:
            current = value(phase)
            require(current['flags'] == DEPRECATED and current['cache'][0] == 0 and
                    1 <= current['cache'][1] <= 2, 'actual preferred expiry and remaining valid lifetime')
    aged, fresh = value('finite-deprecated'), value('finite-renew')
    stamp_owned(fresh['cache'][3], updated, saved[('finite-renew', 'first')]['receipt'])
    require(aged['cache'][2:] == initial['cache'][2:] and fresh['flags'] == 0 and
            fresh['cache'][:2] == (2, 4) and fresh['cache'][2] == initial['cache'][2] and
            fresh['cache'][3] != initial['cache'][3] and fresh['label'] == initial['label'] and
            fresh['broadcast'] == initial['broadcast'], 'rejected changes and renewal preserve owned identity')
    for phase in ('finite-deprecated', 'finite-expired'):
        for name, flags in (('permanent', PERMANENT), ('deprecated', PERMANENT | DEPRECATED)):
            current = value(phase, name)
            require(current['flags'] == flags and current['cache'][:2] == (INFINITE, INFINITE),
                    'permanent entries retain the IPv4 infinite-cache convention')
    for scope in ('device', 'global'):
        start = scope + '-promote-create'
        phase = scope + '-promoted'
        before, after = value(start, 'alias'), value(phase, 'alias')
        require(saved[(phase, 'first')]['value'] is None and before['flags'] == PERMANENT | SECONDARY and
                after['flags'] == PERMANENT and after['cache'] == before['cache'] and
                after['label'] == before['label'], 'promotion preserves secondary creation and update stamps')
        require(saved[(phase, 'first')]['request']['monotonic_before_ns'] -
                saved[(start, 'request')]['monotonic_after_ns'] >= 1_500_000_000,
                'actual primary expiry interval before promotion')
    return dict(lane=lane, finite_deprecation=True, renewal=True, valid_expiry=True,
                permanent_normalization=True, cascade=True, device_and_global_promotion=True)


def check_transport(text):
    sends = re.findall(r'^IPV4_LIFETIME_SEND lane=([01]) phase=finite-expired raw=([01]) result=-1 errno=101$', text, re.M)
    binds = re.findall(r'^IPV4_LIFETIME_BIND lane=([01]) phase=finite-expired address=([0-9a-f]{8}) result=-1 errno=99$', text, re.M)
    require(Counter(sends) == Counter((str(lane), str(raw)) for lane in (0, 1) for raw in (0, 1)) and
            Counter(binds) == Counter((str(lane), f'{0xc6122002 + lane * 0x1000:08x}') for lane in (0, 1)),
            'actual later UDP/raw send and fresh bind errors on both interfaces')
    require(len([line for line in text.splitlines() if line.startswith('IPV4_LIFETIME_SEND')]) == 4 and
            len([line for line in text.splitlines() if line.startswith('IPV4_LIFETIME_BIND')]) == 2,
            'no omitted malformed or surplus transport observations')


def check_policy(text):
    rows = []
    for line in text.splitlines():
        if not line.startswith('IPV4_LIFETIME_POLICY'):
            continue
        match = re.fullmatch(r'IPV4_LIFETIME_POLICY lane=([01]) phase=([a-z-]+) '
                             r'scope=(all|eth[01]) write=([01]) value=(-?\d+)', line)
        require(match is not None, 'complete original policy observation')
        lane, phase, scope, write, value = match.groups()
        require(-(1 << 31) <= int(value) < 1 << 31, 'actual signed policy integer')
        rows.append((int(lane), phase, scope, int(write), int(value)))
    require(len(rows) == 20, 'every original policy read and write remains present')
    expected = []
    for lane in (0, 1):
        actual = rows[lane * 10:(lane + 1) * 10]
        interface = 'eth' + str(lane)
        all_value, device_value = actual[0][-1], actual[1][-1]
        expected += [(lane, 'setup', 'all', 0, all_value),
                     (lane, 'setup', interface, 0, device_value),
                     (lane, 'setup', 'all', 1, 0), (lane, 'setup', interface, 1, 0),
                     (lane, 'device-promote-create', interface, 1, 1),
                     (lane, 'device-promoted', interface, 1, 0),
                     (lane, 'global-promote-create', 'all', 1, 1),
                     (lane, 'global-promoted', 'all', 1, 0),
                     (lane, 'cleanup', interface, 1, device_value),
                     (lane, 'cleanup', 'all', 1, all_value)]
    require(rows == expected, 'actual promotion scopes, transitions and restored original values')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('log', type=Path)
    args = parser.parse_args()
    print(json.dumps(verify(args.log)), flush=True)


if __name__ == '__main__':
    main()
