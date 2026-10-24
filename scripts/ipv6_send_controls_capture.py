# SPDX-License-Identifier: GPL-3.0-or-later
"""Reconstruct complete controlled sends from original captures and application input bytes."""
import copy
import hashlib
import ipaddress
import json
from pathlib import Path
import re
import struct
import zipfile
from ipv4_expiry_capture import checksum, encode_capture, read_capture


def require(value, reason):
    if not value:
        raise ValueError(reason)


def address(lane, host, scoped):
    return ipaddress.IPv6Address(f'fe80::{host:x}' if scoped else f'2001:db8:{lane + 1}::{host:x}').packed


def policy(sequence, lane, minus_one_class):
    require(0 <= sequence < 96, 'bounded captured send-control case')
    variant, scope, kind = sequence % 24, sequence % 48 // 24, sequence // 48 + 2
    size = 16384 if variant == 8 else 2048 if variant in (6, 7) else 128
    errors = {7: 90, 13: 19, 14: 22, 15: 22, 16: 22, 17: 22, 18: 22,
              19: 22, 20: 14, 21: 22, 23: 22}
    hop = {4: 43, 8: 43, 9: 0, 10: 255, 12: 44}.get(variant, 33)
    traffic = {5: 0xab, 8: 0xab, 10: 255, 11: minus_one_class, 12: 0xac}.get(variant, 18)
    source = address(lane ^ 1, 2, 0) if variant == 22 else address(lane, 2, scope)
    return dict(destination=address(lane, 100 + sequence if variant == 8 else 1, scope), kind=kind, scope=scope, variant=variant, size=size, error=errors.get(variant, 0),
                hop=hop, traffic=traffic, source=source, fragmented=variant in (6, 8))


def input_control(sequence, lane, indices):
    variant, scoped = sequence % 24, sequence // 24 % 2
    data = bytearray(b'\xa5' * 192)
    used = 0
    def append(kind, payload):
        nonlocal used
        length = 16 + len(payload)
        aligned = (length + 7) & ~7
        data[used:used + aligned] = struct.pack('<Qii', length, 41, kind) + payload + bytes(aligned - length)
        used += aligned
    def integer(kind, value):
        append(kind, struct.pack('<i', value))
    if variant in (1, 2, 3, 8, 13, 14, 15, 22, 23):
        source, index = address(lane, 2, scoped), indices[lane]
        if variant == 2:
            index = 0
        if variant in (3, 23):
            source = bytes(16)
        if variant == 13:
            index = 0x7ffffffe
        if variant == 14:
            source = address(lane, 77, scoped)
        if variant == 15:
            source = ipaddress.IPv6Address('::1').packed
        if variant == 22:
            source = address(lane ^ 1, 2, 0)
        if variant == 23:
            index = indices[lane ^ 1]
        append(50, source + struct.pack('<I', index))
    if variant in (4, 8, 12, 19, 21):
        integer(52, 43)
    if variant in (5, 8, 12):
        integer(67, 0xab)
    if variant in (6, 8):
        integer(62, 0)
    if variant == 7:
        integer(62, 1)
    if variant == 9:
        integer(52, 0)
    if variant == 10:
        integer(52, 255)
        integer(67, 255)
    if variant == 11:
        integer(52, -1)
        integer(67, -1)
    if variant == 12:
        integer(52, 44)
        integer(67, 0xac)
    if variant in (16, 17, 18):
        integer({16: 52, 17: 67, 18: 62}[variant], 2 if variant == 18 else 256)
    if variant == 21:
        data[:8] = struct.pack('<Q', 15)
    return bytes(data), 19 if variant == 19 else 20 if variant == 20 else used


def application(log, lane, index, minus_one_class):
    log = log.replace('\r\n', '\n')
    interfaces = re.findall(r'^IPV6_SEND_WIRE_INTERFACE lane=(\d+) index=(\d+)$', log, re.MULTILINE)
    require(len(interfaces) == 2 and {int(row[0]) for row in interfaces} == {0, 1}, 'both actual output-control interfaces')
    indices = {int(link): int(value) for link, value in interfaces}
    require(len(set(indices.values())) == 2 and all(0 < value < 2**32 for value in indices.values()) and
            indices[lane] == index, 'actual independently recorded output interface indices')
    require(log.splitlines().count('IPV6_SEND_WIRE_DONE adapters=2 cases=192 variants=24 scopes=2 transports=2') == 1 and
            'IPV6_SEND_WIRE_FAIL' not in log, 'actual complete original controlled-output client')
    for link in range(2):
        require(log.splitlines().count(f'IPV6_SEND_WIRE_PASS lane={link} cases=96 scopes=2 variants=24') == 1,
                'both complete original ancillary-output adapters')
    fields = {'lane', 'case', 'type', 'scope', 'variant', 'named', 'bytes', 'result', 'errno',
              'length', 'hops', 'class', 'df', 'control'}
    seen = set()
    for line in log.splitlines():
        if not line.startswith('IPV6_SEND_WIRE_CASE '):
            continue
        pairs = [item.split('=', 1) for item in line.split()[1:]]
        row = dict(pairs)
        require(len(pairs) == len(fields) and set(row) == fields and
                all(re.fullmatch(r'-?\d+', row[key]) for key in fields - {'control'}) and
                re.fullmatch('[0-9a-f]{384}', row['control']) is not None, 'exact original output observation fields')
        actual = {key: int(row[key]) for key in fields - {'control'}}
        link, number = actual['lane'], actual['case']
        require(link in (0, 1) and (link, number) not in seen, 'unique controlled-output observation')
        wanted = policy(number, link, minus_one_class)
        control, capacity = input_control(number, link, indices)
        expected = dict(lane=link, case=number, type=wanted['kind'], scope=wanted['scope'],
                        variant=wanted['variant'], named=wanted['variant'] & 1, bytes=wanted['size'],
                        result=-1 if wanted['error'] else wanted['size'], errno=wanted['error'],
                        length=capacity, hops=33, **{'class': 18}, df=int(wanted['variant'] in (6, 8)))
        require(actual == expected and bytes.fromhex(row['control']) == control,
                'every original result, unchanged shared option, ancillary byte and padding byte')
        seen.add((link, number))
    require(seen == {(link, number) for link in range(2) for number in range(96)}, 'all 192 original send observations')


def boundary(rows, lane):
    guest = bytes.fromhex('5254001234') + bytes([0x10 + lane])
    hits = [n for n, row in enumerate(rows) if row['frame'][6:12] == guest and
            row['frame'][12:21] == b'\x88\xc0IP6W' + bytes([lane, 0, 0])]
    require(len(hits) == 1, 'one original ancillary phase boundary')
    return hits[0]


def stamp(row):
    return row.get('monotonic_ns', row['ns'])


def inspect(rows, lane, log, native=False, interface_index=None, native_send_class=None):
    if native:
        require(interface_index is not None and native_send_class in (18, 255), 'independent native interface and send model')
    else:
        interface_index, native_send_class = lane + 1, 255
    from ipv6_extension_capture import boundary as extension_boundary
    rows = rows[:extension_boundary(rows, lane)]
    application(log, lane, interface_index, native_send_class)
    start = boundary(rows, lane)
    guest = bytes.fromhex('5254001234') + bytes([0x10 + lane])
    control, peer = bytes([2, 73, 80, 54, lane, 0]), bytes([2, 73, 80, 54, lane, 1])
    ready = acknowledged = False
    active = None
    completed = mld = 0
    data, fragments, quiet, groups, calls = [], [], [], {}, {}
    identities = set()
    ownership = []
    # Preserve capture positions while ordering native events by original packet clocks.
    ordered = sorted(range(start, len(rows)), key=lambda at: (stamp(rows[at]), at)) if native else range(start, len(rows))
    for at in ordered:
        row, frame = rows[at], rows[at]['frame']
        if frame[12:14] == b'\x88\xc0':
            require(len(frame) == 60 and frame[14:19] == b'IP6W' + bytes([lane]) and
                    frame[20] in (0, 1) and not any(frame[21:]) and
                    frame[:12] == (guest + control if frame[20] else control + guest),
                    'exact original ancillary boundary and direction')
            phase, reply = frame[19], frame[20]
            if phase >= 193:
                require(active is not None and active['policy']['variant'] == 8 and
                        phase == 193 + active['number'] // 24,
                        'mutation exchange belongs to one queued control owner')
                if reply:
                    require('mutation_request' in active and 'mutation_ack' not in active and
                            stamp(row) >= stamp(rows[active['mutation_request']]),
                            'mutation acknowledgement follows original completed mutation request')
                    active['mutation_ack'] = at
                else:
                    require('mutation_request' not in active, 'one original completed mutation request')
                    active['mutation_request'] = at
                continue
            if phase == 0:
                require(not acknowledged and (ready if reply else not ready), 'one owned ancillary readiness exchange')
                if reply:
                    acknowledged = True
                else:
                    ready = True
                continue
            number = (phase - 1) // 2
            require(acknowledged and number == completed and number < 96, 'ordered original ancillary case')
            if phase & 1 and not reply:
                require(active is None, 'one original controlled send begin')
                active = dict(number=number, policy=policy(number, lane, native_send_class), start=None,
                              end=None, done=False, body=bytearray(), identity=None, pieces=[])
            elif phase & 1:
                require(active is not None and active['start'] is None, 'one original begin acknowledgement')
                active['start'] = at
            elif not reply:
                require(active is not None and active['start'] is not None and active['end'] is None,
                        'one original end request')
                active['end'] = at
            else:
                require(active is not None and active['end'] is not None, 'one original end acknowledgement')
                require(stamp(row) >= stamp(rows[active['end']]), 'controlled end acknowledgement clock follows request')
                require('last_data' not in active or stamp(row) >= stamp(rows[active['last_data']]), 'controlled end acknowledgement clock follows all data')
                if active['policy']['error']:
                    require(not active['body'] and not active['done'] and stamp(row) - stamp(rows[active['end']]) >= 50000000,
                            'rejected controlled send emits no data throughout the full fifty-millisecond observation')
                    quiet.append((active['end'], at))
                else:
                    require(active['done'], 'original end acknowledgement follows the complete controlled datagram')
                    if active['policy']['variant'] == 8:
                        ownership.append((active['mutation_request'], active['mutation_ack'],
                                          active['deferred_probe'], active['deferred_release']))
                completed += 1
                active = None
            continue
        require(acknowledged and frame[12:14] == b'\x86\xdd' and len(frame) >= 54,
                'complete original ancillary-output IPv6 envelope')
        length, protocol, hop = struct.unpack_from('!HBB', frame, 18)
        require(len(frame) >= 54 + length, 'complete original controlled payload')
        source, target, body = frame[22:38], frame[38:54], frame[54:54 + length]
        if native and protocol == 0:
            report = body[8:]
            require(frame[:12] == bytes.fromhex('333300000016') + guest and
                    frame[14:18] == b'\x60\0\0\0' and hop == 1 and source in (bytes(16), address(lane, 2, 1)) and
                    target == ipaddress.IPv6Address('ff02::16').packed and body[:8] == b'\x3a\0\5\2\0\0\1\0' and
                    len(report) >= 8 and report[:2] == b'\x8f\0' and
                    not checksum(source + target + struct.pack('!I3xB', len(report), 58) + report), 'owned original native MLD report')
            mld += 1
            continue
        if protocol == 58 and body[:1] in (b'\x87', b'\x88'):
            require(frame[14:18] == b'\x60\0\0\0' and hop == 255 and len(body) == 32 and
                    not checksum(source + target + struct.pack('!I3xB', length, 58) + body), 'original controlled neighbor envelope')
            if body[0] == 135:
                destination = body[8:24]
                group = b'\xff\x02' + bytes(9) + b'\1\xff' + destination[-3:]
                deferred = active is not None and active['policy']['variant'] == 8 and destination == active['policy']['destination']
                require((destination in (address(lane, 1, 0), address(lane, 1, 1)) or deferred) and
                        source in (address(lane, 2, 0), address(lane, 2, 1)) and
                        (target == group and frame[:12] == b'\x33\x33' + group[-4:] + guest or
                         target == destination and frame[:12] == peer + guest) and body[:2] == b'\x87\0' and
                        body[4:8] == bytes(4) and body[24:] == b'\1\1' + guest, 'owned multicast or unicast neighbor solicitation')
                if deferred:
                    require('deferred_probe' not in active, 'one original unresolved neighbor probe')
                    active['deferred_probe'] = at
            else:
                deferred = active is not None and active['policy']['variant'] == 8 and source == active['policy']['destination']
                require(frame[:12] == guest + peer and (source in (address(lane, 1, 0), address(lane, 1, 1)) or deferred) and
                        target in (address(lane, 2, 0), address(lane, 2, 1)) and body[:2] == b'\x88\0' and
                        body[4:8] == b'\x60\0\0\0' and body[8:24] == source and body[24:] == b'\2\1' + peer,
                        'owned original neighbor advertisement')
                if deferred:
                    require('deferred_probe' in active and 'mutation_ack' in active and
                            'deferred_release' not in active and stamp(row) >= stamp(rows[active['mutation_ack']]) and
                            stamp(row) >= stamp(rows[active['deferred_probe']]),
                            'actual queued neighbor release follows copied input mutation and owner retirement')
                    active['deferred_release'] = at
            continue
        require(active is not None and active['start'] is not None and not active['done'] and
                not active['policy']['error'], 'one actual datagram belongs to its accepted ancillary send')
        require(stamp(row) >= stamp(rows[active['start']]), 'controlled data clock follows begin acknowledgement')
        wanted = active['policy']
        if wanted['variant'] == 8:
            require('deferred_release' in active and stamp(row) >= stamp(rows[active['deferred_release']]),
                    'every actual queued fragment follows independent neighbor release')
        require(frame[:12] == peer + guest and source == wanted['source'] and target == wanted['destination'] and
                struct.unpack_from('!I', frame, 14)[0] == (6 << 28 | wanted['traffic'] << 20) and
                hop == wanted['hop'] and length + 40 <= 1500, 'every original packet source, route, hop, class and MTU')
        data.append(at)
        active['last_data'] = at
        calls.setdefault(active['number'], at)
        if protocol == 44:
            require(wanted['fragmented'] and len(body) > 8 and body[1] == 0, 'permitted original controlled Fragment header')
            protocol, _, offset, identity = struct.unpack_from('!BBHI', body)
            require(identity and not offset & 6 and offset & 0xfff8 == len(active['body']), 'contiguous original controlled fragments')
            if active['identity'] is None:
                require((source, target, identity) not in identities, 'fresh controlled datagram identification')
                identities.add((source, target, identity))
                active['identity'] = identity
            require(active['identity'] == identity and len(active['body']) + len(body) - 8 <=
                    wanted['size'] + (8 if wanted['kind'] == 2 else 0), 'stable original identification and reassembly bounds')
            active['body'].extend(body[8:])
            active['pieces'].append(at)
            fragments.append(at)
            if offset & 1:
                require((len(body) - 8) % 8 == 0, 'aligned original nonfinal controlled fragment')
                continue
            body = bytes(active['body'])
            groups[active['number']] = list(active['pieces'])
        else:
            require(not active['body'] and not wanted['fragmented'], 'every oversized accepted controlled datagram uses actual fragments')
        require(protocol == (17 if wanted['kind'] == 2 else 58) and
                not checksum(source + target + struct.pack('!I3xB', len(body), protocol) + body),
                'complete original controlled transport checksum')
        payload = bytes((n * 19 + active['number'] * 11 + lane) & 255 for n in range(wanted['size']))
        if wanted['kind'] == 2:
            require(len(body) == wanted['size'] + 8 and struct.unpack_from('!HHH', body) ==
                    (47000 + lane + wanted['scope'] * 10, 48000 + lane + wanted['scope'] * 10, len(body)) and
                    body[6:8] != bytes(2) and body[8:] == payload, 'every original controlled UDP field and byte')
        else:
            require(len(body) == wanted['size'] and body[:2] + bytes(2) + body[4:] == b'\x81\0\0\0' + payload[4:],
                    'every original controlled raw application byte')
        active['done'] = True
    require(acknowledged and completed == 96 and active is None and len(quiet) == 44 and len(groups) == 8,
            'complete controlled output, fragmentation and rejection inventory')
    require(len(ownership) == 4, 'four actual deferred ownership conversations')
    require(all(len(groups[number]) > 8 for number in (8, 32, 56, 80)), 'large queued datagrams extend beyond one eight-piece submission batch')
    return dict(passed=True, lane=lane, cases=completed, fragment_groups=len(groups), fragments=len(fragments),
                deferred_ownership=len(ownership), negative_cases=len(quiet), minimum_quiet_ms=min((stamp(rows[b]) - stamp(rows[a])) / 1000000 for a, b in quiet),
                native_minus_one_class=native_send_class, native_MLD_reports=mld), dict(
                    data=data, fragments=fragments, quiet=quiet, groups=groups, calls=calls, ownership=ownership)


def verify_capture(path, lane, log_path, archive, native=False, interface_index=None, native_send_class=None):
    path, log_path = Path(path), Path(log_path)
    original, original_log = path.read_bytes(), log_path.read_bytes()
    rows, log = read_capture(path), original_log.decode(errors='replace')
    result, proof = inspect(rows, lane, log, native, interface_index, native_send_class)
    names = ('missing-data', 'duplicate-data', 'fragment-id', 'fragment-offset', 'fragment-hop',
             'fragment-class', 'checksum', 'valid-checksum-wrong-source', 'valid-checksum-wrong-payload',
             'valid-checksum-queued-payload', 'wrong-MAC', 'wrong-class', 'wrong-hop', 'wrong-model-class',
             'wrong-input-index', 'written-input-padding', 'changed-sticky', 'wrong-result',
             'missing-case', 'duplicate-case', 'emitted-despite-DF', 'missing-end-ACK', 'short-quiet',
             'data-before-begin-ACK', 'end-ACK-before-data', 'missing-mutation-ACK',
             'missing-deferred-probe', 'early-neighbor-release')
    rejected = []
    with zipfile.ZipFile(archive, 'w', zipfile.ZIP_DEFLATED) as saved:
        for name in names:
            changed, text = copy.deepcopy(rows), log
            index = proof['data'][0]
            if name in ('missing-mutation-ACK', 'missing-deferred-probe', 'early-neighbor-release'):
                _, ack, probe, release = proof['ownership'][0]
                if name == 'missing-mutation-ACK':
                    del changed[ack]
                elif name == 'missing-deferred-probe':
                    del changed[probe]
                else:
                    changed[release]['ns'] = changed[ack]['ns'] - 1000
                    changed[release]['monotonic_ns'] = stamp(changed[ack]) - 1000
            elif name in ('data-before-begin-ACK', 'end-ACK-before-data'):
                data = proof['data'][0]
                before = next(n for n in range(len(changed)) if changed[n]['frame'][12:14] == b'\x88\xc0' and
                             changed[n]['frame'][19:21] == b'\x01\x01')
                after = next(n for n in range(len(changed)) if
                             changed[n]['frame'][12:14] == b'\x88\xc0' and
                             changed[n]['frame'][19:21] == b'\x02\x01')
                target, reference = (data, before) if name == 'data-before-begin-ACK' else (after, data)
                changed[target]['ns'] = changed[reference]['ns'] - 1000
                changed[target]['monotonic_ns'] = stamp(changed[reference]) - 1000
            elif name == 'missing-data':
                del changed[index]
            elif name == 'duplicate-data':
                changed.insert(index, copy.deepcopy(changed[index]))
            elif name in ('missing-end-ACK', 'short-quiet', 'emitted-despite-DF'):
                begin, end = proof['quiet'][0]
                if name == 'missing-end-ACK':
                    del changed[end]
                elif name == 'short-quiet':
                    changed[end]['ns'] = changed[begin]['ns'] + 49000000
                    changed[end]['monotonic_ns'] = stamp(changed[begin]) + 49000000
                else:
                    unexpected = copy.deepcopy(changed[index])
                    unexpected['ns'] = changed[begin]['ns'] + 1
                    unexpected['monotonic_ns'] = stamp(changed[begin]) + 1
                    changed.insert(begin + 1, unexpected)
            elif name in ('wrong-input-index', 'written-input-padding', 'changed-sticky', 'wrong-result', 'missing-case', 'duplicate-case'):
                lines = text.splitlines()
                number = 1 if name in ('wrong-input-index', 'written-input-padding') else 0
                at = next(n for n, line in enumerate(lines) if line.startswith(f'IPV6_SEND_WIRE_CASE lane={lane} case={number} '))
                if name == 'missing-case':
                    del lines[at]
                elif name == 'duplicate-case':
                    lines.insert(at, lines[at])
                else:
                    row = dict(item.split('=', 1) for item in lines[at].split()[1:])
                    if name in ('changed-sticky', 'wrong-result'):
                        key = 'class' if name == 'changed-sticky' else 'result'
                        row[key] = str(int(row[key]) ^ 1)
                    else:
                        data = bytearray.fromhex(row['control'])
                        data[32 if name == 'wrong-input-index' else 36] ^= 1
                        row['control'] = data.hex()
                    lines[at] = 'IPV6_SEND_WIRE_CASE ' + ' '.join(key + '=' + value for key, value in row.items())
                text = '\n'.join(lines) + '\n'
            elif name == 'valid-checksum-queued-payload':
                group = proof['groups'][8]
                frames = [bytearray(changed[n]['frame']) for n in group]
                payload = bytearray().join(frame[62:54 + int.from_bytes(frame[18:20], 'big')] for frame in frames)
                payload[-1] ^= 1
                payload[6:8] = bytes(2)
                value = checksum(bytes(frames[0][22:54]) + struct.pack('!I3xB', len(payload), 17) + payload)
                frames[0][68:70] = value.to_bytes(2, 'big')
                frames[-1][54 + int.from_bytes(frames[-1][18:20], 'big') - 1] ^= 1
                for n, frame in zip(group, frames):
                    changed[n]['frame'] = bytes(frame)
            else:
                if name.startswith('fragment-'):
                    index = proof['fragments'][1 if name in ('fragment-hop', 'fragment-class') else 0]
                elif name == 'wrong-model-class':
                    index = proof['calls'][11]
                frame = bytearray(changed[index]['frame'])
                if name == 'wrong-model-class':
                    wrong = 18 if result['native_minus_one_class'] == 255 else 255
                    struct.pack_into('!I', frame, 14, 6 << 28 | wrong << 20)
                else:
                    offset = {'fragment-id': 58, 'fragment-offset': 57, 'fragment-hop': 21,
                              'fragment-class': 15, 'checksum': 60, 'valid-checksum-wrong-source': 37,
                              'valid-checksum-wrong-payload': 75, 'wrong-MAC': 0, 'wrong-class': 15, 'wrong-hop': 21}[name]
                    frame[offset] ^= 1
                    if name.startswith('valid-checksum-'):
                        frame[60:62] = bytes(2)
                        length = int.from_bytes(frame[18:20], 'big')
                        frame[60:62] = checksum(bytes(frame[22:54]) + struct.pack('!I3xB', length, 17) +
                                               bytes(frame[54:54 + length])).to_bytes(2, 'big')
                changed[index]['frame'] = bytes(frame)
            saved.writestr(name + '.pcap', encode_capture(changed))
            saved.writestr(name + '.log', text)
            try:
                inspect(changed, lane, text, native, interface_index, native_send_class)
            except ValueError as failure:
                rejected.append(dict(name=name, reason=str(failure)))
            else:
                raise ValueError('accepted damaged controlled-output evidence: ' + name)
        saved.writestr('rejections.json', json.dumps(rejected, indent=2))
    require(path.read_bytes() == original and log_path.read_bytes() == original_log,
            'all original controlled-output packets and logs remain unchanged')
    result.update(damaged_rejected=len(rejected), original_sha256=hashlib.sha256(original).hexdigest(),
                  archive_sha256=hashlib.sha256(Path(archive).read_bytes()).hexdigest(), native_clock_qualified=False)
    return result
