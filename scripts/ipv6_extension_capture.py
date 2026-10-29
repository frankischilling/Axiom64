# SPDX-License-Identifier: GPL-3.0-or-later
"""Independently reconstruct extension-bearing sends from original packets and inputs."""
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


def address(lane, host, scope):
    return ipaddress.IPv6Address(f'fe80::{host:x}' if scope else f'2001:db8:{lane + 1}::{host:x}').packed


def specification(number, lane):
    require(0 <= number < 64, 'bounded original extension observation')
    variant, scope, kind = number % 16, number % 32 // 16, number // 32 + 2
    sizes = {8: 2048, 9: 16384, 10: 2048}
    errors = {10: 90, 11: 22, 12: 22, 13: 1, 14: 22}
    hop = {1: 0, 4: 0, 6: 0, 7: 16, 9: 16}.get(variant, 8)
    destination = 0 if variant in (0, 6, 11, 12, 14) else 16 if variant in (7, 9) else 8
    return dict(variant=variant, scope=scope, kind=kind, size=sizes.get(variant, 128),
                error=errors.get(variant, 0), hop=hop, destination=destination,
                fragmented=variant in (8, 9), source=address(lane, 2, scope),
                target=address(lane, 160 + number if variant == 9 else 1, scope))


def option_header(length, value, following):
    return bytes([following, length // 8 - 1, 30, length - 4]) + bytes([value]) * (length - 4)


def original_control(number, lane, index):
    wanted = specification(number, lane)
    variant = wanted['variant']
    result = bytearray()
    def append(kind, payload):
        length = len(payload) + 16
        result.extend(struct.pack('<QII', length, 41, kind) + payload + bytes(-length % 8))
    def integer(kind, value):
        append(kind, struct.pack('<i', value))
    def extension(kind, size, value, malformed=False):
        data = bytearray(option_header(size, value, 250))
        if malformed:
            data[1] += 1
        append(kind, bytes(data))
    append(50, wanted['source'] + struct.pack('<I', index))
    integer(52, 47)
    integer(67, 0xcd)
    size = 16 if variant in (7, 9) else 8
    if variant in (3, 4):
        extension(59, 8, 0x11)
    if variant in (6, 15):
        extension(55, 8, 0x33)
    if variant not in (1, 4, 6):
        extension(3 if variant == 5 else 54, size, 0x44, variant == 12)
    if variant not in (0, 6, 11, 12, 14):
        extension(4 if variant == 5 else 59, size, 0x55)
    if variant in (11, 14):
        extension(3 if variant == 14 else 54, 8, 0x66)
    if variant in (8, 9, 10):
        integer(62, int(variant == 10))
    length = len(result)
    require(length <= 256, 'bounded independent extension input')
    return bytes(result) + b'\xa5' * (256 - length), length


def application(text, lane, index):
    text = text.replace('\r\n', '\n')
    require('IPV6_EXTENSION_WIRE_FAIL' not in text and text.splitlines().count(
        'IPV6_EXTENSION_WIRE_DONE adapters=2 cases=128 variants=16 scopes=2 transports=2') == 1,
        'actual complete extension application')
    interfaces = re.findall(r'^IPV6_SEND_WIRE_INTERFACE lane=(\d+) index=(\d+)$', text, re.MULTILINE)
    require(len(interfaces) == 2 and {int(row[0]) for row in interfaces} == {0, 1}, 'actual extension egress identities')
    indices = {int(link): int(value) for link, value in interfaces}
    require(indices[lane] == index and len(set(indices.values())) == 2 and all(value > 0 for value in indices.values()),
            'independent actual extension interface index')
    for link in range(2):
        require(text.splitlines().count(f'IPV6_EXTENSION_WIRE_PASS lane={link} cases=64 variants=16 scopes=2 transports=2') == 1,
                'both original extension adapters complete')
    keys = {'lane', 'case', 'type', 'scope', 'variant', 'named', 'bytes', 'result', 'errno',
            'length', 'hops', 'class', 'df', 'control'}
    seen = set()
    for line in text.splitlines():
        if not line.startswith('IPV6_EXTENSION_WIRE_CASE '):
            continue
        fields = [field.split('=', 1) for field in line.split()[1:]]
        row = dict(fields)
        require(len(fields) == len(keys) and set(row) == keys and
                all(re.fullmatch('-?[0-9]+', row[key]) for key in keys - {'control'}) and
                re.fullmatch('[0-9a-f]{512}', row['control']) is not None, 'exact original extension result fields')
        actual = {key: int(row[key]) for key in keys - {'control'}}
        link, number = actual['lane'], actual['case']
        require(link in (0, 1) and (link, number) not in seen, 'unique original extension call')
        wanted = specification(number, link)
        control, capacity = original_control(number, link, indices[link])
        expected = dict(lane=link, case=number, type=wanted['kind'], scope=wanted['scope'],
                        variant=wanted['variant'], named=(wanted['variant'] + wanted['scope']) % 2,
                        bytes=wanted['size'], result=-1 if wanted['error'] else wanted['size'],
                        errno=wanted['error'], length=capacity, hops=37, **{'class': 0x25},
                        df=int(wanted['variant'] in (8, 9)))
        require(actual == expected and bytes.fromhex(row['control']) == control,
                'every extension result, original ancillary byte, padding and shared option')
        seen.add((link, number))
    require(seen == {(link, number) for link in range(2) for number in range(64)}, 'all 128 original extension calls')


def boundary(rows, lane):
    guest = bytes.fromhex('5254001234') + bytes([0x10 + lane])
    hits = [n for n, row in enumerate(rows) if row['frame'][6:12] == guest and
            row['frame'][12:21] == b'\x88\xc1IP6X' + bytes([lane, 0, 0])]
    require(len(hits) == 1, 'one original extension readiness boundary')
    return hits[0]


def stamp(row):
    return row.get('monotonic_ns', row['ns'])


def inspect(rows, lane, text, native=False, interface_index=None):
    require(not native or interface_index is not None, 'independent native extension interface identity')
    from ipv6_routing_capture import boundary as routing_boundary
    rows = rows[:routing_boundary(rows, lane, optional=True)]
    application(text, lane, interface_index if native else lane + 1)
    start = boundary(rows, lane)
    guest = bytes.fromhex('5254001234') + bytes([0x10 + lane])
    control, peer = bytes([2, 73, 80, 54, lane, 0]), bytes([2, 73, 80, 54, lane, 1])
    ready = acknowledged = False
    active = None
    completed = mld = 0
    data, fragments, quiet, ownership = [], [], [], []
    calls, groups = {}, {}
    identities = set()
    order = sorted(range(start, len(rows)), key=lambda n: (stamp(rows[n]), n)) if native else range(start, len(rows))
    for at in order:
        row, frame = rows[at], rows[at]['frame']
        if frame[12:14] == b'\x88\xc1':
            require(len(frame) == 60 and frame[14:19] == b'IP6X' + bytes([lane]) and
                    frame[20] in (0, 1) and not any(frame[21:]) and
                    frame[:12] == (guest + control if frame[20] else control + guest), 'exact extension boundary direction and bytes')
            phase, reply = frame[19:21]
            if phase >= 193:
                require(active is not None and active['policy']['variant'] == 9 and phase == 193 + active['number'] // 16,
                        'mutation belongs to one original queued extension send')
                if reply:
                    require('mutation_request' in active and 'mutation_ack' not in active and
                            stamp(row) >= stamp(rows[active['mutation_request']]), 'extension mutation ACK follows original request')
                    active['mutation_ack'] = at
                else:
                    require('mutation_request' not in active, 'one extension mutation request')
                    active['mutation_request'] = at
                continue
            if phase == 0:
                require(not acknowledged and (ready if reply else not ready), 'one ordered extension readiness exchange')
                if reply:
                    acknowledged = True
                else:
                    ready = True
                continue
            number = (phase - 1) // 2
            require(acknowledged and number == completed and number < 64, 'ordered original extension case')
            if phase & 1 and not reply:
                require(active is None, 'one extension begin request')
                active = dict(number=number, policy=specification(number, lane), start=None, end=None,
                              done=False, identity=None, body=bytearray(), pieces=[])
            elif phase & 1:
                require(active is not None and active['start'] is None, 'one extension begin ACK')
                active['start'] = at
            elif not reply:
                require(active is not None and active['start'] is not None and active['end'] is None,
                        'one extension end request')
                active['end'] = at
            else:
                require(active is not None and active['end'] is not None and stamp(row) >= stamp(rows[active['end']]),
                        'one extension end ACK after its request')
                if active['policy']['error']:
                    require(stamp(row) - stamp(rows[active['end']]) >= 50000000, 'full fifty-millisecond extension rejection interval')
                    quiet.append((active['end'], at))
                else:
                    require(active['done'] and stamp(row) >= stamp(rows[active['last_data']]), 'extension end ACK follows complete original data')
                    if active['policy']['variant'] == 9:
                        require(all(key in active for key in ('mutation_request', 'mutation_ack', 'probe', 'release')),
                                'complete independent queued-extension ownership conversation')
                        ownership.append(tuple(active[key] for key in ('mutation_request', 'mutation_ack', 'probe', 'release')))
                completed += 1
                active = None
            continue
        require(frame[12:14] == b'\x86\xdd' and len(frame) >= 54, 'original extension Ethernet protocol')
        size, protocol, hop = struct.unpack_from('!HBB', frame, 18)
        require(len(frame) >= size + 54, 'complete captured extension envelope')
        source, target, body = frame[22:38], frame[38:54], frame[54:54 + size]
        if native and target == ipaddress.IPv6Address('ff02::16').packed:
            report = body[8:]
            require(protocol == 0 and frame[:12] == bytes.fromhex('333300000016') + guest and
                    frame[14:18] == b'\x60\0\0\0' and hop == 1 and source in (bytes(16), address(lane, 2, 1)) and
                    body[:8] == b'\x3a\0\5\2\0\0\1\0' and len(report) >= 8 and report[:2] == b'\x8f\0' and
                    not checksum(source + target + struct.pack('!I3xB', len(report), 58) + report), 'original native extension-phase MLD report')
            mld += 1
            continue
        if protocol == 58 and body[:1] in (b'\x87', b'\x88'):
            require(frame[14:18] == b'\x60\0\0\0' and hop == 255 and len(body) == 32 and
                    not checksum(source + target + struct.pack('!I3xB', len(body), 58) + body), 'original extension neighbor checksum and envelope')
            if body[0] == 135:
                destination = body[8:24]
                group = b'\xff\x02' + bytes(9) + b'\1\xff' + destination[-3:]
                deferred = active is not None and active['policy']['variant'] == 9 and destination == active['policy']['target']
                require((destination in (address(lane, 1, 0), address(lane, 1, 1)) or deferred) and
                        source in (address(lane, 2, 0), address(lane, 2, 1)) and body[:2] == b'\x87\0' and
                        not any(body[4:8]) and body[24:] == b'\1\1' + guest and
                        (target == group and frame[:12] == b'\x33\x33' + group[-4:] + guest or
                         target == destination and frame[:12] == peer + guest), 'owned original extension neighbor probe')
                if deferred:
                    require('probe' not in active, 'one original deferred extension probe')
                    active['probe'] = at
            else:
                deferred = active is not None and active['policy']['variant'] == 9 and source == active['policy']['target']
                require((source in (address(lane, 1, 0), address(lane, 1, 1)) or deferred) and
                        target in (address(lane, 2, 0), address(lane, 2, 1)) and frame[:12] == guest + peer and
                        body[:2] == b'\x88\0' and body[4:8] == b'\x60\0\0\0' and body[8:24] == source and body[24:] == b'\2\1' + peer,
                        'owned original extension neighbor release')
                if deferred:
                    require('probe' in active and 'mutation_ack' in active and 'release' not in active and
                            stamp(row) >= stamp(rows[active['probe']]) and stamp(row) >= stamp(rows[active['mutation_ack']]),
                            'extension release follows actual probe and retired-owner mutation ACK')
                    active['release'] = at
            continue
        require(active is not None and active['start'] is not None and not active['done'] and not active['policy']['error'],
                'original extension packet belongs to one accepted send')
        require(stamp(row) >= stamp(rows[active['start']]), 'extension data follows original begin ACK')
        wanted = active['policy']
        if wanted['variant'] == 9:
            require('release' in active and stamp(row) >= stamp(rows[active['release']]), 'every queued extension fragment follows original neighbor release')
        require(frame[:12] == peer + guest and source == wanted['source'] and target == wanted['target'] and
                int.from_bytes(frame[14:18], 'big') == (6 << 28 | 0xcd << 20) and hop == 47 and size + 40 <= 1500,
                'every actual extension packet source, egress, class, hop and MTU')
        data.append(at)
        calls.setdefault(active['number'], at)
        active['last_data'] = at
        transport = 17 if wanted['kind'] == 2 else 58
        following = 60 if wanted['destination'] else 44 if wanted['fragmented'] else transport
        if wanted['hop']:
            require(protocol == 0 and body[:wanted['hop']] == option_header(wanted['hop'], 0x44, following),
                    'all original copied Hop-by-Hop bytes repeat before each Fragment header')
            protocol, body = body[0], body[wanted['hop']:]
        if wanted['destination']:
            require(protocol == 60 and body[:wanted['destination']] == option_header(wanted['destination'], 0x55, 44 if wanted['fragmented'] else transport),
                    'every copied Destination byte repeats before the native Fragment boundary')
            protocol, body = body[0], body[wanted['destination']:]
        if wanted['fragmented']:
            require(protocol == 44 and len(body) > 8, 'original Fragment placement after unfragmentable headers')
            following, reserved, offset, identity = struct.unpack_from('!BBHI', body)
            require(following == transport and not reserved and identity and
                    not offset & 6 and offset & 0xfff8 == len(active['body']), 'original extension fragment linkage and offsets')
            if active['identity'] is None:
                require((source, target, identity) not in identities, 'fresh original extension fragment identity')
                identities.add((source, target, identity))
                active['identity'] = identity
            require(active['identity'] == identity, 'unchanged original extension fragment identity')
            total = wanted['size'] + (8 if transport == 17 else 0)
            remaining = total - len(active['body'])
            limit = 1500 - 40 - wanted['hop'] - wanted['destination'] - 8
            expected = min(remaining, limit) if remaining <= limit else limit & ~7
            require(len(body) - 8 == expected and bool(offset & 1) == (expected < remaining),
                    'actual native-sized contiguous extension fragment pieces')
            active['body'].extend(body[8:])
            active['pieces'].append(at)
            fragments.append(at)
            if offset & 1:
                continue
            protocol, body = following, bytes(active['body'])
            groups[active['number']] = list(active['pieces'])
        else:
            require(protocol != 44 and not active['body'], 'original small extension packet is unfragmented')
        require(protocol == transport and not checksum(source + target + struct.pack('!I3xB', len(body), transport) + body),
                'actual upper-layer checksum excludes every extension byte')
        payload = bytes((n * 23 + active['number'] * 13 + lane) & 255 for n in range(wanted['size']))
        if transport == 17:
            require(len(body) == wanted['size'] + 8 and struct.unpack_from('!HHH', body) ==
                    (49000 + lane + wanted['scope'] * 10, 50000 + lane + wanted['scope'] * 10, len(body)) and
                    body[6:8] != bytes(2) and body[8:] == payload, 'every original extension UDP header and payload byte')
        else:
            require(len(body) == wanted['size'] and body[:2] + bytes(2) + body[4:] == b'\x81\0\0\0' + payload[4:],
                    'every original extension raw payload byte')
        active['done'] = True
    require(acknowledged and active is None and completed == 64 and len(quiet) == 20 and len(groups) == 8 and len(ownership) == 4,
            'complete original extension success, rejection, fragmentation and ownership inventory')
    require(all(len(groups[number]) > 8 for number in (9, 25, 41, 57)), 'queued extensions survive beyond one submission batch')
    return dict(passed=True, lane=lane, cases=completed, fragment_groups=len(groups), fragments=len(fragments),
                negative_cases=len(quiet), deferred_ownership=len(ownership), native_MLD_reports=mld,
                minimum_quiet_ms=min(stamp(rows[b]) - stamp(rows[a]) for a, b in quiet) / 1000000), dict(
                    data=data, fragments=fragments, quiet=quiet, ownership=ownership, calls=calls, groups=groups)


def verify_capture(path, lane, log_path, archive, native=False, interface_index=None):
    path, log_path = Path(path), Path(log_path)
    original, original_log = path.read_bytes(), log_path.read_bytes()
    rows, text = read_capture(path), original_log.decode(errors='replace')
    start = boundary(rows, lane)
    # Damaged controls retain original extension-phase bytes and clocks. Earlier
    # independent phases remain in the original capture, avoiding duplicate copies.
    rows = rows[start:]
    result, proof = inspect(rows, lane, text, native, interface_index)
    names = ('missing-data', 'duplicate-data', 'hop-option-byte', 'destination-option-byte',
             'repeated-hop-byte', 'fragment-placement', 'fragment-id', 'fragment-offset',
             'valid-checksum-wrong-payload', 'valid-checksum-queued-payload', 'wrong-MAC',
             'wrong-input-index', 'written-input-padding', 'changed-sticky', 'wrong-result',
             'missing-case', 'duplicate-case', 'emitted-despite-DF', 'missing-end-ACK', 'short-quiet',
             'data-before-begin-ACK', 'end-ACK-before-data', 'missing-mutation-ACK', 'missing-probe',
             'early-neighbor-release')
    rejected = []
    with zipfile.ZipFile(archive, 'w', zipfile.ZIP_DEFLATED) as saved:
        for name in names:
            changed, log = copy.deepcopy(rows), text
            first = proof['data'][0]
            if name in ('missing-data', 'duplicate-data'):
                if name == 'missing-data':
                    del changed[first]
                else:
                    changed.insert(first, copy.deepcopy(changed[first]))
            elif name in ('missing-mutation-ACK', 'missing-probe', 'early-neighbor-release'):
                _, ack, probe, release = proof['ownership'][0]
                if name == 'missing-mutation-ACK':
                    del changed[ack]
                elif name == 'missing-probe':
                    del changed[probe]
                else:
                    changed[release]['ns'] = changed[ack]['ns'] - 1000
                    changed[release]['monotonic_ns'] = stamp(changed[ack]) - 1000
            elif name in ('wrong-input-index', 'written-input-padding', 'changed-sticky', 'wrong-result', 'missing-case', 'duplicate-case'):
                lines = log.splitlines()
                at = next(n for n, line in enumerate(lines) if line.startswith(f'IPV6_EXTENSION_WIRE_CASE lane={lane} case=0 '))
                if name == 'missing-case':
                    del lines[at]
                elif name == 'duplicate-case':
                    lines.insert(at, lines[at])
                else:
                    row = dict(value.split('=', 1) for value in lines[at].split()[1:])
                    if name in ('changed-sticky', 'wrong-result'):
                        key = 'class' if name == 'changed-sticky' else 'result'
                        row[key] = str(int(row[key]) ^ 1)
                    else:
                        data = bytearray.fromhex(row['control'])
                        data[32 if name == 'wrong-input-index' else 36] ^= 1
                        row['control'] = data.hex()
                    lines[at] = 'IPV6_EXTENSION_WIRE_CASE ' + ' '.join(key + '=' + value for key, value in row.items())
                log = '\n'.join(lines) + '\n'
            elif name in ('data-before-begin-ACK', 'end-ACK-before-data'):
                phase = 1 if name == 'data-before-begin-ACK' else 2
                ack = next(n for n, row in enumerate(changed) if row['frame'][12:14] == b'\x88\xc1' and row['frame'][19:21] == bytes([phase, 1]))
                target, reference = (first, ack) if phase == 1 else (ack, first)
                changed[target]['ns'] = changed[reference]['ns'] - 1000
                changed[target]['monotonic_ns'] = stamp(changed[reference]) - 1000
            elif name in ('missing-end-ACK', 'short-quiet', 'emitted-despite-DF'):
                begin, end = proof['quiet'][0]
                if name == 'missing-end-ACK':
                    del changed[end]
                elif name == 'short-quiet':
                    changed[end]['ns'] = changed[begin]['ns'] + 49000000
                    changed[end]['monotonic_ns'] = stamp(changed[begin]) + 49000000
                else:
                    unexpected = copy.deepcopy(changed[first])
                    unexpected['ns'] = changed[begin]['ns'] + 1
                    unexpected['monotonic_ns'] = stamp(changed[begin]) + 1
                    changed.insert(begin + 1, unexpected)
            elif name == 'valid-checksum-queued-payload':
                group = proof['groups'][9]
                frames = [bytearray(changed[n]['frame']) for n in group]
                body = bytearray().join(frame[94:54 + int.from_bytes(frame[18:20], 'big')] for frame in frames)
                body[-1] ^= 1
                body[6:8] = bytes(2)
                value = checksum(bytes(frames[0][22:54]) + struct.pack('!I3xB', len(body), 17) + body)
                frames[0][100:102] = value.to_bytes(2, 'big')
                frames[-1][54 + int.from_bytes(frames[-1][18:20], 'big') - 1] ^= 1
                for n, frame in zip(group, frames):
                    changed[n]['frame'] = bytes(frame)
            else:
                index = proof['calls'][1] if name == 'destination-option-byte' else proof['fragments'][1] if name == 'repeated-hop-byte' else proof['fragments'][0] if name.startswith('fragment-') else first
                frame = bytearray(changed[index]['frame'])
                offset = {'hop-option-byte': 58, 'destination-option-byte': 58, 'repeated-hop-byte': 58,
                          'fragment-placement': 20, 'fragment-id': 74, 'fragment-offset': 73,
                          'valid-checksum-wrong-payload': 75, 'wrong-MAC': 0}[name]
                frame[offset] ^= 1
                if name == 'valid-checksum-wrong-payload':
                    frame[68:70] = bytes(2)
                    body = bytes(frame[62:54 + int.from_bytes(frame[18:20], 'big')])
                    frame[68:70] = checksum(bytes(frame[22:54]) + struct.pack('!I3xB', len(body), 17) + body).to_bytes(2, 'big')
                changed[index]['frame'] = bytes(frame)
            saved.writestr(name + '.pcap', encode_capture(changed))
            saved.writestr(name + '.log', log)
            try:
                inspect(changed, lane, log, native, interface_index)
            except ValueError as failure:
                rejected.append(dict(name=name, reason=str(failure)))
            else:
                raise ValueError('accepted damaged extension evidence: ' + name)
        saved.writestr('rejections.json', json.dumps(rejected, indent=2))
    require(path.read_bytes() == original and log_path.read_bytes() == original_log, 'original extension packets and log unchanged')
    result.update(damaged_rejected=len(rejected), original_sha256=hashlib.sha256(original).hexdigest(),
                  archive_sha256=hashlib.sha256(Path(archive).read_bytes()).hexdigest(),
                  phase_start_record=start, native_clock_qualified=False)
    return result
