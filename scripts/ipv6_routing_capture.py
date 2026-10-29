# SPDX-License-Identifier: GPL-3.0-or-later
"""Independently reconstruct routing-bearing sends from original packets and inputs."""
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
    require(0 <= number < 64, 'bounded original routed send')
    variant, scope, kind = number % 16, number % 32 // 16, number // 32 + 2
    full = variant in (2, 3, 8, 9, 10, 14)
    return dict(variant=variant, scope=scope, kind=kind,
                size={8: 2048, 9: 16384, 10: 2048}.get(variant, 128),
                error={10: 90, 11: 22, 12: 22, 14: 1, 15: 22}.get(variant, 0),
                hop=8 if full else 0, before=8 if full or variant in (4, 7) else 0,
                before_value=0x22 if variant == 4 else 0x66 if variant == 7 else 0x33,
                destination=8 if full or variant in (4, 5, 7) else 0,
                fragmented=variant in (8, 9), source=address(lane, 2, scope),
                target=address(lane, 220 + number // 16 * 4 if variant == 9 else 1, scope),
                final=address(lane, 71, scope))


def option_header(length, value, following):
    return bytes([following, length // 8 - 1, 30, length - 4]) + bytes([value]) * (length - 4)


def original_control(number, lane, index):
    wanted = specification(number, lane)
    variant = wanted['variant']
    full = variant in (2, 3, 8, 9, 10, 14)
    result = bytearray()
    def append(kind, payload):
        length = len(payload) + 16
        result.extend(struct.pack('<QII', length, 41, kind) + payload + bytes(-length % 8))
    def extension(kind, value):
        append(kind, option_header(8, value, 250))
    append(50, wanted['source'] + struct.pack('<I', index))
    append(52, struct.pack('<i', 47))
    append(67, struct.pack('<i', 0xcd))
    if variant == 3:
        extension(59, 0x55)
    if variant in (4, 5):
        extension(4 if variant == 4 else 59, 0x22 if variant == 4 else 0x55)
    routing = bytearray(bytes([250, 2, 2, 1, 0x71, 0x72, 0x73, 0x74]) + wanted['target'])
    if variant == 6:
        routing[23] = 77
        append(57, bytes(routing))
        routing[23] = 1
    if full and variant != 3:
        extension(54, 0x44)
    if full or variant == 7:
        extension(55, 0x33)
    if variant == 7:
        extension(55, 0x66)
    if variant in (11, 15):
        routing[2] = 0 if variant == 11 else 4
    if variant == 12:
        routing[3] = 0
    append(5 if variant in (1, 4) else 57, bytes(routing))
    if full and variant == 3:
        extension(54, 0x44)
    if full and variant != 3 or variant in (4, 7):
        extension(59, 0x55)
    if variant in (8, 9, 10):
        append(62, struct.pack('<i', int(variant == 10)))
    length = len(result)
    require(length <= 256, 'bounded independent routed input')
    return bytes(result) + b'\xa5' * (256 - length), length


def application(text, lane, index):
    text = text.replace('\r\n', '\n')
    require('IPV6_ROUTING_WIRE_FAIL' not in text and text.splitlines().count(
        'IPV6_ROUTING_WIRE_DONE adapters=2 cases=128 variants=16 scopes=2 transports=2') == 1,
        'actual complete routing application')
    interfaces = re.findall(r'^IPV6_SEND_WIRE_INTERFACE lane=(\d+) index=(\d+)$', text, re.MULTILINE)
    require(len(interfaces) == 2 and {int(row[0]) for row in interfaces} == {0, 1}, 'actual routing egress identities')
    indices = {int(link): int(value) for link, value in interfaces}
    require(indices[lane] == index and len(set(indices.values())) == 2 and all(value > 0 for value in indices.values()),
            'independent actual routing interface index')
    for link in range(2):
        require(text.splitlines().count(f'IPV6_ROUTING_WIRE_PASS lane={link} cases=64 variants=16 scopes=2 transports=2') == 1,
                'both original routing adapters complete')
    keys = {'lane', 'case', 'type', 'scope', 'variant', 'named', 'bytes', 'result', 'errno',
            'length', 'hops', 'class', 'df', 'control'}
    seen = set()
    for line in text.splitlines():
        if not line.startswith('IPV6_ROUTING_WIRE_CASE '):
            continue
        fields = [field.split('=', 1) for field in line.split()[1:]]
        row = dict(fields)
        require(len(fields) == len(keys) and set(row) == keys and
                all(re.fullmatch('-?[0-9]+', row[key]) for key in keys - {'control'}) and
                re.fullmatch('[0-9a-f]{512}', row['control']) is not None, 'exact original routing result fields')
        actual = {key: int(row[key]) for key in keys - {'control'}}
        link, number = actual['lane'], actual['case']
        require(link in (0, 1) and (link, number) not in seen, 'unique original routing call')
        wanted = specification(number, link)
        control, capacity = original_control(number, link, indices[link])
        expected = dict(lane=link, case=number, type=wanted['kind'], scope=wanted['scope'],
                        variant=wanted['variant'], named=(wanted['variant'] + wanted['scope']) % 2,
                        bytes=wanted['size'], result=-1 if wanted['error'] else wanted['size'],
                        errno=wanted['error'], length=capacity, hops=37, **{'class': 0x25},
                        df=int(wanted['variant'] in (8, 9)))
        require(actual == expected and bytes.fromhex(row['control']) == control,
                'every routing result, original ancillary byte, padding and shared option')
        seen.add((link, number))
    require(seen == {(link, number) for link in range(2) for number in range(64)}, 'all 128 original routing calls')


def boundary(rows, lane, optional=False):
    guest = bytes.fromhex('5254001234') + bytes([0x10 + lane])
    hits = [n for n, row in enumerate(rows) if row['frame'][6:12] == guest and
            row['frame'][12:21] == b'\x88\xc2IP6R' + bytes([lane, 0, 0])]
    require(len(hits) == 1 or optional and not hits, 'one original routing readiness boundary')
    return hits[0] if hits else len(rows)


def stamp(row):
    return row.get('monotonic_ns', row['ns'])


def inspect(rows, lane, text, native=False, interface_index=None):
    require(not native or interface_index is not None, 'independent native routing interface identity')
    application(text, lane, interface_index if native else lane + 1)
    from ipv6_sticky_capture import boundary as sticky_boundary
    rows = rows[:sticky_boundary(rows, lane, optional=True)]
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
        if frame[12:14] == b'\x88\xc2':
            require(len(frame) == 60 and frame[14:19] == b'IP6R' + bytes([lane]) and
                    frame[20] in (0, 1) and not any(frame[21:]) and
                    frame[:12] == (guest + control if frame[20] else control + guest), 'exact routing boundary direction and bytes')
            phase, reply = frame[19:21]
            if phase >= 193:
                require(active is not None and active['policy']['variant'] == 9 and phase == 193 + active['number'] // 16,
                        'mutation belongs to one original queued routing send')
                if reply:
                    require('mutation_request' in active and 'mutation_ack' not in active and
                            stamp(row) >= stamp(rows[active['mutation_request']]), 'routing mutation ACK follows original request')
                    active['mutation_ack'] = at
                else:
                    require('mutation_request' not in active, 'one routing mutation request')
                    active['mutation_request'] = at
                continue
            if phase == 0:
                require(not acknowledged and (ready if reply else not ready), 'one ordered routing readiness exchange')
                if reply:
                    acknowledged = True
                else:
                    ready = True
                continue
            number = (phase - 1) // 2
            require(acknowledged and number == completed and number < 64, 'ordered original routing case')
            if phase & 1 and not reply:
                require(active is None, 'one routing begin request')
                active = dict(number=number, policy=specification(number, lane), start=None, end=None,
                              done=False, identity=None, body=bytearray(), pieces=[])
            elif phase & 1:
                require(active is not None and active['start'] is None, 'one routing begin ACK')
                active['start'] = at
            elif not reply:
                require(active is not None and active['start'] is not None and active['end'] is None,
                        'one routing end request')
                active['end'] = at
            else:
                require(active is not None and active['end'] is not None and stamp(row) >= stamp(rows[active['end']]),
                        'one routing end ACK after its request')
                if active['policy']['error']:
                    require(stamp(row) - stamp(rows[active['end']]) >= 50000000, 'full fifty-millisecond routing rejection interval')
                    quiet.append((active['end'], at))
                else:
                    require(active['done'] and stamp(row) >= stamp(rows[active['last_data']]), 'routing end ACK follows complete original data')
                    if active['policy']['variant'] == 9:
                        require(all(key in active for key in ('mutation_request', 'mutation_ack', 'probe', 'release')),
                                'complete independent queued-routing ownership conversation')
                        ownership.append(tuple(active[key] for key in ('mutation_request', 'mutation_ack', 'probe', 'release')))
                completed += 1
                active = None
            continue
        require(frame[12:14] == b'\x86\xdd' and len(frame) >= 54, 'original routing Ethernet protocol')
        size, protocol, hop = struct.unpack_from('!HBB', frame, 18)
        require(len(frame) >= size + 54, 'complete captured routing envelope')
        source, target, body = frame[22:38], frame[38:54], frame[54:54 + size]
        if native and target == ipaddress.IPv6Address('ff02::16').packed:
            report = body[8:]
            require(protocol == 0 and frame[:12] == bytes.fromhex('333300000016') + guest and
                    frame[14:18] == b'\x60\0\0\0' and hop == 1 and source in (bytes(16), address(lane, 2, 1)) and
                    body[:8] == b'\x3a\0\5\2\0\0\1\0' and len(report) >= 8 and report[:2] == b'\x8f\0' and
                    not checksum(source + target + struct.pack('!I3xB', len(report), 58) + report), 'original native routing-phase MLD report')
            mld += 1
            continue
        if protocol == 58 and body[:1] in (b'\x87', b'\x88'):
            require(frame[14:18] == b'\x60\0\0\0' and hop == 255 and len(body) == 32 and
                    not checksum(source + target + struct.pack('!I3xB', len(body), 58) + body), 'original routing neighbor checksum and envelope')
            if body[0] == 135:
                destination = body[8:24]
                group = b'\xff\x02' + bytes(9) + b'\1\xff' + destination[-3:]
                deferred = active is not None and active['policy']['variant'] == 9 and destination == active['policy']['target']
                require((destination in (address(lane, 1, 0), address(lane, 1, 1)) or deferred) and
                        source in (address(lane, 2, 0), address(lane, 2, 1)) and body[:2] == b'\x87\0' and
                        not any(body[4:8]) and body[24:] == b'\1\1' + guest and
                        (target == group and frame[:12] == b'\x33\x33' + group[-4:] + guest or
                         target == destination and frame[:12] == peer + guest), 'owned original routing neighbor probe')
                if deferred:
                    require('probe' not in active, 'one original deferred routing probe')
                    active['probe'] = at
            else:
                deferred = active is not None and active['policy']['variant'] == 9 and source == active['policy']['target']
                require((source in (address(lane, 1, 0), address(lane, 1, 1)) or deferred) and
                        target in (address(lane, 2, 0), address(lane, 2, 1)) and frame[:12] == guest + peer and
                        body[:2] == b'\x88\0' and body[4:8] == b'\x60\0\0\0' and body[8:24] == source and body[24:] == b'\2\1' + peer,
                        'owned original routing neighbor release')
                if deferred:
                    require('probe' in active and 'mutation_ack' in active and 'release' not in active and
                            stamp(row) >= stamp(rows[active['probe']]) and stamp(row) >= stamp(rows[active['mutation_ack']]),
                            'routing release follows actual probe and retired-owner mutation ACK')
                    active['release'] = at
            continue
        require(active is not None and active['start'] is not None and not active['done'] and not active['policy']['error'],
                'original routing packet belongs to one accepted send')
        require(stamp(row) >= stamp(rows[active['start']]), 'routing data follows original begin ACK')
        wanted = active['policy']
        if wanted['variant'] == 9:
            require('release' in active and stamp(row) >= stamp(rows[active['release']]), 'every queued routing fragment follows original neighbor release')
        require(frame[:12] == peer + guest and source == wanted['source'] and target == wanted['target'] and
                int.from_bytes(frame[14:18], 'big') == (6 << 28 | 0xcd << 20) and hop == 47 and size + 40 <= 1500,
                'every actual routing packet source, egress, class, hop and MTU')
        data.append(at)
        calls.setdefault(active['number'], at)
        active['last_data'] = at
        transport = 17 if wanted['kind'] == 2 else 58
        following = 60 if wanted['before'] else 43
        if wanted['hop']:
            require(protocol == 0 and body[:wanted['hop']] == option_header(wanted['hop'], 0x44, following),
                    'all original copied Hop-by-Hop bytes repeat before each Fragment header')
            protocol, body = body[0], body[wanted['hop']:]
        if wanted['before']:
            require(protocol == 60 and body[:8] == option_header(8, wanted['before_value'], 43),
                    'every original pre-routing Destination option byte')
            protocol, body = body[0], body[8:]
        following = 44 if wanted['fragmented'] else 60 if wanted['destination'] else transport
        routing = bytes([following, 2, 2, 1, 0x71, 0x72, 0x73, 0x74]) + wanted['final']
        require(protocol == 43 and body[:24] == routing, 'every copied type-2 routing field and final destination')
        protocol, body = body[0], body[24:]
        if wanted['fragmented']:
            require(protocol == 44 and len(body) > 8, 'original Fragment placement after unfragmentable headers')
            following, reserved, offset, identity = struct.unpack_from('!BBHI', body)
            require(following == (60 if wanted['destination'] else transport) and not reserved and identity and
                    not offset & 6 and offset & 0xfff8 == len(active['body']), 'original routing fragment linkage and offsets')
            if active['identity'] is None:
                require((source, target, identity) not in identities, 'fresh original routing fragment identity')
                identities.add((source, target, identity))
                active['identity'] = identity
            require(active['identity'] == identity, 'unchanged original routing fragment identity')
            total = wanted['destination'] + wanted['size'] + (8 if transport == 17 else 0)
            remaining = total - len(active['body'])
            limit = 1500 - 40 - wanted['hop'] - wanted['before'] - 24 - 8
            expected = min(remaining, limit) if remaining <= limit else limit & ~7
            require(len(body) - 8 == expected and bool(offset & 1) == (expected < remaining),
                    'actual native-sized contiguous routing fragment pieces')
            active['body'].extend(body[8:])
            active['pieces'].append(at)
            fragments.append(at)
            if offset & 1:
                continue
            protocol, body = following, bytes(active['body'])
            groups[active['number']] = list(active['pieces'])
        else:
            require(protocol != 44 and not active['body'], 'original small routing packet is unfragmented')
        if wanted['destination']:
            require(protocol == 60 and body[:8] == option_header(8, 0x55, transport),
                    'copied final Destination header appears inside the reassembled fragmentable portion')
            protocol, body = body[0], body[8:]
        require(protocol == transport and not checksum(source + wanted['final'] + struct.pack('!I3xB', len(body), transport) + body),
                'actual upper-layer checksum excludes every routing byte')
        payload = bytes((n * 23 + active['number'] * 13 + lane) & 255 for n in range(wanted['size']))
        if transport == 17:
            require(len(body) == wanted['size'] + 8 and struct.unpack_from('!HHH', body) ==
                    (51000 + lane + wanted['scope'] * 10, 52000 + lane + wanted['scope'] * 10, len(body)) and
                    body[6:8] != bytes(2) and body[8:] == payload, 'every original routing UDP header and payload byte')
        else:
            require(len(body) == wanted['size'] and body[:2] + bytes(2) + body[4:] == b'\x81\0\0\0' + payload[4:],
                    'every original routing raw payload byte')
        active['done'] = True
    require(acknowledged and active is None and completed == 64 and len(quiet) == 20 and len(groups) == 8 and len(ownership) == 4,
            'complete original routing success, rejection, fragmentation and ownership inventory')
    require(all(len(groups[number]) > 8 for number in (9, 25, 41, 57)), 'queued routings survive beyond one submission batch')
    return dict(passed=True, lane=lane, cases=completed, fragment_groups=len(groups), fragments=len(fragments),
                negative_cases=len(quiet), deferred_ownership=len(ownership), native_MLD_reports=mld,
                minimum_quiet_ms=min(stamp(rows[b]) - stamp(rows[a]) for a, b in quiet) / 1000000), dict(
                    data=data, fragments=fragments, quiet=quiet, ownership=ownership, calls=calls, groups=groups)


def verify_capture(path, lane, log_path, archive, native=False, interface_index=None):
    path, log_path = Path(path), Path(log_path)
    original, original_log = path.read_bytes(), log_path.read_bytes()
    rows, text = read_capture(path), original_log.decode(errors='replace')
    start = boundary(rows, lane)
    # Damaged controls retain original routing-phase bytes and clocks. Earlier
    # independent phases remain in the original capture, avoiding duplicate copies.
    from ipv6_sticky_capture import boundary as sticky_boundary
    rows = rows[start:sticky_boundary(rows, lane, optional=True)]
    result, proof = inspect(rows, lane, text, native, interface_index)
    names = ('missing-data', 'duplicate-data', 'routing-type', 'routing-reserved',
             'repeated-routing-address', 'wrong-first-hop', 'valid-checksum-wrong-final', 'pre-routing-byte', 'post-routing-byte', 'fragment-placement', 'fragment-id', 'fragment-offset',
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
                at = next(n for n, line in enumerate(lines) if line.startswith(f'IPV6_ROUTING_WIRE_CASE lane={lane} case=0 '))
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
                    lines[at] = 'IPV6_ROUTING_WIRE_CASE ' + ' '.join(key + '=' + value for key, value in row.items())
                log = '\n'.join(lines) + '\n'
            elif name in ('data-before-begin-ACK', 'end-ACK-before-data'):
                phase = 1 if name == 'data-before-begin-ACK' else 2
                ack = next(n for n, row in enumerate(changed) if row['frame'][12:14] == b'\x88\xc2' and row['frame'][19:21] == bytes([phase, 1]))
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
                body = bytearray().join(frame[102:54 + int.from_bytes(frame[18:20], 'big')] for frame in frames)
                body[-1] ^= 1
                body[14:16] = bytes(2)
                value = checksum(bytes(frames[0][22:38]) + bytes(frames[0][78:94]) + struct.pack('!I3xB', len(body) - 8, 17) + body[8:])
                frames[0][116:118] = value.to_bytes(2, 'big')
                frames[-1][54 + int.from_bytes(frames[-1][18:20], 'big') - 1] ^= 1
                for n, frame in zip(group, frames):
                    changed[n]['frame'] = bytes(frame)
            else:
                if name == 'repeated-routing-address':
                    index = proof['groups'][8][1]
                elif name == 'pre-routing-byte':
                    index = proof['calls'][2]
                elif name == 'post-routing-byte' or name.startswith('fragment-'):
                    index = proof['groups'][8][0]
                else:
                    index = first
                frame = bytearray(changed[index]['frame'])
                offset = {'routing-type': 56, 'routing-reserved': 58, 'repeated-routing-address': 93,
                          'wrong-first-hop': 53, 'valid-checksum-wrong-final': 77, 'pre-routing-byte': 66,
                          'post-routing-byte': 106, 'fragment-placement': 20, 'fragment-id': 98,
                          'fragment-offset': 97, 'valid-checksum-wrong-payload': 93, 'wrong-MAC': 0}[name]
                frame[offset] ^= 1
                if name in ('valid-checksum-wrong-payload', 'valid-checksum-wrong-final'):
                    frame[84:86] = bytes(2)
                    body = bytes(frame[78:54 + int.from_bytes(frame[18:20], 'big')])
                    frame[84:86] = checksum(bytes(frame[22:38]) + bytes(frame[62:78]) +
                                           struct.pack('!I3xB', len(body), 17) + body).to_bytes(2, 'big')
                changed[index]['frame'] = bytes(frame)
            saved.writestr(name + '.pcap', encode_capture(changed))
            saved.writestr(name + '.log', log)
            try:
                inspect(changed, lane, log, native, interface_index)
            except ValueError as failure:
                rejected.append(dict(name=name, reason=str(failure)))
            else:
                raise ValueError('accepted damaged routing evidence: ' + name)
        saved.writestr('rejections.json', json.dumps(rejected, indent=2))
    require(path.read_bytes() == original and log_path.read_bytes() == original_log, 'original routing packets and log unchanged')
    result.update(damaged_rejected=len(rejected), original_sha256=hashlib.sha256(original).hexdigest(),
                  archive_sha256=hashlib.sha256(Path(archive).read_bytes()).hexdigest(),
                  phase_start_record=start, native_clock_qualified=False)
    return result
