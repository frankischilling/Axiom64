# SPDX-License-Identifier: GPL-3.0-or-later
"""Bind error-queue metadata to original emitted packets and received ICMP headers."""
import copy
import hashlib
import ipaddress
import json
from pathlib import Path
import re
import struct
import zipfile
from ipv4_expiry_capture import checksum, encode_capture, read_capture
from ipv6_controls_capture import multicast_report

DONE = 'IPV6_ERROR_METADATA_PASS adapters=2 cases=160 variants=20 scopes=2 transports=2'
SCALARS = {'lane', 'case', 'kind', 'scope', 'variant', 'mask', 'capacity', 'input_flags',
           'result', 'errno', 'name_length', 'length', 'flags', 'queued', 'queue_errno',
           'normal', 'normal_errno', 'control_visible', 'name_visible'}
BUFFERS = {'before_header', 'header', 'name', 'name_prefix', 'control', 'payload', 'drain'}


def require(condition, reason):
    if not condition:
        raise ValueError(reason)


def boundary(rows, lane, outer=False):
    protocol = b"\x88\xc4IP6X" if outer else b"\x88\xbeIP6M"
    matches = [i for i,row in enumerate(rows) if row['frame'][12:20] ==
               protocol + bytes([lane, 0]) and row['frame'][20:21] == b'\0']
    require(len(matches) == 1, 'one original error metadata transition')
    return matches[0]


def address(lane, host, scoped):
    return ipaddress.IPv6Address(f'fe80::{host:x}' if scoped else
                                f'2001:db8:{lane + 1}::{host:x}').packed


def sockaddr(value, port=0, scope=0):
    return struct.pack('<H', 10) + struct.pack('!H', port) + bytes(4) + value + struct.pack('<I', scope)


def samples(log, lane, outer=False):
    label = "IPV6_ERROR_EXTENSIONS" if outer else "IPV6_ERROR_METADATA"
    rows = []
    for line in log.splitlines():
        if not line.startswith(label + "_CASE "):
            continue
        pairs = [item.split('=', 1) for item in line.split()[1:]]
        require(all(len(item) == 2 for item in pairs), 'complete metadata result fields')
        row = dict(pairs)
        require(len(pairs) == len(SCALARS | BUFFERS) and set(row) == SCALARS | BUFFERS and
                all(re.fullmatch(r'-?\d+', row[key]) for key in SCALARS),
                'exact metadata result inventory')
        for key in BUFFERS:
            require(re.fullmatch('[0-9a-f]*', row[key]) is not None, 'original hexadecimal buffer')
        rows.append(row)
    require([(int(row['lane']), int(row['case'])) for row in rows] ==
            [(side, case) for side in range(2) for case in range(80)],
            'every ordered metadata result on both adapters')
    return [row for row in rows if int(row['lane']) == lane]


def normalize_header(encoded, before, null_name):
    value, original = bytearray.fromhex(encoded), bytes.fromhex(before)
    require(len(value) == len(original) == 56, 'complete original message headers')
    for offset in (0, 16, 32):
        pointer = int.from_bytes(original[offset:offset + 8], 'little')
        require((pointer == 0 if offset == 0 and null_name else 0 < pointer < 2**47) and
                value[offset:offset + 8] == original[offset:offset + 8], 'unchanged input pointers')
        value[offset:offset + 8] = bytes(8)
    return value.hex()


def expected(lane, sequence, index, original, received, native_copy_order='length-first', outer=False):
    variant, scoped, raw = sequence % 20, sequence // 20 % 2, sequence >= 40
    mask = variant * (9 if outer else 1) if variant < 8 else 0 if variant == 12 else 63 if outer else 7
    capacity = {8:16, 9:36, 10:88}.get(variant, 384 if outer else 192)
    visible = 143 if variant == 14 else 17 if variant == 18 else 384 if outer else 192
    name_visible = 1 if variant == 16 else 0
    incoming = original['body'] if raw else original['body'][8:]
    copied = 5 if variant == 15 else 8 if variant == 13 else 32
    payload = bytearray(b'\xa5' * 32)
    payload[:copied] = incoming[:copied]
    control = bytearray(b'\xa5' * visible)
    used, output_flags = 0, 0x2000 | (0x20 if variant == 13 else 0) | (0x40000000 if variant == 19 else 0)
    info = received['destination'] + struct.pack('<I', index)
    offender = sockaddr(received['source'], scope=index if scoped else 0)
    error = struct.pack('<IBBBBII', 111, 3, 1, 4, 0, 0, 0) + offender

    def store(offset, data):
        if offset + len(data) > visible:
            return False
        control[offset:offset + len(data)] = data
        return True

    if variant != 15:
        fields = [(1, 50, info), (2, 52, struct.pack('<I', received['hop'])),
                  (4, 67, struct.pack('<I', received['traffic_class']))]
        fields += [(8 if kind == 0 else 16 if kind == 43 else 32,
                    54 if kind == 0 else 57 if kind == 43 else 59, data)
                   for kind, data in received['extensions']] if outer else []
        fields.append((0, 25, error))
        for bit, kind, data in fields:
            if bit and not mask & bit:
                continue
            available = capacity - used
            if available < 16:
                output_flags |= 8
                continue
            length = min(available, 16 + len(data))
            if length < 16 + len(data):
                output_flags |= 8
            complete = store(used, struct.pack('<Q', length)) and \
                store(used + 8, struct.pack('<I', 41)) and store(used + 12, struct.pack('<I', kind))
            offset, remaining = 0, length - 16
            while complete and remaining:
                size = 8 if remaining >= 8 else 4 if remaining >= 4 else 2 if remaining >= 2 else 1
                complete = store(used + 16 + offset, data[offset:offset + size])
                offset += size
                remaining -= size
            if complete:
                used += min(available, (16 + len(data) + 7) & ~7)
    source_name = sockaddr(original['destination'], 0 if raw else 48000 + sequence,
                           index if scoped else 0)
    name = bytearray(b'\xa5' * 40)
    if variant not in (15, 16, 19):
        name[:28] = source_name
    before = bytearray(b'\xa5' * 56)
    for offset in (0, 16, 32):
        before[offset:offset + 8] = bytes(8)
    before[8:12] = struct.pack('<I', 40)
    before[24:32] = struct.pack('<Q', 2)
    before[40:48] = struct.pack('<Q', capacity)
    before[48:52] = struct.pack('<I', 0x5a5a)
    after = bytearray(before)
    failed = variant in (15, 16, 17)
    if variant not in (15, 19) and not (variant == 16 and native_copy_order == 'address-first'):
        after[8:12] = struct.pack('<I', 28)
    if not failed:
        after[40:48] = struct.pack('<Q', used)
        after[48:52] = struct.pack('<I', output_flags)
    input_flags = 0x2040 | (2 if variant in (12, 18) else 0) | \
        (0x20 if variant == 13 else 0) | (0x40000000 if variant == 19 else 0)
    return dict(lane=str(lane), case=str(sequence), kind='3' if raw else '2', scope=str(scoped),
                variant=str(variant), mask=str(mask), capacity=str(capacity), input_flags=str(input_flags),
                result='-1' if failed else str(copied), errno='14' if failed else '0',
                name_length=str(int.from_bytes(after[8:12], 'little')),
                length=str(int.from_bytes(after[40:48], 'little')),
                flags=str(int.from_bytes(after[48:52], 'little')),
                queued='-1', queue_errno='11', normal='-1', normal_errno='11',
                control_visible=str(visible), name_visible=str(name_visible), before_header=before.hex(),
                header=after.hex(), name=name.hex(), name_prefix=source_name[:name_visible].hex(),
                control=control.hex(), payload=payload.hex(), drain=(b'\xa5' * 32).hex())


def inspect(rows, lane, log, native=False, interface_index=None, native_copy_order='length-first', outer=False):
    label = 'IPV6_ERROR_EXTENSIONS' if outer else 'IPV6_ERROR_METADATA'
    protocol_bytes = b'\x88\xc4' if outer else b'\x88\xbe'
    magic = b'IP6X' if outer else b'IP6M'
    done = label + '_PASS adapters=2 cases=160 variants=20 scopes=2 transports=2'
    require(native_copy_order in ('address-first', 'length-first') and
            (native or native_copy_order == 'length-first'), 'explicit native or target copy order')
    require(log.splitlines().count(done) == 1 and 'IPV6_ERROR_METADATA_FAIL' not in log,
            'complete actual error metadata execution')
    require(log.splitlines().count(f'{label}_WIRE_PASS lane={lane} cases=80 scopes=2 variants=20') == 1,
            'complete adapter metadata execution')
    actual = [int(match.group(1)) for line in log.splitlines() if
              (match := re.fullmatch(rf'IPV6_ERROR_METADATA_INTERFACE lane={lane} index=(\d+)', line))]
    require(len(actual) == 1 and (actual[0] == interface_index if interface_index is not None
                                else actual[0] == lane + 1), 'actual metadata interface binding')
    index = actual[0]
    observed = samples(log, lane, outer)
    guest = bytes([0x52, 0x54, 0, 0x12, 0x34, 0x10 + lane])
    peer, control = bytes([2, 0x49, 0x50, 0x36, lane, 1]), bytes([2, 0x49, 0x50, 0x36, lane, 0])
    requests, replies, data, errors, neighbors = {}, {}, {}, [], {}
    begin = boundary(rows, lane, outer)
    for at in range(begin, len(rows)):
        frame = rows[at]['frame']
        require(len(frame) >= 14, 'complete metadata Ethernet frame')
        if not outer and frame[12:20] == b'\x88\xc4IP6X' + bytes([lane, 0]):
            break
        if frame[12:14] == protocol_bytes:
            require(len(frame) == 60 and frame[14:19] == magic + bytes([lane]) and
                    frame[20] in (0, 1) and not any(frame[21:]), 'exact metadata barrier bytes')
            phase, reply = frame[19], frame[20]
            require(frame[:12] == (guest + control if reply else control + guest), 'barrier MAC ownership')
            book = replies if reply else requests
            require(phase not in book, 'unique metadata barrier')
            book[phase] = at
            continue
        require(len(frame) >= 54 and frame[12:14] == b'\x86\xdd', 'defined metadata Ethernet protocol')
        size, protocol, hop = struct.unpack('!HBB', frame[18:22])
        require(frame[14] >> 4 == 6 and 54 + size <= len(frame), 'complete original IPv6 envelope')
        source, destination, body = frame[22:38], frame[38:54], frame[54:54 + size]
        if native and protocol == 0 and frame[6:12] == guest:
            multicast_report(frame, guest, address(lane, 2, True))
            continue
        require(protocol in (17, 58) and not checksum(source + destination +
                struct.pack('!I3xB', size, protocol) + body) if frame[6:12] == guest else True,
                'valid original guest transport checksum')
        if protocol == 58 and body[:1] in (b'\x87', b'\x88'):
            target = body[8:24]
            require(size == 32 and hop == 255 and target[-1] in range(128, 208) and
                    target[:-1] in (address(lane, 2, False)[:-1], address(lane, 2, True)[:-1]),
                    'owned metadata neighbor target')
            if body[0] == 135:
                require(source in (address(lane, 2, False), address(lane, 2, True)) and
                        destination == b'\xff\x02' + bytes(9) + b'\x01\xff' + target[-3:] and
                        frame[:12] == b'\x33\x33' + destination[-4:] + guest and
                        body[4:8] == bytes(4) and body[24:] == b'\1\1' + guest,
                        'exact original metadata solicitation')
                neighbors[target] = (source, at)
            else:
                require(target in neighbors and source == target and frame[:12] == guest + peer and
                        destination == neighbors[target][0] and body[4:8] == b'\x60\0\0\0' and
                        body[24:] == b'\2\1' + peer and not checksum(source + destination +
                            struct.pack('!I3xB', size, 58) + body), 'solicited matching metadata advertisement')
                require(rows[at]['ns'] >= rows[neighbors[target][1]]['ns'], 'causal neighbor packet clocks')
                del neighbors[target]
            continue
        upper, extensions = 54, []
        if frame[6:12] == peer:
            while protocol in (0, 43, 60):
                require(upper + 8 <= 54 + size, 'complete outer extension header')
                length = (frame[upper + 1] + 1) * 8
                require(upper + length <= 54 + size, 'bounded outer extension length')
                extensions.append((protocol, frame[upper:upper + length]))
                protocol, upper = frame[upper], upper + length
            body = frame[upper:54 + size]
        packet = dict(at=at, frame=frame[:54 + size], source=source, destination=destination,
                      body=body, hop=hop, extensions=extensions, upper=upper,
                      traffic_class=(int.from_bytes(frame[14:18], 'big') >> 20) & 255)
        if frame[6:12] == guest:
            sequence = destination[-1] - 128
            require(sequence in range(80) and sequence not in data, 'one original metadata datagram')
            scoped, raw = sequence // 20 % 2, sequence >= 40
            require(frame[:6] == peer and source == address(lane, 2, scoped) and
                    destination == address(lane, 128 + sequence, scoped) and
                    protocol == (58 if raw else 17) and hop == 33 + sequence and
                    frame[14:18] == b'\x60\0\0\0', 'exact original output headers')
            payload = bytes((sequence * 7 + lane * 13 + n * 19) & 255 for n in range(32))
            require((size == 32 and body[:2] + bytes(2) + body[4:] ==
                     b'\x81\0\0\0\x6d\x45' + sequence.to_bytes(2, 'big') + payload[8:]) if raw else
                    (size == 40 and body[:6] == struct.pack('!HHH', 46000 + sequence, 48000 + sequence, 40) and
                     body[8:] == payload), 'every original application output byte')
            data[sequence] = packet
        else:
            require(frame[:12] == guest + peer and protocol == 58, 'controlled incoming metadata error')
            errors.append(packet)
    require(set(requests) == set(replies) == set(range(161)) and len(data) == 80 and len(errors) == 160,
            'complete original metadata transactions, datagrams and checksum controls')
    require(not neighbors, 'every metadata neighbor solicitation is answered')
    for phase in range(161):
        require(requests[phase] < replies[phase] and
                rows[replies[phase]]['ns'] >= rows[requests[phase]]['ns'] and
                (not phase or replies[phase - 1] < requests[phase]), 'causal ordered metadata barriers')
        require(log.splitlines().count(f'{label}_PHASE_PASS lane={lane} phase={phase}') == 1,
                'actual metadata phase completion')
    for sequence in range(80):
        bad, good = errors[2 * sequence:2 * sequence + 2]
        original, scoped = data[sequence], sequence // 20 % 2
        require(good['body'][:2] == b'\x01\x04' and good['body'][4:8] == bytes(4) and
                good['body'][8:] == original['frame'][14:] and
                good['source'] == address(lane, 250, scoped) and good['destination'] == original['source'] and
                good['hop'] == 7 + sequence * 11 % 248 and
                good['traffic_class'] == (sequence * 37 + lane * 59) % 256 and
                good['frame'][14:18] == ((6 << 28) | (good['traffic_class'] << 20)).to_bytes(4, 'big') and
                not checksum(good['source'] + good['destination'] + struct.pack('!I3xB', len(good['body']), 58) + good['body']),
                'actual complete quote and independently varied received header')
        expected_extensions = []
        if outer:
            kinds = (0, 43, 60, 43, 60) if sequence % 3 == 0 else (0, 60, 43, 60)
            for n, kind in enumerate(kinds):
                following = kinds[n + 1] if n + 1 < len(kinds) else 58
                value = (bytes([following, 2, 4, 0, 0, 0, 0x73, n]) + original['source']
                         if kind == 43 else bytes([following, 0, 30, 4]) + bytes([0x31 + n]) * 4)
                expected_extensions.append((kind, value))
        require(good['extensions'] == expected_extensions and
                good['frame'][20] == (0 if outer else 58), 'every original outer extension byte and order')
        altered = bytearray(good['frame']); altered[good['upper'] + 1] ^= 1
        require(bad['frame'] == bytes(altered) and checksum(bad['source'] + bad['destination'] +
                struct.pack('!I3xB', len(bad['body']), 58) + bad['body']), 'distinct checksum-invalid code control')
        require(original['at'] < good['at'] and requests[2 * sequence + 1] < bad['at'] < good['at'] <
                replies[2 * sequence + 1] < requests[2 * sequence + 2] and
                rows[good['at']]['ns'] >= rows[original['at']]['ns'], 'owned original data/error delivery causality')
        actual = dict(observed[sequence])
        before = actual['before_header']
        for field in ('before_header', 'header'):
            actual[field] = normalize_header(actual[field], before, sequence % 20 == 19)
        wanted = expected(lane, sequence, index, original, good, native_copy_order, outer)
        changed = sorted(key for key in wanted if actual[key] != wanted[key])
        require(not changed, f'original error metadata case {sequence}: {changed}')
    return dict(passed=True, lane=lane, cases=80, original_datagrams=80, received_errors=160,
                actual_interface_index=index), dict(data=[data[n]['at'] for n in range(80)],
                errors=[row['at'] for row in errors])


def alter_log(log, lane, sequence, field, offset=None, outer=False):
    label = "IPV6_ERROR_EXTENSIONS" if outer else "IPV6_ERROR_METADATA"
    lines = log.splitlines()
    at = next(i for i,line in enumerate(lines) if line.startswith(
        f'{label}_CASE lane={lane} case={sequence} '))
    row = dict(item.split('=', 1) for item in lines[at].split()[1:])
    if offset is None:
        row[field] = str(int(row[field]) ^ 1)
    else:
        data = bytearray.fromhex(row[field]); data[offset] ^= 1; row[field] = data.hex()
    lines[at] = label + '_CASE ' + ' '.join(key+'='+value for key,value in row.items())
    return '\n'.join(lines)+'\n'


def verify_capture(path, lane, log_path, archive, native=False, interface_index=None, native_copy_order='length-first', outer=False):
    label = 'IPV6_ERROR_EXTENSIONS' if outer else 'IPV6_ERROR_METADATA'
    path, log_path = Path(path), Path(log_path)
    raw, original_log = path.read_bytes(), log_path.read_bytes()
    rows, log = read_capture(path), original_log.decode(errors='replace')
    result, proof = inspect(rows, lane, log, native, interface_index, native_copy_order, outer)
    names = ('missing-output','duplicate-output','missing-error','checksum','quote','hop','class',
             'source','destination','MAC','missing-case','result','flags','length','packet-address',
             'packet-index','hop-control','class-control','offender','source-name','payload',
             'written-padding','header-padding','queue','drain','name-prefix')
    if outer:
        names += ('outer-hop-byte', 'outer-route-byte', 'outer-destination-byte',
                  'outer-next-header', 'outer-length', 'routing-control-type',
                  'after-queue-enable', 'after-queue-disable')
    rejected = []
    with zipfile.ZipFile(archive,'w',zipfile.ZIP_DEFLATED) as saved:
        for name in names:
            changed, text = copy.deepcopy(rows), log
            at = proof['errors'][15]
            if name == 'missing-output':del changed[proof['data'][7]]
            elif name == 'duplicate-output':changed.insert(proof['data'][7],copy.deepcopy(changed[proof['data'][7]]))
            elif name == 'missing-error':del changed[at]
            elif name == 'missing-case':
                text = re.sub(rf'^{label}_CASE lane={lane} case=7 .*\n','',text,count=1,flags=re.MULTILINE)
            elif name in ('after-queue-enable', 'after-queue-disable'):
                text = alter_log(text, lane, 11 if name == 'after-queue-enable' else 12,
                                 'mask', outer=True)
            elif name == 'routing-control-type':
                text = alter_log(text, lane, 7, 'control', 148, True)
            elif name in ('result','flags','length','queue'):
                text = alter_log(text,lane,7,'queued' if name=='queue' else name,outer=outer)
            elif name in ('packet-address','packet-index','hop-control','class-control','offender',
                          'source-name','payload','written-padding','header-padding','drain','name-prefix'):
                field,offset,sequence={'packet-address':('control',16,7),'packet-index':('control',32,7),
                    'hop-control':('control',56,7),'class-control':('control',80,7),'offender':('control',128,7),
                    'source-name':('name',8,7),'payload':('payload',0,7),'written-padding':('control',37,7),
                    'header-padding':('header',12,7),'drain':('drain',0,7),'name-prefix':('name_prefix',0,16)}[name]
                if outer and name == 'offender':
                    offset += 104
                text = alter_log(text,lane,sequence,field,offset,outer)
            else:
                frame = bytearray(changed[at]['frame'])
                upper = 54
                protocol = frame[20]
                while protocol in (0, 43, 60):
                    protocol, upper = frame[upper], upper + (frame[upper + 1] + 1) * 8
                offset={'checksum':upper + 2,'quote':len(frame)-1,'hop':21,'class':15,'source':37,
                        'destination':53,'MAC':5,'outer-hop-byte':58,'outer-route-byte':78,
                        'outer-destination-byte':66,'outer-next-header':54,'outer-length':55}[name]
                frame[offset] ^= 1
                if name not in ('checksum','MAC','hop','class'):
                    frame[upper + 2:upper + 4]=bytes(2)
                    size=int.from_bytes(frame[18:20],'big') - (upper - 54)
                    frame[upper + 2:upper + 4]=checksum(frame[22:54]+struct.pack('!I3xB',size,58)+frame[upper:upper+size]).to_bytes(2,'big')
                changed[at]['frame']=bytes(frame)
            saved.writestr(name+'.pcap',encode_capture(changed));saved.writestr(name+'.log',text)
            try:inspect(changed,lane,text,native,interface_index,native_copy_order,outer)
            except ValueError as error:rejected.append(dict(name=name,reason=str(error)))
            else:raise ValueError('accepted damaged error metadata: '+name)
        saved.writestr('rejections.json',json.dumps(rejected,indent=2))
    require(path.read_bytes()==raw and log_path.read_bytes()==original_log,'original metadata evidence unchanged')
    result.update(damaged_rejected=len(rejected),original_sha256=hashlib.sha256(raw).hexdigest(),
                  original_log_sha256=hashlib.sha256(original_log).hexdigest(),
                  archive_sha256=hashlib.sha256(Path(archive).read_bytes()).hexdigest(),
                  requires_parent_native_clock_check=native)
    return result
