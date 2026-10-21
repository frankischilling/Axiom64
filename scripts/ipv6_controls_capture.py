# SPDX-License-Identifier: GPL-3.0-or-later
"""Audit original Ethernet inputs and every visible IPv6 receive-control byte."""
import copy
import hashlib
import ipaddress
import json
from pathlib import Path
import re
import struct
import zipfile
from ipv4_expiry_capture import checksum, encode_capture, read_capture
from tcp_capture_clock import bind_native_clock

SCALARS = {'lane', 'case', 'kind', 'scope', 'variant', 'mask', 'capacity', 'input_flags',
           'result', 'errno', 'name_length', 'length', 'flags', 'queued', 'queue_errno',
           'control_visible', 'name_visible'}
BUFFERS = {'before_header', 'header', 'name', 'name_prefix', 'control', 'payload', 'drain'}
DONE = 'IPV6_CONTROLS_PASS adapters=2 cases=160 variants=20 scopes=2 transports=2'


def require(value, reason):
    if not value:
        raise ValueError(reason)


def sample_lines(log, lane):
    selected = []
    all_rows = []
    for line in log.splitlines():
        if not line.startswith('IPV6_CONTROLS_CASE '):
            continue
        pairs = [item.split('=', 1) for item in line.split()[1:]]
        require(all(len(item) == 2 for item in pairs), 'complete metadata log fields')
        row = dict(pairs)
        require(len(pairs) == len(SCALARS | BUFFERS) and set(row) == SCALARS | BUFFERS,
                'exact metadata log field inventory')
        require(all(re.fullmatch(r'-?\d+', row[key]) for key in SCALARS),
                'integer metadata result fields')
        require(all(re.fullmatch(r'[0-9a-f]*', row[key]) for key in BUFFERS),
                'hexadecimal original metadata bytes')
        all_rows.append(row)
        if int(row['lane']) == lane:
            selected.append(row)
    require(len(all_rows) == 160 and
            [(int(r['lane']), int(r['case'])) for r in all_rows] ==
            [(side, case) for side in range(2) for case in range(80)],
            'all ordered original metadata results for both adapters')
    return selected


def normalized_header(encoded, before):
    value = bytearray.fromhex(encoded)
    original = bytes.fromhex(before)
    require(len(value) == len(original) == 56, 'complete original Linux message headers')
    for at in (0, 16, 32):
        require(0 < int.from_bytes(original[at:at + 8], 'little') < 2**47 and
                value[at:at + 8] == original[at:at + 8], 'unchanged actual input pointers')
        value[at:at + 8] = bytes(8)
    return bytes(value)


def expected_sample(lane, sequence, index, packet, native_copy_order='length-first'):
    variant, scoped = sequence % 20, sequence // 20 % 2
    mask = variant if variant < 8 else 7
    capacity = {8: 16, 9: 36, 10: 56, 11: 88}.get(variant, 96)
    visible = 37 if variant == 14 else 17 if variant == 18 else 96
    name_visible = 1 if variant == 16 else 0
    incoming = packet['body'][8:] if packet['protocol'] == 17 else packet['body']
    require(len(incoming) == 32, 'complete original application input')
    payload = bytearray(b'\xa5' * 32)
    copied = 5 if variant == 15 else 8 if variant == 13 else 32
    payload[:copied] = incoming[:copied]
    name = bytearray(b'\xa5' * 40)
    source = (struct.pack('<H', 10) + struct.pack('!H', 0 if sequence >= 40 else 42000 + sequence) +
              bytes(4) + packet['source'] + struct.pack('<I', index if scoped else 0))
    if variant not in (15, 16, 19):
        name[:28] = source
    control = bytearray(b'\xa5' * visible)
    full = bytearray(b'\xa5' * 96)
    used, flags = 0, 0
    # Successful CMSG layouts follow the Linux x86-64 ABI. Protected-page
    # variants below assert their separately observed native visible prefixes.
    for bit, kind, data in [(1, 50, packet['destination'] + struct.pack('<I', index)),
                            (2, 52, struct.pack('<I', packet['hop'])),
                            (4, 67, struct.pack('<I', packet['traffic_class']))]:
        if not mask & bit:
            continue
        remaining = capacity - used
        if remaining < 16:
            flags |= 8
            continue
        size = min(remaining, 16 + len(data))
        if size < 16 + len(data):
            flags |= 8
        full[used:used + size] = struct.pack('<QII', size, 41, kind) + data[:size - 16]
        used += min(remaining, (16 + len(data) + 7) & ~7)
    control[:] = full[:visible]
    if variant == 14:
        used, flags = 40, 0
    elif variant == 18:
        control[:] = struct.pack('<QII', 20, 41, 67) + b'\xa5'
        used, flags = 0, 0
    elif variant == 15:
        control[:] = b'\xa5' * visible
    before = bytearray(b'\xa5' * 56)
    for at in (0, 16, 32):
        before[at:at + 8] = bytes(8)
    before[8:12] = struct.pack('<I', 0 if variant == 19 else 40)
    before[24:32] = struct.pack('<Q', 2)
    before[40:48] = struct.pack('<Q', capacity)
    before[48:52] = struct.pack('<I', 0x5a5a)
    after = bytearray(before)
    failed = variant in (15, 16, 17)
    if variant != 15 and not (variant == 16 and native_copy_order == 'address-first'):
        after[8:12] = struct.pack('<I', 28)
    if not failed:
        after[48:52] = struct.pack('<I', flags | (32 if variant == 13 else 0))
        after[40:48] = struct.pack('<Q', used)
    peek = variant in (12, 18)
    return dict(lane=str(lane), case=str(sequence), kind='3' if sequence >= 40 else '2',
                scope=str(scoped), variant=str(variant), mask=str(mask), capacity=str(capacity),
                input_flags=str(2 if peek else 32 if variant == 13 else 0),
                result='-1' if failed else '32', errno='14' if failed else '0',
                name_length=str(int.from_bytes(after[8:12], 'little')),
                length=str(int.from_bytes(after[40:48], 'little')),
                flags=str(int.from_bytes(after[48:52], 'little')),
                queued='32' if peek else '-1', queue_errno='0' if peek else '11',
                control_visible=str(visible), name_visible=str(name_visible),
                before_header=before.hex(), header=after.hex(), name=name.hex(),
                name_prefix=source[:name_visible].hex(), control=control.hex(),
                payload=payload.hex(), drain=(incoming if peek else b'\xa5' * 32).hex())


def multicast_report(frame, guest, link):
    require(len(frame) >= 78 and frame[:12] == bytes.fromhex('333300000016') + guest and
            frame[14:18] == b'\x60\0\0\0' and frame[20:22] == b'\0\1' and
            frame[22:38] in (bytes(16), link) and
            frame[38:54] == ipaddress.IPv6Address('ff02::16').packed and
            frame[54:62] == b'\x3a\0\5\2\0\0\1\0', 'native MLD report envelope')
    end = 54 + int.from_bytes(frame[18:20], 'big')
    require(end <= len(frame), 'complete native multicast report')
    body = frame[62:end]
    require(len(body) >= 8 and body[:2] == b'\x8f\0' and not checksum(
        frame[22:54] + struct.pack('!I3xB', len(body), 58) + body), 'native MLD checksum')
    at = 8
    for _ in range(int.from_bytes(body[6:8], 'big')):
        require(at + 20 <= len(body), 'complete native multicast record')
        size = 20 + body[at + 1] * 4 + int.from_bytes(body[at + 2:at + 4], 'big') * 16
        require(body[at] in range(1, 7) and body[at + 4] == 255 and at + size <= len(body),
                'bounded native multicast group')
        at += size
    require(at == len(body), 'exact native multicast record length')


def inspect(rows, lane, log, native=False, interface_index=None, native_copy_order='length-first'):
    require(native_copy_order in ('address-first', 'length-first') and
            (native or native_copy_order == 'length-first'), 'explicit native or target copy order')
    require(log.count(DONE) == 1 and 'IPV6_CONTROLS_FAIL' not in log,
            'actual complete metadata client')
    for marker in ('IPV6_CONTROL_LOCAL_DONE cases=650 transports=2 capacities=34 guards=40',
                   'IPV6_CONTROL_FAULT_DONE cases=108 transports=2 prefixes=12 peek=2 operations=2 length_faults=12',
                   'IPV6_CONTROL_HEADER_DONE cases=96 transports=2 headers=20 names=4 peek=2'):
        require(log.splitlines().count(marker) == 1, 'complete original local receive observations')
    require(log.count(f'IPV6_CONTROLS_WIRE_PASS lane={lane} cases=80 scopes=2 variants=20') == 1,
            'complete per-adapter metadata workload')
    matches = [match.group(1) for line in log.splitlines()
               if (match := re.fullmatch(rf'IPV6_CONTROLS_INTERFACE lane={lane} index=(\d+)', line))]
    require(len(matches) == 1 and int(matches[0]) > 0, 'actual metadata interface index')
    index = int(matches[0])
    require(interface_index is None or index == interface_index,
            'native interface record matches client packet information')
    samples = sample_lines(log, lane)
    guest = bytes([0x52, 0x54, 0, 0x12, 0x34, 0x10 + lane])
    peer = bytes([2, 0x49, 0x50, 0x36, lane, 1])
    control = bytes([2, 0x49, 0x50, 0x36, lane, 0])
    local = ipaddress.IPv6Address(f'2001:db8:{lane + 1}::2').packed
    remote = ipaddress.IPv6Address(f'2001:db8:{lane + 1}::1').packed
    link, remote_link = (ipaddress.IPv6Address(value).packed for value in ('fe80::2', 'fe80::1'))
    requests, replies, packets, firmware, mld = {}, {}, [], [], []
    ready = False
    for at, row in enumerate(rows):
        frame = row['frame']
        require(len(frame) >= 14, 'complete metadata Ethernet header')
        if frame[12:14] == b'\x88\xbd':
            require(len(frame) == 60 and frame[14:19] == b'IP6C' + bytes([lane]) and
                    not any(frame[21:]) and frame[20] in (0, 1), 'complete metadata barrier')
            phase, reply = frame[19:21]
            require(phase in range(161) and frame[:12] ==
                    (guest + control if reply else control + guest), 'owned metadata barrier')
            book = replies if reply else requests
            require(phase not in book, 'unique metadata barrier')
            book[phase] = at
            if phase == 0 and not reply:
                ready = True
            continue
        if not ready and not native:
            require(frame[6:12] == guest and len(firmware) < 256,
                    'bounded metadata firmware belongs to this adapter')
            firmware.append(hashlib.sha256(frame).hexdigest())
            continue
        require(frame[12:14] == b'\x86\xdd', 'defined metadata cohort Ethernet protocols')
        if native and frame[20] == 0:
            multicast_report(frame, guest, link)
            mld.append(at)
            continue
        require(len(frame) >= 54 and frame[:12] == guest + peer,
                'metadata input belongs to the controlled peer')
        length, protocol, hop = struct.unpack('!HBB', frame[18:22])
        require(protocol in (17, 58) and 54 + length <= len(frame),
                'complete metadata transport frame')
        packets.append(dict(index=at, frame=frame, body=frame[54:54 + length],
                            source=frame[22:38], destination=frame[38:54], protocol=protocol,
                            hop=hop, traffic_class=(int.from_bytes(frame[14:18], 'big') >> 20) & 255))
    require(set(requests) == set(replies) == set(range(161)), 'all original metadata barriers')
    require(requests[0] < replies[0], 'causal metadata readiness')
    require(len(packets) == 160, 'one damaged and one valid input for every receive')
    for phase in range(161):
        require(requests[phase] < replies[phase] and
                (not phase or replies[phase - 1] < requests[phase]),
                'ordered original metadata barrier transactions')
        require(log.splitlines().count(f'IPV6_CONTROLS_PHASE_PASS lane={lane} phase={phase}') == 1,
                'actual metadata phase completion')
    for sequence in range(80):
        bad, good = packets[2 * sequence:2 * sequence + 2]
        require(requests[2 * sequence + 1] < bad['index'] < good['index'] <
                replies[2 * sequence + 1] < requests[2 * sequence + 2],
                'each original input lies inside its own delivery transaction')
        scoped, raw = sequence // 20 % 2, sequence >= 40
        source, destination = (remote_link, link) if scoped else (remote, local)
        protocol = 58 if raw else 17
        traffic_class, hop = (sequence * 37 + lane * 59) % 256, 7 + sequence * 11 % 248
        require((good['source'], good['destination'], good['protocol'], good['hop'],
                 good['traffic_class']) == (source, destination, protocol, hop, traffic_class),
                'exact original metadata addresses, scope, hop limit and traffic class')
        require(good['frame'][14:18] == ((6 << 28) | (traffic_class << 20)).to_bytes(4, 'big'),
                'exact original version and zero flow label')
        payload = bytes((sequence * 7 + lane * 13 + n * 19) & 255 for n in range(32))
        body = good['body']
        if raw:
            require(len(body) == 32 and body[:2] + bytes(2) + body[4:] ==
                    b'\x81\0\0\0\x6c\x44' + sequence.to_bytes(2, 'big') + payload[8:],
                    'exact original raw application bytes')
        else:
            require(len(body) == 40 and body[:6] == struct.pack('!HHH', 42000 + sequence,
                    41000 + sequence, 40) and body[6:8] != bytes(2) and body[8:] == payload,
                    'exact original UDP ports, length and application bytes')
        pseudo = source + destination + struct.pack('!I3xB', len(body), protocol)
        require(not checksum(pseudo + body), 'valid original input pseudo-header checksum')
        altered = bytearray(good['frame'])
        altered[-1] ^= 1
        require(bad['frame'] == bytes(altered) and checksum(pseudo + bad['body']),
                'original checksum rejection input differs by exactly one payload bit')
        actual = dict(samples[sequence])
        actual['header'] = normalized_header(actual['header'], actual['before_header']).hex()
        actual['before_header'] = normalized_header(actual['before_header'], actual['before_header']).hex()
        expected = expected_sample(lane, sequence, index, good, native_copy_order)
        differences = sorted(key for key in expected if actual[key] != expected[key])
        require(not differences, f'original metadata result case {sequence}: {differences}')
    return dict(passed=True, lane=lane, cases=80, original_inputs=160,
                actual_interface_index=index, firmware_frames=len(firmware),
                firmware_sha256=firmware, native_MLD_reports=len(mld),
                incoming=[packet['index'] for packet in packets])


def damaged_log(log, lane, sequence, field, offset=None):
    lines = log.splitlines()
    at = next(at for at, line in enumerate(lines)
              if line.startswith(f'IPV6_CONTROLS_CASE lane={lane} case={sequence} '))
    row = dict(item.split('=', 1) for item in lines[at].split()[1:])
    if offset is None:
        row[field] = str(int(row[field]) ^ 1)
    else:
        value = bytearray.fromhex(row[field])
        value[offset] ^= 1
        row[field] = value.hex()
    lines[at] = 'IPV6_CONTROLS_CASE ' + ' '.join(key + '=' + value for key, value in row.items())
    return '\n'.join(lines) + '\n'


def verify_capture(path, lane, log_path, archive, native=False, statistics=None,
                   interface_index=None, native_copy_order='length-first'):
    path, log_path = Path(path), Path(log_path)
    original, original_log = path.read_bytes(), log_path.read_bytes()
    rows, log = read_capture(path), original_log.decode(errors='replace')
    clock = None
    if native:
        selected = []
        for row in rows:
            row['stamp'] = row['ns'] // 1000
            frame = row['frame']
            if frame[12:14] != b'\x86\xdd' or frame[20] != 0:
                selected.append(row)
        clock = bind_native_clock(path, selected, statistics)
    proof = inspect(rows, lane, log, native, interface_index, native_copy_order)
    names = ('missing-input', 'duplicate-input', 'checksum', 'hop', 'traffic-class',
             'source', 'destination', 'MAC', 'payload', 'missing-case', 'wrong-result',
             'wrong-queue', 'wrong-flags', 'wrong-hop-control', 'wrong-class-control',
             'wrong-packet-destination', 'wrong-packet-index', 'wrong-source-name',
             'wrong-payload-copy', 'wrong-drain-copy', 'header-store-order', 'header-padding')
    rejected = []
    with zipfile.ZipFile(archive, 'w', zipfile.ZIP_DEFLATED) as saved:
        for name in names:
            changed, text = copy.deepcopy(rows), log
            at = proof['incoming'][15]  # The valid UDP input for all three controls.
            if name == 'missing-input':
                del changed[at]
            elif name == 'duplicate-input':
                changed.insert(at, copy.deepcopy(changed[at]))
            elif name == 'missing-case':
                text = re.sub(rf'^IPV6_CONTROLS_CASE lane={lane} case=7 .*\n', '', text,
                              count=1, flags=re.MULTILINE)
            elif name in ('wrong-result', 'wrong-queue', 'wrong-flags'):
                text = damaged_log(text, lane, 7, {'wrong-result': 'result',
                    'wrong-queue': 'queued', 'wrong-flags': 'flags'}[name])
            elif name in ('wrong-hop-control', 'wrong-class-control', 'wrong-packet-destination',
                          'wrong-packet-index', 'wrong-source-name', 'wrong-payload-copy',
                          'wrong-drain-copy', 'header-padding'):
                field, offset, case = {
                    'wrong-hop-control': ('control', 56, 7),
                    'wrong-class-control': ('control', 80, 7),
                    'wrong-packet-destination': ('control', 16, 7),
                    'wrong-packet-index': ('control', 32, 7),
                    'wrong-source-name': ('name', 8, 7),
                    'wrong-payload-copy': ('payload', 0, 7),
                    'wrong-drain-copy': ('drain', 0, 12),
                    'header-padding': ('header', 12, 7)}[name]
                text = damaged_log(text, lane, case, field, offset)
            elif name == 'header-store-order':
                lines = text.splitlines()
                pos = next(i for i, line in enumerate(lines) if line.startswith(
                    f'IPV6_CONTROLS_CASE lane={lane} case=17 '))
                row = dict(item.split('=', 1) for item in lines[pos].split()[1:])
                header = bytearray.fromhex(row['header'])
                header[40:48] = struct.pack('<Q', 88)
                row['length'], row['header'] = '88', header.hex()
                lines[pos] = 'IPV6_CONTROLS_CASE ' + ' '.join(key + '=' + value
                                                            for key, value in row.items())
                text = '\n'.join(lines) + '\n'
            else:
                frame = bytearray(changed[at]['frame'])
                offset = {'checksum': 60, 'hop': 21, 'traffic-class': 15,
                          'source': 37, 'destination': 53, 'MAC': 5,
                          'payload': len(frame) - 1}[name]
                frame[offset] ^= 1
                if name != 'checksum':
                    frame[60:62] = bytes(2)
                    body = frame[54:94]
                    value = checksum(frame[22:54] + struct.pack('!I3xB', len(body), 17) + body)
                    struct.pack_into('!H', frame, 60, value or 65535)
                changed[at]['frame'] = bytes(frame)
            saved.writestr(name + '.pcap', encode_capture(changed))
            saved.writestr(name + '.log', text)
            try:
                inspect(changed, lane, text, native, interface_index, native_copy_order)
            except ValueError as error:
                rejected.append(dict(name=name, reason=str(error)))
            else:
                raise ValueError('accepted damaged metadata evidence: ' + name)
        saved.writestr('rejections.json', json.dumps(rejected, indent=2))
    require(path.read_bytes() == original and log_path.read_bytes() == original_log,
            'original metadata packets and client output remain unchanged')
    proof.update(damaged_rejected=len(rejected), native_clock=clock,
                 original_sha256=hashlib.sha256(original).hexdigest(),
                 original_log_sha256=hashlib.sha256(original_log).hexdigest(),
                 archive_sha256=hashlib.sha256(Path(archive).read_bytes()).hexdigest())
    return proof
