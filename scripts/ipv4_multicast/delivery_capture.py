# SPDX-License-Identifier: GPL-3.0-or-later
"""Bind source-filtered Ethernet delivery to actual packets and socket observations."""
import hashlib
import json
from pathlib import Path
import struct
import zipfile

from ipv4_multicast_capture import checksum, products, records, require, query_timer_upper
from tcp_capture_clock import bind_native_clock

GROUP = bytes.fromhex('ef7f2a01')
GROUP_MAC = bytes.fromhex('01005e7f2a01')
MASKS = ((85, 102), (85, 102), (84, 102), (0, 102),
         (69, 102), (85, 102), (17, 34), (0, 0))
MARKER = ('IPV4_SOURCE_WIRE_DELIVERY_PASS stages=8 lanes=2 actions=48 sends=32 '
          'receives=92 quiet_windows=16 source_phases=8')
ACTIONS = {
    1: ('include-udp', 'include-raw', 'exclude-udp-join', 'exclude-udp-block',
        'exclude-raw-join', 'exclude-raw-block', 'duplicate-udp', 'duplicate-raw'),
    2: ('close-original-udp', 'close-original-raw'),
    3: ('final-close-udp', 'fresh-udp'), 4: ('final-close-raw', 'fresh-raw'),
    5: ('include-udp',), 6: ('include-raw',),
    7: ('all-zero-udp', 'all-zero-raw'),
    8: ('leave-include-udp', 'leave-exclude-udp', 'leave-include-raw',
        'leave-exclude-raw', 'all-one-udp', 'all-one-raw')}


def source(number, which):
    return bytes([10, 67, number + 1, 1 + which * 2])


def igmp(frame, number):
    ip = frame[14:]
    require(len(ip) >= 32 and ip[0] == 0x46, 'delivery IGMP IPv4 header')
    total = int.from_bytes(ip[2:4], 'big')
    local = bytes([10, 67, number + 1, 2])
    guest = bytes([0x52, 0x54, 0, 0x12, 0x34, 0x10 + number])
    require(32 <= total <= min(len(ip), 1500) and not checksum(ip[:24]) and
            ip[1] == 0xc0 and int.from_bytes(ip[6:8], 'big') & ~0x4000 == 0 and
            ip[8:10] == b'\x01\x02' and
            ip[12:16] == local and ip[16:20] == bytes.fromhex('e0000016') and
            ip[20:24] == b'\x94\x04\0\0' and
            frame[:12] == bytes.fromhex('01005e000016') + guest,
            'delivery IGMP addresses Router Alert and checksum')
    body = ip[24:total]
    require(body[:2] == b'\x22\0' and not any(body[4:6]) and not checksum(body),
            'delivery complete IGMPv3 report checksum')
    count = int.from_bytes(body[6:8], 'big')
    require(count > 0, 'delivery nonempty IGMP report')
    offset = 8
    for _ in range(count):
        require(offset + 8 <= len(body), 'delivery complete IGMP group record')
        kind, auxiliary, size = struct.unpack_from('!BBH', body, offset)
        end = offset + 8 + size * 4
        require(kind in range(1, 7) and auxiliary == 0 and size <= 64 and
                end <= len(body) and body[offset + 4:offset + 8] == GROUP,
                'delivery IGMP group and source bounds')
        entries = [body[offset + 8 + n * 4:offset + 12 + n * 4] for n in range(size)]
        require(len(set(entries)) == len(entries) and all(item == source(number, 0) for item in entries),
                'delivery actual IGMP source addresses')
        offset = end
    require(offset == len(body), 'delivery all IGMP bytes consumed')
    return count


def lane(path, number, native, statistics):
    packets = records(path)
    clock = None
    if native:
        selected = [row for row in packets if row['frame'][12:14] in (b'\x08\x00', b'\x88\xb9')]
        clock = bind_native_clock(path, selected, statistics)
    guest = bytes([0x52, 0x54, 0, 0x12, 0x34, 0x10 + number])
    peer = bytes([2, 0x41, 0x58, 0x4d, 0x43, number])
    local = bytes([10, 67, number + 1, 2])
    started, completed, controls = [], [], []
    incoming, outgoing, windows = {}, {}, {}
    stage = None
    reports = groups = 0
    for row in packets:
        frame = row['frame']
        stamp = row.get('monotonic_ns', row['stamp'] * 1000)
        if frame[12:14] == b'\x88\xb9':
            require(len(frame) == 60 and frame[18] == number, 'delivery control lane and bounds')
            kind, value = frame[14:18], frame[19]
            if kind == b'AXSB':
                require(frame[:12] == peer + guest and not any(frame[20:]) and
                        value == len(started) + 1 and value <= 8 and started == completed,
                        'delivery ordered physical start')
                started.append(value)
                stage = value
                controls.append(('begin', stage))
            elif kind == b'AXSD':
                require(frame[:12] == peer + guest and not any(frame[20:]) and value == stage and
                        controls[-1] == ('begin-ack', stage), 'delivery operation follows physical start')
                controls.append(('done', stage))
                windows[stage] = stamp
            else:
                require(kind == b'AXSA' and frame[:12] == guest + peer and not any(frame[21:]) and
                        value == stage and frame[20] in (ord('B'), ord('D')),
                        'delivery actual peer acknowledgment')
                done = frame[20] == ord('D')
                require(controls[-1] == ('done' if done else 'begin', stage),
                        'delivery acknowledgment order')
                if done:
                    require(stamp - windows[stage] >= 3_000_000_000,
                            'delivery complete unscaled three-second observation')
                    completed.append(stage)
                controls.append(('done-ack' if done else 'begin-ack', stage))
            continue
        if frame[12:14] != b'\x08\x00':
            continue
        ip = frame[14:]
        require(len(ip) >= 20, 'delivery complete IPv4 header')
        if ip[9] == 2:
            groups += igmp(frame, number)
            reports += 1
            continue
        require(ip[0] == 0x45 and ip[1] == 0 and ip[8:10] == b'\x01\x11' and
                int.from_bytes(ip[2:4], 'big') == 36 and len(ip) >= 36 and
                int.from_bytes(ip[6:8], 'big') & ~0x4000 == 0 and not checksum(ip[:20]),
                'delivery actual complete IPv4 UDP header and checksum')
        require(ip[16:20] == GROUP and frame[:6] == GROUP_MAC,
                'delivery exact wire multicast destination')
        udp, payload = ip[20:36], ip[28:36]
        source_port, destination, size, check = struct.unpack('!HHHH', udp[:8])
        require(destination == 39901 and size == 16 and payload[4] == number and
                payload[5] == stage and payload[7] == 0x7e and stage in range(1, 9) and
                controls[-1] in (('begin-ack', stage), ('done', stage)),
                'delivery packet belongs to its physical interface and open stage')
        pseudo = ip[12:20] + b'\0\x11\0\x10'
        if payload[:4] == b'AXSI':
            which = payload[6]
            require(which in (0, 1) and frame[6:12] == peer and ip[12:16] == source(number, which) and
                    controls[-1] == ('done', stage) and source_port == 41002 and check != 0 and
                    not checksum(pseudo + udp) and ip[4:8] == b'\x10\x67\0\0',
                    'delivery exact injected source datagram and checksum')
            key = (stage, which)
            require(key not in incoming, 'delivery exactly one injection per source and stage')
            incoming[key] = ip[:36]
        else:
            raw = int(payload[6] == ord('R'))
            require(payload[:4] == b'AXSO' and payload[6] in (ord('U'), ord('R')) and
                    frame[6:12] == guest and ip[12:16] == local and source_port == 41000 + raw and
                    (check == 0 if raw else check != 0 and not checksum(pseudo + udp)),
                    'delivery real guest raw and UDP output payloads')
            key = (stage, raw)
            require(key not in outgoing, 'delivery exactly one output per socket protocol and stage')
            outgoing[key] = ip[:36]
    require(started == completed == list(range(1, 9)) and len(controls) == 32,
            'delivery complete eight-stage wire inventory')
    wanted = {(stage, which) for stage in range(1, 9) for which in range(2)}
    require(set(incoming) == set(outgoing) == wanted,
            'delivery every real source injection and guest output captured')
    return dict(lane=number, frames=len(packets), injected=16, output=16,
                full_three_second_windows=8, igmp_reports=reports, igmp_records=groups,
                native_clock=clock), incoming


def verify(directory):
    directory = Path(directory)
    metadata = json.loads((directory / 'results.json').read_text())
    inputs = json.loads((directory / 'inputs.json').read_text())
    digest = lambda path: hashlib.sha256(path.read_bytes()).hexdigest()
    require(metadata['suite'] == 'source' and metadata['source_case'] == 'delivery' and
            type(metadata['native']) is bool and metadata['passed'] is True and
            metadata['products'] == inputs['products'], 'delivery explicit producer domain and products')
    frozen = inputs['source']
    require(frozen == metadata['source'] and digest(directory / 'source.zip') == frozen['source_zip_sha256'] and
            digest(directory / 'source-inputs.json') == frozen['source_inputs_sha256'],
            'delivery original complete source fingerprints')
    sources = json.loads((directory / 'source-inputs.json').read_text())
    with zipfile.ZipFile(directory / 'source.zip') as archive:
        require(len(sources) == frozen['files'] == len(archive.namelist()) and set(archive.namelist()) == set(sources),
                'delivery complete unique source archive')
        for name, expected in sources.items():
            require(hashlib.sha256(archive.read(name)).hexdigest() == expected, 'delivery original source bytes')
    require('userspace/tests/net/ipv4_multicast_source_delivery.c' in sources and
            'userspace/tests/net/ipv4_multicast_source_delivery.h' in sources,
            'delivery complete linked C implementation source')
    for name, expected in inputs['products'].items():
        require(Path(name).name == name and digest(directory / name) == expected,
                'delivery actual retained product bytes')
    query_timer_upper(directory, metadata)
    products(directory, metadata, inputs, sources, program_prefix='ipv4-multicast-source-wire',
             source_name='userspace/tests/net/ipv4_multicast_source_wire.c')
    program = 'ipv4-multicast-source-wire-' + metadata['profile']
    compiler = json.loads((directory / (program + '.inputs.json')).read_text())
    require(compiler['sources'].get('userspace/tests/net/ipv4_multicast_source_delivery.c') ==
            sources['userspace/tests/net/ipv4_multicast_source_delivery.c'],
            'delivery actual linked helper compilation')
    text = (directory / 'client.log').read_text()
    require(text.splitlines().count(MARKER) == 1 and 'IPV4_SOURCE_WIRE_FAIL' not in text and
            metadata['error'] is None and metadata['returncode'] == (0 if metadata['native'] else 1),
            'delivery actual complete client execution')
    if not metadata['native']:
        require(text.splitlines().count('AXIOM64_TESTS_PASS') == 1 and 'AXIOM64_EXIT status=0' in text and
                'Firmware: ' + metadata['firmware'].upper() in text, 'delivery actual guest boot and exit')
        command = json.loads((directory / 'command.json').read_text())
        devices = [command[n + 1] for n, value in enumerate(command[:-1]) if value == '-device']
        require(sum(value.startswith('virtio-net-pci,') for value in devices) == 1 and
                sum(value.startswith('e1000,') for value in devices) == 1 and
                any(('disable-legacy=on' if metadata['transport'] == 'modern' else 'disable-modern=on') in value
                    for value in devices if value.startswith('virtio-net-pci,')),
                'delivery actual paired device and virtio transport command')
    statistics = metadata['capture_statistics'] if metadata['native'] else [None, None]
    require(len(statistics) == 2, 'delivery both complete packet captures')
    checked = [lane(directory / f'lane{n}.pcap', n, metadata['native'], statistics[n]) for n in range(2)]
    parsed = [json.loads(line) for line in text.splitlines() if line.startswith('{')]
    require(parsed and parsed[0] == dict(kind='kernel', sysname='Linux' if metadata['native'] else 'Axiom64',
            release=metadata['native_kernel_release'] if metadata['native'] else '0.1', case='delivery'),
            'delivery actual execution kernel and scenario')
    cursor = 1
    for stage in range(1, 9):
        for number in range(2):
            for operation in ACTIONS[stage]:
                row = parsed[cursor]
                cursor += 1
                descriptor = operation.startswith(('duplicate-', 'fresh-'))
                require(set(row) == {'kind', 'lane', 'stage', 'operation', 'returncode', 'errno'} and
                        row['kind'] == 'delivery-action' and row['lane'] == number and row['stage'] == stage and
                        row['operation'] == operation and row['errno'] == 0 and
                        type(row['returncode']) is int and (row['returncode'] >= 0 if descriptor else row['returncode'] == 0),
                        'delivery complete ordered source and description operations')
            for raw in range(2):
                row = parsed[cursor]
                cursor += 1
                require(row['kind'] == 'delivery-send' and row['lane'] == number and row['stage'] == stage and
                        row['raw'] == raw and row['returncode'] == (16 if raw else 8) and row['errno'] == 0 and
                        0 <= row['begin_ns'] <= row['end_ns'], 'delivery actual raw and UDP send results')
        row = parsed[cursor]
        cursor += 1
        require(row['kind'] == 'observation' and row['stage'] == stage and
                0 < row['begin_ns'] < row['end_ns'], 'delivery actual observation clock')
        for number in range(2):
            seen = set()
            expected = {(slot, which) for which, mask in enumerate(MASKS[stage - 1])
                        for slot in range(8) if mask & (1 << slot)}
            while cursor < len(parsed) and parsed[cursor]['kind'] == 'delivery-data':
                row = parsed[cursor]
                cursor += 1
                require(row['lane'] == number and row['stage'] == stage, 'delivery receive phase and interface')
                slot = row['slot']
                which = next((n for n in range(2) if row['source'] == int.from_bytes(source(number, n), 'big')), None)
                require((slot, which) in expected and (slot, which) not in seen,
                        'delivery source filters final close and fresh-description isolation')
                packet = checked[number][1][(stage, which)]
                raw = slot >= 4
                body = packet if raw else packet[28:36]
                require(row['bytes'] == len(body) and row['hex'] == body.hex() and
                        row['source_port'] == (0 if raw else 41002),
                        'delivery complete received bytes match actual injected packet')
                seen.add((slot, which))
            require(seen == expected, 'delivery every allowed source and independent receive queue')
            row = parsed[cursor]
            cursor += 1
            require(row['kind'] == 'delivery-phase' and row['lane'] == number and row['stage'] == stage and
                    (row['mask_a'], row['mask_b']) == MASKS[stage - 1] and row['received'] == len(expected) and
                    row['quiet_begin_ns'] > 0 and row['quiet_end_ns'] - row['quiet_begin_ns'] >= 200_000_000,
                    'delivery complete masks and unscaled 200ms quiet observation')
    require(cursor == len(parsed) and len(parsed) == 197, 'delivery complete operation and receive inventory')
    return dict(passed=True, native=metadata['native'], profile=metadata['profile'], scenario='delivery',
                source_files=len(sources), lanes=[row[0] for row in checked],
                actions=48, actual_sends=32, actual_receives=92, complete_200ms_quiet_windows=16,
                source_phases=8, complete_three_second_wire_windows=16,
                actual_kernel_sha256=None if metadata['native'] else digest(directory / 'axiom64.elf'),
                igmp_transition_count_acceptance=False, full_feature_acceptance=False)
