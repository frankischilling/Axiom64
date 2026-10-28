# SPDX-License-Identifier: GPL-3.0-or-later
"""Reopen physical source changes and queries, complete source and boot products."""
import argparse
import hashlib
import json
from pathlib import Path
import struct
import zipfile

from ipv4_multicast_capture import checksum, products, records, require, query_timer_upper
from tcp_capture_clock import bind_native_clock

GROUP = bytes.fromhex('ef7f2a01')
FIRST = 0xc0000201
EXPECTED = ((5, (FIRST,)), (5, (FIRST + 1,)), (6, (FIRST,)),
            (4, (FIRST + 2,)), (6, (FIRST + 3,)), (5, (FIRST + 2,)), (3, ()))
OPTIONS = (39, 39, 40, 41, 38, 37, 36)
MARKER = 'IPV4_SOURCE_WIRE_PASS stages=7 lanes=2 operations=14'
NATIVE_EXCLUDE_KERNELS = {'6.6.87.2-microsoft-standard-WSL2', '6.17.0-1022-azure', '7.0.0-1017-azure'}


def contract(scenario, native, release):
    if scenario == 'settled':
        return ({stage: [record, record] for stage, record in enumerate(EXPECTED, 1)},
                dict(enumerate(OPTIONS, 1)), {}, MARKER)
    if scenario == 'overlap':
        reports = {1: [(4, ())], 2: [(4, (FIRST,)), (6, (FIRST,))],
                   3: [(6, (FIRST,))] * 2, 4: [(5, (FIRST + 1,))] * 2,
                   5: [(6, (FIRST + 1,))], 6: [(5, (FIRST + 1,))] * 2, 7: [(3, ())] * 2}
        return reports, {1: 35, 2: 38, 3: (37, 38), 4: (38, 37), 5: 38, 6: 37, 7: 36}, {}, 'IPV4_SOURCE_WIRE_OVERLAP_PASS stages=7 lanes=2 operations=18 first_packet_barriers=4 full_observations_each=5'
    if scenario == 'mtu':
        sources = tuple(FIRST + n for n in range(64))
        # RFC 9776 section 4.2.17 splits INCLUDE records; EXCLUDE uses one
        # stable prefix that fits the actual link MTU, never IP fragments.
        include_change = [(3, sources[n:n + 7]) for n in range(0, 64, 7)]
        include_query = [(1, sources[n:n + 7]) for n in range(0, 64, 7)]
        reports = {1: [(4, ())] * 2, 2: include_change * 2, 3: include_query,
                   4: [(4, sources[:7])] * 2, 5: [(2, sources[:7])], 6: [(2, sources)], 7: [(3, ())] * 2}
        return reports, {1: 35, 2: 41, 4: 41, 7: 36}, {3: (False, ()), 5: (False, ()), 6: (False, ())}, 'IPV4_SOURCE_WIRE_MTU_PASS stages=7 lanes=2 operations=8 queries=6 sources=64 minimum_mtu=68 restored_mtu=1500 restored_policy=10'
    require(scenario == 'queries', 'known source multicast case')
    if native:
        require(release in NATIVE_EXCLUDE_KERNELS, 'measured native-only EXCLUDE query kernel profile')
    # RFC 9776 Table 5 requires IS_IN(B-A). These measured native kernels
    # instead send the full EXCLUDE(A) record for a nonempty source response.
    exclude_response = (2, (FIRST,)) if native else (1, (FIRST + 2,))
    include = (1, (FIRST, FIRST + 1))
    excluded = (2, (FIRST,))
    reports = {1: [(5, (FIRST,))] * 2, 2: [(5, (FIRST + 1,))] * 2,
               3: [(1, (FIRST,))], 4: [], 5: [include], 6: [include],
               7: [(4, (FIRST,))] * 2, 8: [exclude_response], 9: [],
               10: [excluded], 11: [excluded], 12: [(3, ())] * 2}
    queries = {3: (False, (FIRST, FIRST + 2)), 4: (False, (FIRST + 2,)),
               5: (False, ()), 6: (True, ()), 8: (False, (FIRST, FIRST + 2)),
               9: (False, (FIRST,)), 10: (False, ()), 11: (True, ())}
    return reports, {1: 39, 2: 39, 7: 41, 12: 36}, queries, 'IPV4_SOURCE_WIRE_QUERY_PASS stages=12 lanes=2 operations=8 queries=16'


def lane(path, number, native, statistics, expected, query_cases, mtu=1500, expansion_stage=None, first_packet_stages=(), query_upper_us=1010000, overlap=False):
    rows = records(path)
    clock = None
    if native:
        selected = [row for row in rows if row['frame'][12:14] in (b'\x08\x00', b'\x88\xb9')]
        clock = bind_native_clock(path, selected, statistics)
    guest = bytes([0x52, 0x54, 0, 0x12, 0x34, 0x10 + number])
    peer = bytes([2, 0x41, 0x58, 0x4d, 0x43, number])
    local, remote = bytes([10, 67, number + 1, 2]), bytes([10, 67, number + 1, 1])
    started, completed, controls, reports, windows, queries = [], [], [], {}, {}, {}
    current = None
    first_reports = {}
    report_packets = {}
    events = []
    for packet_number, row in enumerate(rows):
        frame = row['frame']
        stamp = row.get('monotonic_ns', row['stamp'] * 1000)
        if frame[12:14] == b'\x88\xb9':
            require(len(frame) == 60 and frame[18] == number, 'source control interface and bounds')
            kind, stage = frame[14:18], frame[19]
            if kind == b'AXSB':
                require(frame[:12] == peer + guest and not any(frame[20:]) and
                        stage == len(started) + 1 and started == completed and stage <= len(expected),
                        'ordered physical source start request')
                events.append(('begin', stage))
                started.append(stage);current = stage;report_packets[stage] = 0
                controls.append(('begin', stage));reports[stage] = []
            elif kind == b'AXSD':
                require(frame[:12] == peer + guest and not any(frame[20:]) and
                        current == stage and controls[-1] == ('begin-ack', stage),
                        'source operation follows acknowledged start')
                events.append(('applied', stage))
                controls.append(('done', stage));windows[stage] = [stamp]
            else:
                require(kind == b'AXSA' and frame[:12] == guest + peer and not any(frame[21:]) and
                        current == stage and frame[20] in (ord('B'), ord('D')),
                        'actual source peer acknowledgment identity')
                done = frame[20] == ord('D')
                require(controls[-1] == ('done' if done else 'begin', stage),
                        'source acknowledgment follows its request')
                controls.append(('done-ack' if done else 'begin-ack', stage))
                events.append(('end' if done else 'ready', stage))
                if done:
                    if stage in first_packet_stages:
                        require(len(reports[stage]) >= 1 and stage in first_reports and
                                first_reports[stage] <= stamp,
                                'actual first report precedes source update barrier')
                    else:
                        require(stamp - windows[stage][0] >= 3_000_000_000,
                                'complete unscaled three-second source observation')
                    windows[stage].append(stamp);completed.append(stage)
            continue
        if frame[12:14] != b'\x08\x00':
            continue
        ip = frame[14:]
        require(len(ip) >= 24 and ip[0] == 0x46, 'source IGMP IPv4 header')
        total = int.from_bytes(ip[2:4], 'big')
        limit = 1500 if expansion_stage and (current or 0) >= expansion_stage else mtu
        require(24 <= total <= len(ip) and total <= limit and not checksum(ip[:24]) and
                not int.from_bytes(ip[6:8], 'big') & ~0x4000,
                'source IGMP original IPv4 bounds and checksum')
        require(ip[1] == 0xc0 and ip[8:10] == b'\x01\x02' and ip[20:24] == b'\x94\x04\0\0',
                'source IGMP Router Alert TTL and control class')
        body = ip[24:total]
        require(len(body) >= 8 and not checksum(body), 'source IGMP original payload checksum')
        if body[0] == 0x11:
            require(current in query_cases and current not in queries and controls[-1] == ('done', current),
                    'one query in its actual source observation')
            general, queried = query_cases[current]
            destination = bytes.fromhex('e0000001') if general else GROUP
            expected_mac = b'\x01\x00\x5e' + bytes([destination[1] & 127]) + destination[2:]
            require(frame[:12] == expected_mac + peer and ip[12:16] == remote and ip[16:20] == destination,
                    'actual source query addresses and interface')
            expected_body = b'\x11\x0a\0\0' + (bytes(4) if general else GROUP) + b'\x02\x7d' + struct.pack('!H', len(queried))
            expected_body += b''.join(struct.pack('!I', source) for source in queried)
            require(body[:2] + b'\0\0' + body[4:] == expected_body,
                    'actual complete source query and response interval')
            queries[current] = stamp
            continue
        require(frame[:12] == bytes.fromhex('01005e000016') + guest and ip[12:16] == local and
                ip[16:20] == bytes.fromhex('e0000016'), 'source IGMP report addresses and interface')
        require(body[:2] == b'\x22\0' and not any(body[4:6]) and int.from_bytes(body[6:8], 'big') > 0,
                'source IGMPv3 report checksum and header')
        require(current is not None and (overlap or controls[-1][0] in ('begin-ack', 'done')),
                'source report belongs to an open physical observation')
        if current in query_cases:
            require(current in queries and 0 <= stamp - queries[current] <= query_upper_us * 1000,
                    'actual unscaled source query response interval')
        first_reports.setdefault(current, stamp)
        report_packets[current] += 1
        offset = 8
        packet_records = set()
        for _ in range(int.from_bytes(body[6:8], 'big')):
            require(offset + 8 <= len(body), 'complete source group record')
            kind, auxiliary, count = struct.unpack_from('!BBH', body, offset)
            end = offset + 8 + 4 * count
            require(kind in range(1, 7) and not auxiliary and end <= len(body) and
                    body[offset + 4:offset + 8] == GROUP, 'source group record identity and bounds')
            sources = tuple(struct.unpack_from('!I', body, offset + 8 + n * 4)[0] for n in range(count))
            record = (kind, sources)
            if overlap:
                require(record not in packet_records, 'separate physical source report transmissions')
            packet_records.add(record)
            events.append(('report', current, packet_number, record))
            reports[current].append(record);offset = end
        require(offset == len(body), 'all physical source report bytes consumed')
    require(started == completed == list(range(1, len(expected) + 1)) and len(controls) == len(expected) * 4,
            'complete physical source stage inventory')
    require(set(queries) == set(query_cases), 'every original source query captured')
    if overlap:
        from ipv4_multicast.source_overlap import valid
        require(valid(events), 'native-derived exact source transition and retransmission')
    for stage, wanted in (() if overlap else expected.items()):
        reason = ('measured native source-query profile' if native else 'RFC 9776 source-query record') if stage in query_cases else 'native-derived exact source transition and retransmission'
        require(reports[stage] == wanted, reason)
        require(report_packets[stage] == len(wanted), 'separate physical source report transmissions')
    return dict(lane=number, frames=len(rows), reports=sum(map(len, reports.values())), queries=len(queries),
                stages=len(expected), complete_three_second_observations=len(expected) - len(first_packet_stages),
                first_packet_barriers=len(first_packet_stages), native_clock=clock)


def verify(directory):
    directory = Path(directory)
    metadata = json.loads((directory / 'results.json').read_text())
    if metadata.get('source_case') == 'delivery':
        from ipv4_multicast.delivery_capture import verify as verify_delivery
        return verify_delivery(directory)
    inputs = json.loads((directory / 'inputs.json').read_text())
    digest = lambda path: hashlib.sha256(path.read_bytes()).hexdigest()
    require(metadata['suite'] == 'source' and type(metadata['native']) is bool,
            'explicit source multicast execution domain')
    require(metadata['passed'] is True and metadata['products'] == inputs['products'],
            'source multicast producer outcome and product inventory')
    source = inputs['source']
    require(source == metadata['source'] and digest(directory / 'source.zip') == source['source_zip_sha256'] and
            digest(directory / 'source-inputs.json') == source['source_inputs_sha256'],
            'original complete source multicast fingerprints')
    sources = json.loads((directory / 'source-inputs.json').read_text())
    with zipfile.ZipFile(directory / 'source.zip') as archive:
        require(len(sources) == source['files'] == len(archive.namelist()) and set(archive.namelist()) == set(sources),
                'complete unique source multicast source archive')
        for name, expected in sources.items():
            require(hashlib.sha256(archive.read(name)).hexdigest() == expected, 'actual source multicast source bytes')
    for name, expected in inputs['products'].items():
        require(Path(name).name == name and digest(directory / name) == expected, 'actual retained source multicast product')
    products(directory, metadata, inputs, sources, program_prefix='ipv4-multicast-source-wire',
             source_name='userspace/tests/net/ipv4_multicast_source_wire.c')
    text = (directory / 'client.log').read_text()
    parsed = [json.loads(line) for line in text.splitlines() if line.startswith('{')]
    require(parsed and parsed[0]['kind'] == 'kernel' and (parsed[0]['sysname'] == 'Linux') == metadata['native'] and
            parsed[0]['release'], 'actual source multicast kernel and observations')
    scenario = metadata.get('source_case', 'settled')
    policy = [row for row in parsed if row.get('kind') == 'policy']
    if scenario == 'mtu':
        require(policy == [{'kind': 'policy', 'phase': 'configured', 'previous': 10, 'value': 64, 'mtu': 68},
                           {'kind': 'policy', 'phase': 'restored', 'value': 10}] and
                parsed[1] == policy[0] and parsed[-1] == policy[1],
                'actual configured source capacity and restored policy')
        parsed = [row for row in parsed if row.get('kind') != 'policy']
    else:
        require(not policy, 'no unrelated source policy mutation')
    require(parsed[0].get('case', 'settled') == scenario, 'actual source multicast case')
    expected, options, queries, marker = contract(scenario, metadata['native'], parsed[0]['release'])
    action_rows = sum(2 * (len(value) if isinstance(value, tuple) else 1) for value in options.values())
    query_rows = 2 * (len(expected) - len(options))
    require(len(parsed) == 1 + action_rows + query_rows + len(expected), 'all source multicast observations')
    require(text.splitlines().count(marker) == 1 and 'IPV4_SOURCE_WIRE_FAIL' not in text and
            metadata['error'] is None and metadata['returncode'] == (0 if metadata['native'] else 1),
            'actual source multicast client completion')
    cursor = 1
    for stage in expected:
        for number in range(2):
            operations = options.get(stage, (None,))
            if not isinstance(operations, tuple):
                operations = (operations,)
            for option in operations:
                row = parsed[cursor];cursor += 1
                require(row['lane'] == number and row['stage'] == stage, 'ordered source multicast action identity')
                if option is not None:
                    require(row['kind'] == 'action' and row['option'] == option and
                            row['returncode'] == row['errno'] == 0 and 0 <= row['begin_ns'] <= row['end_ns'],
                            'actual complete source membership operation')
                elif scenario == 'mtu' and stage == 6:
                    require(row['kind'] == 'mtu-change' and row['returncode'] == 0 and row['mtu'] == 1500 and
                            0 <= row['begin_ns'] <= row['end_ns'], 'actual live source interface MTU change')
                else:
                    require(row['kind'] == 'query-ready' and row['monotonic_ns'] > 0, 'actual source query readiness')
        row = parsed[cursor];cursor += 1
        first_packet = scenario == 'overlap' and stage in (1, 5)
        duration = row['end_ns'] - row['begin_ns']
        # A first-packet barrier may finish within one guest clock tick.
        # Every full observation still requires increasing clocks and the
        # independent complete three-second wire interval above.
        require(row['kind'] == 'observation' and row['stage'] == stage and
                (duration >= 0 if first_packet else duration > 0),
                'actual guest or native observation clock')
    require(cursor == len(parsed), 'all source multicast observations')
    if not metadata['native']:
        require(text.splitlines().count('AXIOM64_TESTS_PASS') == 1 and 'AXIOM64_EXIT status=0' in text,
                'actual source multicast guest completion')
    upper = query_timer_upper(directory, metadata)
    statistics = metadata['capture_statistics'] if metadata['native'] else [None, None]
    require(len(statistics) == 2, 'both physical source multicast captures')
    lanes = [lane(directory / f'lane{number}.pcap', number, metadata['native'], statistics[number], expected, queries, 68 if scenario == 'mtu' else 1500, 6 if scenario == 'mtu' else None, (1, 5) if scenario == 'overlap' else (), upper, scenario == 'overlap') for number in range(2)]
    return dict(passed=True, native=metadata['native'], profile=metadata['profile'], scenario=scenario,
                source_files=len(sources), actual_kernel_sha256=None if metadata['native'] else digest(directory / 'axiom64.elf'),
                stages_each=len(expected), lanes=lanes, full_feature_acceptance=False,
                minimum_mtu_guest_packets_verified=scenario == 'mtu' and not metadata['native'],
                overlap_guest_packets_verified=scenario == 'overlap' and not metadata['native'], full_matrix_pending=True)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('directory', type=Path)
    print(json.dumps(verify(parser.parse_args().directory), indent=2))
