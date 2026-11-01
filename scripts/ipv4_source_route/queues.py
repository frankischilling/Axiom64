# SPDX-License-Identifier: GPL-3.0-or-later
"""Check retained forwarding, unanswered ARP and delayed option processing."""
import copy
from pathlib import Path
import re

from ipv4_source_route.controls import decode, require
from ipv4_source_route.corpus import checksum, option_fields
from ipv4_source_route.packets import CLOCK_BOUND_NS, DAY_MS, client_trace, clocks
from ipv4_source_route.wire_evidence import integer, router
from ipv4_source_route.native import PRECISION_NS


def definitions():
    saved = decode(Path(__file__).with_name('queues.json').read_text())
    rows = copy.deepcopy(saved['cases'])
    require(saved['schema'] == 1 and len(rows) == 16 and
            [row['case'] for row in rows] == list(range(16)) and
            len({row['name'] for row in rows}) == len({row['input'][36:40] for row in rows}) == 16,
            'complete independent sixteen-case queue corpus')
    for row in rows:
        require(row['kind'] in ('packet', 'held') and row['observation_seconds'] == 5 and
                row['action'] == 'queue' and row['clocked'] is False and
                all(type(row[key]) is bool for key in ('timed', 'suppress_arp', 'prepare_alias', 'complete_route')) and
                (not row['prepare_alias'] or row['kind'] == 'held') and
                row['suppress_arp'] == (row['kind'] == 'packet') and
                row['transmitted'] == [row['input']] and row['reference'] in saved['references'],
                'fixed complete queue input and policy')
        frame = bytes.fromhex(row['input'])
        header = (frame[14] & 15) * 4
        require(frame[12:14] == b'\x08\x00' and len(frame) == 14 + int.from_bytes(frame[16:18], 'big') and
                checksum(frame[14:14 + header]) == 0, 'original complete checksummed queue input')
    return rows


def sample_records(text, rows):
    samples = {row['case']: {} for row in rows}
    drained, aliases, addresses = {}, [], []
    lines = text.replace('\r\n', '\n').splitlines()
    for position, line in enumerate(lines):
        if line.startswith('IPV4_SOURCE_SAMPLE '):
            match = re.fullmatch(r'IPV4_SOURCE_SAMPLE case=(\d+) phase=(early|late-before|late-after) '
                                 r'realtime_ns=(\d+) monotonic_before_ns=(\d+) monotonic_after_ns=(\d+)', line)
            require(match and int(match[1]) < len(rows), 'complete known delayed source-clock record')
            number, phase = int(match[1]), match[2]
            real, before, after = map(int, match.groups()[2:])
            require(rows[number]['timed'] and phase not in samples[number] and
                    0 <= real < 1 << 63 and 0 <= before <= after < 1 << 63 and
                    after - before <= CLOCK_BOUND_NS, 'unique bounded actual delayed clock sample')
            samples[number][phase] = dict(realtime_ns=real, monotonic_before_ns=before,
                                          monotonic_after_ns=after, position=position)
        elif line.startswith('IPV4_SOURCE_DRAINED '):
            match = re.fullmatch(r'IPV4_SOURCE_DRAINED case=(\d+) packets=(\d+)', line)
            require(match and int(match[1]) < len(rows), 'complete known early raw drain')
            number = int(match[1])
            require(rows[number]['timed'] and number not in drained and
                    int(match[2]) == int(rows[number]['complete_route']), 'one actual early raw drain')
            drained[number] = position
        elif line.startswith('IPV4_SOURCE_ALIAS '):
            aliases.append(line)
        elif line.startswith('IPV4_SOURCE_ADDRESS '):
            addresses.append(line)
    expected = [f'IPV4_SOURCE_ALIAS case={row["case"]} phase={phase} address=0a020001'
                for row in rows if row['prepare_alias'] for phase in ('prepared', 'survived')]
    require(aliases == expected, 'actual prepared and surviving egress alias queries')
    expected_addresses = [f'IPV4_SOURCE_ADDRESS case={row["case"]} action={row["mutation"]} address=0a010001 '
                          f'value={"ffffffff" if row["mutation"] == "egress-mask" else "0a01007f"}'
                          for row in rows if row.get('mutation') in ('egress-mask', 'egress-broadcast')]
    require(addresses == expected_addresses, 'actual same-source mask and broadcast replacement queries')
    for row in rows:
        number = row['case']
        phases = samples[number]
        require(list(phases) == (['early', 'late-before', 'late-after'] if row['timed'] else []),
                'complete ordered early and delayed clock samples')
        if row['timed']:
            require(phases['early']['position'] < drained[number] < phases['late-before']['position'] <
                    phases['late-after']['position'] < lines.index(
                        f'IPV4_SOURCE_WIRE_OBSERVED case={number} packets={2 * int(row["complete_route"])}'),
                    'actual raw drain and source samples before final observation')
        if row['prepare_alias']:
            require(lines.index(f'IPV4_SOURCE_WIRE_READY case={number}') < lines.index(expected[0]) <
                    lines.index(expected[1]) < lines.index(
                        f'IPV4_SOURCE_WIRE_MUTATED case={number} action=egress-address'),
                    'alias exists before admission and survives the actual address removal')
        if row.get('mutation') in ('egress-mask', 'egress-broadcast'):
            record = next(line for line in expected_addresses if line.startswith(f'IPV4_SOURCE_ADDRESS case={number} '))
            require(lines.index(f'IPV4_SOURCE_WIRE_READY case={number}') < lines.index(record) < lines.index(
                    f'IPV4_SOURCE_WIRE_MUTATED case={number} action={row["mutation"]}'),
                    'actual replacement getter precedes mutation completion')
    return samples


def receive_clocks(text, rows):
    synchronized, received = {}, {row['case']: {} for row in rows}
    for line in text.replace('\r\n', '\n').splitlines():
        if line.startswith('IPV4_SOURCE_SYNC '):
            match = re.fullmatch(r'IPV4_SOURCE_SYNC case=(\d+) phase=input realtime_ns=(\d+) '
                                 r'monotonic_before_ns=(\d+) monotonic_after_ns=(\d+)', line)
            require(match and int(match[1]) < len(rows), 'complete known source synchronization')
            number = int(match[1])
            require(number not in synchronized, 'one actual source synchronization per case')
            real, before, after = map(int, match.groups()[1:])
            target = synchronized
        elif line.startswith('IPV4_SOURCE_RAW_CLOCK '):
            match = re.fullmatch(r'IPV4_SOURCE_RAW_CLOCK case=(\d+) packet=(\d+) mode=(poll|command) '
                                 r'realtime_ns=(\d+) monotonic_before_ns=(\d+) monotonic_after_ns=(\d+) empty_before_ns=(\d+)', line)
            require(match and int(match[1]) < len(rows) and int(match[2]) < 1000,
                    'complete known actual raw observation clock')
            owner, number = int(match[1]), int(match[2])
            target = received[owner]
            require(number not in target, 'unique actual raw observation clock')
            real, before, after, empty = map(int, match.groups()[3:])
        else:
            continue
        require(0 <= real < 1 << 63 and 0 <= before <= after < 1 << 63 and after - before <= CLOCK_BOUND_NS,
                'actual source sampling within the original one-second bound')
        target[number] = dict(realtime_ns=real, monotonic_before_ns=before, monotonic_after_ns=after)
        if line.startswith('IPV4_SOURCE_RAW_CLOCK '):
            target[number]['mode'] = match[3]
            require(0 <= empty <= before, 'actual preceding empty raw observation')
            target[number]['empty_before_ns'] = empty
    require(set(synchronized) == set(range(len(rows))), 'all actual per-case source synchronizations')
    return synchronized, received


def guard_records(text, rows):
    armed, guarded = {}, {}
    lines = text.replace('\r\n', '\n').splitlines()
    for position, line in enumerate(lines):
        if line.startswith('IPV4_SOURCE_GUARD_ARM '):
            match = re.fullmatch(r'IPV4_SOURCE_GUARD_ARM case=(\d+)', line)
            require(match and int(match[1]) < len(rows), 'complete known raw guard arm')
            case = int(match[1])
            require(case not in armed, 'one raw guard arm per local error')
            armed[case] = position
        elif line.startswith('IPV4_SOURCE_GUARD '):
            match = re.fullmatch(r'IPV4_SOURCE_GUARD case=(\d+) packets=(\d+) revents=(\d+)', line)
            require(match and int(match[1]) < len(rows), 'complete known actual empty raw guard')
            case = int(match[1])
            require(case not in guarded and case in armed and int(match[2]) == 1 and int(match[3]) == 0,
                    'actual empty raw guard before local error')
            guarded[case] = position
    expected = {row['case'] for row in rows if row['suppress_arp'] and row['complete_route']}
    require(set(armed) == set(guarded) == expected, 'complete armed empty guards for every local error')
    for case in expected:
        original = [n for n, line in enumerate(lines) if line.startswith(f'IPV4_SOURCE_RAW_CLOCK case={case} packet=0 ')]
        error = [n for n, line in enumerate(lines) if line.startswith(f'IPV4_SOURCE_RAW_CLOCK case={case} packet=1 ')]
        require(len(original) == len(error) == 1, 'complete original and error raw clocks around the guard')
        require(original[0] < armed[case] < guarded[case] < error[0],
                'actual raw input then arm then empty guard then local error observation')
    return guarded


def guard_commands(directory, rows):
    values = decode((Path(directory) / 'commands.json').read_text())
    require(type(values) is list and 0 < len(values) < 10000, 'bounded original host command stream')
    expected = {row['case'] for row in rows if row['suppress_arp'] and row['complete_route']}
    guards = {}
    previous = -1
    for value in values:
        require(set(value) == {'command', 'monotonic_ns', 'input_hex'} and type(value['command']) is str,
                'complete original host command and actual input bytes')
        now = integer(value['monotonic_ns'])
        require(now >= previous, 'ordered actual host commands')
        previous = now
        match = re.fullmatch(r'guard (\d+)', value['command'])
        encoded = b'!' if match else (value['command'] + '\n').encode()
        require(value['input_hex'] == encoded.hex(), 'actual single-byte raw guard and complete command framing')
        if match:
            case = int(match[1])
            require(case in expected and case not in guards, 'one actual single-byte command per local error guard')
            guards[case] = now
    require(set(guards) == expected, 'complete actual single-byte guard command inventory')
    return guards


def reader(directory):
    from ipv4_source_route.native import bounds
    receipt = decode((Path(directory) / 'completed.json').read_text())
    require(receipt['mode'] in ('native', 'guest'), 'known queue reader execution domain')
    limits = bounds(Path(directory)) if receipt['mode'] == 'native' else (980000000, 2020000000)
    commands = guard_commands(directory, definitions())
    return lambda text, wire, results, native: observations(text, wire, results, native, timer_bounds=limits,
                                                          guard_commands=commands)


def canonical_ip(value, role, row, intervals=None):
    """Validate originals before masking generated identifiers and sampled times."""
    data = bytearray(value)
    require(len(data) >= 20 and data[0] >> 4 == 4, 'complete queue IPv4 datagram')
    header = (data[0] & 15) * 4
    require(20 <= header <= len(data) and int.from_bytes(data[2:4], 'big') == len(data),
            'complete queue header and payload length')
    count = (1 if role == 'input-raw' else 3 if role == 'quote' and row['complete_route'] else
             2 if role == 'quote' else 4 if role == 'local-error' else 3)
    stale = checksum(bytes(data[:header])) != 0
    require(role != 'wire-error' or not stale, 'actual queue Ethernet IPv4 checksum')
    restored = bytearray(data[:header])
    timestamps = []
    for at, kind, size in option_fields(data):
        if kind == 7:
            capacity = (size - 3) // 4
            require(size in (7, 15) and data[at + 2] == 4 + 4 * min(capacity, count),
                    'exact native RR progress through receive reply and failure')
            if stale and count <= capacity:
                pointer = data[at + 2]
                restored[at + 2] -= 4
                restored[at + pointer - 5:at + pointer - 1] = bytes(4)
        elif kind == 68:
            mode = data[at + 3] & 15
            require(mode in (0, 1) and intervals is not None, 'actual timed queue observation')
            width = 4 if mode == 0 else 8
            capacity = (size - 4) // width
            require(size == 4 + capacity * width and data[at + 2] == 5 + width * min(capacity, count),
                    'exact native timestamp progress')
            used = (data[at + 2] - 5) // width
            for number in range(used):
                stamp = at + 4 + number * width + (4 if mode == 1 else 0)
                timestamp = int.from_bytes(data[stamp:stamp + 4], 'big')
                require(timestamp < DAY_MS, 'actual UTC timestamp range')
                early = number == 0 or (row['complete_route'] and role != 'input-raw' and number == 1)
                before, after = intervals['early' if early else 'late']
                require(type(before) is int and type(after) is int and 0 <= after - before < 5000,
                        'unchanged bounded source-clock interval')
                delta = (timestamp - before % DAY_MS + DAY_MS + 20) % DAY_MS
                require(delta <= after - before + 40, 'every timestamp belongs to its actual source interval')
                timestamps.append(stamp)
            if stale and count <= capacity:
                pointer = data[at + 2]
                restored[at + 2] -= width
                restored[at + pointer - width - 1:at + pointer - 1] = bytes(width)
            elif stale:
                require(data[at + 3] >> 4, 'actual receive timestamp overflow')
                restored[at + 3] -= 16
    # Receive processing may retain the emitted checksum after one RR/TS update.
    # The unused fixture slots were zero: undo that exact update only for this check.
    require(not stale or checksum(bytes(restored)) == 0, 'validated original emitted header checksum')
    if data[9] == 1:
        require(len(data) >= header + 8 and checksum(bytes(data[header:])) == 0,
                'original complete queue ICMP checksum')
        if data[header] in (3, 11, 12):
            data[header + 8:] = bytes.fromhex(canonical_ip(data[header + 8:], 'quote', row, intervals))
            data[header + 2:header + 4] = bytes(2)
    for stamp in timestamps:
        data[stamp:stamp + 4] = bytes(4)
    source = bytes(data[12:16])
    require(source in (bytes((10, 0, 0, 2)), bytes((10, 0, 0, 1)), bytes((10, 1, 0, 1))),
            'actual fixture sender or selected router source')
    if source != bytes((10, 0, 0, 2)):
        data[4:6] = bytes(2)
        data[10:12] = bytes(2)
    if timestamps:
        data[10:12] = bytes(2)
    return data.hex()


def observations(text, wire, results, native, *, timer_bounds=None, guard_commands=None):
    rows = definitions()
    require(type(timer_bounds) is tuple and len(timer_bounds) == 2 and
            all(type(value) is int for value in timer_bounds) and timer_bounds[0] == 1000000000 - PRECISION_NS and
            timer_bounds[0] < timer_bounds[1] < 3000000000, 'explicit original protocol and observer timer bounds')
    raw = client_trace(text, rows, native)
    samples = sample_records(text, rows)
    synchronized, raw_clocks = receive_clocks(text, rows)
    guards = guard_records(text, rows)
    require(type(guard_commands) is dict and set(guard_commands) == set(guards),
            'actual host command evidence for every empty raw guard')
    require(type(wire) is list and type(results) is list and len(results) == len(rows),
            'complete queue observation matrix')
    previous = -1
    for value in wire:
        require(set(value) == {'case', 'index', 'direction', 'frame', 'monotonic_ns', 'realtime_ns', 'packet_type'} and
                type(value['case']) is int and 0 <= value['case'] < len(rows) and
                type(value['index']) is int and value['index'] in (0, 1) and value['direction'] in ('input', 'output') and
                isinstance(value['frame'], str) and re.fullmatch(r'[0-9a-f]{28,131106}', value['frame']) and
                len(value['frame']) % 2 == 0, 'complete bounded original queue Ethernet record')
        now = integer(value['monotonic_ns'])
        require(now >= previous, 'ordered actual queue wire receipts')
        previous = now
        integer(value['realtime_ns'])
        packet_type = value['packet_type']
        require(packet_type is None or (native and value['direction'] == 'output' and
                type(packet_type) is int and 0 <= packet_type <= 4), 'actual native queue socket metadata')
    outcomes = []
    for row, result in zip(rows, results):
        number = row['case']
        require(set(result) == {'name', 'case', 'packets', 'matched_native_reference', 'input_began_ns',
                               'input_realtime_ns', 'observation_began_ns', 'observation_seconds', 'ended_ns',
                               'raw_inputs', 'source_clocks', 'clock_request_ns', 'clock_response_ns',
                               'timestamp_receipts', 'sample_requests', 'output_packets', 'raw_receipts',
                               'source_request_ns', 'source_response_ns', 'error_guard'} and
                result['name'] == row['name'] and type(result['case']) is int and result['case'] == number,
                'complete exact ordered queue result')
        began, observed, ended = (integer(result[key]) for key in
                                  ('input_began_ns', 'observation_began_ns', 'ended_ns'))
        integer(result['input_realtime_ns'])
        require(type(result['observation_seconds']) is int and result['observation_seconds'] == 5 and
                began <= observed <= ended and ended - observed >= 5000000000,
                'full original five-second queue observation')
        origin = clocks(text, number, len(rows))
        require(result['source_clocks'] == origin and set(origin) == {'before'} and
                result['clock_request_ns'] is result['clock_response_ns'] is None,
                'actual queue source-clock origin')
        sync = synchronized[number]
        requested, responded = integer(result['source_request_ns']), integer(result['source_response_ns'])
        require(requested <= responded <= began and responded - requested <= CLOCK_BOUND_NS and
                sync['monotonic_before_ns'] >= origin['before']['monotonic_after_ns'],
                'actual source synchronization and original one-second response bound')
        intervals = None
        requests = result['sample_requests']
        require(type(requests) is list and [value['phase'] for value in requests] == list(samples[number]),
                'complete actual delayed sample requests')
        if row['timed']:
            sample = samples[number]
            ordered = [origin['before'], *sample.values()]
            require(all(right['monotonic_before_ns'] >= left['monotonic_after_ns']
                        for left, right in zip(ordered, ordered[1:])), 'ordered actual source-clock samples')
            intervals = dict(early=(origin['before']['realtime_ns'] // 1000000, sample['early']['realtime_ns'] // 1000000),
                             late=(sample['late-before']['realtime_ns'] // 1000000,
                                   sample['late-after']['realtime_ns'] // 1000000))
            for value in requests:
                require(set(value) == {'phase', 'requested_ns', 'responded_ns'} and
                        0 <= integer(value['responded_ns']) - integer(value['requested_ns']) <= CLOCK_BOUND_NS,
                        'unchanged one-second source sample response bound')
            require(requests[2]['responded_ns'] <= ended, 'prompt delayed source sample within the full observation')
        selected = [value for value in wire if value['case'] == number]
        incoming = [value for value in selected if value['direction'] == 'input' and value['frame'][24:28] == '0800']
        require(len(incoming) == 1 and incoming[0]['index'] == 0 and incoming[0]['frame'] == row['input'] and
                began <= incoming[0]['monotonic_ns'] <= observed, 'actual queue input bytes and ingress')
        output, retries, declared, timestamps, error_receipts = [], [], [], [], []
        for value in selected:
            frame, index = bytes.fromhex(value['frame']), value['index']
            if value['direction'] != 'output' or not router(frame, index):
                continue
            if frame[12:14] == b'\x08\x06':
                require(began <= value['monotonic_ns'] <= ended, 'actual ARP within the full queue observation')
                require(len(frame) >= 42 and frame[14:22] == bytes.fromhex('0001080006040001') and
                        frame[38:42] == bytes((10, index, 0, 2)), 'actual expected next-hop ARP request')
                if index == 1:
                    retries.append(value['monotonic_ns'])
                continue
            if frame[12:14] != b'\x08\x00':
                continue
            require(began <= value['monotonic_ns'] <= ended, 'actual IPv4 output within the full queue observation')
            length = int.from_bytes(frame[16:18], 'big')
            require(len(frame) == length + 14 or (len(frame) == 60 and length + 14 < 60 and
                    not any(frame[length + 14:])), 'exact queue IPv4 length and zero Ethernet padding')
            ip = frame[14:14 + length]
            if any(kind == 68 for _, kind, _ in option_fields(ip)):
                timestamps.append(value['monotonic_ns'])
            declared.append(dict(index=index, ethernet=frame[:14].hex(), ip=ip.hex()))
            output.append(dict(index=index, ethernet=frame[:14].hex(), ip=canonical_ip(ip, 'wire-error', row, intervals)))
            if row['suppress_arp']:
                error_receipts.append(value['monotonic_ns'])
        require(len(retries) == (3 if row['suppress_arp'] else 1), 'all actual neighbor retries retained')
        if row['suppress_arp']:
            require(all(timer_bounds[0] <= right - left <= timer_bounds[1]
                        for left, right in zip(retries, retries[1:])), 'actual one-second ARP retry spacing')
            require(all(timer_bounds[0] <= receipt - retries[2] <= timer_bounds[1] for receipt in error_receipts),
                    'actual ICMP error follows the third ARP retransmission timer')
        if row['timed']:
            require(retries[0] <= requests[0]['requested_ns'] <= requests[0]['responded_ns'] <= retries[0] + CLOCK_BOUND_NS and
                    retries[2] <= requests[1]['requested_ns'] <= requests[1]['responded_ns'] <= retries[2] + CLOCK_BOUND_NS,
                    'actual first and third ARP requests bracket the early and late source samples')
        require(result['timestamp_receipts'] == timestamps and result['output_packets'] == declared and
                type(result['packets']) is int and result['packets'] == len(output), 'original output bytes and declared receipts')
        require(raw[number] == result['raw_inputs'], 'original complete queue raw datagrams')
        require(set(raw_clocks[number]) == set(range(len(raw[number]))) and type(result['raw_receipts']) is list and
                len(result['raw_receipts']) == len(raw[number]), 'every raw datagram has an actual source clock and host receipt')
        for packet_number, receipt in enumerate(result['raw_receipts']):
            require(set(receipt) == {'case', 'packet', 'monotonic_ns'} and type(receipt['case']) is int and
                    receipt['case'] == number and type(receipt['packet']) is int and receipt['packet'] == packet_number,
                    'complete ordered actual raw clock receipt')
            observed_raw = integer(receipt['monotonic_ns'])
            source = raw_clocks[number][packet_number]
            require(began <= observed_raw <= ended and source['monotonic_before_ns'] >= sync['monotonic_after_ns'],
                    'actual raw observation within its complete case window')
            lower = requested + source['monotonic_before_ns'] - sync['monotonic_after_ns'] - PRECISION_NS
            upper = responded + source['monotonic_after_ns'] - sync['monotonic_before_ns'] + PRECISION_NS
            require(lower <= observed_raw <= upper + CLOCK_BOUND_NS,
                    'actual raw clock and host receipt within the original precision and one-second observer bound')
            lower, upper = max(lower, observed_raw - CLOCK_BOUND_NS), min(upper, observed_raw)
            require(lower <= upper, 'nonempty independent source and host raw observation bracket')
            if packet_number == 1:
                require(source['mode'] == 'poll', 'local error observed by actual raw readiness polling')
                require(upper - retries[2] >= timer_bounds[0] and lower - retries[2] <= timer_bounds[1],
                        'local raw error follows the third ARP retransmission timer')
                empty = source['empty_before_ns']
                require(sync['monotonic_after_ns'] <= empty and
                        source['monotonic_after_ns'] - empty <= CLOCK_BOUND_NS,
                        'local raw readiness and dequeue within the original one-second observer bound')
                error_receipts.append(observed_raw)
        guard = result['error_guard']
        if number in guards:
            require(type(guard) is dict and set(guard) == {'arm_requested_ns', 'arm_responded_ns', 'requested_ns', 'responded_ns'},
                    'complete actual host empty guard requests')
            arm_request, arm_response, guard_request, guard_response = (integer(guard[key]) for key in
                ('arm_requested_ns', 'arm_responded_ns', 'requested_ns', 'responded_ns'))
            require(retries[2] <= arm_request <= arm_response <= guard_request <= guard_response <= ended and
                    arm_response - arm_request <= CLOCK_BOUND_NS and guard_response - guard_request <= CLOCK_BOUND_NS and
                    guard_request - retries[2] >= timer_bounds[0] and
                    guard_request <= result['raw_receipts'][1]['monotonic_ns'],
                    'causal empty guard follows the third ARP retransmission timer within original observer bounds')
            require(guard_request <= integer(guard_commands[number]) <= guard_response,
                    'actual single-byte guard command belongs to its recorded host request')
        else:
            require(guard is None, 'no undeclared raw error guard')
        if row['timed']:
            require(error_receipts and min(error_receipts) <= requests[2]['requested_ns'] <= requests[2]['responded_ns'] and
                    requests[2]['responded_ns'] - min(error_receipts) <= CLOCK_BOUND_NS,
                    'prompt actual source sample after physical or local raw error observation')
        actual_raw = [canonical_ip(bytes.fromhex(value), 'input-raw' if n == 0 else 'local-error', row, intervals)
                      for n, value in enumerate(raw[number])]
        actual = dict(output=output, raw=actual_raw)
        require(actual == row['expected'], 'every queue Ethernet IP ICMP quote raw and option byte matches native Linux')
        outcomes.append(dict(case=number, name=row['name'], **actual))
    if not native:
        lines = text.replace('\r\n', '\n').splitlines()
        require(lines.count('AXIOM64_TESTS_PASS') == lines.count('AXIOM64_EXIT status=0') == 1, 'actual guest init and process success')
    return dict(cases=len(rows), packets=sum(len(row['output']) for row in outcomes),
                raw_packets=sum(len(row['raw']) for row in outcomes), timestamp_cases=6, outcomes=outcomes)
