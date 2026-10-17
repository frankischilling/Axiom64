# SPDX-License-Identifier: GPL-3.0-or-later
"""Independently audit ICMP quotes, actual TCP ownership and driver receipts."""
import argparse
from collections import Counter, defaultdict, deque
import hashlib
import json
from pathlib import Path
from tcp_capture_clock import bind_native_clock, microseconds
import re
import struct
from fetch import ROOT


def require(value, message):
    if not value:
        raise ValueError(message)


def checksum(data):
    total = 0
    for at in range(0, len(data), 2):
        total += (data[at] << 8) | (data[at + 1] if at + 1 < len(data) else 0)
    while total > 65535:
        total = (total & 65535) + (total >> 16)
    return total ^ 65535


def fnv(frame):
    result = 0xcbf29ce484222325
    for byte in frame:
        result = (result ^ byte) * 0x100000001b3 & 0xffffffffffffffff
    return f'{result:016x}'


def packets(path, statistics=None):
    raw = path.read_bytes()
    require(len(raw) >= 24 and raw[:4] == bytes.fromhex('d4c3b2a1'), 'PCAP header')
    header = struct.unpack_from('<IHHIIII', raw)
    require(header[1:3] == (2, 4) and header[6] == 1, 'Ethernet PCAP version')
    at, previous, rows = 24, 0, []
    while at < len(raw):
        require(at + 16 <= len(raw), 'complete PCAP record')
        seconds, microseconds, size, original = struct.unpack_from('<IIII', raw, at)
        at += 16
        require(size == original and 14 <= size <= header[5] and microseconds < 1000000 and
                at + size <= len(raw), 'complete captured Ethernet bytes')
        stamp = seconds * 1000000 + microseconds
        frame = raw[at:at + size]
        at += size
        if frame[12:14] != b'\x08\x00':
            continue
        require(statistics is not None or stamp >= previous, 'monotonic IPv4 PCAP receipt clock')
        previous = stamp
        ip = frame[14:]
        require(len(ip) >= 20 and ip[0] == 0x45 and checksum(ip[:20]) == 0,
                'actual outer IPv4 header and checksum')
        total = int.from_bytes(ip[2:4], 'big')
        require(20 <= total <= len(ip) and not int.from_bytes(ip[6:8], 'big') & 0xbfff,
                'bounded unfragmented actual IPv4 packet')
        body = ip[20:total]
        if ip[9] == 6:
            require(len(body) >= 20 and 20 <= (body[12] >> 4) * 4 <= len(body) and
                    checksum(ip[12:20] + bytes([0, 6]) + len(body).to_bytes(2, 'big') + body) == 0,
                    'actual TCP header, payload bounds and pseudo-header checksum')
        else:
            require(ip[9] == 1, 'only TCP and ICMP in the isolated fixture')
        rows.append(dict(stamp=stamp, frame=frame, ip=ip[:total], body=body, protocol=ip[9]))
    require(rows, 'nonempty actual traffic')
    if statistics is not None:
        bind_native_clock(path, rows, statistics)
    return rows


def contract():
    text = (ROOT / 'userspace/tests/net/tcp_icmp_cases.h').read_text()
    rows = re.findall(r'\{"([a-z-]+)",\s*(\d+),\s*(\d+),\s*"([a-z-]+)",\s*ICMP_([A-Z_]+),\s*(\d+)\}', text)
    require(len(rows) == 57 and len({row[0] for row in rows}) == 57, 'complete ICMP case contract')
    return [dict(name=name, type=int(kind), code=int(code), mutation=mutation, mode=mode, error=int(error))
            for name, kind, code, mutation, mode, error in rows]


def expected_quote(original, mutation):
    result = bytearray(original[:28])
    if mutation == 'options':
        result[20:20] = b'\x01\x01\0\0'
        result[0] = 0x46
        result[2:4] = (int.from_bytes(result[2:4], 'big') + 4).to_bytes(2, 'big')
    changes = {'version': (0, 0x20), 'protocol': (9, 23), 'local': (15, 64),
               'peer': (19, 64), 'source-port': (21, 1), 'target-port': (23, 1)}
    if mutation in changes:
        at, value = changes[mutation]
        result[at] ^= value
    if mutation == 'ihl': result[0] = 0x44
    if mutation == 'short-original': result[2:4] = b'\0\x1c'
    if mutation in ('fragment', 'more-fragments', 'reserved'):
        result[6:8] = {'fragment': b'\0\1', 'more-fragments': b'\x20\0', 'reserved': b'\x80\0'}[mutation]
    if mutation in ('old-sequence', 'future-sequence', 'upper-edge', 'half-range'):
        sequence = int.from_bytes(result[24:28], 'big')
        change = {'old-sequence': -1, 'future-sequence': 2, 'upper-edge': 1, 'half-range': 0x80000000}[mutation]
        result[24:28] = ((sequence + change) & 0xffffffff).to_bytes(4, 'big')
    result[10:12] = bytes(2)
    header = 24 if mutation == 'options' else 20
    result[10:12] = checksum(result[:header]).to_bytes(2, 'big')
    if mutation == 'quote-checksum': result[10] ^= 1
    if mutation == 'truncated': result = result[:-1]
    return bytes(result)


def tcp_fields(item):
    body = item['body']
    return dict(source=int.from_bytes(body[:2], 'big'), target=int.from_bytes(body[2:4], 'big'),
                sequence=int.from_bytes(body[4:8], 'big'), acknowledgment=int.from_bytes(body[8:12], 'big'),
                flags=body[13], data=body[(body[12] >> 4) * 4:])


def verify_controls(packets, quotes, cases, native, windows):
    """Prove the good handshake, request replacement and ACK progress from bytes."""
    native_accepts = {'quote-checksum', 'short-original', 'version', 'fragment', 'more-fragments', 'reserved'}
    for lane in range(2):
        for ordinal, case in enumerate(cases):
            mode = case['mode']
            items = []
            for item in packets:
                if item['protocol'] != 6 or item['lane'] != lane:
                    continue
                fields = tcp_fields(item)
                if mode.startswith('PASSIVE'):
                    belongs = (fields['source' if item['outgoing'] else 'target'] == 40000 + lane * 1000 + ordinal and
                               fields['target' if item['outgoing'] else 'source'] in
                               (56000 + lane * 1000 + ordinal * 2, 56001 + lane * 1000 + ordinal * 2))
                else:
                    belongs = fields['target' if item['outgoing'] else 'source'] == 48000 + lane * 1000 + ordinal
                if belongs:
                    items.append((item, fields))
            actual_quotes = quotes[(lane, ordinal)]
            require(len(actual_quotes) == (2 if case['mutation'] == 'last-error' else 1),
                    'exact one-error or last-error replacement injection count')
            start, end = windows[(lane, ordinal)]
            for item, source in actual_quotes:
                require(start - 100 <= source['driver_ms'] <= end + 100 and
                        start - 100 <= item['driver_ms'] <= end + 100,
                        'actual quoted transmission and driver delivery occur in their socket lifetime')
                if item['lane'] == source['lane']:
                    require(item['peer_ms'] >= source['peer_ms'], 'causal independent peer receipt clock')
            outgoing = [(item, fields) for item, fields in items if item['outgoing']]
            incoming = [(item, fields) for item, fields in items if not item['outgoing']]
            syns = [(item, fields) for item, fields in outgoing if fields['flags'] & 2]
            require(syns, 'actual socket emits its owned handshake')
            failed = mode in ('PENDING', 'BLOCKING', 'INTERRUPT', 'RETAINED') or (
                mode == 'IGNORE' and native and case['mutation'] in native_accepts)
            if failed:
                require(not any(fields['flags'] == 18 for _, fields in incoming) and end - start < 1500,
                        'owned pending error completes without a successful handshake or timeout')
                continue
            if mode.startswith('PASSIVE'):
                selected_port = 56000 + lane * 1000 + ordinal * 2 + int(mode == 'PASSIVE_DROP')
                selected = [(item, fields) for item, fields in syns if fields['target'] == selected_port]
                require(selected, 'actual passive completion selects the expected request generation')
                syn, opening = selected[0]
                peer_syns = [(item, fields) for item, fields in incoming if fields['source'] == selected_port and
                             fields['flags'] == 2 and microseconds(item) < microseconds(syn)]
                require(peer_syns and opening['flags'] == 18 and opening['acknowledgment'] ==
                        (peer_syns[-1][1]['sequence'] + 1) & 0xffffffff,
                        'passive SYN-ACK acknowledges its actual selected peer SYN')
                acknowledgments = [(item, fields) for item, fields in incoming if fields['source'] == selected_port and
                                   fields['flags'] == 16 and fields['acknowledgment'] ==
                                   (opening['sequence'] + 1) & 0xffffffff and microseconds(item) > microseconds(syn)]
                require(acknowledgments and any(fields['target'] == selected_port and fields['data'] == b'P' and
                                               microseconds(item) > microseconds(acknowledgments[0][0])
                                               for item, fields in outgoing),
                        'accepted passive request completes the real handshake and sends application bytes')
                if mode == 'PASSIVE_DROP':
                    require(selected_port != tcp_fields(actual_quotes[0][1])['target'] and
                            not any(fields['data'] for _, fields in outgoing if fields['target'] != selected_port),
                            'the failed unaccepted request cannot deliver application bytes')
                continue
            syn, opening = syns[-1] if mode == 'RETRY' else syns[0]
            if mode == 'RETRY':
                require(len({fields['sequence'] for _, fields in syns}) == 2 and
                        microseconds(syn) > microseconds(actual_quotes[0][0]),
                        'retry creates a fresh sequence owner after consuming the actual failure')
            synacks = [(item, fields) for item, fields in incoming if fields['flags'] == 18 and
                       fields['acknowledgment'] == (opening['sequence'] + 1) & 0xffffffff and
                       microseconds(item) > microseconds(syn)]
            require(synacks, f'successful control receives its actual owned SYN-ACK: lane={lane} case={case["name"]}')
            reply, reply_fields = synacks[0]
            origin = (opening['sequence'] + 1) & 0xffffffff
            peer_origin = (reply_fields['sequence'] + 1) & 0xffffffff
            require(any(fields['flags'] & 16 and fields['acknowledgment'] == peer_origin and
                        fields['sequence'] == origin and microseconds(item) > microseconds(reply)
                        for item, fields in outgoing), 'successful control acknowledges its real SYN-ACK')
            if mode == 'IGNORE':
                require(microseconds(reply) - microseconds(syn) >= 350000 and
                        microseconds(reply) > microseconds(actual_quotes[0][0]),
                        'ignored quote preserves the socket until the delayed successful handshake')
            if mode in ('SOFT', 'RECOVER', 'CONSUME'):
                data = [(item, fields) for item, fields in outgoing if fields['data'] == b'one']
                require(data and all(fields['sequence'] == origin for _, fields in data) and
                        end - data[0][0]['driver_ms'] >= 2300,
                        'actual outstanding bytes retain the configured delivery timeout')
                if case['mutation'] == 'last-error':
                    require([item['body'][:2] for item, _ in actual_quotes] == [b'\x03\x03', b'\x0c\0'] and
                            microseconds(actual_quotes[1][0]) - microseconds(actual_quotes[0][0]) >= 40000,
                            'the later actual parameter error replaces the earlier port diagnostic')
                if mode == 'RECOVER':
                    progress = [(item, fields) for item, fields in incoming if fields['data'] == b'K' and
                                fields['sequence'] == peer_origin and fields['acknowledgment'] ==
                                (origin + 3) & 0xffffffff and microseconds(item) > microseconds(actual_quotes[0][0])]
                    require(len(progress) == 1 and microseconds(progress[0][0]) - microseconds(data[0][0]) >= 450000,
                            'actual ACK progress and recovery byte follow the soft error')
                    second = [(item, fields) for item, fields in outgoing if fields['data'] == b'two']
                    require(second and all(fields['sequence'] == (origin + 3) & 0xffffffff and
                                           fields['acknowledgment'] == (peer_origin + 1) & 0xffffffff and
                                           microseconds(item) > microseconds(progress[0][0]) for item, fields in second) and
                            end - second[0][0]['driver_ms'] >= 2300,
                            'actual post-progress bytes remain outstanding until their new delivery timeout')
                    require(not any(fields['flags'] & 16 and fields['acknowledgment'] ==
                                    (origin + 6) & 0xffffffff for _, fields in incoming),
                            'the delivery timeout does not follow acknowledged second bytes')
            if mode == 'TIME_WAIT':
                fin, _ = actual_quotes[0]
                own_fin = tcp_fields(actual_quotes[0][1])
                peer_fins = [(item, fields) for item, fields in incoming if fields['flags'] & 1 and
                             fields['acknowledgment'] == (own_fin['sequence'] + 1) & 0xffffffff and
                             microseconds(item) < microseconds(fin)]
                require(peer_fins and any(fields['flags'] == 16 and fields['acknowledgment'] ==
                                         (peer_fins[0][1]['sequence'] + 1) & 0xffffffff and
                                         microseconds(peer_fins[0][0]) < microseconds(item) < microseconds(fin)
                                         for item, fields in outgoing),
                        'actual FIN exchange and final ACK enter TIME_WAIT before the late ICMP')


def verify_companions(packets, text, cases):
    completed = re.findall(r'^ICMP_COMPANION_PASS lane=(\d+) role=(\d+) checkpoints=(\d+)\r?$', text, re.M)
    require(len(completed) == 4 and {(int(lane), int(role), int(count)) for lane, role, count in completed} ==
            {(lane, role, len(cases) + 10) for lane in range(2) for role in range(2)},
            'actual active and accepted companions survive every case and repeated-tuple phase')
    for lane in range(2):
        for role in range(2):
            rows = [(item, tcp_fields(item)) for item in packets if item['lane'] == lane and item['protocol'] == 6]
            rows = [(item, fields) for item, fields in rows if (
                fields['target' if item['outgoing'] else 'source'] == 47000 + lane * 1000 if role == 0 else
                fields['source' if item['outgoing'] else 'target'] == 39000 + lane * 1000 and
                fields['target' if item['outgoing'] else 'source'] == 57000 + lane * 1000)]
            sent = [(item, fields) for item, fields in rows if item['outgoing']]
            received = [(item, fields) for item, fields in rows if not item['outgoing']]
            own_syn = next(((item, fields) for item, fields in sent if fields['flags'] & 2), None)
            peer_syn = next(((item, fields) for item, fields in received if fields['flags'] & 2), None)
            require(own_syn and peer_syn and peer_syn[1]['sequence'] == 0xfffffffd,
                    'actual unrelated stream has independent guest and wrapped peer sequence owners')
            if role == 0:
                require(own_syn[1]['flags'] == 2 and peer_syn[1]['flags'] == 18 and
                        microseconds(own_syn[0]) < microseconds(peer_syn[0]) and peer_syn[1]['acknowledgment'] ==
                        (own_syn[1]['sequence'] + 1) & 0xffffffff, 'actual unrelated active handshake')
            else:
                require(peer_syn[1]['flags'] == 2 and own_syn[1]['flags'] == 18 and
                        microseconds(peer_syn[0]) < microseconds(own_syn[0]) and own_syn[1]['acknowledgment'] ==
                        (peer_syn[1]['sequence'] + 1) & 0xffffffff, 'actual unrelated passive handshake')
            requests = [(item, fields) for item, fields in sent if fields['data']]
            replies = [(item, fields) for item, fields in received if fields['data']]
            require(len(requests) == len(replies) == len(cases) + 10 and
                    not any(fields['flags'] & 4 for _, fields in rows),
                    'every unaffected connection transfers its complete stream without reset')
            for number, ((request, request_fields), (reply, reply_fields)) in enumerate(zip(requests, replies)):
                require(request_fields['data'] == b'S' and reply_fields['data'] == b'Q' and
                        request_fields['sequence'] == (own_syn[1]['sequence'] + 1 + number) & 0xffffffff and
                        reply_fields['sequence'] == (peer_syn[1]['sequence'] + 1 + number) & 0xffffffff and
                        reply_fields['acknowledgment'] == (request_fields['sequence'] + 1) & 0xffffffff and
                        microseconds(request) < microseconds(reply), 'actual exact unaffected stream through ICMP attacks')


def audit_inputs(inputs, input_root=None, host_libraries=None):
    input_root = input_root or ROOT
    for group in ('sources', 'products'):
        require(inputs[group], 'nonempty source and compiled product fingerprints')
        for name, digest in inputs[group].items():
            require(not Path(name).is_absolute() and '..' not in Path(name).parts,
                    'bounded source/product manifest paths')
            require(hashlib.sha256((input_root / name).read_bytes()).hexdigest() == digest,
                    f'actual {group} input: {name}')
    if inputs['native'] and inputs['linkage'] == 'native':
        require(set(inputs['host_libraries']) == {'libc.so.6', 'ld-linux-x86-64.so.2'},
                'the native client records its actual glibc and loader')
        for name, library in inputs['host_libraries'].items():
            if 'retained' in library:
                require(inputs['products'].get(library['retained']) == library['sha256'],
                        f'retained native shared library fingerprint: {name}')
                data = (input_root / library['retained']).read_bytes()
            else:
                data = host_libraries[name] if host_libraries is not None else Path(library['path']).read_bytes()
            require(hashlib.sha256(data).hexdigest() == library['sha256'],
                    f'actual native shared library: {name}')


def audit_row(root, row, cases, input_root=None, host_libraries=None):
    require(row['wire'] == 'icmp' and row['passed'] and not row['error'] and not row['missing'],
            'actual ICMP runner succeeds without omitted cases')
    native = 'client_namespace' in row
    require(row['returncode'] == (0 if native else 1), 'actual application/QEMU exit status')
    if native:
        require(len({row[key] for key in ('parent_namespace', 'peer_namespace', 'client_namespace')}) == 3,
                'three independent Linux network namespaces')
        require(len(row['capture_statistics']) == 2 and all(
            value['dropped'] == 0 and value['packets'] > 0 for value in row['capture_statistics']),
            'both independent native monitors retain all packets')
    inputs = json.loads((root / row['inputs']).read_text())
    require(inputs['linkage'] == row['linkage'] and inputs['native'] == native,
            'the reported client and linkage have their real input manifest')
    audit_inputs(inputs, input_root, host_libraries)
    text = (root / row['log']).read_text()
    require('TCP_ICMP_FAIL' not in text and text.count('TCP_ICMP_PASS cases=57 nics=2 cycles=128') == 1,
            'one complete actual application verdict')
    complete = re.findall(r'^ICMP_CASE_PASS lane=(\d+) case=(\d+) name=([a-z-]+) elapsed_ms=(\d+) '
                          r'start_ms=(\d+) end_ms=(\d+)\r?$', text, re.M)
    require(len(complete) == 114 and {(int(lane), int(ordinal), name) for lane, ordinal, name, *_ in complete} ==
            {(lane, ordinal, case['name']) for lane in range(2) for ordinal, case in enumerate(cases)},
            'all 57 socket cases really finish on both NICs')
    windows = {(int(lane), int(ordinal)): (int(start), int(end))
               for lane, ordinal, _, elapsed, start, end in complete}
    require(all(int(end) - int(start) == int(elapsed) and int(start) <= int(end)
                for _, _, _, elapsed, start, end in complete), 'actual per-case monotonic start/end clocks')
    require(all(windows[(lane, ordinal)][1] <= windows[(lane, ordinal + 1)][0]
                for lane in range(2) for ordinal in range(len(cases) - 1)), 'ordered actual socket cases')
    cycle_rows = re.findall(r'^ICMP_CYCLE_PASS cycle=(\d+) lane=(\d+) fd=(\d+) '
                            r'start_ms=(\d+) ignored_ms=(\d+) end_ms=(\d+)\r?$', text, re.M)
    require(len(cycle_rows) == 128 and {(int(cycle), int(lane)) for cycle, lane, *_ in cycle_rows} ==
            {(cycle, cycle % 2) for cycle in range(128)} and len({value[2] for value in cycle_rows}) == 1,
            '128 actual descriptor reuses on both NICs')
    require(all(70 <= int(ignored) - int(start) <= 300 and 140 <= int(end) - int(start) <= 1000 and
                int(ignored) < int(end) for _, _, _, start, ignored, end in cycle_rows),
            'actual stale-quote silence and later owned failure clocks')
    retries = re.findall(r'^ICMP_RETRY_RESULT lane=(\d+) poll=(\d+) events=([0-9a-f]+) error=(\d+)\r?$', text, re.M)
    require(len(retries) == 2 and {value[0] for value in retries} == {'0', '1'} and
            all(int(ready) == 1 and int(events, 16) & 4 and int(error) == 0
                for _, ready, events, error in retries), 'actual successful same-description retry readiness')
    quote_results = re.findall(r'^ICMP_QUOTE_RESULT lane=(\d+) case=(\d+) native=(\d+) poll=(\d+) '
                               r'events=([0-9a-f]+) error=(\d+) elapsed_ms=(\d+)\r?$', text, re.M)
    expected_ignore = {(lane, ordinal) for lane in range(2) for ordinal, case in enumerate(cases)
                       if case['mode'] == 'IGNORE'}
    require(len(quote_results) == len(expected_ignore) and
            {(int(lane), int(ordinal)) for lane, ordinal, *_ in quote_results} == expected_ignore,
            'every ignored/differential quote has an actual socket observation')
    measured = []
    native_accepts = {'quote-checksum', 'short-original', 'version', 'fragment', 'more-fragments', 'reserved'}
    for lane, ordinal, actual_native, ready, events, error, elapsed in quote_results:
        case = cases[int(ordinal)]
        accepted = native and case['mutation'] in native_accepts
        require(int(actual_native) == int(native) and int(ready) == int(accepted) and
                int(error) == (111 if accepted else 0) and
                (int(events, 16) & 8 if accepted else int(events, 16) == 0) and
                (0 <= int(elapsed) < 200 if accepted else 190 <= int(elapsed) < 1000),
                f'measured Linux/guest quote policy: {case["name"]}')
        measured.append(dict(lane=int(lane), case=case['name'], error=int(error), elapsed_ms=int(elapsed)))
    frames = [packets(root / name, row['capture_statistics'][lane] if native else None)
              for lane, name in enumerate(row['captures'])]
    require(len(frames) == 2, 'both actual Ethernet captures')
    peers = json.loads((root / row['peer']).read_text())
    require(len(peers) == 2 and {peer['lane'] for peer in peers} == {0, 1}, 'both independent peer records')
    receipts = re.findall(r'^ICMP_FRAME lane=(\d+) index=(\d+) length=(\d+) kind=(\d+) '
                         r'hash=([0-9a-f]{16}) monotonic_ms=(\d+)\r?$', text, re.M)
    capture_stats = re.findall(r'^ICMP_CAPTURE_PASS lane=(\d+) index=(\d+) packets=(\d+) dropped=(\d+) ipv4=(\d+)\r?$', text, re.M)
    require(len(capture_stats) == 2 and {int(value[0]) for value in capture_stats} == {0, 1},
            'both completed driver observers')
    actual = Counter((int(lane), int(size), int(kind), digest) for lane, _, size, kind, digest, _ in receipts)
    receipt_clocks = defaultdict(deque)
    for lane, _, _, _, digest, clock in receipts:
        receipt_clocks[(int(lane), digest)].append(int(clock))
    expected = Counter()
    all_packets = []
    for lane, captured in enumerate(frames):
        guest_mac = bytes([0x52, 0x54, 0, 0x12, 0x34, 0x10 + lane])
        peer_mac = bytes([2, 0x41, 0x58, 0x54, 0x43, lane])
        peer = next(value for value in peers if value['lane'] == lane)
        observed = Counter((packet['frame'].hex(), 'receive' if packet['frame'][6:12] == guest_mac else 'send')
                           for packet in captured)
        claimed = Counter((value['frame'], value['direction']) for value in peer['frames']
                          if bytes.fromhex(value['frame'])[12:14] == b'\x08\x00')
        require(observed == claimed, 'peer record exactly matches independent captured bytes and directions')
        peer_clocks = defaultdict(deque)
        for value in peer['frames']:
            peer_clocks[value['frame']].append(value['ms'])
        for item in captured:
            frame = item['frame']
            require({frame[:6], frame[6:12]} == {guest_mac, peer_mac}, 'actual configured Ethernet addresses')
            outgoing = frame[6:12] == guest_mac
            if item['protocol'] == 6:
                addresses = bytes([10, 23, lane + 1, 2, 10, 23, lane + 1, 1])
                require(item['ip'][12:20] == (addresses if outgoing else addresses[4:] + addresses[:4]),
                        'actual configured TCP source and destination addresses')
            expected[(lane, len(frame), 4 if outgoing else 0, fnv(frame))] += 1
            item.update(lane=lane, outgoing=outgoing)
            key = (lane, fnv(frame))
            require(receipt_clocks[key], 'actual receipt clock for each independently captured frame')
            item['driver_ms'] = receipt_clocks[key].popleft()
            item['peer_ms'] = peer_clocks[frame.hex()].popleft()
            all_packets.append(item)
        _, index, count, dropped, ip_count = next(value for value in capture_stats if int(value[0]) == lane)
        lane_receipts = [value for value in receipts if int(value[0]) == lane]
        clocks = [int(value[-1]) for value in lane_receipts]
        require(int(count) >= int(ip_count) == len(lane_receipts) and int(dropped) == 0 and clocks == sorted(clocks) and
                all(value[1] == index for value in lane_receipts), 'zero-drop driver receipt accounting and clocks')
        if not native:
            require(int(index) == lane + 1, 'actual virtio/e1000 driver observer index')
    require(actual == expected and bool(actual), f'every independent IPv4 packet has its exact actual driver receipt: missing={list((expected-actual).items())[:4]} extra={list((actual-expected).items())[:4]}')
    all_packets.sort(key=microseconds)
    verify_companions(all_packets, text, cases)
    sent, quoted, cycle_syns, stale_quotes = [], Counter(), [[], []], Counter()
    quotes = defaultdict(list)
    for item in all_packets:
        if item['protocol'] == 6:
            if item['outgoing']:
                sent.append(item)
                port = int.from_bytes(item['body'][2:4], 'big')
                if item['body'][13] == 2 and port == 49000 + item['lane'] * 1000:
                    require(int.from_bytes(item['body'][:2], 'big') == 41000 + item['lane'],
                            'reclamation reuses the exact client and peer ports')
                    values = cycle_syns[item['lane']]
                    if not values or values[-1]['body'][4:8] != item['body'][4:8]: values.append(item)
            continue
        require(not item['outgoing'] and len(item['body']) >= 8, 'complete independently injected ICMP')
        body, matched = item['body'], []
        for source in reversed(sent):
            tcp, lane = source['body'], source['lane']
            source_port, target_port = struct.unpack_from('!HH', tcp)
            ordinal = target_port - (48000 + lane * 1000)
            cycle = target_port == 49000 + lane * 1000
            if not 0 <= ordinal < len(cases) and not cycle:
                ordinal = source_port - (40000 + lane * 1000)
            if cycle:
                case = dict(type=3, code=3, mutation='valid')
                ordinal = -1
            elif not 0 <= ordinal < len(cases):
                continue
            else:
                case = cases[ordinal]
            types = [(case['type'], case['code'], case['mutation'])]
            if case['mutation'] == 'last-error': types += [(12, 0, 'valid')]
            for kind, code, mutation in types:
                if body[:2] != bytes([kind, code]) or body[8:] != expected_quote(source['ip'], mutation):
                    continue
                require((checksum(body) != 0) == (mutation == 'icmp-checksum'), 'intentional versus unexpected ICMP checksum')
                receiving_lane = 1 - lane if mutation.startswith('other-') else lane
                require(item['lane'] == receiving_lane and item['ip'][12:16] == bytes([10, 23, receiving_lane + 1, 1]) and
                        item['ip'][16:20] == source['ip'][12:16], 'owned quoted source and explicit receiving NIC')
                matched.append((lane, ordinal, source, cycle))
            if matched: break
        require(len(matched) == 1, f'each ICMP quote matches its actual earlier owned transmission and exact case mutation: lane={item["lane"]} body={body.hex()}')
        lane, ordinal, source, cycle = matched[0]
        if not cycle:
            mode = cases[ordinal]['mode']
            tcp_header = (source['body'][12] >> 4) * 4
            if mode in ('SOFT', 'RECOVER', 'CONSUME'):
                require(source['body'][tcp_header:] == b'one' and source['body'][13] & 16 and
                        not source['body'][13] & 3, 'soft ICMP quotes actual outstanding application bytes')
            elif mode == 'TIME_WAIT':
                require(source['body'][13] & 1, 'late time-wait ICMP quotes the actual owned FIN')
            else:
                require(source['body'][13] & 2, 'pending/request ICMP quotes the actual handshake')
        quoted[(lane, ordinal)] += 1
        quotes[(lane, ordinal)].append((item, source))
        if cycle and cycle_syns[lane][-1]['body'][4:8] != source['body'][4:8]:
            require(len(cycle_syns[lane]) >= 2 and cycle_syns[lane][-2]['body'][4:8] == source['body'][4:8],
                    'stale quote belongs to the preceding generation of the same tuple')
            stale_quotes[lane] += 1
    require(set(quoted) == {(lane, ordinal) for lane in range(2) for ordinal in range(-1, len(cases))},
            'every socket case and repeated tuple really receives its quoted error')
    require(all(len(values) == 64 for values in cycle_syns) and stale_quotes == Counter({0: 63, 1: 63}) and
            all(quoted[(lane, -1)] == 127 for lane in range(2)), '64 fresh owners and 63 stale ICMP receipts per NIC')
    verify_controls(all_packets, quotes, cases, native, windows)
    for cycle, lane, _, start, ignored, end in cycle_rows:
        lane, number = int(lane), int(cycle) // 2
        syn = cycle_syns[lane][number]
        own = [(item, source) for item, source in quotes[(lane, -1)] if source is syn]
        current = next((item for item, _ in own if
                        item['driver_ms'] >= int(ignored) and item['driver_ms'] <= int(end) + 100), None)
        require(current is not None, 'actual owned cycle failure follows the observed silence')
        require(int(start) - 100 <= syn['driver_ms'] <= int(ignored) and
                microseconds(current) - microseconds(syn) >= 140000,
                'current-generation failure follows actual SYN and the complete silence interval')
        if number:
            stale = next((item for item, source in quotes[(lane, -1)] if
                          source is cycle_syns[lane][number - 1] and microseconds(syn) < microseconds(item) < microseconds(current)), None)
            require(stale is not None, 'actual preceding-generation quote arrives during the new cycle')
            require(int(start) <= stale['driver_ms'] <= int(ignored) + 100 and
                    microseconds(current) - microseconds(stale) >= 100000,
                    'actual stale receipt precedes the later current-generation failure')
    for lane, ordinal, _, elapsed, *_ in complete:
        if cases[int(ordinal)]['mode'] in ('SOFT', 'RECOVER', 'CONSUME'):
            require(2400 <= int(elapsed) <= 4500, 'actual unshortened configured TCP delivery timeout')
    terminal = re.findall(r'^ICMP_TERMINAL_ERRORS lane=(\d+) case=(\d+) hard=(\d+) diagnostic=(\d+)\r?$', text, re.M)
    terminal_cases = {(lane, ordinal) for lane in range(2) for ordinal, case in enumerate(cases)
                      if case['mode'] in ('SOFT', 'RECOVER', 'CONSUME')}
    require(len(terminal) == len(terminal_cases) and
            {(int(lane), int(ordinal)) for lane, ordinal, _, _ in terminal} == terminal_cases,
            'every established error has its actual hard and soft consumption observation')
    for _, ordinal, hard, diagnostic in terminal:
        case = cases[int(ordinal)]
        require(int(hard) == case['error'] and int(diagnostic) == (case['error'] if case['mode'] == 'SOFT' else 0),
                'Linux hard-error and soft-diagnostic consumption order')
    require(text.count('ICMP_BLOCKED_READ_PASS lane=0 error=111') == 1 and
            set(re.findall(r'^ICMP_SOFT_CONSUMED lane=(\d+) error=111\r?$', text, re.M)) == {'0', '1'},
            'actual blocked read and SO_ERROR soft consumption')
    return dict(linkage=row['linkage'], native=native, captures=len(frames), cases=114, cycles=128,
                companion_streams=4, companion_checkpoints=4 * (len(cases) + 10),
                quoted_errors=sum(quoted.values()), stale_quotes=sum(stale_quotes.values()),
                driver_receipts=sum(actual.values()), measured_quotes=measured,
                files={name: hashlib.sha256((root / name).read_bytes()).hexdigest()
                       for name in [row['log'], row['peer'], row['inputs'], *row['captures']]})


def audit(report, root=None, input_root=None, host_libraries=None):
    root = root or report.parent
    rows = json.loads(report.read_text())
    require(rows, 'actual runner report is nonempty')
    cases = contract()
    checked = [audit_row(root, row, cases, input_root, host_libraries) for row in rows]
    return dict(rows=checked, cases=sum(row['cases'] for row in checked),
                cycles=sum(row['cycles'] for row in checked),
                companion_streams=sum(row['companion_streams'] for row in checked),
                companion_checkpoints=sum(row['companion_checkpoints'] for row in checked),
                captures=sum(row['captures'] for row in checked),
                quoted_errors=sum(row['quoted_errors'] for row in checked),
                stale_quotes=sum(row['stale_quotes'] for row in checked),
                driver_receipts=sum(row['driver_receipts'] for row in checked))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--report', action='append')
    args = parser.parse_args()
    reports = [ROOT / 'build' / name for name in args.report] if args.report else [
        ROOT / 'build/tcp-icmp-native-results.json', ROOT / 'build/tcp-icmp-results.json']
    for report in reports:
        result = audit(report)
        report.with_name(report.stem + '-checked.json').write_text(json.dumps(result, indent=2) + '\n')
        print(f'TCP_ICMP_CAPTURE_PASS report={report.name} cases={result["cases"]} cycles={result["cycles"]} '
              f'captures={result["captures"]} quotes={result["quoted_errors"]} stale={result["stale_quotes"]} '
              f'receipts={result["driver_receipts"]}')


if __name__ == '__main__':
    main()
