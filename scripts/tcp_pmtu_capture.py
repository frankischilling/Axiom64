# SPDX-License-Identifier: GPL-3.0-or-later
"""Audit actual PMTU quotes, stream ownership, recovery bytes and driver receipts."""
import argparse
from collections import Counter
import json
from pathlib import Path
from tcp_capture_clock import microseconds
import re
from tcp_icmp_capture import audit_inputs, checksum, fnv, packets, require, tcp_fields

MASK = 0xffffffff
SIZE = 4096
CASES = 12


def expected_bytes(lane, case, direction):
    return bytes(((at * 29) ^ (at >> 7) ^ (lane * 53) ^ (case * 97) ^ (direction * 41)) & 255
                 for at in range(SIZE))


def quoted_bytes(original, case, origin, damaged):
    quote = bytearray(original[:28])
    if damaged:
        if case == 5:
            quote[10] ^= 1
        elif case in (6, 7):
            sequence = origin + (SIZE + 2 if case == 6 else -1)
            quote[24:28] = (sequence & MASK).to_bytes(4, 'big')
        elif case in (8, 9):
            quote[21 if case == 8 else 23] ^= 1
        elif case == 10:
            quote[9] = 17
            quote[10:12] = b'\0\0'
            quote[10:12] = checksum(quote[:20]).to_bytes(2, 'big')
    return bytes(quote)


def prefix(coverage):
    end = 0
    while end in coverage:
        end += 1
    return end


def verify_flow(items, lane, case, native):
    guest = bytes([10, 23, lane + 1, 2])
    remote = bytes([10, 23, lane + 1, 10 + case])
    port = 44000 + case * 20 + lane
    rows = [item for item in items if {item['ip'][12:16], item['ip'][16:20]} == {guest, remote}]
    tcp = [item for item in rows if item['protocol'] == 6]
    syns = [item for item in tcp if tcp_fields(item)['flags'] & 2]
    outgoing_syn = [item for item in syns if item['outgoing']]
    incoming_syn = [item for item in syns if not item['outgoing']]
    require(outgoing_syn and incoming_syn, 'both actual handshake directions')
    first_guest, first_peer = tcp_fields(outgoing_syn[0]), tcp_fields(incoming_syn[0])
    origin = (first_guest['sequence'] + 1) & MASK
    peer_origin = (first_peer['sequence'] + 1) & MASK
    guest_port = first_guest['source']
    require(peer_origin == 0xfffffff1 and first_peer['source'] == port and
            first_peer['target'] == guest_port and first_guest['target'] == port,
            'independent handshake tuple and wrapping peer sequence')
    require(bool(first_guest['flags'] & 16) == bool(case & 1) and
            bool(first_peer['flags'] & 16) != bool(case & 1), 'active/passive SYN ownership')
    for item in syns:
        body = item['body']
        end, at, mss = (body[12] >> 4) * 4, 20, None
        while at < end:
            kind = body[at]
            if kind == 0:
                break
            if kind == 1:
                at += 1
                continue
            require(at + 2 <= end and body[at + 1] >= 2 and at + body[at + 1] <= end,
                    'complete actual SYN options')
            if kind == 2:
                require(body[at + 1] == 4 and mss is None, 'one well-formed advertised MSS')
                mss = int.from_bytes(body[at + 2:at + 4], 'big')
            at += body[at + 1]
        require(mss == 1460, 'both peers advertise the actual interface MSS before path learning')
    if case & 1:
        require(guest_port == 45000 + case * 20 + lane and
                first_guest['acknowledgment'] == peer_origin and
                microseconds(incoming_syn[0]) <= microseconds(outgoing_syn[0]), 'actual passive handshake')
    else:
        require(first_peer['acknowledgment'] == origin and
                microseconds(outgoing_syn[0]) <= microseconds(incoming_syn[0]), 'actual active handshake')
    coverage = [set(), set()]
    fins, acknowledged = [False, False], [0, 0]
    earlier, quotes, reduced_first = [], [], []
    ceiling = 1400 if case == 3 else 576
    oversized = resized = 0
    for item in rows:
        body = item['body']
        if item['protocol'] == 1:
            damaged = case >= 4 and not quotes
            require(not item['outgoing'] and len(body) == 36 and body[:2] == b'\x03\x04' and
                    body[4:6] == b'\0\0' and
                    (checksum(body) != 0) == (damaged and case == 4),
                    'complete deliberate fragmentation-needed checksum and minimum quote')
            mtu = int.from_bytes(body[6:8], 'big')
            expected_mtu = 0 if case == 2 else 65535 if damaged and case == 11 else 576
            if case == 3:
                require(mtu in (1400, 576) and (not quotes or mtu <= quotes[-1]['mtu']),
                        'successive decreasing path hints')
                if mtu == 576:
                    ceiling = 576
            else:
                require(mtu == expected_mtu, 'case-specific next-hop hint')
            matches = [old for old in earlier if microseconds(old) <= microseconds(item) and
                       quoted_bytes(old['ip'], case, origin, damaged) == body[8:]]
            require(matches and all(len(old['ip']) > (1400 if mtu == 1400 else 576)
                                    for old in matches), 'quote owns exact earlier oversized wire bytes')
            quotes.append(dict(stamp=item['stamp'], clock_us=microseconds(item), mtu=mtu,
                               damaged=damaged, frame=fnv(item['frame'])))
            continue
        fields = tcp_fields(item)
        outgoing = item['outgoing']
        direction = 0 if outgoing else 1
        require((fields['source'], fields['target']) ==
                ((guest_port, port) if outgoing else (port, guest_port)), 'exact TCP ports')
        require(not fields['flags'] & 4, 'PMTU remains nonfatal without resets')
        if fields['flags'] & 2:
            require(not fields['data'], 'no unsupported SYN data')
            continue
        offset = (fields['sequence'] - (origin if outgoing else peer_origin)) & MASK
        data = fields['data']
        if data:
            if case == 3 and outgoing and quotes and 576 < len(item['ip']) <= 1400:
                ceiling = 576
            require(offset + len(data) <= SIZE and
                    data == expected_bytes(lane, case, direction)[offset:offset + len(data)],
                    'actual independent per-tuple payload and sequence bounds')
            if outgoing:
                earlier.append(item)
                oversized += len(item['ip']) > ceiling
                resized += len(item['ip']) <= ceiling
                if offset == 0 and len(item['ip']) <= 576:
                    reduced_first.append(microseconds(item))
            if not outgoing or len(item['ip']) <= ceiling:
                coverage[direction].update(range(offset, offset + len(data)))
        if fields['flags'] & 1:
            require(offset + len(data) == SIZE, 'FIN follows exact owned bytes')
            fins[direction] = True
        if fields['flags'] & 16:
            other = 1 - direction
            ack = (fields['acknowledgment'] - (peer_origin if outgoing else origin)) & MASK
            require(ack <= prefix(coverage[other]) + int(fins[other] and len(coverage[other]) == SIZE),
                    'cumulative ACK owns only wire-delivered bytes and FIN')
            acknowledged[other] = max(acknowledged[other], ack)
    require(all(len(value) == SIZE for value in coverage) and all(fins) and
            acknowledged == [SIZE + 1, SIZE + 1] and quotes and oversized and resized,
            'both complete recovered streams and independently acknowledged closes')
    valid = [quote for quote in quotes if not quote['damaged']]
    if case == 5 and native:
        require(len(quotes) == 1 and not valid and reduced_first and
                min(reduced_first) >= quotes[0]['clock_us'],
                'measured Linux recovery from damaged inner checksum without a later valid hint')
    else:
        require(valid, 'an actual valid owned hint causes recovery')
        if case >= 4:
            require(quotes[0]['damaged'] and valid[0]['clock_us'] - quotes[0]['clock_us'] >= 45000 and
                    reduced_first and min(reduced_first) >= valid[0]['clock_us'],
                    'real damaged-hint silence before valid reduction')
    if case == 3:
        require({quote['mtu'] for quote in quotes} == {576, 1400}, 'both path reductions captured')
    # Legacy zero-MTU hints can select a different native route plateau. Read
    # the sending limit from the actual full segments after path learning.
    learned = valid or quotes
    minimum_mtu = min(quote['mtu'] for quote in learned)
    threshold = next(quote['clock_us'] for quote in learned if quote['mtu'] == minimum_mtu)
    resized_payloads = [len(tcp_fields(item)['data']) for item in tcp
                        if item['outgoing'] and microseconds(item) >= threshold and
                        len(item['ip']) <= 576 and tcp_fields(item)['data']]
    require(resized_payloads, 'full recovered sending segments remain observable')
    return dict(case=case, passive=bool(case & 1), guest_port=guest_port,
                bytes_each=SIZE, oversized=oversized, resized=resized, quotes=len(quotes),
                damaged=int(case >= 4), native_inner_checksum_control=case == 5 and native,
                effective_send_mss=max(resized_payloads))


def audit_row(root, row, input_root=None, host_libraries=None):
    require(row['wire'] == 'pmtu' and row['passed'] and not row['error'] and not row['missing'],
            'actual complete PMTU runner verdict')
    native = 'client_namespace' in row
    require(row['returncode'] == (0 if native else 1), 'actual native or QEMU exit status')
    if native:
        require(len({row[key] for key in ('parent_namespace', 'peer_namespace', 'client_namespace')}) == 3,
                'independent native network namespaces')
        require(len(row['capture_statistics']) == 2 and all(
            value['dropped'] == 0 and value['packets'] > 0 for value in row['capture_statistics']),
            'both independent native capture monitors lose no frames')
    inputs = json.loads((root / row['inputs']).read_text())
    require(inputs['linkage'] == row['linkage'] and inputs['native'] == native,
            'actual client linkage and input manifest')
    from tcp_pmtu_inputs import SOURCES
    require(set(inputs['sources']) == set(SOURCES), 'complete PMTU source contract')
    audit_inputs(inputs, input_root, host_libraries)
    text = (root / row['log']).read_text()
    require(text.count('TCP_PMTU_PASS lanes=2 flows_each=12 bytes_each=4096') == 1 and
            'TCP_FAULT_FAIL' not in text, 'one complete actual client verdict')
    flows = re.findall(r'^TCP_PMTU_FLOW_PASS lane=(\d+) case=(\d+) sent=4096 received=4096 '
                       r'milliseconds=(\d+)\r?$', text, re.M)
    require(len(flows) == CASES * 2 and {(int(lane), int(case)) for lane, case, _ in flows} ==
            {(lane, case) for lane in range(2) for case in range(CASES)}, 'every actual socket case')
    maximum_segments = re.findall(r'^TCP_PMTU_MAXSEG lane=(\d+) case=(\d+) '
                                  r'stage=(connected|recovered) value=(\d+)\r?$', text, re.M)
    require(len(maximum_segments) == CASES * 4 and
            Counter((int(lane), int(case), stage)
                    for lane, case, stage, value in maximum_segments) ==
            Counter((lane, case, stage) for lane in range(2) for case in range(CASES)
                    for stage in ('connected', 'recovered')) and
            all(0 < int(value) <= 1460 for _, _, _, value in maximum_segments),
            'actual socket MSS follows negotiated and recovered wire limits for every tuple')
    maximum_values = {(int(lane), int(case), stage): int(value)
                      for lane, case, stage, value in maximum_segments}
    receipts = re.findall(r'^PMTU_FRAME lane=(\d+) index=(\d+) length=(\d+) kind=(\d+) '
                          r'hash=([0-9a-f]{16}) monotonic_ms=(\d+)\r?$', text, re.M)
    stats = re.findall(r'^PMTU_CAPTURE_PASS lane=(\d+) index=(\d+) packets=(\d+) dropped=(\d+) '
                       r'ipv4=(\d+)\r?$', text, re.M)
    require(len(stats) == 2 and {int(value[0]) for value in stats} == {0, 1}, 'both actual driver counters')
    require(len(row['captures']) == 2, 'both independent packet captures')
    require(len(row['peers']) == 2 and {peer['lane'] for peer in row['peers']} == {0, 1} and
            all(len(peer['flows']) == CASES and {flow['role'] for flow in peer['flows']} == set(range(CASES))
                and all(flow['done'] and flow['bytes_received'] == flow['bytes_acked'] == SIZE
                        for flow in peer['flows']) for peer in row['peers']),
            'complete reported peer cases agree with the independently checked transfers')
    reports = []
    for lane in range(2):
        items = packets(root / row['captures'][lane], row['capture_statistics'][lane] if native else None)
        guest_mac = bytes([0x52, 0x54, 0, 0x12, 0x34, 0x10 + lane])
        peer_mac = bytes([2, 0x41, 0x58, 0x54, 0x43, lane])
        expected = Counter()
        for item in items:
            frame = item['frame']
            outgoing = frame[6:12] == guest_mac
            require(frame[:12] == (peer_mac + guest_mac if outgoing else guest_mac + peer_mac),
                    'actual owned Ethernet source and destination')
            item['outgoing'] = outgoing
            expected[(len(frame), 4 if outgoing else 0, fnv(frame))] += 1
        actual_rows = [value for value in receipts if int(value[0]) == lane]
        actual = Counter((int(length), int(kind), digest)
                         for _, _, length, kind, digest, _ in actual_rows)
        require(actual == expected, 'every original IPv4 wire byte has its real driver receipt')
        counters = next(value for value in stats if int(value[0]) == lane)
        require(int(counters[3]) == 0 and int(counters[2]) >= int(counters[4]) == len(actual_rows) and
                {value[1] for value in actual_rows} == {counters[1]}, 'driver identity and zero drops')
        clocks = [int(value[-1]) for value in actual_rows]
        require(clocks == sorted(clocks) and (native or int(counters[1]) == lane + 1),
                'actual driver receipt clock and NIC identity')
        require({item['ip'][16:20] if item['outgoing'] else item['ip'][12:16] for item in items} ==
                {bytes([10, 23, lane + 1, 10 + case]) for case in range(CASES)},
                'all independent paths present without unrelated tuples')
        checked_flows = [verify_flow(items, lane, case, native) for case in range(CASES)]
        for flow in checked_flows:
            case = flow['case']
            require(maximum_values[lane, case, 'connected'] == 1460 and
                    maximum_values[lane, case, 'recovered'] == flow['effective_send_mss'],
                    'actual socket MSS follows negotiated and recovered wire limits for every tuple')
            flow['reported_connected_mss'] = maximum_values[lane, case, 'connected']
            flow['reported_recovered_mss'] = maximum_values[lane, case, 'recovered']
        reports.append(dict(lane=lane, frames=len(items), driver_receipts=len(actual_rows),
                            flows=checked_flows))
    return dict(linkage=row['linkage'], native=native, captures=2, lanes=reports, passed=True)


def audit(report, root=None, input_root=None, host_libraries=None):
    report = Path(report)
    root = Path(root) if root else report.parent
    rows = json.loads(report.read_text())
    require(isinstance(rows, list) and rows, 'nonempty original runtime results')
    return [audit_row(root, row, input_root, host_libraries) for row in rows]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('report', type=Path)
    parser.add_argument('--root', type=Path)
    parser.add_argument('--input-root', type=Path)
    parser.add_argument('--output', type=Path)
    args = parser.parse_args()
    rows = audit(args.report, args.root, args.input_root)
    value = dict(passed=True, profiles=len(rows), captures=len(rows) * 2,
                 flows=len(rows) * CASES * 2, reports=rows)
    if args.output:
        args.output.write_text(json.dumps(value, indent=2) + '\n')
    print(json.dumps({key: value[key] for key in ('passed', 'profiles', 'captures', 'flows')}))


if __name__ == '__main__':
    main()
