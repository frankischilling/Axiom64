# SPDX-License-Identifier: GPL-3.0-or-later
"""Audit real NIC traffic, socket pressure, complete expiry and preserved companions."""
import argparse
from collections import Counter, defaultdict
import json
from pathlib import Path
from tcp_capture_profiles import require_complete_profiles
from tcp_capture_clock import bind_native_clock, microseconds
import re
import struct
from tcp_icmp_capture import audit_inputs, checksum, fnv, require, tcp_fields

MASK = 0xffffffff


def packets(path, statistics=None):
    raw = path.read_bytes()
    require(len(raw) >= 24 and raw[:4] == bytes.fromhex('d4c3b2a1'), 'pressure PCAP header')
    header = struct.unpack_from('<IHHIIII', raw)
    require(header[1:3] == (2, 4) and header[6] == 1, 'pressure Ethernet PCAP version')
    at, previous, result = 24, 0, []
    while at < len(raw):
        require(at + 16 <= len(raw), 'complete pressure PCAP record')
        seconds, fraction, size, original = struct.unpack_from('<IIII', raw, at)
        at += 16
        require(14 <= size == original <= header[5] and fraction < 1000000 and at + size <= len(raw),
                'complete original pressure frame')
        frame = raw[at:at + size]
        at += size
        stamp = seconds * 1000000 + fraction
        if frame[12:14] != b'\x08\x00':
            continue
        # Unrelated native IPv6 control frames can retain earlier timestamps
        # across veth delivery. The observed IPv4 workload must remain ordered.
        require(statistics is not None or stamp >= previous, 'monotonic pressure packet clock')
        previous = stamp
        ip = frame[14:]
        require(len(ip) >= 20 and ip[0] == 0x45 and checksum(ip[:20]) == 0,
                'pressure IPv4 header and checksum')
        total = int.from_bytes(ip[2:4], 'big')
        require(20 <= total <= len(ip) and not int.from_bytes(ip[6:8], 'big') & 0xbfff,
                'unfragmented bounded pressure IPv4 packet')
        body = ip[20:total]
        protocol = ip[9]
        require(protocol in (6, 17), 'only owned TCP and UDP in the pressure fixture')
        pseudo = ip[12:20] + struct.pack('!BBH', 0, protocol, len(body))
        require(checksum(pseudo + body) == 0, 'pressure transport pseudo-header checksum')
        if protocol == 6:
            require(len(body) >= 20 and 20 <= (body[12] >> 4) * 4 <= len(body), 'pressure TCP bounds')
        else:
            require(len(body) == 24 and int.from_bytes(body[4:6], 'big') == len(body) and
                    body[6:8] != b'\0\0', 'pressure UDP length and transmitted checksum')
        result.append(dict(frame=frame, ip=ip[:total], body=body, protocol=protocol, stamp=stamp))
    require(result, 'nonempty actual pressure traffic')
    if statistics is not None:
        bind_native_clock(path, result, statistics)
    return result


def pattern(lane, step, direction):
    return bytes(((at * 29) ^ (lane * 53) ^ (step * 97) ^ (direction * 41)) & 255
                 for at in range(16))


def prefix(coverage):
    end = 0
    while end in coverage:
        end += 1
    return end


def companion(items, lane, phases):
    rows = [item for item in items if item['protocol'] == 6]
    outgoing_syn = [item for item in rows if item['outgoing'] and tcp_fields(item)['flags'] & 2]
    incoming_syn = [item for item in rows if not item['outgoing'] and tcp_fields(item)['flags'] & 2]
    require(outgoing_syn and incoming_syn, 'both actual companion handshake directions')
    guest, peer = tcp_fields(outgoing_syn[0]), tcp_fields(incoming_syn[0])
    origin, peer_origin = (guest['sequence'] + 1) & MASK, (peer['sequence'] + 1) & MASK
    port, guest_port = 46000 + lane, guest['source']
    require(guest_port and guest['target'] == peer['source'] == port and peer['target'] == guest_port and
            not guest['flags'] & 16 and peer['flags'] & 16 and peer['acknowledgment'] == origin and
            peer_origin == 0xfffffff1 and microseconds(outgoing_syn[0]) <= microseconds(incoming_syn[0]),
            'actual active companion tuple and wrapping peer sequence')
    require(all(tcp_fields(item)['sequence'] == ((origin - 1) & MASK) for item in outgoing_syn) and
            all(tcp_fields(item)['sequence'] == ((peer_origin - 1) & MASK) for item in incoming_syn),
            'companion identity survives every handshake retry')
    size = (phases + 1) * 16
    expected = [b''.join(pattern(lane, step, direction) for step in range(phases + 1))
                for direction in range(2)]
    coverage, fins, acknowledged = [set(), set()], [False, False], [0, 0]
    events = defaultdict(list)
    for item in rows:
        fields = tcp_fields(item)
        outgoing = item['outgoing']
        direction = 0 if outgoing else 1
        require((fields['source'], fields['target']) ==
                ((guest_port, port) if outgoing else (port, guest_port)), 'owned companion TCP ports')
        require(not fields['flags'] & 4, 'unrelated pressure never resets a live companion')
        if fields['flags'] & 2:
            require(not fields['data'], 'companion handshake has no data')
            continue
        offset = (fields['sequence'] - (origin if outgoing else peer_origin)) & MASK
        data = fields['data']
        if data:
            require(offset + len(data) <= size and data == expected[direction][offset:offset + len(data)],
                    'exact independent companion bytes throughout pressure and expiry')
            require(offset // 16 == (offset + len(data) - 1) // 16,
                    'application phases remain independently observable')
            coverage[direction].update(range(offset, offset + len(data)))
            events[(direction, offset // 16)].append(item)
        if fields['flags'] & 1:
            require(offset + len(data) == size, 'companion FIN follows all phases')
            fins[direction] = True
        if fields['flags'] & 16:
            other = 1 - direction
            ack = (fields['acknowledgment'] - (peer_origin if outgoing else origin)) & MASK
            require(ack <= prefix(coverage[other]) + int(fins[other] and len(coverage[other]) == size),
                    'companion ACK owns only delivered bytes and FIN')
            acknowledged[other] = max(acknowledged[other], ack)
    require(all(len(value) == size for value in coverage) and all(fins) and acknowledged == [size + 1] * 2,
            'complete preserved companion and both acknowledged closes')
    require(set(events) == {(direction, step) for direction in range(2) for step in range(phases + 1)},
            'all pre-pressure, saturated and recovered companion exchanges')
    for step in range(phases + 1):
        require(min(microseconds(item) for item in events[(0, step)]) <=
                min(microseconds(item) for item in events[(1, step)]), 'real peer answers an earlier request')
    return events


def datagrams(items, lane, phases):
    seen = defaultdict(list)
    ports = defaultdict(set)
    owners = {}
    for item in items:
        if item['protocol'] != 17:
            continue
        source, target, _, _ = struct.unpack_from('!HHHH', item['body'])
        outgoing = item['outgoing']
        remote_port, guest_port = (target, source) if outgoing else (source, target)
        index = remote_port - 47000 - lane * 100
        data = item['body'][8:]
        request = bytes(value ^ (0 if outgoing else 0x80) for value in data)
        phase = request[1]
        require(guest_port and 0 <= phase < phases and index in range(lane, 32, 2) and
                request[:1] == b'U' and request[2:4] == bytes([index, lane]), 'owned pressure UDP tuple')
        expected = bytes([ord('U'), phase, index, lane]) + bytes(
            ((at * 29) ^ (phase * 53) ^ (index * 97) ^ (lane * 41)) & 255 for at in range(4, 16))
        require(request == expected, 'exact independently generated pressure UDP bytes')
        seen[(phase, index, 0 if outgoing else 1)].append(item)
        owners[(phase, index, 0 if outgoing else 1)] = guest_port
        if outgoing:
            ports[phase].add(guest_port)
    expected_keys = {(phase, index, direction) for phase in range(phases)
                     for index in range(lane, 32, 2) for direction in range(2)}
    require(set(seen) == expected_keys and all(len(value) == 1 for value in seen.values()),
            'every fresh UDP endpoint has exactly one captured request and reply')
    require(all(len(ports[phase]) == 16 for phase in range(phases)), 'sixteen simultaneously held UDP ports per NIC')
    for phase in range(phases):
        for index in range(lane, 32, 2):
            require(owners[(phase, index, 0)] == owners[(phase, index, 1)],
                    'UDP reply targets its original socket')
            require(microseconds(seen[(phase, index, 0)][0]) <= microseconds(seen[(phase, index, 1)][0]),
                    'UDP reply follows the exact request')
    return seen


def verify_expiry(tcp, exchanges):
    last_phase0 = max(microseconds(value[0]) for key, value in exchanges.items() if key[0] == 0)
    recovered = min(microseconds(item) for item in tcp[(0, 2)])
    require(recovered - last_phase0 >= 120000000, 'independent packet clock observes the full expiry interval')


def audit_row(root, row, input_root=None, host_libraries=None, required_phases=2):
    require(row['wire'] == 'pressure' and row['passed'] and not row['error'] and not row['missing'],
            'actual complete pressure runner verdict')
    native = 'client_namespace' in row
    require(row['returncode'] == (0 if native else 1), 'actual pressure client or QEMU exit status')
    if native:
        require(len({row[key] for key in ('parent_namespace', 'peer_namespace', 'client_namespace')}) == 3,
                'three independent native pressure namespaces')
        require(len(row['capture_statistics']) == 2 and all(value['packets'] and not value['dropped']
            for value in row['capture_statistics']), 'both independent native pressure captures lose no frames')
    inputs = json.loads((root / row['inputs']).read_text())
    from tcp_pressure_inputs import SOURCES
    require(set(inputs['sources']) == set(SOURCES) and inputs['native'] == native and
            inputs['linkage'] == row['linkage'], 'complete actual pressure source and linkage contract')
    audit_inputs(inputs, input_root, host_libraries)
    text = (root / row['log']).read_text()
    require(required_phases in (1, 2) and text.count(
        f'TCP_PRESSURE_PASS phases={required_phases} udp_each=32 aborted=2560 companions=2') == 1 and
        'TCP_PRESSURE_FAIL' not in text and 'TCP_PRESSURE_BAD_' not in text,
        'one complete required pressure application verdict')
    mode = f'TCP_PRESSURE_MODE native={int(native)} expiry={int(required_phases == 2)} external=1'
    require(text.count(mode) == 1 and text.count('TCP_PRESSURE_ABORTED_PASS retained=1280 detached=1280') == 1,
            'actual failed-connect and detached-abort workloads finish before saturation')
    listeners = re.findall(r'^TCP_PRESSURE_LISTENER_MODE_PASS mode=(\d+) cycles=1280 independent_bytes=10\r?$', text, re.M)
    require(len(listeners) == 4 and set(listeners) == {'0', '1', '2', '3'} and
            text.count('TCP_PRESSURE_LISTENER_PASS modes=4 cycles=5120 independent_bytes=40') == 1,
            'all listener, queued-child, unread-reset and backlog reclamation cycles finish')
    results = re.findall(r'^TCP_PRESSURE_RESULT phase=(\d+) cycles=(\d+) target=1280 stage=([^ ]+) '
                         r'tcp_error=(\d+) udp=(\d+) udp_error=(\d+) milliseconds=(\d+)\r?$', text, re.M)
    require(len(results) == required_phases and {int(value[0]) for value in results} == set(range(required_phases)) and
            all(int(value[1]) == (1280 if native else 1021) and int(value[4]) == 32 and int(value[5]) == 0 and
                ((value[2] == 'none' and int(value[3]) == 0) if native else
                 (value[2] == 'client-connect' and int(value[3]) in (105, 115))) for value in results),
            'every saturated and recovered socket budget preserves all UDP endpoints')
    wait = re.findall(r'^TCP_PRESSURE_EXPIRY_END start_ms=(\d+) end_ms=(\d+) elapsed_ms=(\d+)\r?$', text, re.M)
    if required_phases == 2:
        require(len(wait) == 1 and int(wait[0][1]) - int(wait[0][0]) == int(wait[0][2]) >= 120000 and
                row['seconds'] >= int(wait[0][2]) / 1000, 'complete real expiry and independent host duration')
        began = re.findall(r'^TCP_PRESSURE_EXPIRY_BEGIN start_ms=(\d+) required_ms=120000\r?$', text, re.M)
        require(began == [wait[0][0]], 'one actual complete expiry observation begins')
    else:
        require(not wait, 'a diagnostic phase cannot claim expiry observation')
    calls = re.findall(r'^TCP_PRESSURE_COMPANION_PASS lane=(\d+) step=(\d+) bytes=16 monotonic_ms=(\d+)\r?$', text, re.M)
    require(len(calls) == 2 * (required_phases + 1) and {(int(lane), int(step)) for lane, step, _ in calls} ==
            {(lane, step) for lane in range(2) for step in range(required_phases + 1)},
            'both live companions finish every real exchange')
    udp = re.findall(r'^TCP_PRESSURE_UDP_PASS phase=(\d+) index=(\d+) lane=(\d+) bytes=16 monotonic_ms=(\d+)\r?$', text, re.M)
    require(len(udp) == required_phases * 32 and {(int(phase), int(index), int(lane)) for phase, index, lane, _ in udp} ==
            {(phase, index, index % 2) for phase in range(required_phases) for index in range(32)},
            'all actual UDP socket byte and address checks finish')
    if required_phases == 2:
        require(max(int(value[3]) for value in udp if value[0] == '0') <= int(wait[0][0]) and
                min(int(value[2]) for value in calls if value[1] == '2') >= int(wait[0][1]),
                'real wire exchanges bracket the complete expiry wait')
    receipts = re.findall(r'^PRESSURE_FRAME lane=(\d+) index=(\d+) length=(\d+) kind=(\d+) '
                          r'hash=([0-9a-f]{16}) monotonic_ms=(\d+)\r?$', text, re.M)
    stats = re.findall(r'^PRESSURE_CAPTURE_PASS lane=(\d+) index=(\d+) packets=(\d+) dropped=(\d+) ipv4=(\d+)\r?$', text, re.M)
    require(len(stats) == 2 and {int(value[0]) for value in stats} == {0, 1} and len(row['captures']) == 2,
            'both actual pressure driver counters and captures')
    require(len(row['peers']) == 2 and {peer['lane'] for peer in row['peers']} == {0, 1} and
            all(peer['phases'] == required_phases and peer['datagrams'] == required_phases * 16 and
                len(peer['flows']) == 1 and peer['flows'][0]['done'] and
                peer['flows'][0]['steps'] == required_phases + 1 and
                peer['flows'][0]['bytes_each'] == (required_phases + 1) * 16 for peer in row['peers']),
            'reported pressure peers agree with the independently captured workload')
    reports = []
    for lane in range(2):
        items = packets(root / row['captures'][lane], row['capture_statistics'][lane] if native else None)
        guest_mac = bytes([0x52, 0x54, 0, 0x12, 0x34, 0x10 + lane])
        peer_mac = bytes([2, 0x41, 0x58, 0x54, 0x43, lane])
        guest_ip, peer_ip = bytes([10, 23, lane + 1, 2]), bytes([10, 23, lane + 1, 1])
        expected = Counter()
        for item in items:
            frame = item['frame']
            outgoing = frame[6:12] == guest_mac
            require(frame[:12] == (peer_mac + guest_mac if outgoing else guest_mac + peer_mac) and
                    item['ip'][12:20] == (guest_ip + peer_ip if outgoing else peer_ip + guest_ip),
                    'actual pressure NIC MAC and IPv4 identity')
            item['outgoing'] = outgoing
            expected[(len(frame), 4 if outgoing else 0, fnv(frame))] += 1
        actual_rows = [value for value in receipts if int(value[0]) == lane]
        actual = Counter((int(length), int(kind), digest) for _, _, length, kind, digest, _ in actual_rows)
        require(actual == expected, 'every original pressure IPv4 frame has its real driver receipt')
        counter = next(value for value in stats if int(value[0]) == lane)
        require(counter[3] == '0' and int(counter[2]) >= int(counter[4]) == len(actual_rows) and
                {value[1] for value in actual_rows} == {counter[1]} and
                (native or int(counter[2]) == len(actual_rows)), 'correct pressure driver identity and zero drops')
        clocks = [int(value[-1]) for value in actual_rows]
        require(clocks == sorted(clocks) and (native or int(counter[1]) == lane + 1), 'actual pressure receipt clocks')
        tcp = companion(items, lane, required_phases)
        exchanges = datagrams(items, lane, required_phases)
        if required_phases == 2:
            verify_expiry(tcp, exchanges)
        reports.append(dict(lane=lane, frames=len(items), driver_receipts=len(actual_rows),
                            TCP_bytes_each=(required_phases + 1) * 16,
                            actual_UDP_requests=required_phases * 16, zero_drops=True))
    return dict(passed=True, native=native, linkage=row['linkage'], phases=required_phases,
                full_observation=required_phases == 2, lanes=reports)


def audit(report, root=None, input_root=None, host_libraries=None):
    report = Path(report)
    root = Path(root) if root else report.parent
    rows = json.loads(report.read_text())
    require_complete_profiles(rows)
    return [audit_row(root, row, input_root, host_libraries) for row in rows]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('report', type=Path)
    parser.add_argument('--root', type=Path)
    parser.add_argument('--input-root', type=Path)
    parser.add_argument('--output', type=Path)
    args = parser.parse_args()
    rows = audit(args.report, args.root, args.input_root)
    value = dict(passed=True, full_observation=True, profiles=len(rows), captures=len(rows) * 2, reports=rows)
    if args.output:
        args.output.write_text(json.dumps(value, indent=2) + '\n')
    print(json.dumps({key: value[key] for key in ('passed', 'full_observation', 'profiles', 'captures')}))


if __name__ == '__main__':
    main()
