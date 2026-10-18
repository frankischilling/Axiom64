# SPDX-License-Identifier: GPL-3.0-or-later
"""Reconstruct actual old/successor streams independently of the reconnect peer."""
import argparse
import hashlib
import json
from pathlib import Path
import re
from tcp_icmp_capture import audit_inputs, packets, require, tcp_fields
from tcp_fault_capture import decode as decode_tcp

MASK = 0xffffffff


def expected_bytes(lane, role, phase, direction, size):
    return bytes(((position * 29) ^ (position // 128) ^ (lane * 53) ^ (role * 97) ^
                  (phase * 71) ^ (direction * 41)) & 255 for position in range(size))


def decode(path, lane, statistics=None):
    values = packets(Path(path), statistics)
    guest_mac = bytes([0x52, 0x54, 0, 0x12, 0x34, 0x10 + lane])
    peer_mac = bytes([2, 0x41, 0x58, 0x54, 0x43, lane])
    guest_ip, peer_ip = bytes([10, 23, lane + 1, 2]), bytes([10, 23, lane + 1, 1])
    ports = tuple(49000 + role * 20 + lane + alternate for role in range(6)
                  for alternate in range(2 if 2 <= role < 4 or role == 5 else 1))
    for item in values:
        require(item['protocol'] == 6, 'only actual reconnect TCP traffic')
        decode_tcp(item['frame'], lane, ports)
        fields = tcp_fields(item)
        outgoing = item['frame'][6:12] == guest_mac
        require(item['frame'][:12] == (peer_mac + guest_mac if outgoing else guest_mac + peer_mac) and
                item['ip'][12:20] == (guest_ip + peer_ip if outgoing else peer_ip + guest_ip),
                'actual reconnect NIC MAC and IPv4 ownership')
        local = fields['source'] if outgoing else fields['target']
        remote = fields['target'] if outgoing else fields['source']
        role = (local - 48000 - lane) // 20
        require(0 <= role < 6 and local == 48000 + role * 20 + lane and
                remote in (49000 + role * 20 + lane, 49000 + role * 20 + lane + int(2 <= role < 4 or role == 5)),
                'actual reconnect bound source and old/successor destination ports')
        item.update(fields, outgoing=outgoing, role=role, remote=remote,
                    window=int.from_bytes(item['body'][14:16], 'big'))
    return values


def phase(rows, lane, role, ordinal):
    opening = [item for item in rows if item['outgoing'] and item['flags'] & 2]
    answers = [item for item in rows if not item['outgoing'] and item['flags'] & 2]
    require(opening and answers and len({item['sequence'] for item in opening}) == 1 and
            all(not item['flags'] & 16 and not item['data'] for item in opening),
            'one stable actual active reconnect SYN')
    initial = opening[0]['sequence']
    origin = ((initial + 1) & MASK, (answers[0]['sequence'] + 1) & MASK)
    window = 65535 if role == 5 or role % 2 == 0 else 8192
    require(len({item['sequence'] for item in answers}) == 1 and all(
        item['flags'] & 16 and item['acknowledgment'] == origin[0] and item['window'] == window and
        not item['data'] for item in answers), 'owned SYN-ACK and actual advertised peer window')
    size = (262144, 16, 512)[ordinal] if role == 5 else 32768 if role < 2 else 4096
    expected = (expected_bytes(lane, role, ordinal, 0, size), expected_bytes(lane, role, ordinal, 1, 16))
    covered = [bytearray(size), bytearray(16)]
    present = [set(), set()]
    prefix, acknowledged = [0, 0], [0, 0]
    finishes, resets = [False, False], [0, 0]
    for item in rows:
        direction = 0 if item['outgoing'] else 1
        opposite = 1 - direction
        flags = item['flags']
        if flags & 2:
            continue
        position = (item['sequence'] - origin[direction]) & MASK
        data = item['data']
        require(position <= len(expected[direction]) + int(finishes[direction]),
                'reconnect segment owns its phase sequence interval')
        if data:
            require(position + len(data) <= len(expected[direction]) and
                    data == expected[direction][position:position + len(data)],
                    'exact independent old and successor payloads')
            covered[direction][position:position + len(data)] = data
            present[direction].update(range(position, position + len(data)))
            while prefix[direction] in present[direction]:
                prefix[direction] += 1
        if flags & 1:
            require(position + len(data) == len(expected[direction]) and
                    prefix[direction] == len(expected[direction]), 'FIN follows the complete reconnect stream')
            finishes[direction] = True
        if flags & 16:
            value = (item['acknowledgment'] - origin[opposite]) & MASK
            require(value <= prefix[opposite] + int(finishes[opposite]),
                    'reconnect ACK never owns untransmitted bytes or FIN')
            acknowledged[opposite] = max(acknowledged[opposite], value)
        if flags & 4:
            require(direction == 0 and ((ordinal == 0 and role < 2) or (role == 5 and ordinal < 2)) and not data and
                    position == size and not any(finishes), 'explicit reconnect reset owns only its old stream')
            resets[direction] += 1
    require(prefix == [size, 16] and covered == [bytearray(value) for value in expected],
            'all exact old and successor stream bytes are captured')
    abort = (ordinal == 0 and role < 2) or (role == 5 and ordinal < 2)
    require((resets[0] > 0 and resets[1] == 0 and not any(finishes) and acknowledged == [size, 16]) if abort else
            (resets == [0, 0] and all(finishes) and acknowledged == [size + 1, 17]),
            'complete old reset or both independently acknowledged FINs')
    return dict(initial=initial, end=(origin[0] + size + int(finishes[0])) & MASK,
                window=window, bytes_each=[size, 16], reset=abort, full_close=not abort)


def stream(values, lane, role):
    owned = [item for item in values if item['role'] == role]
    identities, starts = [], []
    for index, item in enumerate(owned):
        if item['outgoing'] and item['flags'] & 2:
            key = (item['remote'], item['sequence'])
            if key not in identities:
                identities.append(key)
                starts.append(index)
    count = 3 if role == 5 else 2
    require(len(starts) == count and starts[0] == 0, 'all actual opens for each bound description')
    result = [phase(owned[starts[ordinal]:starts[ordinal + 1] if ordinal + 1 < count else len(owned)], lane, role, ordinal)
              for ordinal in range(count)]
    delta = (result[-1]['initial'] - result[0]['end']) & MASK
    if role == 5:
        require([identity[0] for identity in identities] == [49100 + lane, 49101 + lane, 49100 + lane],
                'actual A-B-A destinations retain the same bound source')
        require(result[0]['window'] + 2 <= delta < 0x80000000 and all(
                    previous['window'] + 2 <= (current['initial'] - previous['end']) & MASK < 0x80000000
                    for previous, current in zip(result, result[1:])),
                'revisited tuple and each intervening open exclude every old sequence window')
    elif role < 2:
        require(identities[0][0] == identities[1][0] and result[0]['window'] + 2 <= delta < 0x80000000,
                'successor SYN excludes the entire old transmitted sequence window')
    else:
        require(identities[1][0] == identities[0][0] + 1,
                'completed tuple stays protected while an independent destination works')
    return dict(role=role, same_tuple=role < 2 or role == 5, reuse_delta=delta, phases=result)


def audit_row(root, row, input_root=None, host_libraries=None):
    native = 'client_namespace' in row
    require(row['passed'] and row['wire'] == 'reconnect' and row['error'] is None and not row['missing'] and
            row['returncode'] == (0 if native else 1), 'actual complete reconnect producer status')
    inputs = json.loads((root / row['inputs']).read_text())
    from tcp_reconnect_inputs import SOURCES
    require(set(inputs['sources']) == set(SOURCES) and inputs['native'] == native and
            inputs['linkage'] == row['linkage'], 'complete actual reconnect source and linkage inputs')
    audit_inputs(inputs, input_root, host_libraries)
    if native:
        require(len({row[key] for key in ('parent_namespace', 'peer_namespace', 'client_namespace')}) == 3 and
                len(row['capture_statistics']) == 2 and all(value['packets'] and not value['dropped']
                    for value in row['capture_statistics']), 'isolated native reconnect namespaces and lossless monitors')
    text = (root / row['log']).read_text()
    require(text.count('TCP_RECONNECT_PASS nics=2 cases_each=6 ordinary_phases_each=2 '
                       'revisit_phases=3 queued_phases_each=2 queued_each=512') == 1 and
            'TCP_RECONNECT_FAIL' not in text, 'one complete actual reconnect client verdict')
    calls = re.findall(r'^TCP_RECONNECT_PHASE_PASS lane=(\d+) case=(\d+) phase=(\d+) sent=(\d+) received=16 monotonic_ms=(\d+)\r?$', text, re.M)
    require(len(calls) == 16 and {(int(lane), int(role), int(ordinal), int(size)) for lane, role, ordinal, size, _ in calls} ==
            {(lane, role, ordinal, 32768 if role < 2 else 4096) for lane in range(2) for role in range(4) for ordinal in range(2)},
            'every actual old and successor byte/address operation completes')
    require([int(value[4]) for value in calls] == sorted(int(value[4]) for value in calls),
            'actual reconnect application clock is monotonic')
    revisits = re.findall(r'^TCP_RECONNECT_REVISIT_PHASE_PASS lane=([01]) phase=([012]) sent=(\d+) received=16\r?$', text, re.M)
    require(revisits == [(str(lane), str(ordinal), str(size)) for lane in range(2)
                        for ordinal, size in enumerate((262144, 16, 512))],
            'every actual A-B-A byte and retained bound-source operation completes in order')
    guards = re.findall(r'^TCP_RECONNECT_GUARD_PASS lane=(\d+) case=(\d+) errno=99\r?$', text, re.M)
    require(len(guards) == 4 and set(guards) == {(str(lane), str(role)) for lane in range(2) for role in (2, 3)},
            'every completed-tuple guard is exercised before changing destination')
    require(len(row['captures']) == len(row['peers']) == 2 and {peer['lane'] for peer in row['peers']} == {0, 1},
            'both original reconnect NIC captures and peer metadata')
    reports, decoded = [], []
    for lane in range(2):
        values = decode(root / row['captures'][lane], lane, row['capture_statistics'][lane] if native else None)
        decoded.append(values)
        flows = [stream(values, lane, role) for role in (*range(4), 5)]
        metadata = next(peer for peer in row['peers'] if peer['lane'] == lane)['flows']
        require(len(metadata) == 6 and {flow['role'] for flow in metadata} == set(range(6)),
                'complete reported reconnect flow identities')
        for actual in flows:
            reported = next(flow for flow in metadata if flow['role'] == actual['role'])
            require(reported['done'] and reported['reuse_delta'] == actual['reuse_delta'] and
                    len(reported['phases']) == len(actual['phases']) and all(
                        given['closed'] and given['initial'] == observed['initial'] and given['old_end'] == observed['end'] and
                        given['bytes_received'] == observed['bytes_each'][0] and given['reply_acked'] == 16 and
                        given['reset'] == observed['reset'] for given, observed in zip(reported['phases'], actual['phases'])),
                    'reported reconnect phases agree with original packet ownership')
        reports.append(dict(lane=lane, frames=len(values), flows=flows))
    from tcp_reconnect_queued_capture import audit_queued
    for report, queued in zip(reports, audit_queued(root, row, decoded, text)):
        report['flows'].append(queued)
    return dict(passed=True, linkage=row['linkage'], native=native, lanes=reports)


def audit(report, input_root=None, host_libraries=None, complete=False):
    path = Path(report)
    rows = json.loads(path.read_text())
    require(isinstance(rows, list) and rows, 'nonempty original reconnect report')
    if complete:
        native = all('client_namespace' in row for row in rows)
        if native:
            actual = [row.get('linkage') for row in rows]
            expected = {'native', 'static', 'dynamic'}
        else:
            actual = [tuple(row.get(key) for key in ('linkage', 'firmware', 'transport')) for row in rows]
            expected = {(linkage, firmware, transport) for linkage in ('static', 'dynamic')
                        for firmware in ('bios', 'uefi') for transport in ('modern', 'legacy')}
        require(len(actual) == len(expected) and set(actual) == expected,
                'complete native or guest reconnect cohort')
    return [audit_row(path.parent, row, input_root, host_libraries) for row in rows]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('report', type=Path)
    parser.add_argument('--input-root', type=Path)
    parser.add_argument('--output', type=Path)
    args = parser.parse_args()
    rows = audit(args.report, args.input_root, complete=True)
    value = dict(passed=True, full_matrix=True, profiles=len(rows), captures=len(rows) * 2, phases=len(rows) * 26,
                 verifier_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(), reports=rows)
    if args.output:
        args.output.write_text(json.dumps(value, indent=2) + '\n')
    print(json.dumps({key: value[key] for key in ('passed', 'profiles', 'captures', 'phases')}))


if __name__ == '__main__':
    main()
