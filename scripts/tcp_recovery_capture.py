# SPDX-License-Identifier: GPL-3.0-or-later
"""Independently verify TCP recovery bytes, control barriers and actual output holds."""
import argparse
import hashlib
import json
from pathlib import Path
import re
from tcp_icmp_capture import packets, require, tcp_fields
from tcp_icmp_capture import audit_inputs
from tcp_fault_capture import decode as decode_tcp
from tcp_capture_clock import microseconds

MASK = 0xffffffff


def decode(path, lane, statistics=None):
    rows = packets(Path(path), statistics)
    guest = bytes([0x52, 0x54, 0, 0x12, 0x34, 0x10 + lane])
    peer = bytes([2, 0x41, 0x58, 0x54, 0x43, lane])
    guest_ip, peer_ip = bytes([10, 23, lane + 1, 2]), bytes([10, 23, lane + 1, 1])
    for row in rows:
        require(row['protocol'] == 6, 'only owned recovery TCP packets')
        decode_tcp(row['frame'], lane, (49000 + lane,))
        row.update(tcp_fields(row))
        row['outgoing'] = row['frame'][6:12] == guest
        require(row['frame'][:12] == (peer + guest if row['outgoing'] else guest + peer) and
                row['ip'][12:20] == (guest_ip + peer_ip if row['outgoing'] else peer_ip + guest_ip),
                'exact recovery Ethernet and IP ownership')
        require((row['source'], row['target']) == ((48000 + lane, 49000 + lane) if row['outgoing'] else
                (49000 + lane, 48000 + lane)), 'exact bound recovery tuple')
    return rows


def stream(path, lane, statistics=None):
    rows = decode(path, lane, statistics)
    syns = [row for row in rows if row['outgoing'] and row['flags'] & 2]
    answers = [row for row in rows if not row['outgoing'] and row['flags'] & 2]
    require(syns and answers and len({row['sequence'] for row in syns}) == 1 and
            len({row['sequence'] for row in answers}) == 1, 'one stable actual recovery handshake')
    origin = ((syns[0]['sequence'] + 1) & MASK, (answers[0]['sequence'] + 1) & MASK)
    require(all(not row['flags'] & 16 and not row['data'] for row in syns) and
            all(row['flags'] & 16 and not row['data'] and row['acknowledgment'] == origin[0] for row in answers),
            'owned active SYN and SYN-ACK')
    data = bytes(((position * 29) ^ (position // 128) ^ (lane * 53)) & 255 for position in range(6224))
    barrier = 1040 + lane * 512
    expiry_barrier = 2064 + lane * 512
    expected = (data, data[:barrier] + b'QH' + data[barrier:expiry_barrier] + b'QH' + data[expiry_barrier:])
    covered = [bytearray(6224), bytearray(6228)]
    present, prefix, acknowledged, finishes = [set(), set()], [0, 0], [0, 0], [False, False]
    control = set()
    for row in rows:
        direction = 0 if row['outgoing'] else 1
        opposite = 1 - direction
        flags, payload = row['flags'], row['data']
        require(not flags & 4, 'no reset in a recovered stream')
        if flags & 2:
            continue
        require(flags & 16, 'established recovery segment has ACK')
        position = (row['sequence'] - origin[direction]) & MASK
        require(position <= len(expected[direction]) + int(finishes[direction]), 'owned recovery sequence interval')
        if payload:
            require(position + len(payload) <= len(expected[direction]) and
                    payload == expected[direction][position:position + len(payload)], 'exact independent recovery bytes')
            if direction == 1:
                for offset, boundary, byte in ((barrier, barrier, ord('Q')), (barrier + 1, barrier, ord('H')),
                        (expiry_barrier + 2, expiry_barrier, ord('Q')),
                        (expiry_barrier + 3, expiry_barrier, ord('H'))):
                    if position <= offset < position + len(payload):
                        require(payload[offset - position] == byte and prefix[0] == boundary,
                                'actual Q/H controls precede every held guest fault byte')
                        control.add(offset)
            covered[direction][position:position + len(payload)] = payload
            present[direction].update(range(position, position + len(payload)))
            while prefix[direction] in present[direction]:
                prefix[direction] += 1
        if flags & 1:
            require(position + len(payload) == len(expected[direction]) and
                    prefix[direction] == len(expected[direction]), 'FIN follows every exact recovered byte')
            finishes[direction] = True
        value = (row['acknowledgment'] - origin[opposite]) & MASK
        require(value <= prefix[opposite] + int(finishes[opposite]), 'recovery ACK owns only captured emitted bytes')
        acknowledged[opposite] = max(acknowledged[opposite], value)
    require(prefix == [6224, 6228] and covered == [bytearray(value) for value in expected] and
            all(finishes) and acknowledged == [6225, 6229] and
            control == {barrier, barrier + 1, expiry_barrier + 2, expiry_barrier + 3},
            'complete recovered streams, actual control barriers and both acknowledged FINs')
    return dict(lane=lane, frames=len(rows), bytes_each=prefix, acknowledged=acknowledged,
                exact_control_barrier=True, full_close=True)


def output_hold(root, metadata, lane, native, expiry=False):
    name = metadata['metadata']
    require(Path(name).name == name, 'bounded output-hold metadata name')
    require(metadata['confirmed'] and metadata['restored'] and
            metadata['debugger_timing_excluded'] == (not native), 'producer records actual hold and restoration')
    value = json.loads((root / name).read_text())
    require(value['lane'] == lane and value['native'] == native and value['confirmed'] and value['restored'] and
            value['expiry'] == expiry,
            'actual interface-scoped hold metadata')
    if native:
        events = value['events']
        require(len(events) == 3 and all(event['returncode'] == 0 and not event['stderr'] for event in events),
                'all actual native queue operations succeed')
        pid = events[0]['command'][2]
        require(str(pid).isdigit() and int(pid) > 0, 'one actual native client process')
        prefix = ['nsenter', '-t', pid, '-n', 'tc']
        expected = [prefix + ['qdisc', 'add', 'dev', f'eth{lane}', 'root', 'netem', 'delay',
                             '10000ms' if expiry else '1000ms'],
                    prefix + ['-j', '-s', 'qdisc', 'show', 'dev', f'eth{lane}'],
                    prefix + ['qdisc', 'del', 'dev', f'eth{lane}', 'root']]
        require([event['command'] for event in events] == expected, 'exact interface and private namespace queue operations')
        queues = json.loads(events[1]['stdout'])
        require(any(queue.get('kind') == 'netem' and queue.get('backlog', 0) >= 512 and
                    queue.get('qlen', 0) >= 1 for queue in queues), 'actual native payload remains queued before interface down')
    else:
        events = value['events']
        require(len(events) == 1 and events[0]['stage'] == 'armed' and events[0]['debugger_pid'] > 0,
                'one owned guest output-boundary observer')
        text = (root / Path(name).with_suffix('.log')).read_text()
        suffix = r' expired=[1-9]\d*' if expiry else ''
        require(text.count(f'TCP_OUTPUT_HELD index={lane + 1}') == 1 and
                len(re.findall(rf'^TCP_OUTPUT_RELEASED index={lane + 1} held=[1-9]\d*{suffix}$', text, re.M)) == 1,
                'actual guest output was held and later recovered at the same boundary')
        if expiry:
            require(text.count(f'TCP_OUTPUT_EXPIRED index={lane + 1}') == 1,
                    'actual owned IPv4 copy expiry is independently recorded')
    return dict(lane=lane, actual_output_confirmed=True, restored=True, native=native)


def carrier(root, row, native, text):
    claims = [peer['carrier'] for peer in row['peers']]
    require(claims[0] == claims[1] and type(claims[0]['native']) is bool and claims[0]['native'] == native and
            type(claims[0]['transitions']) is int and claims[0]['transitions'] == 4 and claims[0]['restored'] is True,
            'one shared physical-carrier controller owns both interfaces')
    name = claims[0]['metadata']
    require(Path(name).name == name, 'bounded physical-carrier metadata path')
    encoded = (root / name).read_bytes()
    require(hashlib.sha256(encoded).hexdigest() == claims[0]['sha256'], 'exact physical-carrier metadata fingerprint')
    value = json.loads(encoded)
    require(type(value['native']) is bool and value['native'] == native and value['pending'] is None and
            value['down_confirmed'] == value['restored'] == [True, True] and len(value['held']) == 2,
            'both physical links actually lost and regained carrier')
    events = value['events']
    require(len(events) == 4 and [(event['lane'], event['up']) for event in events] ==
            [(0, False), (0, True), (1, False), (1, True)], 'ordered selected physical-carrier operations')
    previous = 0
    for event in events:
        lane, up = event['lane'], event['up']
        start, end = event['start_monotonic_ns'], event['end_monotonic_ns']
        require(type(lane) is int and type(up) is bool and type(start) is type(end) is int and
                previous <= start <= end, 'actual ordered physical-carrier operation clocks')
        previous = end
        commands = event['commands']
        if native:
            pid = value['native_pid']
            require(type(pid) is int and pid > 0 and len(commands) >= 4 and (len(commands) - 1) % 3 == 0,
                    'actual selected native carrier command and interface observations')
            require(commands[0]['command'] == ['ip', 'link', 'set', f'peer{lane}', 'up' if up else 'down'],
                    'only the selected physical veth port changes administrative state')
            expected = [
                ['ip', '-j', 'link', 'show', 'dev', f'peer{lane}'],
                ['ip', '-j', 'link', 'show', 'dev', f'bridge{lane}'],
                ['nsenter', '-t', str(pid), '-n', 'ip', '-j', 'link', 'show', 'dev', f'eth{lane}']]
            require(all(command['returncode'] == 0 and not command['stderr'] for command in commands) and
                    all(command['command'] == expected[index % 3] for index, command in enumerate(commands[1:])),
                    'every real native carrier operation and state query succeeds')
            actual = {}
            for key, command in zip(('port', 'observer', 'client'), commands[-3:]):
                states = json.loads(command['stdout'])
                require(len(states) == 1, 'one actual observed native interface')
                actual[key] = states[0]
            require(event['state'] == actual and
                    [actual[key]['ifname'] for key in ('port', 'observer', 'client')] ==
                    [f'peer{lane}', f'bridge{lane}', f'eth{lane}'] and
                    'UP' in actual['observer']['flags'] and 'UP' in actual['client']['flags'] and
                    ('UP' in actual['port']['flags']) == up and ('LOWER_UP' in actual['client']['flags']) == up,
                    'real carrier changes while the client and observer remain administratively up')
        else:
            require(value['native_pid'] is None and not commands and event['qmp'] ==
                    dict(command='set_link', name=f'carrier{lane}', up=up, result={}),
                    'actual selected QMP carrier operations use the shared monitor')
    for lane, held in enumerate(value['held']):
        require(held is not None and type(held['error']) is type(held['available']) is int and
                held['error'] == held['available'] == 0 and
                type(held['flags']) is int and held['flags'] & 1 and type(held['monotonic_ns']) is int and
                events[lane * 2]['end_monotonic_ns'] <= held['monotonic_ns'] <=
                events[lane * 2 + 1]['start_monotonic_ns'],
                'real held carrier bytes preserve administrative state without error or delivery')
        require(text.count(f'TCP_RECOVERY_CARRIER_REQUEST lane={lane} up=0') == 1 and
                text.count(f'TCP_RECOVERY_CARRIER_REQUEST lane={lane} up=1') == 1 and
                text.count(f'TCP_RECOVERY_CARRIER_HELD lane={lane} error=0 available=0 flags={held["flags"]:x}') == 1 and
                text.count(f'TCP_RECOVERY_CARRIER_PASS lane={lane} retained=512 companion=512 administrative_up=1') == 1,
                'actual application confirms both selected physical-carrier recoveries')
    rows = [decode(root / name, lane, row['capture_statistics'][lane] if native else None)
            for lane, name in enumerate(row['captures'])]
    origins = []
    for packets in rows:
        origins.append(tuple((next(packet['sequence'] for packet in packets if
                                  packet['outgoing'] == outgoing and packet['flags'] & 2) + 1) & MASK
                             for outgoing in (True, False)))

    def observed_time(packet):
        return packet['monotonic_ns'] if native else microseconds(packet) * 1000

    def first_bytes(lane, outgoing, begin, size):
        times = [None] * size
        for packet in rows[lane]:
            if packet['outgoing'] != outgoing or not packet['data']:
                continue
            offset = (packet['sequence'] - origins[lane][int(not outgoing)]) & MASK
            for position in range(max(begin, offset), min(begin + size, offset + len(packet['data']))):
                if times[position - begin] is None:
                    times[position - begin] = observed_time(packet)
        require(all(value is not None for value in times), 'every exact carrier-phase byte has its original packet observation')
        return times

    reports = []
    for lane in range(2):
        begin = 5200 + lane * 512
        healthy = first_bytes(1 - lane, False, begin + 4, 512)
        fault = first_bytes(lane, True, begin, 512)
        require(max(healthy) <= min(fault), 'complete healthy companion echo precedes every selected carrier fault byte')
        if native:
            require(min(healthy) >= events[lane * 2]['end_monotonic_ns'] and
                    min(fault) >= events[lane * 2 + 1]['start_monotonic_ns'],
                    'independent native packets confirm actual physical carrier hold and restoration')
        reports.append(dict(lane=lane, held=512, companion=512, administrative_up=True, restored=True))
    return reports


def audit_row(root, row, input_root=None, host_libraries=None):
    from tcp_recovery_inputs import SOURCES
    native = 'client_namespace' in row
    require(row['passed'] and row['wire'] == 'recovery' and row['error'] is None and not row['missing'] and
            row['returncode'] == (0 if native else 1), 'actual complete recovery producer status')
    inputs = json.loads((root / row['inputs']).read_text())
    require(set(inputs['sources']) == set(SOURCES) and inputs['native'] == native and
            inputs['linkage'] == row['linkage'], 'complete recovery source and linkage fingerprints')
    audit_inputs(inputs, input_root, host_libraries)
    if native:
        require(len({row[key] for key in ('parent_namespace', 'peer_namespace', 'client_namespace')}) == 3 and
                len(row['capture_statistics']) == 2 and all(value['packets'] and not value['dropped']
                    for value in row['capture_statistics']), 'isolated native namespaces and lossless packet monitors')
    text = (root / row['log']).read_text()
    require(text.count('TCP_RECOVERY_PASS nics=2 exact_each=6224 queued_each=512 expiry_ms=4500 routes_each=2 carrier_each=1') == 1 and
            text.count('TCP_RECOVERY_CONFIG_PASS nics=2') == 1 and 'TCP_RECOVERY_FAIL' not in text,
            'one actual complete recovery application verdict')
    sends = re.findall(r'^TCP_RECOVERY_SEND lane=(\d+) requested=(\d+) result=(\d+) errno=(\d+)\r?$', text, re.M)
    require(len(sends) == 28 and all(int(lane) in (0, 1) and requested == result and error == '0'
            for lane, requested, result, error in sends) and all(
                sorted(int(requested) for lane, requested, _, _ in sends if lane == str(index)) == [16, 64] + [512] * 12
                for index in range(2)), 'actual per-NIC sends retain every exact byte')
    errors = re.findall(r'^TCP_RECOVERY_ERROR lane=(\d+) error=0\r?$', text, re.M)
    queued = re.findall(r'^TCP_RECOVERY_QUEUE_ERROR lane=(\d+) error=(0|101)\r?$', text, re.M)
    require(len(errors) == len(queued) == 2 and set(errors) == {'0', '1'} and
            {lane for lane, _ in queued} == {'0', '1'}, 'both synchronous and advisory queued error contracts')
    expiry_errors = re.findall(r'^TCP_RECOVERY_EXPIRY_ERROR lane=(\d+) error=0\r?$', text, re.M)
    waits = re.findall(r'^TCP_RECOVERY_EXPIRY_RELEASE lane=(\d+) elapsed_ms=(\d+)\r?$', text, re.M)
    require(len(expiry_errors) == 2 and set(expiry_errors) == {'0', '1'}, 'both owned-copy expiries keep TCP usable')
    require(len(waits) == 2 and {lane for lane, _ in waits} == {'0', '1'} and
            all(int(elapsed) >= 4500 for _, elapsed in waits), 'both actual queue-expiry waits retain their full duration')
    route_cases = {(str(lane), str(mode)) for lane in range(2) for mode in range(2)}
    fresh = re.findall(r'^TCP_RECOVERY_ROUTE_FRESH lane=(\d+) mode=(\d+) errno=101\r?$', text, re.M)
    require(len(fresh) == 4 and set(fresh) == route_cases, 'every withdrawn route rejects a fresh connect')
    route_errors = re.findall(r'^TCP_RECOVERY_ROUTE_ERROR lane=(\d+) mode=(\d+) error=(0|101|113) available=0\r?$', text, re.M)
    require(len(route_errors) == 4 and {(lane, mode) for lane, mode, _ in route_errors} == route_cases,
            'both route mechanisms retain undelivered bytes without a hard socket failure')
    route_passes = re.findall(r'^TCP_RECOVERY_ROUTE_PASS lane=(\d+) mode=(\d+) retained=512 companion=512\r?$', text, re.M)
    require(len(route_passes) == 4 and set(route_passes) == route_cases, 'all four exact route recoveries complete')
    masks = re.findall(r'^TCP_RECOVERY_MASK lane=(\d+) value=([0-9a-f]+)\r?$', text, re.M)
    routes = re.findall(r'^TCP_RECOVERY_HOST_ROUTE lane=(\d+) add=(\d+)\r?$', text, re.M)
    require(len(masks) == len(routes) == 8 and all(
        sorted(value for index, value in masks if index == str(lane)) == ['ffffff00'] * 2 + ['ffffffff'] * 2 and
        sorted(value for index, value in routes if index == str(lane)) == ['0'] * 2 + ['1'] * 2
        for lane in range(2)), 'both connected and explicit host routes are changed and restored')
    at = 0
    for mode in range(2):
        for lane in range(2):
            withdraw = (f'TCP_RECOVERY_HOST_ROUTE lane={lane} add=0' if mode else
                        f'TCP_RECOVERY_MASK lane={lane} value=ffffffff')
            restore = (f'TCP_RECOVERY_HOST_ROUTE lane={lane} add=1' if mode else
                       f'TCP_RECOVERY_MASK lane={lane} value=ffffff00')
            events = [withdraw, f'TCP_RECOVERY_ROUTE_FRESH lane={lane} mode={mode}',
                      f'TCP_RECOVERY_SEND lane={lane} requested=512',
                      f'TCP_RECOVERY_ROUTE_ERROR lane={lane} mode={mode}',
                      f'TCP_RECOVERY_SEND lane={1 - lane} requested=512', restore,
                      f'TCP_RECOVERY_ROUTE_PASS lane={lane} mode={mode}']
            for marker in events:
                position = text.find(marker, at)
                require(position >= at, 'route withdrawal, retained output, live companion and restoration order')
                at = position + len(marker)
    for lane in range(2):
        for marker in (f'TCP_RECOVERY_RECOVERED lane={lane} retained=512 companion=512',
                       f'TCP_RECOVERY_QUEUE_PASS lane={lane} retained=512 companion=512',
                       f'TCP_RECOVERY_EXPIRY_PASS lane={lane} retained=512 companion=512'):
            require(text.count(marker) == 1, 'exact restored stream and live companion verdict')
        events = [f'TCP_RECOVERY_QUEUE_ARM lane={lane}', f'TCP_RECOVERY_QUEUE_HELD lane={lane}',
                  f'TCP_RECOVERY_FLAGS lane={lane} up=0', f'TCP_RECOVERY_QUEUE_ERROR lane={lane}',
                  f'TCP_RECOVERY_SEND lane={1 - lane} requested=512', f'TCP_RECOVERY_FLAGS lane={lane} up=1',
                  f'TCP_RECOVERY_QUEUE_PASS lane={lane}']
        at = 0
        for marker in events:
            position = text.find(marker, at)
            require(position >= at, 'owned queued interface down, live companion and recovery order')
            at = position + len(marker)
        events = [f'TCP_RECOVERY_EXPIRY_ARM lane={lane}', f'TCP_RECOVERY_EXPIRY_HELD lane={lane}',
                  f'TCP_RECOVERY_EXPIRY_ERROR lane={lane}', f'TCP_RECOVERY_SEND lane={1 - lane} requested=512',
                  f'TCP_RECOVERY_EXPIRY_RELEASE lane={lane}', f'TCP_RECOVERY_EXPIRY_PASS lane={lane}']
        at = 0
        for marker in events:
            position = text.find(marker, at)
            require(position >= at, 'owned-copy expiry, live companion and output release order')
            at = position + len(marker)
    if not native:
        require(all(marker in text for marker in ('AXIOM64_TESTS_PASS', 'AXIOM64_EXIT status=0',
            f'Firmware: {row["firmware"].upper()}', f'virtio-net: index=1 transport={row["transport"]}',
            'e1000: index=2 model=82540EM')), 'actual firmware and both real adapter paths')
    require(len(row['captures']) == len(set(row['captures'])) == len(row['peers']) == 2 and
            {peer['lane'] for peer in row['peers']} == {0, 1}, 'both distinct original NIC captures and peer reports')
    reports = []
    for lane in range(2):
        actual = stream(root / row['captures'][lane], lane, row['capture_statistics'][lane] if native else None)
        peer = next(peer for peer in row['peers'] if peer['lane'] == lane)
        require(len(peer['flows']) == 1 and peer['flows'][0]['done'] and peer['flows'][0]['received'] == 6224 and
                peer['flows'][0]['acknowledged'] == 6228, 'peer result agrees with actual complete recovered stream')
        actual['hold'] = output_hold(root, peer['output_hold'], lane, native)
        actual['expiry_hold'] = output_hold(root, peer['expiry_hold'], lane, native, expiry=True)
        reports.append(actual)
    return dict(passed=True, linkage=row['linkage'], native=native, lanes=reports,
                carrier=carrier(root, row, native, text))


def audit(report, input_root=None, host_libraries=None, complete=False):
    report = Path(report)
    rows = json.loads(report.read_text())
    require(isinstance(rows, list) and rows, 'nonempty original recovery report')
    if complete:
        native = all('client_namespace' in row for row in rows)
        if native:
            actual = [row.get('linkage') for row in rows]
            expected = {'native', 'static', 'dynamic'}
        else:
            actual = [tuple(row.get(key) for key in ('linkage', 'firmware', 'transport')) for row in rows]
            expected = {(linkage, firmware, transport) for linkage in ('static', 'dynamic')
                        for firmware in ('bios', 'uefi') for transport in ('modern', 'legacy')}
        require(len(actual) == len(expected) and set(actual) == expected, 'complete unique native or guest recovery cohort')
    return [audit_row(report.parent, row, input_root, host_libraries) for row in rows]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('report', type=Path)
    parser.add_argument('--input-root', type=Path)
    parser.add_argument('--host-libraries', type=Path)
    parser.add_argument('--output', type=Path)
    args = parser.parse_args()
    libraries = {path.name: path.read_bytes() for path in args.host_libraries.iterdir()} if args.host_libraries else None
    rows = audit(args.report, args.input_root, libraries, complete=True)
    value = dict(passed=True, full_matrix=True, profiles=len(rows), captures=len(rows) * 2,
                 streams=len(rows) * 2, verifier_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(), reports=rows)
    if args.output:
        args.output.write_text(json.dumps(value, indent=2) + '\n')
    print(json.dumps({key: value[key] for key in ('passed', 'profiles', 'captures', 'streams')}))


if __name__ == '__main__':
    main()
