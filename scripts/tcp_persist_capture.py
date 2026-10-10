# SPDX-License-Identifier: GPL-3.0-or-later
"""Independently verify stopped-window probes, elapsed backoff and exact recovery."""
import hashlib
import itertools
import json
from pathlib import Path
from tcp_fault_capture import MASK, decode, packets, require
from tcp_reordering_capture import verify as verify_order


def period(flow, native):
    origin = (next(row['seq'] for row in flow if row['outgoing'] and row['flags'] & 2) + 1) & MASK
    closed = next((index for index, row in enumerate(flow)
                   if not row['outgoing'] and row['flags'] & 16 and not row['flags'] & 2 and not row['window']), None)
    require(closed is not None, 'actual stopped receive window exists')
    acknowledgement = (origin + 1072) & MASK
    require(flow[closed]['ack'] == acknowledgement, 'zero window follows exactly two accepted segments')
    require(any(not row['outgoing'] and row['ack'] == (origin + 536) & MASK and row['window'] == 536
                for row in flow[:closed]), 'one clean segment follows the acknowledged data retry')
    clean = [row for row in flow[:closed] if row['outgoing'] and row['data'] and
             row['seq'] == (origin + 536) & MASK and len(row['data']) == 536]
    require(len(clean) == 1, 'exactly one clean 536-byte segment before the stopped window')
    opened = next((index for index in range(closed + 1, len(flow))
                   if not flow[index]['outgoing'] and flow[index]['flags'] & 16 and flow[index]['window']), None)
    require(opened is not None, 'actual receive window reopens')
    require(flow[opened]['ack'] == acknowledgement and flow[opened]['window'] == 8192,
            'reopening advertises space without accepting a probe byte')
    stopped = flow[closed + 1:opened]
    require(all(row['ack'] == acknowledgement and not row['window']
                for row in stopped if not row['outgoing'] and row['flags'] & 16),
            'stopped receiver never acknowledges or admits queued bytes')
    probes = []
    for index in range(closed + 1, opened):
        row = flow[index]
        if not row['outgoing']:
            continue
        require(row['flags'] & 16 and not row['flags'] & 7, 'stopped sender retains the established stream')
        if not row['data'] and row['seq'] == acknowledgement:
            continue
        require((native and not row['data'] and row['seq'] == (acknowledgement - 1) & MASK) or
                (not native and len(row['data']) == 1 and row['seq'] == acknowledgement),
                'actual native empty or guest one-byte persist probe sequence')
        probes.append(index)
    require(len(probes) == 3, 'three actual probes precede reopening')
    for begin, end in zip(probes, probes[1:]):
        require(any(not row['outgoing'] and row['flags'] & 16 and row['ack'] == acknowledgement and
                    not row['window'] for row in flow[begin + 1:end]),
                'each continued probe receives a real zero-window acknowledgement')
    times = [flow[index]['ms'] for index in probes]
    previous = [flow[closed]['ms'], *times[:-1]]
    intervals = [now - then for then, now in zip(previous, times)]
    require((180 if native else 850) <= intervals[0] <= 5000 and
            all(now + 100 >= then * 1.6 and now <= then * 3 + 1000
                for then, now in zip(intervals, intervals[1:])),
            'elapsed first probe and bounded exponential persist backoff')
    return [round(value, 3) for value in intervals]


def verify(path, lane, peer_rows, native=False):
    result = verify_order(path, lane, peer_rows, native)
    rows = packets(path, lane)
    records = []
    for record in peer_rows['frames']:
        row = decode(bytes.fromhex(record['frame']), lane)
        if row is not None:
            records.append(dict(row, ms=record['ms']))
    checked = []
    for role in range(2):
        intervals = period([row for row in rows if row['role'] == role], native)
        monotonic = period([row for row in records if row['role'] == role], native)
        checked.append(dict(role=role, accepted_before_zero=1072, probes=3,
                            capture_intervals_ms=intervals, peer_intervals_ms=monotonic, passed=True))
    return dict(result, zero_window=checked)


def check_results(directory):
    verified, reports = [], {}
    for name in ('tcp-persist-native-results.json', 'tcp-persist-results.json'):
        path = directory / name
        require(path.is_file(), 'both complete persist reports exist')
        reports[name] = hashlib.sha256(path.read_bytes()).hexdigest()
        rows = json.loads(path.read_text())
        native = name == 'tcp-persist-native-results.json'
        if native:
            require(len(rows) == 3 and {row['linkage'] for row in rows} == {'native', 'static', 'dynamic'},
                    'three native persist profiles')
        else:
            expected = set(itertools.product(('static', 'dynamic'), ('bios', 'uefi'), ('modern', 'legacy')))
            require(len(rows) == 8 and {(row['linkage'], row['firmware'], row['transport']) for row in rows} == expected,
                    'eight guest persist profiles')
        for row in rows:
            require(row['wire'] == 'persist' and row['passed'] and not row['error'] and not row['missing'],
                    'successful actual persist result')
            if native:
                require(len(row['capture_statistics']) == 2 and
                        all(stat['dropped'] == 0 and stat['packets'] > 0 and stat['buffer_bytes'] >= 4 * 1024 * 1024
                            for stat in row['capture_statistics']), 'no native persist capture drops')
            require(Path(row['peer']).name == row['peer'] and len(row['captures']) == 2,
                    'persist evidence path bounds')
            peers = json.loads((directory / row['peer']).read_text())
            require(len(peers) == 2, 'both independent persist peer reports')
            for lane, name in enumerate(row['captures']):
                require(Path(name).name == name, 'persist capture path bounds')
                verified.append(verify(directory / name, lane, peers[lane], native))
    require(len(verified) == 22, 'all 22 persist captures')
    output = dict(captures=verified, flows=44, reports=reports, passed=True)
    (directory / 'tcp-persist-capture-results.json').write_text(json.dumps(output, indent=2) + '\n')
    print('TCP_PERSIST_CAPTURE_PASS captures=22 flows=44 actual_zero probes backoff recovery exact_bytes wrap')
    return output


if __name__ == '__main__':
    check_results(Path(__file__).resolve().parents[1] / 'build')
