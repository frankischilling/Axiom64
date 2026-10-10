# SPDX-License-Identifier: GPL-3.0-or-later
"""Reject valid packet/record pairs with false timeout or recovery evidence."""
from collections import Counter
import copy
import hashlib
import json
from pathlib import Path
import struct
import sys
import tempfile
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from tcp_timeout_capture import decode, packets, peer_evidence, verify
from tcp_fault_capture_test import records
from tcp_reordering_capture_test import repair
from tcp_persist_capture_test import counterpart, rewrite


def mutations(path, lane, evidence, native, directory):
    original = path.read_bytes()
    endian, entries = records(original)
    flows = {control: [] for control in range(2)}
    for offset, frame in entries:
        row = decode(frame, lane)
        if row is not None and row['role'] == 0:
            seconds, micros = struct.unpack_from(endian + 'II', original, offset)
            row['ms'] = seconds * 1000 + micros / 1000
            flows[row['control']].append((offset, frame, row))
    closed = [next(entry for entry in flows[control] if not entry[2]['outgoing'] and
                   entry[2]['flags'] == 16 and not entry[2]['window']) for control in range(2)]
    opened = next(entry for entry in flows[1] if entry[0] > closed[1][0] and
                  not entry[2]['outgoing'] and entry[2]['window'])
    probes = [[entry for entry in flows[control] if entry[0] > closed[control][0] and
               (not control or entry[0] < opened[0]) and entry[2]['outgoing'] and
               entry[2]['seq'] == (closed[control][2]['ack'] - int(native)) & 0xffffffff and
               len(entry[2]['data']) == int(not native)] for control in range(2)]
    answer = next(entry for entry in flows[0] if entry[0] > probes[0][0][0] and not entry[2]['outgoing'])
    candidate = directory / path.name
    count = 0

    def reject(data, adjusted):
        nonlocal count
        candidate.write_bytes(data)
        decoded = packets(candidate, lane)
        expected = Counter(bytes.fromhex(entry['frame']) for entry in adjusted['frames']
                           if decode(bytes.fromhex(entry['frame']), lane) is not None)
        assert Counter(row['frame'] for row in decoded) == expected
        try:
            verify(candidate, lane, adjusted, native)
        except ValueError:
            count += 1
            return
        raise AssertionError('false user-timeout/recovery evidence was accepted')

    def change(entry, modified, timestamp=None, peer_time=None):
        data, adjusted = rewrite(original, entry[0], modified, evidence, endian, timestamp, peer_time)
        reject(data, adjusted)

    for entry in (probes[0][0], answer, opened):
        change(entry, None)
    for entry, field, value, layout in (
            (closed[0], 14, 536, '!H'),
            (answer, 8, (closed[0][2]['ack'] + 1) & 0xffffffff, '!I'),
            (probes[0][0], 4, (closed[0][2]['ack'] - 2) & 0xffffffff, '!I')):
        modified = bytearray(entry[1])
        tcp_at = 14 + (modified[14] & 15) * 4
        struct.pack_into(layout, modified, tcp_at + field, value)
        change(entry, repair(modified))
    accepted = next(entry for entry in flows[1] if entry[0] > opened[0] and entry[2]['outgoing'] and entry[2]['data'])
    modified = bytearray(accepted[1])
    tcp_at = 14 + (modified[14] & 15) * 4
    modified[tcp_at + (modified[tcp_at + 12] >> 4) * 4] ^= 1
    change(accepted, repair(modified))
    for field, value in (('option_ms', 0), ('error', 0)):
        adjusted = copy.deepcopy(evidence)
        next(flow for flow in adjusted['flows'] if not flow['role'] and not flow['control'])['application'][field] = value
        reject(original, adjusted)
    for delta in (-2200, 5000):
        adjusted = copy.deepcopy(evidence)
        app = next(flow for flow in adjusted['flows'] if not flow['role'] and not flow['control'])['application']
        app['ms'] += delta
        app['elapsed_ms'] += delta
        reject(original, adjusted)
    closed_record = counterpart(original, closed[1][0], evidence)
    data, adjusted = rewrite(original, opened[0], opened[1], evidence, endian,
                             closed[1][2]['ms'] + 1000, closed_record['ms'] + 1000)
    next(flow for flow in adjusted['flows'] if not flow['role'] and flow['control'])['reopened_at'] = closed_record['ms'] + 1000
    reject(data, adjusted)
    change(probes[0][0], probes[0][0][1], probes[0][0][2]['ms'] + 600)
    previous, last = probes[1][-2:]
    previous_record = counterpart(original, previous[0], evidence)
    data, adjusted = rewrite(original, last[0], last[1], evidence, endian,
                             previous[2]['ms'] + 100, previous_record['ms'] + 100)
    next(flow for flow in adjusted['flows'] if not flow['role'] and flow['control'])['probe_ms'][-1] = previous_record['ms'] + 100
    reject(data, adjusted)
    assert count == 14
    return count


def main():
    directory = Path(__file__).resolve().parents[2] / 'build'
    report = json.loads((directory / 'tcp-timeout-capture-results.json').read_text())
    assert report['passed'] and report['flows'] == 88 and len(report['captures']) == 22
    verified = {row['file']: row for row in report['captures']}
    captures, negatives = 0, 0
    with tempfile.TemporaryDirectory(prefix='axiom64-tcp-timeout-captures-') as temporary:
        for report_name in ('tcp-timeout-native-results.json', 'tcp-timeout-results.json'):
            path = directory / report_name
            assert hashlib.sha256(path.read_bytes()).hexdigest() == report['reports'][report_name]
            for row in json.loads(path.read_text()):
                peers = peer_evidence(directory, row)
                for lane, name in enumerate(row['captures']):
                    path = directory / name
                    native = report_name == 'tcp-timeout-native-results.json'
                    assert verify(path, lane, peers[lane], native) == verified[name]
                    negatives += mutations(path, lane, peers[lane], native, Path(temporary))
                    captures += 1
    assert captures == 22 and negatives == 308
    print(f'TCP_TIMEOUT_CAPTURE_CHECKER_PASS captures={captures} negative_cases={negatives}')


if __name__ == '__main__':
    main()
