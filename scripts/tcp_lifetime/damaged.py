# SPDX-License-Identifier: GPL-3.0-or-later
"""Reject synchronized valid packets with incomplete or false full-lifetime evidence."""
from collections import Counter
import copy
import hashlib
import json
from pathlib import Path
import struct
import sys
import tempfile

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tests'))
from tcp_fault_capture_test import records
from tcp_persist_capture_test import counterpart, rewrite
from tcp_reordering_capture_test import repair
from tcp_lifetime.capture import DEFAULT_MS, LONGER_MS, decode, packets, peer_evidence, verify


def mutations(path, lane, evidence, native, directory):
    original = path.read_bytes()
    endian, entries = records(original)
    flows = {kind: [] for kind in range(6)}
    for offset, frame in entries:
        row = decode(frame, lane)
        if row is not None and row['role'] == 0:
            seconds, micros = struct.unpack_from(endian + 'II', original, offset)
            row['ms'] = seconds * 1000 + micros / 1000
            flows[row['kind']].append((offset, frame, row))
    data = [entry for entry in flows[0] if entry[2]['outgoing'] and entry[2]['data']]
    fins = [entry for entry in flows[1] if entry[2]['outgoing'] and entry[2]['flags'] & 1]
    opened = next(entry for entry in flows[3] if not entry[2]['outgoing'] and
                  entry[2]['flags'] == 16 and entry[2]['window'])
    probes = [entry for entry in flows[3] if entry[0] < opened[0] and entry[2]['outgoing'] and
              (entry[2]['data'] or not entry[2]['flags'] & 2 and entry[2]['seq'] ==
               (next(row[2]['seq'] for row in flows[3] if row[2]['outgoing'] and row[2]['flags'] & 2)))]
    # Empty native probes use UNA-1, equal to the initial SYN sequence.
    answer = next(entry for entry in flows[3] if entry[0] > probes[0][0] and not entry[2]['outgoing'])
    recovered = next(entry for entry in flows[3] if entry[0] > opened[0] and entry[2]['outgoing'] and entry[2]['data'])
    candidate = directory / path.name
    count = 0

    def reject(bytes_, adjusted):
        nonlocal count
        candidate.write_bytes(bytes_)
        decoded = packets(candidate, lane)
        expected = Counter(bytes.fromhex(entry['frame']) for entry in adjusted['frames']
                           if decode(bytes.fromhex(entry['frame']), lane) is not None)
        assert Counter(row['frame'] for row in decoded) == expected
        try:
            verify(candidate, lane, adjusted, native)
        except ValueError:
            count += 1
            return
        raise AssertionError('false full-lifetime evidence was accepted')

    def changed(entry, modified, timestamp=None, peer_time=None):
        bytes_, adjusted = rewrite(original, entry[0], modified, evidence, endian, timestamp, peer_time)
        reject(bytes_, adjusted)

    for entry, kind in ((data[1], 0), (fins[1], 1), (probes[1], 3)):
        bytes_, adjusted = rewrite(original, entry[0], None, evidence, endian)
        removed = counterpart(original, entry[0], evidence)['ms']
        next(flow for flow in adjusted['flows'] if flow['kind'] == kind and flow['role'] == 0)['attempts_ms'].remove(removed)
        reject(bytes_, adjusted)
    for entry in (answer, opened):
        changed(entry, None)
    for entry, field, value, layout in ((answer, 8, (answer[2]['ack'] + 1) & 0xffffffff, '!I'),
                                       (answer, 14, 8192, '!H'),
                                       (probes[0], 4, (probes[0][2]['seq'] - 2) & 0xffffffff, '!I')):
        modified = bytearray(entry[1])
        tcp_at = 14 + (modified[14] & 15) * 4
        struct.pack_into(layout, modified, tcp_at + field, value)
        changed(entry, repair(modified))
    modified = bytearray(recovered[1])
    tcp_at = 14 + (modified[14] & 15) * 4
    modified[tcp_at + (modified[tcp_at + 12] >> 4) * 4] ^= 1
    changed(recovered, repair(modified))
    for kind, field, value in ((0, 'option_ms', 2500), (0, 'error', 0), (0, 'reclaimed', 0),
                               (4, 'option_ms', 0)):
        adjusted = copy.deepcopy(evidence)
        next(flow for flow in adjusted['flows'] if flow['kind'] == kind and flow['role'] == 0)['application'][field] = value
        reject(original, adjusted)
    for delta in (-DEFAULT_MS + 3000, 500000):
        adjusted = copy.deepcopy(evidence)
        app = next(flow for flow in adjusted['flows'] if flow['kind'] == 0 and flow['role'] == 0)['application']
        app['ms'] += delta
        app['elapsed_ms'] += delta
        reject(original, adjusted)
    changed(data[-1], data[-1][1], data[-1][2]['ms'] + 1000)
    # Move reopening and its report together; packet equality alone must not accept a shortened observation.
    initial = counterpart(original, probes[0][0], evidence)['ms']
    bytes_, adjusted = rewrite(original, opened[0], opened[1], evidence, endian,
                               opened[2]['ms'] - LONGER_MS + 1000, initial + 1000)
    next(flow for flow in adjusted['flows'] if flow['kind'] == 3 and flow['role'] == 0)['reopened_at'] = initial + 1000
    reject(bytes_, adjusted)
    assert count == 17
    return count


def main():
    directory = Path(__file__).resolve().parents[2] / 'build'
    report = json.loads((directory / 'tcp-lifetime-capture-results.json').read_text())
    assert report['passed'] and report['flows'] == len(report['captures']) * 12
    verified = {row['file']: row for row in report['captures']}
    captures = negatives = 0
    with tempfile.TemporaryDirectory(prefix='axiom64-tcp-lifetime-damage-') as temporary:
        for name, digest in report['reports'].items():
            path = directory / name
            assert hashlib.sha256(path.read_bytes()).hexdigest() == digest
            for row in json.loads(path.read_text()):
                peers = peer_evidence(directory, row)
                for lane, item in enumerate(row['captures']):
                    capture = directory / item
                    native = name == 'tcp-lifetime-native-results.json'
                    assert verify(capture, lane, peers[lane], native) == verified[item]
                    negatives += mutations(capture, lane, peers[lane], native, Path(temporary))
                    captures += 1
    assert captures == len(report['captures']) and negatives == captures * 17
    print(f'TCP_LIFETIME_CAPTURE_CHECKER_PASS captures={captures} negative_cases={negatives}')
    (directory / 'tcp-lifetime-damage-results.json').write_text(json.dumps(dict(captures=captures,
        negative_cases=negatives, complete_matrix=report['complete_matrix'], passed=True), indent=2) + '\n')


if __name__ == '__main__':
    main()
