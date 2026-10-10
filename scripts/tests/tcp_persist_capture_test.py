# SPDX-License-Identifier: GPL-3.0-or-later
"""Reject synchronized persist damage that passes all earlier wire requirements."""
import copy
import hashlib
import json
from pathlib import Path
import struct
import sys
import tempfile

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from tcp_fault_capture import MASK, decode
from tcp_reordering_capture import verify as verify_order
from tcp_persist_capture import verify
from tcp_fault_capture_test import records
from tcp_reordering_capture_test import repair


def counterpart(data, at, evidence):
    _, entries = records(data)
    frame = next(frame for offset, frame in entries if offset == at)
    occurrence = sum(candidate == frame for offset, candidate in entries if offset < at)
    return [row for row in evidence['frames'] if row['frame'] == frame.hex()][occurrence]


def rewrite(data, at, modified, evidence, endian, timestamp=None, peer_time=None):
    adjusted = copy.deepcopy(evidence)
    entry = counterpart(data, at, adjusted)
    size = int.from_bytes(data[at + 8:at + 12], 'little' if endian == '<' else 'big')
    end = at + 16 + size
    if modified is None:
        adjusted['frames'].remove(entry)
        return data[:at] + data[end:], adjusted
    entry['frame'] = bytes(modified).hex()
    if peer_time is not None:
        entry['ms'] = peer_time
    header = bytearray(data[at:at + 16])
    struct.pack_into(endian + 'II', header, 8, len(modified), len(modified))
    if timestamp is not None:
        seconds, micros = divmod(round(timestamp * 1000), 1000000)
        struct.pack_into(endian + 'II', header, 0, seconds, micros)
    return data[:at] + header + modified + data[end:], adjusted


def reject(path, lane, evidence, native):
    verify_order(path, lane, evidence, native)
    try:
        verify(path, lane, evidence, native)
    except ValueError:
        return
    raise AssertionError('damaged persist behavior was accepted')


def mutations(path, lane, evidence, native, directory):
    data = path.read_bytes()
    endian, entries = records(data)
    flow = []
    for at, frame in entries:
        row = decode(frame, lane)
        if row is not None and row['role'] == 0:
            seconds, micros = struct.unpack_from(endian + 'II', data, at)
            row['ms'] = seconds * 1000 + micros / 1000
            flow.append((at, frame, row))
    closed = next(entry for entry in flow if not entry[2]['outgoing'] and
                  entry[2]['flags'] & 16 and not entry[2]['flags'] & 2 and not entry[2]['window'])
    opened = next(entry for entry in flow if entry[0] > closed[0] and
                  not entry[2]['outgoing'] and entry[2]['window'])
    acknowledgement = closed[2]['ack']
    stopped = [entry for entry in flow if closed[0] < entry[0] < opened[0]]
    probes = [entry for entry in stopped if entry[2]['outgoing'] and
              (entry[2]['data'] or entry[2]['seq'] == (acknowledgement - 1) & MASK)]
    assert len(probes) == 3
    answer = next(entry for entry in stopped if probes[0][0] < entry[0] < probes[1][0] and
                  not entry[2]['outgoing'])
    candidate = directory / path.name
    count = 0

    def check_change(entry, modified, timestamp=None, peer_time=None):
        nonlocal count
        damaged, adjusted = rewrite(data, entry[0], modified, evidence, endian, timestamp, peer_time)
        candidate.write_bytes(damaged)
        reject(candidate, lane, adjusted, native)
        count += 1

    for entry in (probes[0], answer, opened):
        check_change(entry, None)

    modified = bytearray(closed[1])
    tcp_at = 14 + (modified[14] & 15) * 4
    struct.pack_into('!H', modified, tcp_at + 14, 536)
    check_change(closed, repair(modified))

    modified = bytearray(answer[1])
    tcp_at = 14 + (modified[14] & 15) * 4
    struct.pack_into('!I', modified, tcp_at + 8, (acknowledgement + 1) & MASK)
    check_change(answer, repair(modified))

    at, frame, row = probes[0]
    tcp_at = 14 + (frame[14] & 15) * 4
    payload_at = tcp_at + (frame[tcp_at + 12] >> 4) * 4
    modified = bytearray(frame[:payload_at] + frame[payload_at + len(row['data']):])
    modified.extend(bytes(max(0, 60 - len(modified))))
    struct.pack_into('!H', modified, 16, int.from_bytes(frame[16:18], 'big') - len(row['data']))
    struct.pack_into('!I', modified, tcp_at + 4, (acknowledgement - 2) & MASK)
    check_change(probes[0], repair(modified))

    closed_record = counterpart(data, closed[0], evidence)
    check_change(probes[0], probes[0][1], closed[2]['ms'] + 10, closed_record['ms'] + 10)
    previous, last = probes[1], probes[2]
    first_record = counterpart(data, probes[0][0], evidence)
    previous_record = counterpart(data, previous[0], evidence)
    check_change(last, last[1], previous[2]['ms'] + previous[2]['ms'] - probes[0][2]['ms'],
                 previous_record['ms'] + previous_record['ms'] - first_record['ms'])
    assert count == 8
    return count


def main():
    directory = Path(__file__).resolve().parents[2] / 'build'
    report = json.loads((directory / 'tcp-persist-capture-results.json').read_text())
    assert report['passed'] and report['flows'] == 44 and len(report['captures']) == 22
    verified = {row['file']: row for row in report['captures']}
    captures, negatives = 0, 0
    with tempfile.TemporaryDirectory(prefix='axiom64-tcp-persist-captures-') as temporary:
        for report_name in ('tcp-persist-native-results.json', 'tcp-persist-results.json'):
            path = directory / report_name
            assert hashlib.sha256(path.read_bytes()).hexdigest() == report['reports'][report_name]
            for row in json.loads(path.read_text()):
                peers = json.loads((directory / row['peer']).read_text())
                for lane, name in enumerate(row['captures']):
                    path = directory / name
                    native = report_name == 'tcp-persist-native-results.json'
                    assert verify(path, lane, peers[lane], native) == verified[name]
                    negatives += mutations(path, lane, peers[lane], native, Path(temporary))
                    captures += 1
    assert captures == 22 and negatives == 176
    print(f'TCP_PERSIST_CAPTURE_CHECKER_PASS captures={captures} negative_cases={negatives}')


if __name__ == '__main__':
    main()
