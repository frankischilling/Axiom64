# SPDX-License-Identifier: GPL-3.0-or-later
"""Reject damaged clock records using actual independently captured native frames."""
import argparse
from copy import deepcopy
import hashlib
import json
from pathlib import Path
import struct
import sys
import tempfile

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
sys.path.insert(0, str(Path(__file__).resolve().parent))
from tcp_capture_clock import bind_native_clock, milliseconds, require
from tcp_fault_capture_test import records


def decoded(path):
    data = path.read_bytes()
    endian, entries = records(data)
    rows, indices = [], []
    for index, (at, frame) in enumerate(entries):
        if len(frame) < 34 or frame[12:14] != b'\x08\x00' or frame[23] not in (1, 6, 17):
            continue
        seconds, micros = struct.unpack_from(endian + 'II', data, at)
        rows.append(dict(frame=frame, stamp=seconds * 1000000 + micros,
                         ms=seconds * 1000 + micros / 1000))
        indices.append(index)
    require(rows, 'actual native workload for clock controls')
    return rows, indices, endian, entries


def audit(path, statistics):
    before = path.read_bytes()
    rows, _, _, _ = decoded(path)
    original = deepcopy(rows)
    info = bind_native_clock(path, rows, statistics)
    require(path.read_bytes() == before and all(
        all(row[key] == old[key] for key in ('frame', 'stamp', 'ms')) and
        milliseconds(row) == row['monotonic_ns'] / 1000000
        for row, old in zip(rows, original)), 'clock binding preserves every original packet and timestamp')
    return info


def rejected(action, label):
    try:
        action()
    except ValueError as error:
        return dict(control=label, reason=str(error))
    raise ValueError(f'damaged native clock evidence was accepted: {label}')


def controls(path, statistics, directory):
    original = path.read_bytes()
    rows, timed, endian, entries = decoded(path)
    sidecar = path.parent / statistics['monotonic_receipts']
    raw_receipts = sidecar.read_bytes()
    receipts = [json.loads(line) for line in raw_receipts.splitlines()]
    candidate = directory / path.name
    clock_file = directory / sidecar.name
    results = []

    def restore():
        candidate.write_bytes(original)
        clock_file.write_bytes(raw_receipts)
        return deepcopy(statistics)

    for label in ('receipt-path', 'receipt-fingerprint', 'dropped-frame'):
        changed = restore()
        if label == 'receipt-path':
            changed['monotonic_receipts'] = '../outside.clocks.jsonl'
        elif label == 'receipt-fingerprint':
            changed['monotonic_receipts_sha256'] = '0' * 64
        else:
            changed['dropped'] = 1
        results.append(rejected(lambda: audit(candidate, changed), label))

    for label in ('missing-receipt', 'frame-hash', 'kernel-timestamp', 'backward-receipt',
                  'inverted-pair', 'wide-pair', 'late-reader', 'future-kernel-receipt',
                  'duplicate-index', 'noninteger-observation'):
        changed = restore()
        values = deepcopy(receipts)
        receipt = values[timed[-1]]
        if label == 'missing-receipt':
            values.pop()
        elif label == 'frame-hash':
            receipt['sha256'] = '0' * 64
        elif label == 'kernel-timestamp':
            receipt['kernel_realtime_ns'] += 1000000
        elif label == 'backward-receipt':
            receipt['receipt_monotonic_ns'] = values[0]['receipt_monotonic_ns'] - 1
            receipt['receipt_monotonic_after_ns'] = receipt['receipt_monotonic_ns']
        elif label == 'inverted-pair':
            receipt['receipt_monotonic_after_ns'] = receipt['receipt_monotonic_ns'] - 1
        elif label == 'wide-pair':
            receipt['receipt_monotonic_after_ns'] = receipt['receipt_monotonic_ns'] + 100000001
        elif label == 'late-reader':
            receipt['receipt_realtime_ns'] = receipt['kernel_realtime_ns'] + 1000000001
        elif label == 'future-kernel-receipt':
            receipt['receipt_realtime_ns'] = receipt['kernel_realtime_ns'] - 1
        elif label == 'duplicate-index':
            receipt['frame'] = 0
        else:
            receipt['receipt_monotonic_ns'] = str(receipt['receipt_monotonic_ns'])
        data = ''.join(json.dumps(value) + '\n' for value in values).encode()
        clock_file.write_bytes(data)
        # Repair the file fingerprint to exercise the independent semantic
        # checks rather than rejecting only because the bytes were changed.
        changed['monotonic_receipts_sha256'] = hashlib.sha256(data).hexdigest()
        results.append(rejected(lambda: audit(candidate, changed), label))

    changed = restore()
    at, _ = entries[timed[-1]]
    shifted = bytearray(original)
    seconds, micros = struct.unpack_from(endian + 'II', shifted, at)
    struct.pack_into(endian + 'II', shifted, at, seconds + 1, micros)
    candidate.write_bytes(shifted)
    results.append(rejected(lambda: audit(candidate, changed), 'shifted-pcap-clock'))
    changed = restore()
    rows, _, _, _ = decoded(candidate)
    results.append(rejected(lambda: bind_native_clock(candidate, rows + [dict(rows[-1])], changed),
                            'duplicate-decoded-frame'))
    rows, _, _, _ = decoded(candidate)
    frame = bytearray(rows[-1]['frame'])
    frame[11] ^= 1
    rows[-1]['frame'] = bytes(frame)
    results.append(rejected(lambda: bind_native_clock(candidate, rows, changed), 'changed-decoded-frame'))

    # Existing protocol readers exclude unrelated control traffic. Preserve its
    # original frame/timestamp binding without claiming it times the workload.
    unrelated = next((index for index in range(len(entries)) if index not in timed), None)
    if unrelated is not None:
        changed = restore()
        data, values = bytearray(original), deepcopy(receipts)
        receipt = values[unrelated]
        receipt['kernel_realtime_ns'] -= 5000000000
        at, _ = entries[unrelated]
        stamp = receipt['kernel_realtime_ns']
        struct.pack_into(endian + 'II', data, at, stamp // 1000000000, stamp // 1000 % 1000000)
        candidate.write_bytes(data)
        encoded = ''.join(json.dumps(value) + '\n' for value in values).encode()
        clock_file.write_bytes(encoded)
        changed['monotonic_receipts_sha256'] = hashlib.sha256(encoded).hexdigest()
        audit(candidate, changed)
    require(len(results) == 16, 'all native clock corruption classes rejected')
    return results


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('reports', type=Path, nargs='+')
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    outcomes = []
    for report in args.reports:
        for row in json.loads(report.read_text()):
            require('client_namespace' in row and row['passed'] and row['returncode'] == 0,
                    'original successful native capture producer')
            require(len(row['captures']) == len(row['capture_statistics']) == 2, 'both independent native captures')
            for lane, name in enumerate(row['captures']):
                require(Path(name).name == name, 'bounded original native capture')
                path, statistics = report.parent / name, row['capture_statistics'][lane]
                positive = audit(path, statistics)
                with tempfile.TemporaryDirectory(prefix='axiom64-clock-damage-') as temporary:
                    negative = controls(path, statistics, Path(temporary))
                outcomes.append(dict(capture=name, audit=positive, rejected=negative))
    require(outcomes, 'actual clocked native capture cohort')
    args.output.write_text(json.dumps(dict(passed=True, captures=outcomes,
        rejected=sum(len(row['rejected']) for row in outcomes)), indent=2) + '\n')
    print(json.dumps(dict(passed=True, captures=len(outcomes), rejected=sum(len(row['rejected']) for row in outcomes))))


if __name__ == '__main__':
    main()
