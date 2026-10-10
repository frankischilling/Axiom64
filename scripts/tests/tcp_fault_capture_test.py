# SPDX-License-Identifier: GPL-3.0-or-later
"""Reject damaged actual loss captures, including corruption with repaired checksums."""
import copy
import json
from pathlib import Path
import struct
import sys
import tempfile
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from tcp_capture import checksum
from tcp_fault_capture import decode, verify


def records(data):
    endian = '<' if data[:4] == bytes.fromhex('d4c3b2a1') else '>'
    offset, rows = 24, []
    while offset < len(data):
        size = struct.unpack_from(endian + 'I', data, offset + 8)[0]
        rows.append((offset, data[offset + 16:offset + 16 + size]))
        offset += 16 + size
    return endian, rows


def rejected(path, lane, evidence, native):
    try:
        verify(path, lane, evidence, native=native)
    except (ValueError, struct.error):
        return
    raise AssertionError('damaged controlled TCP evidence was accepted')


def mutations(path, lane, evidence, native, destination):
    data = path.read_bytes()
    endian, rows = records(data)
    tcp = [(at, frame, decode(frame, lane)) for at, frame in rows if decode(frame, lane) is not None]
    candidate = destination / path.name
    candidate.write_bytes(data[:-1])
    rejected(candidate, lane, evidence, native)

    at, frame, _ = tcp[0]
    damaged = bytearray(data)
    damaged[at + 16 + 14 + 10] ^= 1
    candidate.write_bytes(damaged)
    rejected(candidate, lane, evidence, native)

    syns = [(at, frame, row) for at, frame, row in tcp if row['outgoing'] and row['role'] == 0 and row['flags'] & 2]
    at, frame, _ = syns[1]
    candidate.write_bytes(data[:at] + data[at + 16 + len(frame):])
    adjusted = copy.deepcopy(evidence)
    matching = [index for index, row in enumerate(adjusted['frames']) if row['frame'] == frame.hex()]
    del adjusted['frames'][matching[-1]]
    rejected(candidate, lane, adjusted, native)

    candidate.write_bytes(data)
    adjusted = copy.deepcopy(evidence)
    del next(row for row in adjusted['frames'] if row.get('drop') == 'data')['drop']
    rejected(candidate, lane, adjusted, native)

    adjusted = copy.deepcopy(evidence)
    adjusted['lane'] ^= 1
    rejected(candidate, lane, adjusted, native)

    at, frame, row = next(entry for entry in tcp if entry[2]['data'])
    modified = bytearray(frame)
    ip_length = (modified[14] & 15) * 4
    tcp_at = 14 + ip_length
    tcp_length = (modified[tcp_at + 12] >> 4) * 4
    modified[tcp_at + tcp_length] ^= 1
    modified[tcp_at + 16:tcp_at + 18] = b'\0\0'
    total = int.from_bytes(modified[16:18], 'big')
    tcp_bytes = modified[tcp_at:14 + total]
    pseudo = modified[26:34] + struct.pack('!BBH', 0, 6, len(tcp_bytes))
    modified[tcp_at + 16:tcp_at + 18] = struct.pack('!H', checksum(pseudo + tcp_bytes))
    candidate.write_bytes(data[:at + 16] + modified + data[at + 16 + len(frame):])
    adjusted = copy.deepcopy(evidence)
    next(record for record in adjusted['frames'] if record['frame'] == frame.hex())['frame'] = modified.hex()
    rejected(candidate, lane, adjusted, native)

    damaged = bytearray(data)
    first_seconds, first_micros = struct.unpack_from(endian + 'II', data, syns[0][0])
    struct.pack_into(endian + 'II', damaged, syns[1][0], first_seconds, first_micros)
    candidate.write_bytes(damaged)
    rejected(candidate, lane, evidence, native)
    return 7


def main():
    directory = Path(__file__).resolve().parents[2] / 'build'
    report = json.loads((directory / 'tcp-fault-capture-results.json').read_text())
    assert report['passed'] and report['captures'] == 22 and len(report['results']) == 11
    verified = {(row['report'], row['linkage'], row['firmware'], row['transport']): row['captures']
                for row in report['results']}
    captures, negatives = 0, 0
    with tempfile.TemporaryDirectory(prefix='axiom64-tcp-loss-captures-') as temporary:
        for name in ('tcp-fault-native-results.json', 'tcp-fault-results.json'):
            report = directory / name
            if not report.exists():
                continue
            for row in json.loads(report.read_text()):
                captures_verified = verified[name, row['linkage'], row.get('firmware'), row.get('transport')]
                assert row['passed'] and len(captures_verified) == 2
                peers = json.loads((directory / row['peer']).read_text())
                for lane, capture in enumerate(row['captures']):
                    path = directory / capture
                    native = name == 'tcp-fault-native-results.json'
                    assert verify(path, lane, peers[lane], native=native) == captures_verified[lane]
                    negatives += mutations(path, lane, peers[lane], native, Path(temporary))
                    captures += 1
    assert captures
    print(f'TCP_FAULT_CAPTURE_CHECKER_PASS captures={captures} negative_cases={negatives}')


if __name__ == '__main__':
    main()
