# SPDX-License-Identifier: GPL-3.0-or-later
"""Reject ordering damage even when packet and endpoint evidence agree."""
import copy
import hashlib
import json
from pathlib import Path
import struct
import sys
import tempfile

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from tcp_capture import checksum
from tcp_fault_capture import MASK, decode, verify as verify_loss
from tcp_reordering_capture import verify
from tcp_fault_capture_test import records


def replace(data, at, frame, modified, evidence, endian):
    adjusted = copy.deepcopy(evidence)
    entry = next(row for row in adjusted['frames'] if row['frame'] == frame.hex())
    if modified is None:
        adjusted['frames'].remove(entry)
        return data[:at] + data[at + 16 + len(frame):], adjusted
    entry['frame'] = modified.hex()
    header = bytearray(data[at:at + 16])
    struct.pack_into(endian + 'II', header, 8, len(modified), len(modified))
    return data[:at] + header + modified + data[at + 16 + len(frame):], adjusted


def repair(frame):
    frame = bytearray(frame)
    header = (frame[14] & 15) * 4
    tcp_at = 14 + header
    frame[24:26] = b'\0\0'
    frame[24:26] = struct.pack('!H', checksum(frame[14:tcp_at]))
    frame[tcp_at + 16:tcp_at + 18] = b'\0\0'
    # QEMU's short Ethernet frames include padding outside the IPv4 packet.
    total = int.from_bytes(frame[16:18], 'big')
    tcp = frame[tcp_at:14 + total]
    pseudo = frame[26:34] + struct.pack('!BBH', 0, 6, len(tcp))
    frame[tcp_at + 16:tcp_at + 18] = struct.pack('!H', checksum(pseudo + tcp))
    return frame


def reject(path, lane, evidence, native):
    # These damages preserve all old exact-byte/loss/checksum requirements.
    # Only the receive-ordering verifier must reject them.
    verify_loss(path, lane, evidence, native)
    try:
        verify(path, lane, evidence, native)
    except ValueError:
        return
    raise AssertionError('damaged receive ordering was accepted')


def mutations(path, lane, evidence, native, directory):
    data = path.read_bytes()
    endian, entries = records(data)
    rows = [(at, frame, decode(frame, lane)) for at, frame in entries]
    flow = [entry for entry in rows if entry[2] is not None and entry[2]['role'] == 0]
    segments = [entry for entry in flow if not entry[2]['outgoing'] and entry[2]['data']]
    origin = (next(row['seq'] for _, _, row in flow if not row['outgoing'] and row['flags'] & 2) + 1) & MASK
    candidate = directory / path.name
    count = 0
    for at, frame, _ in segments[:2]:
        damaged, adjusted = replace(data, at, frame, None, evidence, endian)
        candidate.write_bytes(damaged)
        reject(candidate, lane, adjusted, native)
        count += 1

    # Remove the consistent overlap while retaining every unique stream byte.
    at, frame, row = segments[2]
    tcp_at = 14 + (frame[14] & 15) * 4
    payload_at = tcp_at + (frame[tcp_at + 12] >> 4) * 4
    modified = bytearray(frame[:payload_at] + frame[payload_at + 268:])
    modified[16:18] = struct.pack('!H', int.from_bytes(frame[16:18], 'big') - 268)
    struct.pack_into('!I', modified, tcp_at + 4, (row['seq'] + 268) & MASK)
    damaged, adjusted = replace(data, at, frame, repair(modified), evidence, endian)
    candidate.write_bytes(damaged)
    reject(candidate, lane, adjusted, native)
    count += 1

    first, duplicate = segments[0][0], segments[1][0]
    at, frame, _ = next(entry for entry in flow if first < entry[0] < duplicate and
                        entry[2]['outgoing'] and entry[2]['flags'] & 16 and
                        not entry[2]['flags'] & 3 and not entry[2]['data'])
    modified = bytearray(frame)
    tcp_at = 14 + (frame[14] & 15) * 4
    struct.pack_into('!I', modified, tcp_at + 8, (origin + 536) & MASK)
    damaged, adjusted = replace(data, at, frame, repair(modified), evidence, endian)
    candidate.write_bytes(damaged)
    reject(candidate, lane, adjusted, native)
    count += 1

    damaged, adjusted = replace(data, at, frame, None, evidence, endian)
    candidate.write_bytes(damaged)
    reject(candidate, lane, adjusted, native)
    return count + 1


def main():
    directory = Path(__file__).resolve().parents[2] / 'build'
    report = json.loads((directory / 'tcp-reordering-capture-results.json').read_text())
    assert report['passed'] and report['flows'] == 44 and len(report['captures']) == 22
    verified = {row['file']: row for row in report['captures']}
    captures, negatives = 0, 0
    with tempfile.TemporaryDirectory(prefix='axiom64-tcp-reordering-captures-') as temporary:
        for report_name in ('tcp-reordering-native-results.json', 'tcp-reordering-results.json'):
            path = directory / report_name
            assert hashlib.sha256(path.read_bytes()).hexdigest() == report['reports'][report_name]
            for row in json.loads(path.read_text()):
                peers = json.loads((directory / row['peer']).read_text())
                for lane, name in enumerate(row['captures']):
                    path = directory / name
                    native = report_name == 'tcp-reordering-native-results.json'
                    assert verify(path, lane, peers[lane], native) == verified[name]
                    negatives += mutations(path, lane, peers[lane], native, Path(temporary))
                    captures += 1
    assert captures == 22 and negatives == 110
    print(f'TCP_REORDERING_CAPTURE_CHECKER_PASS captures={captures} negative_cases={negatives}')


if __name__ == '__main__':
    main()
