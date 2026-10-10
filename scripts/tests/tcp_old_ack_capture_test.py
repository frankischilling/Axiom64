# SPDX-License-Identifier: GPL-3.0-or-later
"""Reject synchronized damaged injection, challenge and boundary evidence."""
import copy
import hashlib
import json
from pathlib import Path
import struct
import sys
import tempfile

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from tcp_fault_capture import MASK, decode
from tcp_fault_capture_test import records
from tcp_reordering_capture_test import repair
from tcp_old_ack_capture import verify


def replace(data, entries, at, frame, modified, evidence, endian):
    adjusted = copy.deepcopy(evidence)
    occurrence = sum(previous == frame for offset, previous in entries if offset < at)
    matching = [index for index, row in enumerate(adjusted['frames']) if row['frame'] == frame.hex()]
    index = matching[occurrence]
    if modified is None:
        adjusted['frames'].pop(index)
        return data[:at] + data[at + 16 + len(frame):], adjusted
    adjusted['frames'][index]['frame'] = modified.hex()
    header = bytearray(data[at:at + 16])
    struct.pack_into(endian + 'II', header, 8, len(modified), len(modified))
    return data[:at] + header + modified + data[at + 16 + len(frame):], adjusted


def mutations(path, lane, evidence, native, directory):
    data = path.read_bytes()
    endian, entries = records(data)
    rows = [(at, frame, decode(frame, lane)) for at, frame in entries]
    candidate = directory / path.name
    count = 0

    def reject(damaged, adjusted):
        nonlocal count
        candidate.write_bytes(damaged)
        try:
            verify(candidate, lane, adjusted, native)
        except ValueError:
            count += 1
            return
        raise AssertionError('damaged old-ACK evidence was accepted')

    def change(entry, offset, value, fmt='I'):
        at, frame, _ = entry
        modified = bytearray(frame)
        tcp_at = 14 + (frame[14] & 15) * 4
        struct.pack_into('!' + fmt, modified, tcp_at + offset, value)
        reject(*replace(data, entries, at, frame, repair(modified), evidence, endian))

    for role in range(2):
        flow = [entry for entry in rows if entry[2] is not None and entry[2]['role'] == role]
        origin = (next(row['seq'] for _, _, row in flow if not row['outgoing'] and row['flags'] & 2) + 1) & MASK
        attacks = [entry for entry in flow if not entry[2]['outgoing'] and entry[2]['window'] == 65535]
        assert len(attacks) == 3
        challenges = [next(entry for entry in flow if entry[0] > attack[0] and entry[2]['outgoing'])
                      for attack in attacks]
        for at, frame, _ in attacks:
            reject(*replace(data, entries, at, frame, None, evidence, endian))
        # Both boundary-adjacent acceptable ACKs must fail the claimed outside-bound injection proof.
        change(attacks[0], 8, (attacks[0][2]['ack'] + 1) & MASK)
        change(attacks[0], 8, (attacks[0][2]['ack'] + 2) & MASK)
        change(attacks[0], 8, (attacks[0][2]['ack'] + 8194) & MASK)
        change(attacks[0], 4, (origin - 1) & MASK)
        change(attacks[0], 14, 8192, 'H')
        at, frame, _ = challenges[0]
        reject(*replace(data, entries, at, frame, None, evidence, endian))
        for entry, consumed in zip(challenges, (3, 1, 4)):
            change(entry, 8, (origin + consumed) & MASK)

        # Add a fabricated duplicate response to both records. Frame counts still agree.
        at, frame, _ = challenges[0]
        adjusted = copy.deepcopy(evidence)
        occurrence = sum(previous == frame for offset, previous in entries if offset < at)
        matching = [index for index, row in enumerate(adjusted['frames']) if row['frame'] == frame.hex()]
        index = matching[occurrence]
        adjusted['frames'].insert(index + 1, copy.deepcopy(adjusted['frames'][index]))
        end = at + 16 + len(frame)
        reject(data[:end] + data[at:end] + data[end:], adjusted)

        # Keep real packet bytes/counts but shorten both independent clocks to 100 ms.
        at, frame, _ = attacks[1]
        adjusted = copy.deepcopy(evidence)
        entry = next(row for row in adjusted['frames'] if row['frame'] == frame.hex())
        challenge = next(row for row in adjusted['frames']
                         if row.get('role') == role and row.get('challenge') == 1)
        entry['ms'] = challenge['ms'] + 100
        seconds, micros = struct.unpack_from(endian + 'II', data, challenges[0][0])
        elapsed = seconds * 1000000 + micros + 100000
        damaged = bytearray(data)
        struct.pack_into(endian + 'II', damaged, at, elapsed // 1000000, elapsed % 1000000)
        reject(damaged, adjusted)
    assert count == 28
    return count


def main():
    directory = Path(__file__).resolve().parents[2] / 'build'
    report = json.loads((directory / 'tcp-old-ack-capture-results.json').read_text())
    assert report['passed'] and report['flows'] == 44 and report['attacks'] == 132 and len(report['captures']) == 22
    verified = {row['file']: row for row in report['captures']}
    captures, negatives = 0, 0
    with tempfile.TemporaryDirectory(prefix='axiom64-tcp-old-ack-captures-') as temporary:
        for name, native in (('tcp-old-ack-native-results.json', True), ('tcp-old-ack-results.json', False)):
            path = directory / name
            assert hashlib.sha256(path.read_bytes()).hexdigest() == report['reports'][name]
            for row in json.loads(path.read_text()):
                peers = json.loads((directory / row['peer']).read_text())
                for lane, name in enumerate(row['captures']):
                    path = directory / name
                    assert verify(path, lane, peers[lane], native) == verified[name]
                    negatives += mutations(path, lane, peers[lane], native, Path(temporary))
                    captures += 1
    assert captures == 22 and negatives == 616
    print(f'TCP_OLD_ACK_CAPTURE_CHECKER_PASS captures={captures} negative_cases={negatives}')


if __name__ == '__main__':
    main()
