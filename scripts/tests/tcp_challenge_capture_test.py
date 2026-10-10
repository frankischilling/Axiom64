# SPDX-License-Identifier: GPL-3.0-or-later
"""Reject synchronized missing, forged, excess, poisoned and shortened-wait evidence."""
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
from tcp_old_ack_capture_test import replace
from tcp_challenge_capture import verify


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
        raise AssertionError('damaged challenge evidence was accepted')

    def evidence_index(entry):
        at, frame, _ = entry
        occurrence = sum(previous == frame for offset, previous in entries if offset < at)
        matching = [index for index, row in enumerate(evidence['frames']) if row['frame'] == frame.hex()]
        return matching[occurrence]

    def change(entry, offset, value, fmt='I'):
        at, frame, _ = entry
        modified = bytearray(frame)
        tcp_at = 14 + (frame[14] & 15) * 4
        struct.pack_into('!' + fmt, modified, tcp_at + offset, value)
        reject(*replace(data, entries, at, frame, repair(modified), evidence, endian))

    for role in range(2):
        flow = [entry for entry in rows if entry[2] is not None and entry[2]['role'] == role]
        attacks = [entry for entry in flow if not entry[2]['outgoing'] and entry[2]['window'] == 65535]
        assert len(attacks) == 136
        triggers = attacks[::17]
        responses = [next(entry for entry in flow if entry[0] > trigger[0] and entry[2]['outgoing'])
                     for trigger in triggers]
        for entry in triggers + responses + attacks[1:9]:
            at, frame, _ = entry
            reject(*replace(data, entries, at, frame, None, evidence, endian))
        for entry in responses:
            change(entry, 8, (entry[2]['ack'] + 3) & MASK)
        # Insert an extra response into both complete observers. Test tagged and untagged copies.
        at, frame, _ = responses[0]
        index = evidence_index(responses[0])
        end = at + 16 + len(frame)
        for tagged in (True, False):
            adjusted = copy.deepcopy(evidence)
            extra = copy.deepcopy(adjusted['frames'][index])
            if not tagged:
                extra.pop('challenge')
            adjusted['frames'].insert(index + 1, extra)
            reject(data[:end] + data[at:end] + data[end:], adjusted)
        # Shorten the actual recorded silence in both clocks while keeping packet bytes/counts.
        at, frame, _ = triggers[1]
        adjusted = copy.deepcopy(evidence)
        adjusted['frames'][evidence_index(triggers[1])]['ms'] = evidence['frames'][index]['ms'] + 100
        seconds, micros = struct.unpack_from(endian + 'II', data, responses[0][0])
        stamp = seconds * 1000000 + micros + 100000
        damaged = bytearray(data)
        struct.pack_into(endian + 'II', damaged, at, stamp // 1000000, stamp % 1000000)
        reject(damaged, adjusted)
        # The claimed old ACK must actually be below the bound; an invalid reset cannot be exact.
        change(triggers[0], 8, (triggers[0][2]['ack'] + 1) & MASK)
        change(triggers[4], 4, responses[0][2]['ack'])
        change(triggers[2], 12, 0x5010, 'H')
        change(triggers[0], 14, 8192, 'H')
        # Hiding a response from only the peer journal must fail the complete observer comparison.
        adjusted = copy.deepcopy(evidence)
        adjusted['frames'].pop(index)
        reject(data, adjusted)
    assert count == 80
    return count


def main():
    directory = Path(__file__).resolve().parents[2] / 'build'
    report = json.loads((directory / 'tcp-challenge-capture-results.json').read_text())
    assert report['passed'] and report['flows'] == 44 and report['attacks'] == 5984 and report['challenges'] == 352
    verified = {row['file']: row for row in report['captures']}
    captures, negatives = 0, 0
    with tempfile.TemporaryDirectory(prefix='axiom64-tcp-challenge-captures-') as temporary:
        for name, native in (('tcp-challenge-native-results.json', True), ('tcp-challenge-results.json', False)):
            path = directory / name
            assert hashlib.sha256(path.read_bytes()).hexdigest() == report['reports'][name]
            for row in json.loads(path.read_text()):
                peers = json.loads((directory / row['peer']).read_text())
                for lane, name in enumerate(row['captures']):
                    path = directory / name
                    assert verify(path, lane, peers[lane], native) == verified[name]
                    negatives += mutations(path, lane, peers[lane], native, Path(temporary))
                    captures += 1
    assert captures == 22 and negatives == 1760
    print(f'TCP_CHALLENGE_CAPTURE_CHECKER_PASS captures={captures} negative_cases={negatives}')


if __name__ == '__main__':
    main()
