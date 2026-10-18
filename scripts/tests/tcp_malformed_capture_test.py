# SPDX-License-Identifier: GPL-3.0-or-later
"""Reject independently damaged copies of the actual malformed-input captures."""
from pathlib import Path
import sys
import tempfile
from copy import deepcopy
import hashlib
import json
import struct

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from tcp_capture import checksum
from tcp_malformed.capture import decode, read, reconstruct, digest, require, MASK, raw_records

def write(items, path, statistics, destination):
    target = destination / 'candidate.pcap'
    header = path.read_bytes()[:24]
    endian = '<' if header[:4] == bytes.fromhex('d4c3b2a1') else '>'
    with target.open('wb') as stream:
        stream.write(header)
        for item in items:
            seconds, micros = divmod(item['stamp'], 1000000)
            stream.write(struct.pack(endian + 'IIII', seconds, micros, len(item['frame']), len(item['frame'])))
            stream.write(item['frame'])
    result = None
    if statistics is not None:
        result = deepcopy(statistics)
        for index, item in enumerate(items):
            item['receipt']['frame'] = index
            item['receipt']['sha256'] = hashlib.sha256(item['frame']).hexdigest()
        receipts = destination / 'candidate.clocks.jsonl'
        receipts.write_text(''.join(json.dumps(item['receipt']) + '\n' for item in items))
        result.update(packets=len(items), receipt_frames=len(items), monotonic_receipts=receipts.name,
                      monotonic_receipts_sha256=digest(receipts))
        (destination / 'candidate-statistics.json').write_text(json.dumps(result, indent=2) + '\n')
    return target, result


def mutate(path, lane, statistics, label):
    items = list(raw_records(path))
    if statistics is not None:
        receipts = [json.loads(line) for line in (path.parent / statistics['monotonic_receipts']).read_text().splitlines()]
        for item, receipt in zip(items, receipts):
            item['receipt'] = receipt
    rows = [(index, decode(item['frame'], lane)) for index, item in enumerate(items)]
    rows = [(index, row) for index, row in rows if row is not None]
    reverse = (next(row for _, row in rows if not row['outgoing'] and row['flags'] & 2)['seq'] + 1) & MASK
    bad = next(index for index, row in rows if not row['valid_checksum'])
    injection = {((row['seq'] - reverse) & MASK) // 16: index for index, row in rows
                 if not row['outgoing'] and row['data'] and (row['options'] or not row['valid_checksum'])}
    recovery = {((row['seq'] - reverse) & MASK) // 16: index for index, row in rows
                if not row['outgoing'] and row['data'] and not row['options'] and row['valid_checksum']}
    if label == 'missing-checksum-injection':
        del items[bad]
    elif label == 'repaired-poison-checksum':
        items[bad]['frame'] = update(items[bad]['frame'])
    elif label in ('legalized-malformed-option', 'invalidated-unknown-option'):
        index = injection[1 if label == 'legalized-malformed-option' else 6]
        frame = bytearray(items[index]['frame'])
        frame[55] = 4 if label == 'legalized-malformed-option' else 0
        items[index]['frame'] = update(frame)
    elif label in ('injection-data', 'recovery-data'):
        index = injection[2] if label == 'injection-data' else recovery[2]
        data = decode(items[index]['frame'], lane)['data']
        items[index]['frame'] = update(items[index]['frame'], data=bytes([data[0] ^ 1]) + data[1:])
    elif label == 'missing-valid-recovery':
        del items[recovery[3]]
    elif label == 'poison-acknowledgment':
        _, row = next((index, row) for index, row in rows if row['outgoing'] and row['flags'] == 16 and not row['data'])
        item = deepcopy(items[bad])
        item['frame'] = update(row['frame'], acknowledgment=reverse + 16)
        items.insert(bad + 1, item)
    elif label == 'FIN-sequence':
        index, row = next((index, row) for index, row in rows if row['outgoing'] and row['flags'] & 1)
        assert not row['data'], 'actual request FIN is separate in this comparison'
        items[index]['frame'] = update(items[index]['frame'], sequence=row['seq'] + 1)
    elif label == 'missing-final-ACK':
        removed = {index for index, row in rows if row['outgoing'] and row['flags'] == 16 and not row['data']
                   and row['ack'] == (reverse + 113) & MASK}
        assert removed
        items[:] = [item for index, item in enumerate(items) if index not in removed]
    else:
        raise ValueError(label)
    return items


def update(frame, *, sequence=None, acknowledgment=None, window=None, data=None, flags=None):
    frame = bytearray(frame)
    ip_header = (frame[14] & 15) * 4
    start = 14 + ip_header
    # Ethernet padding is outside the IPv4 total length and must never become
    # synthetic TCP application data when a short control frame is repaired.
    body = bytearray(frame[start:14 + int.from_bytes(frame[16:18], 'big')])
    if sequence is not None:
        body[4:8] = (sequence & MASK).to_bytes(4, 'big')
    if acknowledgment is not None:
        body[8:12] = (acknowledgment & MASK).to_bytes(4, 'big')
    if window is not None:
        body[14:16] = window.to_bytes(2, 'big')
    if flags is not None:
        body[13] = flags & 255
    if data is not None:
        body[(body[12] >> 4) * 4:] = data
    body[16:18] = b'\0\0'
    body[16:18] = checksum(frame[26:34] + struct.pack('!BBH', 0, 6, len(body)) + body).to_bytes(2, 'big')
    frame[start:] = body
    frame[16:18] = (ip_header + len(body)).to_bytes(2, 'big')
    frame[24:26] = b'\0\0'
    frame[24:26] = checksum(frame[14:start]).to_bytes(2, 'big')
    return bytes(frame)


def main():
    root = Path(__file__).resolve().parents[2] / 'build'
    out = root / 'tcp-malformed-damaged'
    out.mkdir(exist_ok=True)
    controls = {
        'missing-checksum-injection': 'every actual malformed input and its valid recovery is captured',
        'repaired-poison-checksum': 'valid recovery preserves every exact application byte',
        'legalized-malformed-option': 'all distinct checksum and malformed-option encodings are physically captured',
        'invalidated-unknown-option': 'all distinct checksum and malformed-option encodings are physically captured',
        'injection-data': 'only the bad-checksum injection carries deliberately poisoned bytes',
        'recovery-data': 'valid recovery preserves every exact application byte',
        'missing-valid-recovery': 'every actual malformed input and its valid recovery is captured',
        'poison-acknowledgment': 'bad checksum and guest malformed options cannot advance receive ownership',
        'FIN-sequence': 'both FINs follow exact unpoisoned application data',
        'missing-final-ACK': 'both final FINs are actually acknowledged',
    }
    results = []
    originals = {}
    for native in (True, False):
        report = root / ('tcp-malformed-native-results.json' if native else 'tcp-malformed-results.json')
        originals[report] = digest(report)
        for row in json.loads(report.read_text()):
            profile = 'linux-' + row['linkage'] if native else '-'.join(row[key] for key in
                       ('linkage', 'firmware', 'transport'))
            for lane, name in enumerate(row['captures']):
                path = root / name
                originals[path] = digest(path)
                statistics = row['capture_statistics'][lane] if native else None
                if native:
                    receipts = root / statistics['monotonic_receipts']
                    originals[receipts] = digest(receipts)
                reconstruct(read(path, lane, statistics), lane, native)
                for label, reason in controls.items():
                    destination = out / f'{profile}-lane{lane}-{label}'
                    destination.mkdir(exist_ok=True)
                    candidate, candidate_statistics = write(mutate(path, lane, statistics, label),
                                                              path, statistics, destination)
                    try:
                        reconstruct(read(candidate, lane, candidate_statistics), lane, native)
                    except ValueError as error:
                        require(reason in str(error), f'{label}: wrong semantic rejection: {error}')
                        results.append(dict(profile=profile, lane=lane, control=label, reason=str(error),
                            candidate=candidate.relative_to(root).as_posix(), sha256=digest(candidate)))
                    else:
                        raise AssertionError(f'{profile} lane{lane} {label}: damaged evidence was accepted')
    require(len(results) == 220, 'ten semantic negative controls on every one of twenty-two captures')
    require(all(digest(path) == expected for path, expected in originals.items()),
            'negative controls preserve every original report, capture and clock receipt')
    (out / 'results.json').write_text(json.dumps(dict(passed=True, controls_rejected=len(results),
        originals_unchanged=True, candidates_only=True, results=results), indent=2) + '\n')
    print(f'TCP_MALFORMED_DAMAGE_PASS controls={len(results)} originals_unchanged=1')


if __name__ == '__main__':
    main()
