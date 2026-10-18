# SPDX-License-Identifier: GPL-3.0-or-later
"""Reject real RTO flight/window evidence damaged with checksum-valid packets."""
from copy import deepcopy
from pathlib import Path
import hashlib
import json
import struct
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from tcp_congestion.window_capture import reconstruct, packets, decode, MASK, MSS, expected, digest, require
from tcp_malformed.capture import raw_records
from tcp_malformed_capture_test import update

def candidate(path, lane, statistics, label, destination, native):
    records = list(raw_records(path))
    receipts = None
    if native:
        receipts = [json.loads(line) for line in
                    (path.parent / statistics['monotonic_receipts']).read_text().splitlines()]
    items = []
    for index, record in enumerate(records):
        value = deepcopy(record)
        if native:
            value['receipt'] = deepcopy(receipts[index])
        value['decoded'] = decode(value['frame'], lane, (49500 + lane,))
        items.append(value)
    rows = [(index, item['decoded']) for index, item in enumerate(items) if item['decoded'] is not None]
    syn = next(row for _, row in rows if row['outgoing'] and row['flags'] & 2)
    origin = (syn['seq'] + 1) & MASK
    gates = [(index, row) for index, row in rows if not row['outgoing'] and row['flags'] == 16
             and not row['data'] and (row['ack'] - origin) & MASK > 0][:4]
    damaged = None
    if label in ('opening-flight', 'growth-flight', 'recovery-flight', 'small-receive-window'):
        gate = {'opening-flight': 0, 'growth-flight': 1, 'recovery-flight': 2, 'small-receive-window': 3}[label]
        stop = gates[gate][0]
        if label == 'growth-flight':
            # Insert new data before the first actual RTO, so the congestion
            # bound, rather than the RTO retransmission gate, owns rejection.
            seen = set()
            for index, row in rows:
                if index >= stop:
                    break
                if row['outgoing'] and row['data']:
                    at = (row['seq'] - origin) & MASK
                    if all(value in seen for value in range(at, at + len(row['data']))):
                        stop = index
                        break
                    seen.update(range(at, at + len(row['data'])))
        high = max(((row['seq'] - origin) & MASK) + len(row['data']) for index, row in rows
                   if index < stop and row['outgoing'] and row['data'])
        template = next(item for item in items if item['decoded'] is not None
                        and item['decoded']['outgoing'] and item['decoded']['data'])
        inserted = []
        count = 4 if native and label == 'recovery-flight' else 1
        length = 1 if label == 'small-receive-window' else MSS
        for number in range(count):
            value = deepcopy(items[stop - 1])
            at = high + number * MSS
            value['frame'] = update(template['frame'], sequence=origin + at,
                                    data=expected(lane, 0, at, length))
            inserted.append(value)
        items[stop:stop] = inserted
    elif label == 'ACK-beyond-wire':
        damaged = gates[1][0]
        items[damaged]['frame'] = update(items[damaged]['frame'], acknowledgment=gates[1][1]['ack'] + 1)
    elif label == 'retry-payload':
        damaged = next(index for index, row in rows if gates[0][0] < index < gates[1][0]
                       and row['outgoing'] and row['data'] and ((row['seq'] - origin) & MASK) == MSS)
        row = items[damaged]['decoded']
        items[damaged]['frame'] = update(items[damaged]['frame'], data=bytes([row['data'][0] ^ 1]) + row['data'][1:])
    elif label == 'missing-retry':
        damaged = next(index for index, row in rows if gates[0][0] < index < gates[1][0]
                       and row['outgoing'] and row['data'] and ((row['seq'] - origin) & MASK) == MSS)
        del items[damaged]
    elif label == 'missing-final-ACK':
        synack = next(row for _, row in rows if not row['outgoing'] and row['flags'] & 2)
        reverse = (synack['seq'] + 1) & MASK
        indices = {index for index, row in rows if row['outgoing'] and row['flags'] == 16
                   and not row['data'] and ((row['ack'] - reverse) & MASK) == 17}
        assert indices
        items[:] = [item for index, item in enumerate(items) if index not in indices]
    elif label == 'FIN-sequence':
        damaged = next(index for index, row in rows if row['outgoing'] and row['flags'] & 1)
        item = items[damaged]
        row = item['decoded']
        if row['data']:
            # Some guests combine their last application segment and FIN. Keep
            # every original byte at its sequence and damage a separate FIN.
            finish = deepcopy(item)
            finish['frame'] = update(item['frame'], sequence=origin + 65537, data=b'')
            item['frame'] = update(item['frame'], flags=row['flags'] & ~1)
            items.insert(damaged + 1, finish)
        else:
            item['frame'] = update(item['frame'], sequence=row['seq'] + 1)
    else:
        raise ValueError(label)
    output = destination / 'candidate.pcap'
    endian = '<' if path.read_bytes()[:4] == bytes.fromhex('d4c3b2a1') else '>'
    with output.open('wb') as stream:
        stream.write(path.read_bytes()[:24])
        for item in items:
            seconds, micros = divmod(item['stamp'], 1000000)
            stream.write(struct.pack(endian + 'IIII', seconds, micros, len(item['frame']), len(item['frame'])))
            stream.write(item['frame'])
    candidate_statistics = None
    if native:
        candidate_statistics = deepcopy(statistics)
        name = 'candidate.clocks.jsonl'
        for index, item in enumerate(items):
            item['receipt']['frame'] = index
            item['receipt']['sha256'] = hashlib.sha256(item['frame']).hexdigest()
        encoded = ''.join(json.dumps(item['receipt']) + '\n' for item in items)
        (destination / name).write_text(encoded)
        candidate_statistics.update(packets=len(items), receipt_frames=len(items),
            monotonic_receipts=name, monotonic_receipts_sha256=digest(destination / name))
        (destination / 'candidate-statistics.json').write_text(json.dumps(candidate_statistics, indent=2) + '\n')
    return output, candidate_statistics


if __name__ == '__main__':
    from tcp_congestion_controls import run
    controls = {
        'opening-flight': 'opening flight obeys independently derived congestion bound',
        'growth-flight': 'growth flight obeys independently derived congestion bound',
        'recovery-flight': 'post-RTO recovery flight obeys independent congestion bound',
        'small-receive-window': 'every emitted byte remains inside actual receive window',
        'ACK-beyond-wire': 'ACK owns only actually emitted bytes and FIN',
        'retry-payload': 'exact forward application bytes and negotiated MSS',
        'missing-retry': 'full prefix acknowledgment follows both actual RTO retransmissions',
        'missing-final-ACK': 'both exact application streams and acknowledged FINs complete',
        'FIN-sequence': 'forward FIN follows all exact captured data',
    }
    run('window', controls, candidate, reconstruct)
