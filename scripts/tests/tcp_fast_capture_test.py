# SPDX-License-Identifier: GPL-3.0-or-later
"""Reject real fast-recovery evidence with checksum-valid packet changes."""
from copy import deepcopy
from pathlib import Path
import json
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from tcp_congestion.fast_capture import reconstruct
from tcp_congestion.window_capture import packets, decode, MASK, MSS, expected, digest, require
from tcp_malformed.capture import raw_records
from tcp_malformed_capture_test import update, write

def mutate(path, lane, statistics, label, native):
    items = list(raw_records(path))
    if statistics is not None:
        receipts = [json.loads(line) for line in (path.parent / statistics['monotonic_receipts']).read_text().splitlines()]
        for item, receipt in zip(items, receipts):
            item['receipt'] = receipt
    rows = [(index, decode(item['frame'], lane, (49500 + lane,))) for index, item in enumerate(items)]
    rows = [(index, row) for index, row in rows if row is not None]
    origin = (next(row for _, row in rows if row['outgoing'] and row['flags'] & 2)['seq'] + 1) & MASK
    reverse = (next(row for _, row in rows if not row['outgoing'] and row['flags'] & 2)['seq'] + 1) & MASK
    acks = [(index, row) for index, row in rows if not row['outgoing'] and row['flags'] == 16
            and not row['data'] and ((row['ack'] - origin) & MASK) > 0]
    retry, retry_row = next((index, row) for index, row in rows if acks[3][0] < index < acks[4][0]
                           and row['outgoing'] and row['data'] and ((row['seq'] - origin) & MASK) == MSS)
    if label == 'missing-third-duplicate':
        del items[acks[3][0]]
    elif label == 'extra-duplicate':
        item = deepcopy(items[acks[5][0] - 1])
        item['frame'] = items[acks[4][0]]['frame']
        items.insert(acks[5][0], item)
    elif label == 'retry-payload':
        data = retry_row['data']
        items[retry]['frame'] = update(items[retry]['frame'], data=bytes([data[0] ^ 1]) + data[1:])
    elif label == 'retry-sequence':
        items[retry]['frame'] = update(items[retry]['frame'], sequence=retry_row['seq'] + 1,
                                      data=expected(lane, 0, MSS + 1, MSS))
    elif label == 'missing-retry':
        del items[retry]
    elif label in ('fast-inflation', 'fourth-inflation', 'deflation', 'small-window-overrun'):
        gate = {'fast-inflation': 4, 'fourth-inflation': 5, 'deflation': 6, 'small-window-overrun': 7}[label]
        stop = acks[gate][0]
        frontier = max(((row['seq'] - origin) & MASK) + len(row['data']) for index, row in rows
                       if index < stop and row['outgoing'] and row['data'])
        template = next(row['frame'] for _, row in rows if row['outgoing'] and row['data'])
        count = {'fast-inflation': 3, 'fourth-inflation': 2, 'deflation': 3}.get(label, 1) if native else 1
        length = 1 if label == 'small-window-overrun' else MSS
        added = []
        for number in range(count):
            at = frontier + number * MSS
            item = deepcopy(items[stop - 1])
            item['frame'] = update(template, sequence=origin + at, data=expected(lane, 0, at, length))
            added.append(item)
        items[stop:stop] = added
    elif label == 'ACK-beyond-wire':
        index, row = acks[5]
        items[index]['frame'] = update(items[index]['frame'], acknowledgment=row['ack'] + 1)
    elif label == 'missing-final-ACK':
        removed = {index for index, row in rows if row['outgoing'] and row['flags'] == 16 and not row['data']
                   and row['ack'] == (reverse + 17) & MASK}
        assert removed
        items[:] = [item for index, item in enumerate(items) if index not in removed]
    else:
        raise ValueError(label)
    return items


def candidate(path, lane, statistics, label, destination, native):
    return write(mutate(path, lane, statistics, label, native), path, statistics, destination)


if __name__ == '__main__':
    from tcp_congestion_controls import run
    controls = {
        'missing-third-duplicate': 'one advancing ACK, exactly four duplicates, recovery ACK and actual window gates',
        'extra-duplicate': 'one advancing ACK, exactly four duplicates, recovery ACK and actual window gates',
        'retry-payload': 'exact fast-recovery payload and negotiated segment bounds',
        'retry-sequence': 'only the actual oldest segment is fast retransmitted',
        'missing-retry': 'three actual duplicate ACKs precede one oldest-segment retry before the fourth',
        'fast-inflation': 'fast duplicate-ACK flight obeys independent congestion bound',
        'fourth-inflation': 'extra duplicate-ACK flight obeys independent congestion bound',
        'deflation': 'recovery duplicate-ACK flight obeys independent congestion bound',
        'small-window-overrun': 'fast-recovery emission respects actual receive ownership',
        'ACK-beyond-wire': 'fast-recovery ACK owns actual emitted bytes and FIN',
        'missing-final-ACK': 'actual fast recovery deflates, obeys small window, and closes both exact streams',
    }
    run('fast', controls, candidate, reconstruct)
