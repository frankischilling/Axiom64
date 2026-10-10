# SPDX-License-Identifier: GPL-3.0-or-later
"""Verify actual receive holes, duplicates and consistent overlaps independently."""
import hashlib
import itertools
import json
from pathlib import Path
from tcp_fault_capture import MASK, packets, require, verify as verify_loss


def verify(path, lane, peer_rows, native=False):
    result = verify_loss(path, lane, peer_rows, native)
    rows = packets(path, lane)
    reordered = []
    for role in range(2):
        flow = [row for row in rows if row['role'] == role]
        data = [row for row in flow if not row['outgoing'] and row['data']]
        origin = (next(row['seq'] for row in flow if not row['outgoing'] and row['flags'] & 2) + 1) & MASK
        ranges = [((row['seq'] - origin) & MASK, len(row['data'])) for row in data[:4]]
        require(ranges == [(536, 536), (536, 536), (804, 536), (0, 804)],
                'independent actual reordered, repeated, overlapping and gap-fill receive ranges')
        positions = [next(index for index, row in enumerate(flow) if row is segment)
                     for segment in data[:4]]
        first, duplicate, _, fill = positions
        acknowledgements = [row for row in flow[first + 1:fill]
                            if row['outgoing'] and row['flags'] & 16 and not row['flags'] & 2]
        require(len(acknowledgements) >= 2 and all(row['ack'] == origin for row in acknowledgements),
                'independent cumulative ACK cannot cover the actual receive hole')
        for begin, end in ((first, duplicate), (duplicate, fill)):
            require(any(row['outgoing'] and row['flags'] & 16 and row['ack'] == origin
                        for row in flow[begin + 1:end]),
                    'independent hole acknowledgement precedes each actual peer advance')
        require(any(row['outgoing'] and row['flags'] & 16 and row['ack'] == (origin + 1340) & MASK
                    for row in flow[fill + 1:]),
                'independent actual gap-fill ACK promotes all queued overlapping bytes')
        reordered.append(dict(role=role, hole_acknowledgements=len(acknowledgements),
                              queued_bytes=804, cumulative_after_fill=1340, passed=True))
    return dict(result, receive_reordering=reordered)


def check_results(directory):
    verified, reports = [], {}
    for name in ('tcp-reordering-native-results.json', 'tcp-reordering-results.json'):
        path = directory / name
        require(path.is_file(), 'both complete receive-reordering reports exist')
        reports[name] = hashlib.sha256(path.read_bytes()).hexdigest()
        rows = json.loads(path.read_text())
        native = name == 'tcp-reordering-native-results.json'
        if native:
            require(len(rows) == 3 and {row['linkage'] for row in rows} == {'native', 'static', 'dynamic'},
                    'three native receive-reordering profiles')
        else:
            expected = set(itertools.product(('static', 'dynamic'), ('bios', 'uefi'), ('modern', 'legacy')))
            require(len(rows) == 8 and {(row['linkage'], row['firmware'], row['transport']) for row in rows} == expected,
                    'eight guest receive-reordering profiles')
        for row in rows:
            require(row['wire'] == 'reordering' and row['passed'] and not row['error'] and not row['missing'],
                    'successful actual receive-reordering result')
            if native:
                require(len(row['capture_statistics']) == 2 and
                        all(stat['dropped'] == 0 and stat['packets'] > 0 and stat['buffer_bytes'] >= 4 * 1024 * 1024
                            for stat in row['capture_statistics']), 'no native reordering capture drops')
            require(Path(row['peer']).name == row['peer'] and len(row['captures']) == 2,
                    'receive-reordering evidence path bounds')
            peers = json.loads((directory / row['peer']).read_text())
            require(len(peers) == 2, 'both independent receive-reordering peer reports')
            for lane, name in enumerate(row['captures']):
                require(Path(name).name == name, 'receive-reordering capture path bounds')
                verified.append(verify(directory / name, lane, peers[lane], native))
    require(len(verified) == 22, 'all 22 receive-reordering captures')
    output = dict(captures=verified, flows=44, reports=reports, passed=True)
    (directory / 'tcp-reordering-capture-results.json').write_text(json.dumps(output, indent=2) + '\n')
    print('TCP_REORDERING_CAPTURE_PASS captures=22 flows=44 actual_holes duplicates overlap exact_bytes wrap loss FIN')
    return output


if __name__ == '__main__':
    check_results(Path(__file__).resolve().parents[1] / 'build')
