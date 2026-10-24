# SPDX-License-Identifier: GPL-3.0-or-later
"""Serialize damaged copies of actual DAD evidence and require independent rejection."""
from copy import deepcopy
import hashlib
import json
from pathlib import Path
import re
import struct
import tempfile
import zipfile

from ipv6_dad_capture import inspect
from ipv6_router_capture import checksum, qemu_records, require


def repair(frame):
    protocol = frame[20]
    offset = 56 if protocol == 58 else 60
    frame[offset:offset + 2] = bytes(2)
    body = frame[54:]
    value = checksum(bytes(frame[22:54]) + struct.pack('!I3xB', len(body), protocol) + bytes(body))
    struct.pack_into('!H', frame, offset, value or 0xffff)


def encode(header, rows):
    endian = '<' if header[:4] == b'\xd4\xc3\xb2\xa1' else '>'
    data = bytearray(header)
    for row in rows:
        stamp, frame = row['stamp'], row['frame']
        data.extend(struct.pack(endian + 'IIII', stamp // 1000000, stamp % 1000000, len(frame), len(frame)))
        data.extend(frame)
    return bytes(data)


LABELS = (
    'conflict-checksum', 'conflict-hop-limit', 'conflict-code', 'conflict-target',
    'conflict-source-mac', 'conflict-destination', 'conflict-flags', 'conflict-before-prerequisites',
    'missing-conflict', 'missing-candidate-probe', 'duplicate-candidate-probe', 'missing-cycle-probe',
    'changed-cycle-nonce', 'DAD-source', 'DAD-hop-limit', 'DAD-option',
    'early-retry', 'late-retry', 'short-exhausted-observation', 'wrong-prefix-route',
    'wrong-permanent-route-lifetime', 'wrong-route-protocol', 'wrong-final-flags',
    'infinite-regenerated-cache', 'missing-link-owner', 'changed-link-algorithm',
    'missing-client-control', 'wrong-control-observation', 'wrong-tentative-flags',
    'wrong-inherited-lifetime', 'wrong-policy', 'repeated-control-phase', 'damaged-ack-tail',
    'missing-ack', 'UDP-checksum', 'UDP-data', 'UDP-destination-mac', 'UDP-source', 'missing-UDP-reply',
)


def mutate(original, text, lane, label):
    rows = deepcopy(original)
    outgoing = lambda row: row['frame'][6:12] == bytes.fromhex(f'5254001234{16 + lane:02x}')
    control = lambda row: row['frame'][12:14] == b'\x88\xc2'
    requests = [row for row in rows if control(row) and outgoing(row)]
    metadata = {(row['frame'][21], row['frame'][22]): row for row in requests if row['frame'][20] in (2, 3)}
    target = metadata[2, 0]['frame'][36:52]
    nd = lambda row, kind: row['frame'][12:14] == b'\x86\xdd' and row['frame'][20] == 58 and row['frame'][54] == kind
    conflict = next(row for row in rows if nd(row, 136) and row['frame'][62:78] == target)
    probe = next(row for row in rows if nd(row, 135) and row['frame'][62:78] == target)
    if label.startswith('conflict-'):
        frame = bytearray(conflict['frame'])
        if label == 'conflict-checksum':
            frame[56] ^= 1
        elif label == 'conflict-hop-limit':
            frame[21] = 254
        elif label == 'conflict-code':
            frame[55] = 1
        elif label == 'conflict-target':
            frame[77] ^= 1
        elif label == 'conflict-source-mac':
            frame[11] ^= 1
        elif label == 'conflict-destination':
            frame[53] = 2
            frame[5] = 2
        elif label == 'conflict-flags':
            frame[58] = 0x60
        else:
            rows.remove(conflict)
            rows.insert(rows.index(probe), conflict)
        if label != 'conflict-checksum':
            repair(frame)
        conflict['frame'] = bytes(frame)
    elif label in ('missing-conflict', 'missing-candidate-probe', 'duplicate-candidate-probe'):
        if label == 'missing-conflict':
            rows.remove(conflict)
        elif label == 'missing-candidate-probe':
            rows.remove(probe)
        else:
            rows.insert(rows.index(probe), deepcopy(probe))
    elif label in ('missing-cycle-probe', 'changed-cycle-nonce'):
        cycle_target = metadata[6, 0]['frame'][36:52]
        cycle = [row for row in rows if nd(row, 135) and row['frame'][62:78] == cycle_target]
        require(len(cycle) == 3, 'original actual three-probe DAD cycle')
        if label == 'missing-cycle-probe':
            rows.remove(cycle[1])
        else:
            frame = bytearray(cycle[1]['frame'])
            frame[-1] ^= 1
            repair(frame)
            cycle[1]['frame'] = bytes(frame)
    elif label in ('DAD-source', 'DAD-hop-limit', 'DAD-option'):
        frame = bytearray(probe['frame'])
        if label == 'DAD-source':
            frame[22:24] = b'\xfe\x80'
            frame[37] = 1
        elif label == 'DAD-hop-limit':
            frame[21] = 254
        else:
            frame[78] = 1
        repair(frame)
        probe['frame'] = bytes(frame)
    elif label in ('early-retry', 'late-retry', 'short-exhausted-observation'):
        if label == 'short-exhausted-observation':
            last_target = metadata[2, 3]['frame'][36:52]
            anchor = next(row for row in rows if nd(row, 136) and row['frame'][62:78] == last_target)
            selected = next(row for row in requests if row['frame'][20:23] == bytes([4, 2, 0]))
            wanted = 2999999
        else:
            next_target = metadata[2, 1]['frame'][36:52]
            anchor = conflict
            selected = next(row for row in rows if nd(row, 135) and row['frame'][62:78] == next_target)
            wanted = 999999 if label == 'early-retry' else 2100001
        delta = anchor['stamp'] + wanted - selected['stamp']
        for row in rows[rows.index(selected):]:
            row['stamp'] += delta
    elif label in ('wrong-prefix-route', 'wrong-permanent-route-lifetime', 'wrong-route-protocol',
                   'wrong-final-flags', 'infinite-regenerated-cache', 'missing-link-owner',
                   'missing-client-control', 'wrong-control-observation'):
        if label == 'wrong-prefix-route':
            text, count = re.subn(r'(IPV6_DAD_FINISH lane=' + str(lane) + r' scenario=3 .*prefix_routes=)0', r'\g<1>1', text)
        elif label == 'wrong-permanent-route-lifetime':
            text, count = re.subn(r'(IPV6_DAD_(?:FINISH|ROUTE) lane=' + str(lane) + r' scenario=5 .*expires=)0', r'\g<1>1', text)
        elif label == 'wrong-route-protocol':
            text, count = re.subn(r'(IPV6_DAD_ROUTE lane=' + str(lane) + r' scenario=1 .*protocol=)2', r'\g<1>9', text)
        elif label == 'wrong-final-flags':
            text, count = re.subn(r'(IPV6_DAD_FINISH lane=' + str(lane) + r' scenario=5 .*flags=)c8', r'\g<1>8', text)
        elif label == 'infinite-regenerated-cache':
            text, count = re.subn(r'(IPV6_DAD_FINISH lane=' + str(lane) + r' scenario=1 .*preferred=)\d+ valid=\d+', r'\g<1>4294967295 valid=4294967295', text)
        elif label == 'missing-link-owner':
            text, count = re.subn(r'^IPV6_DAD_LINK lane=' + str(lane) + r' stage=5 .*flags=80 .*\n', '', text, count=1, flags=re.M)
        elif label == 'missing-client-control':
            text, count = re.subn(r'^IPV6_DAD_CONTROL lane=' + str(lane) + r' phase=3 .*\n', '', text, count=1, flags=re.M)
        else:
            text, count = re.subn(r'(IPV6_DAD_CONTROL lane=' + str(lane) + r' phase=3 .*observed_ns=)\d+', r'\g<1>1', text, count=1)
        require(count > 0, 'negative control changes the actual queried inventory or control log')
    elif label == 'changed-link-algorithm':
        link = [row for row in rows if nd(row, 135) and row['frame'][22:38] == bytes(16) and
                row['frame'][62:64] == b'\xfe\x80'][-1]
        frame = bytearray(link['frame'])
        frame[77] ^= 1
        frame[51:54] = frame[75:78]
        frame[3:6] = frame[75:78]
        repair(frame)
        link['frame'] = bytes(frame)
    elif label in ('wrong-tentative-flags', 'wrong-inherited-lifetime', 'wrong-policy', 'repeated-control-phase'):
        selected = requests[0] if label == 'wrong-policy' else metadata[2, 1]
        frame = bytearray(selected['frame'])
        if label == 'wrong-policy':
            frame[23] ^= 1
        elif label == 'repeated-control-phase':
            frame[19] -= 1
        elif label == 'wrong-tentative-flags':
            frame[27] ^= 4
        else:
            struct.pack_into('!I', frame, 28, 29)
        selected['frame'] = bytes(frame)
    elif label in ('damaged-ack-tail', 'missing-ack'):
        answer = next(row for row in rows if control(row) and not outgoing(row) and row['frame'][19] == 3)
        if label == 'missing-ack':
            rows.remove(answer)
        else:
            frame = bytearray(answer['frame'])
            frame[-1] = 1
            answer['frame'] = bytes(frame)
    elif label.startswith('UDP-') or label == 'missing-UDP-reply':
        datagrams = [row for row in rows if row['frame'][12:14] == b'\x86\xdd' and row['frame'][20] == 17]
        selected = next(row for row in datagrams if outgoing(row) == (label != 'missing-UDP-reply'))
        if label == 'missing-UDP-reply':
            rows.remove(selected)
        else:
            frame = bytearray(selected['frame'])
            if label == 'UDP-checksum':
                frame[60] ^= 1
            elif label == 'UDP-data':
                frame[-1] ^= 1
            elif label == 'UDP-destination-mac':
                frame[5] ^= 1
            else:
                frame[37] ^= 1
            if label != 'UDP-checksum':
                repair(frame)
            selected['frame'] = bytes(frame)
    else:
        raise ValueError('unknown DAD corruption control')
    return rows, text


def controls(path, lane, text, archive=None):
    original = path.read_bytes()
    rows = list(qemu_records(path))
    inspect(path, lane, text)
    outcomes = []
    output = zipfile.ZipFile(archive, 'x', compression=zipfile.ZIP_DEFLATED) if archive else None
    try:
        with tempfile.TemporaryDirectory(prefix='axiom64-dad-damage-') as temporary:
            candidate = Path(temporary) / 'candidate.pcap'
            for label in LABELS:
                damaged, log = mutate(rows, text, lane, label)
                data = encode(original[:24], damaged)
                require(data != original or log != text, 'each serialized DAD control changes original evidence')
                candidate.write_bytes(data)
                try:
                    inspect(candidate, lane, log)
                except ValueError as failure:
                    outcome = dict(control=label, rejection=str(failure),
                        capture_sha256=hashlib.sha256(data).hexdigest(),
                        log_sha256=hashlib.sha256(log.encode()).hexdigest())
                else:
                    raise ValueError('damaged actual DAD evidence accepted: ' + label)
                outcomes.append(outcome)
                if output:
                    output.writestr(label + '/candidate.pcap', data)
                    output.writestr(label + '/candidate.log', log)
                    output.writestr(label + '/verdict.json', json.dumps(outcome, indent=2) + '\n')
    finally:
        if output:
            output.close()
    require(path.read_bytes() == original and len(outcomes) == len(LABELS),
            'all serialized DAD controls reject while every original packet and timestamp remains unchanged')
    return outcomes
