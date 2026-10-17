# SPDX-License-Identifier: GPL-3.0-or-later
"""Reject checksum-valid forged reconnect histories built from actual captures."""
import argparse
from copy import deepcopy
import hashlib
import json
from pathlib import Path
import re
import shutil
import struct
import sys
import tempfile

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from tcp_clock_mutations import candidate_auditor
from fetch import ROOT
from tcp_icmp_capture import checksum, require
from tcp_reconnect_capture import audit, audit_row, decode, MASK
from tcp_reconnect_queued_controls import packet_controls, mutate_packets, physical_controls


def update(item, body, repair=True):
    body = bytearray(body)
    if repair:
        body[16:18] = b'\0\0'
        body[16:18] = checksum(item['ip'][12:20] + struct.pack('!BBH', 0, 6, len(body)) + body).to_bytes(2, 'big')
    item['frame'] = item['frame'][:34] + body + item['frame'][34 + len(body):]


def retained_capture(path, items):
    data = path.read_bytes()
    require(data[:4] == bytes.fromhex('d4c3b2a1'), 'original reconnect test PCAP format')
    at, raw, cursor = 24, [], 0
    while at < len(data):
        seconds, micros, size, original = struct.unpack_from('<IIII', data, at)
        at += 16
        frame = data[at:at + size]
        at += size
        require(size == original and len(frame) == size, 'complete original reconnect test record')
        record = dict(stamp=seconds * 1000000 + micros, frame=frame)
        if cursor < len(items) and items[cursor]['stamp'] == record['stamp'] and items[cursor]['frame'] == frame:
            items[cursor]['record_index'] = len(raw)
            cursor += 1
        raw.append(record)
    require(cursor == len(items), 'every decoded test packet retains its original record index')
    return data[:24], raw, {item['record_index'] for item in items}


def write_capture(path, items, source=None):
    if source is None:
        header = struct.pack('<IHHIIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1)
    else:
        header, raw, workload = source
        changed = {item['record_index']: item for item in items}
        items = [changed.get(index, record) for index, record in enumerate(raw)
                 if index not in workload or index in changed]
    with path.open('wb') as output:
        output.write(header)
        for item in items:
            stamp, frame = item['stamp'], item['frame']
            output.write(struct.pack('<IIII', stamp // 1000000, stamp % 1000000, len(frame), len(frame)) + frame)


def mutate(items, label):
    if label in packet_controls(True):
        return mutate_packets(items, label, update)
    if label.startswith('revisit-'):
        owned = [item for item in items if item['role'] == 5]
        starts = [index for index, item in enumerate(owned) if item['outgoing'] and item['flags'] & 2]
        require(len(starts) == 3, 'actual three-phase revisit mutation input')
        if label == 'revisit-sequence-floor':
            old_end = next(item['sequence'] for item in owned[:starts[1]] if item['outgoing'] and item['flags'] & 4)
            shift = (old_end + 1 - owned[starts[2]]['sequence']) & MASK
            for item in owned[starts[2]:]:
                body = bytearray(item['body'])
                if item['outgoing']:
                    body[4:8] = ((item['sequence'] + shift) & MASK).to_bytes(4, 'big')
                elif item['flags'] & 16:
                    body[8:12] = ((item['acknowledgment'] + shift) & MASK).to_bytes(4, 'big')
                update(item, body)
        elif label == 'revisit-abort-sequence':
            item = next(item for item in owned[starts[1]:starts[2]] if item['outgoing'] and item['flags'] & 4)
            body = bytearray(item['body'])
            body[4:8] = ((item['sequence'] - 1) & MASK).to_bytes(4, 'big')
            update(item, body)
        else:
            start, end = (starts[1], starts[2]) if label == 'revisit-middle-data' else (starts[2], len(owned))
            item = next(item for item in owned[start:end] if item['outgoing'] and item['data'])
            body = bytearray(item['body'])
            body[(body[12] >> 4) * 4] ^= 1
            update(item, body)
        return
    first = next(item['sequence'] for item in items if item['role'] == 0 and item['outgoing'] and item['flags'] & 2)
    new_index = next(index for index, item in enumerate(items) if item['role'] == 0 and item['outgoing'] and
                     item['flags'] & 2 and item['sequence'] != first)
    if label == 'sequence-floor':
        old_end = next(item['sequence'] for item in items if item['role'] == 0 and item['outgoing'] and item['flags'] & 4)
        shift = (old_end + 1 - items[new_index]['sequence']) & MASK
        for item in items[new_index:]:
            if item['role'] != 0:
                continue
            body = bytearray(item['body'])
            if item['outgoing']:
                body[4:8] = ((item['sequence'] + shift) & MASK).to_bytes(4, 'big')
            elif item['flags'] & 16:
                body[8:12] = ((item['acknowledgment'] + shift) & MASK).to_bytes(4, 'big')
            update(item, body)
        return
    if label in ('old-data', 'new-data', 'checksum'):
        start, end = (new_index, len(items)) if label == 'new-data' else (0, new_index)
        item = next(item for item in items[start:end] if item['role'] == 0 and item['outgoing'] and item['data'])
        body = bytearray(item['body'])
        body[(body[12] >> 4) * 4] ^= 1
        update(item, body, repair=label != 'checksum')
    elif label == 'source-port':
        item = next(item for item in items if item['role'] == 0 and item['outgoing'] and item['flags'] & 2)
        body = bytearray(item['body'])
        body[:2] = (item['source'] + 3).to_bytes(2, 'big')
        update(item, body)
    elif label in ('old-reset-sequence', 'missing-old-reset'):
        index = next(index for index, item in enumerate(items) if item['role'] == 0 and item['outgoing'] and item['flags'] & 4)
        if label == 'missing-old-reset':
            del items[index]
        else:
            item = items[index]
            body = bytearray(item['body'])
            body[4:8] = ((item['sequence'] - 1) & MASK).to_bytes(4, 'big')
            update(item, body)
    elif label == 'missing-close':
        index = next(index for index, item in enumerate(items) if index >= new_index and item['role'] == 0 and
                     not item['outgoing'] and item['flags'] & 1)
        del items[index]
    elif label == 'malformed-option':
        item = items[new_index]
        body = bytearray(item['body'])
        require(len(body) >= 24 and body[20:22] == bytes([2, 4]), 'actual successor SYN starts with its MSS option')
        body[21] = 1
        update(item, body)
    else:
        raise ValueError('unknown reconnect evidence mutation')


def rejected(action, label, expected):
    try:
        action()
    except ValueError as error:
        require(expected in str(error), f'{label}: wrong rejection: {error}')
        return str(error)
    raise ValueError(f'{label}: damaged evidence was accepted')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('reports', nargs='*', type=Path)
    parser.add_argument('--input-root', type=Path)
    parser.add_argument('--host-libraries', type=Path)
    parser.add_argument('--output-directory', type=Path)
    args = parser.parse_args()
    reports = args.reports or [ROOT / 'build/tcp-reconnect-native-results.json', ROOT / 'build/tcp-reconnect-results.json']
    destination = args.output_directory or ROOT / 'build/tcp-reconnect-damaged'
    destination.mkdir(exist_ok=True)
    libraries = {path.name: path.read_bytes() for path in args.host_libraries.iterdir()} if args.host_libraries else None
    controls = {
        'checksum': 'actual TCP header, payload bounds and pseudo-header checksum',
        'old-data': 'exact independent old and successor payloads',
        'new-data': 'exact independent old and successor payloads',
        'source-port': 'actual reconnect bound source and old/successor destination ports',
        'old-reset-sequence': 'explicit reconnect reset owns only its old stream',
        'missing-old-reset': 'complete old reset or both independently acknowledged FINs',
        'missing-close': 'reconnect ACK never owns untransmitted bytes or FIN',
        'sequence-floor': 'successor SYN excludes the entire old transmitted sequence window',
        'malformed-option': 'invalid independent TCP options',
        'revisit-sequence-floor': 'revisited tuple and each intervening open exclude every old sequence window',
        'revisit-abort-sequence': 'explicit reconnect reset owns only its old stream',
        'revisit-middle-data': 'exact independent old and successor payloads',
        'revisit-final-data': 'exact independent old and successor payloads',
    }
    observations = []
    for report in reports:
        root = report.parent
        rows = json.loads(report.read_text())
        if len(rows) in (3, 8):
            audit(report, args.input_root, libraries, complete=True)
            for label, changed in [('missing-profile', rows[:-1]), ('duplicate-profile', rows[:-1] + rows[:1])]:
                path = destination / (report.stem + '-' + label + '.json')
                path.write_text(json.dumps(changed, indent=2) + '\n')
                reason = rejected(lambda: audit(path, args.input_root, libraries, complete=True), label,
                                  'complete native or guest reconnect cohort')
                observations.append(dict(profile=report.stem, control=label, reason=reason,
                    artifact=path.name, sha256=hashlib.sha256(path.read_bytes()).hexdigest()))
        for row in rows:
            audit_row(root, row, args.input_root, libraries)
            native = 'client_namespace' in row
            checked = candidate_auditor(audit_row, root, row)
            name = 'linux-' + row['linkage'] if native else '-'.join(row[key] for key in ('linkage', 'firmware', 'transport'))
            original = decode(root / row['captures'][0], 0, row['capture_statistics'][0] if native else None)
            source = retained_capture(root / row['captures'][0], original)
            with tempfile.TemporaryDirectory(prefix='reconnect-damaged-') as directory:
                scratch = Path(directory)
                extra = {row['peers'][0]['queued_copy']['metadata']}
                for trace in row['peers'][0]['queued_copy']['traces']:
                    extra.update((trace['log'], trace['script']))
                for filename in [*row['captures'], row['inputs'], row['log'], *extra]:
                    shutil.copyfile(root / filename, scratch / filename)
                for label, expected in dict(controls, **packet_controls(native)).items():
                    changed = deepcopy(original)
                    mutate(changed, label)
                    path = destination / (name + '-' + label + '.pcap')
                    write_capture(path, changed, source)
                    shutil.copyfile(path, scratch / row['captures'][0])
                    reason = rejected(lambda: checked(scratch, row, args.input_root, libraries), label, expected)
                    observations.append(dict(profile=name, control=label, reason=reason,
                        artifact=path.name, sha256=hashlib.sha256(path.read_bytes()).hexdigest()))
                shutil.copyfile(root / row['captures'][0], scratch / row['captures'][0])
                text = (root / row['log']).read_text()
                for label in ('missing-guard', 'duplicate-phase', 'missing-revisit-phase'):
                    if label == 'missing-guard':
                        changed = re.sub(r'^TCP_RECONNECT_GUARD_PASS .*\n', '', text, count=1, flags=re.M)
                        expected = 'every completed-tuple guard is exercised before changing destination'
                    elif label == 'duplicate-phase':
                        line = re.search(r'^TCP_RECONNECT_PHASE_PASS .*$', text, re.M)[0]
                        changed = text + line + '\n'
                        expected = 'every actual old and successor byte/address operation completes'
                    else:
                        changed = re.sub(r'^TCP_RECONNECT_REVISIT_PHASE_PASS .*\n', '', text, count=1, flags=re.M)
                        expected = 'every actual A-B-A byte and retained bound-source operation completes in order'
                    require(changed != text, 'an actual reconnect observation was damaged')
                    (scratch / row['log']).write_text(changed)
                    reason = rejected(lambda: checked(scratch, row, args.input_root, libraries), label, expected)
                    observations.append(dict(profile=name, control=label, reason=reason))
                (scratch / row['log']).write_text(text)
                observations.extend(physical_controls(root, scratch, row, name, checked,
                                                       args.input_root, libraries, destination))
                for label in ('status', 'peer-result', 'revisit-peer-result'):
                    changed = deepcopy(row)
                    if label == 'status':
                        changed['returncode'] = 99
                        expected = 'actual complete reconnect producer status'
                    else:
                        role = 5 if label == 'revisit-peer-result' else 0
                        flow = next(flow for flow in changed['peers'][0]['flows'] if flow['role'] == role)
                        flow['phases'][-1]['initial'] ^= 1
                        expected = 'reported reconnect phases agree with original packet ownership'
                    reason = rejected(lambda: checked(scratch, changed, args.input_root, libraries), label, expected)
                    observations.append(dict(profile=name, control=label, reason=reason))
                inputs = json.loads((root / row['inputs']).read_text())
                inputs['sources']['userspace/tests/net/tcp_reconnect.c'] = '0' * 64
                (scratch / row['inputs']).write_text(json.dumps(inputs))
                reason = rejected(lambda: checked(scratch, row, args.input_root, libraries), 'source-fingerprint',
                                  'actual sources input: userspace/tests/net/tcp_reconnect.c')
                observations.append(dict(profile=name, control='source-fingerprint', reason=reason))
    value = dict(passed=True, rejected=len(observations), observations=observations)
    (destination / 'results.json').write_text(json.dumps(value, indent=2) + '\n')
    print(json.dumps(dict(passed=True, rejected=len(observations))), flush=True)


if __name__ == '__main__':
    main()
