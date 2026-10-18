# SPDX-License-Identifier: GPL-3.0-or-later
"""Reject damaged real recovery packets, queue observations and source inputs."""
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
from tcp_recovery_capture import audit, audit_row, decode, MASK


def update(item, body, repair=True):
    body = bytearray(body)
    if repair:
        body[16:18] = b'\0\0'
        body[16:18] = checksum(item['ip'][12:20] + struct.pack('!BBH', 0, 6, len(body)) + body).to_bytes(2, 'big')
    item['frame'] = item['frame'][:34] + body + item['frame'][34 + len(body):]


def write_capture(path, rows):
    with path.open('wb') as output:
        output.write(struct.pack('<IHHIIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1))
        for row in rows:
            stamp, frame = row['stamp'], row['frame']
            output.write(struct.pack('<IIII', stamp // 1000000, stamp % 1000000, len(frame), len(frame)) + frame)


def mutate(rows, label):
    origin = (next(row['sequence'] for row in rows if row['outgoing'] and row['flags'] & 2) + 1) & MASK
    peer_origin = (next(row['sequence'] for row in rows if not row['outgoing'] and row['flags'] & 2) + 1) & MASK
    position = lambda row: (row['sequence'] - (origin if row['outgoing'] else peer_origin)) & MASK
    if label == 'missing-data':
        rows[:] = [row for row in rows if not (row['outgoing'] and row['data'] and
                    position(row) < 1552 and position(row) + len(row['data']) > 1040)]
        return
    if label == 'missing-close':
        rows[:] = [row for row in rows if row['outgoing'] or not row['flags'] & 1]
        return
    if label in ('missing-route-data', 'missing-host-route-data'):
        boundary = 3088 if label == 'missing-route-data' else 4176
        rows[:] = [row for row in rows if not (row['outgoing'] and row['data'] and
                    position(row) < boundary + 512 and position(row) + len(row['data']) > boundary)]
        return
    if label in ('source-port', 'malformed-option', 'wrong-mac'):
        row = next(row for row in rows if row['outgoing'] and row['flags'] & 2)
    elif label == 'future-ack':
        row = next(row for row in rows if row['outgoing'] and row['flags'] & 16 and not row['flags'] & 2)
    elif label == 'reply-data':
        row = next(row for row in rows if not row['outgoing'] and row['data'] and position(row) >= 1042)
    elif label == 'control-byte':
        row = next(row for row in rows if not row['outgoing'] and row['data'] and position(row) == 1040)
    elif label == 'expiry-control':
        row = next(row for row in rows if not row['outgoing'] and row['data'] and position(row) == 2066)
    elif label == 'expiry-data':
        row = next(row for row in rows if row['outgoing'] and row['data'] and position(row) >= 2064)
    elif label in ('route-data', 'host-route-data'):
        boundary = 3088 if label == 'route-data' else 4176
        row = next(row for row in rows if row['outgoing'] and row['data'] and position(row) >= boundary)
    elif label in ('carrier-data', 'carrier-reply'):
        outgoing = label == 'carrier-data'
        row = next(row for row in rows if row['outgoing'] == outgoing and row['data'] and
                   position(row) >= 5200 + (0 if outgoing else 4))
    else:
        row = next(row for row in rows if row['outgoing'] and row['data'] and
                   (label != 'queued-data' or position(row) >= 1040))
    body = bytearray(row['body'])
    if label == 'wrong-mac':
        frame = bytearray(row['frame'])
        frame[11] ^= 1
        row['frame'] = bytes(frame)
        return
    if label == 'source-port':
        body[:2] = (row['source'] + 3).to_bytes(2, 'big')
    elif label == 'malformed-option':
        require(body[20:22] == bytes([2, 4]), 'actual SYN begins with an MSS option')
        body[21] = 1
    elif label == 'future-ack':
        body[8:12] = ((peer_origin + 7000) & MASK).to_bytes(4, 'big')
    elif label == 'reset':
        body[13] |= 4
    else:
        body[(body[12] >> 4) * 4] ^= 1
    update(row, body, repair=label != 'checksum')


def rejected(action, label, expected):
    try:
        action()
    except ValueError as error:
        require(expected in str(error), f'{label}: wrong rejection: {error}')
        return str(error)
    raise ValueError(f'{label}: damaged recovery evidence was accepted')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('reports', nargs='*', type=Path)
    parser.add_argument('--input-root', type=Path)
    parser.add_argument('--host-libraries', type=Path)
    parser.add_argument('--output-directory', type=Path)
    args = parser.parse_args()
    reports = args.reports or [ROOT / 'build/tcp-recovery-native-results.json', ROOT / 'build/tcp-recovery-results.json']
    destination = args.output_directory or ROOT / 'build/tcp-recovery-damaged'
    destination.mkdir(exist_ok=True, parents=True)
    libraries = {path.name: path.read_bytes() for path in args.host_libraries.iterdir()} if args.host_libraries else None
    controls = {
        'checksum': 'actual TCP header, payload bounds and pseudo-header checksum',
        'queued-data': 'exact independent recovery bytes',
        'reply-data': 'exact independent recovery bytes',
        'control-byte': 'exact independent recovery bytes',
        'expiry-control': 'exact independent recovery bytes',
        'expiry-data': 'exact independent recovery bytes',
        'route-data': 'exact independent recovery bytes',
        'host-route-data': 'exact independent recovery bytes',
        'carrier-data': 'exact independent recovery bytes',
        'carrier-reply': 'exact independent recovery bytes',
        'missing-route-data': 'recovery ACK owns only captured emitted bytes',
        'missing-host-route-data': 'recovery ACK owns only captured emitted bytes',
        'source-port': 'exact bound recovery tuple',
        'missing-data': 'recovery ACK owns only captured emitted bytes',
        'missing-close': 'recovery ACK owns only captured emitted bytes',
        'future-ack': 'recovery ACK owns only captured emitted bytes',
        'malformed-option': 'invalid independent TCP options',
        'wrong-mac': 'exact recovery Ethernet and IP ownership',
        'reset': 'no reset in a recovered stream',
    }
    observations = []
    for report in reports:
        root = report.parent
        rows = json.loads(report.read_text())
        audit(report, args.input_root, libraries, complete=True)
        for label, changed in [('missing-profile', rows[:-1]), ('duplicate-profile', rows[:-1] + rows[:1])]:
            path = destination / f'{report.stem}-{label}.json'
            path.write_text(json.dumps(changed, indent=2) + '\n')
            reason = rejected(lambda: audit(path, args.input_root, libraries, complete=True), label,
                              'complete unique native or guest recovery cohort')
            observations.append(dict(profile=report.stem, control=label, reason=reason, artifact=path.name))
        for row in rows:
            native = 'client_namespace' in row
            checked = candidate_auditor(audit_row, root, row)
            name = 'linux-' + row['linkage'] if native else '-'.join(row[key] for key in ('linkage', 'firmware', 'transport'))
            original = decode(root / row['captures'][0], 0)
            with tempfile.TemporaryDirectory(prefix='recovery-damaged-') as directory:
                scratch = Path(directory)
                files = [*row['captures'], row['inputs'], row['log']]
                for peer in row['peers']:
                    files.append(peer['carrier']['metadata'])
                    for kind in ('output_hold', 'expiry_hold'):
                        metadata = peer[kind]['metadata']
                        files.append(metadata)
                        if not native:
                            files.append(str(Path(metadata).with_suffix('.log')))
                for filename in files:
                    shutil.copyfile(root / filename, scratch / filename)
                checked(scratch, row, args.input_root, libraries)
                for label, expected in controls.items():
                    changed = deepcopy(original)
                    mutate(changed, label)
                    path = destination / f'{name}-{label}.pcap'
                    write_capture(path, changed)
                    shutil.copyfile(path, scratch / row['captures'][0])
                    reason = rejected(lambda: checked(scratch, row, args.input_root, libraries), label, expected)
                    observations.append(dict(profile=name, control=label, reason=reason, artifact=path.name,
                        sha256=hashlib.sha256(path.read_bytes()).hexdigest()))
                shutil.copyfile(root / row['captures'][0], scratch / row['captures'][0])
                text = (root / row['log']).read_text()
                changed = re.sub(r'^TCP_RECOVERY_QUEUE_PASS lane=0 .*\n', '', text, count=1, flags=re.M)
                require(changed != text, 'actual queued completion marker removed')
                (scratch / row['log']).write_text(changed)
                reason = rejected(lambda: checked(scratch, row, args.input_root, libraries), 'missing-queue-case',
                                  'exact restored stream and live companion verdict')
                observations.append(dict(profile=name, control='missing-queue-case', reason=reason))
                (scratch / row['log']).write_text(text)
                changed = re.sub(r'^TCP_RECOVERY_EXPIRY_PASS lane=0 .*\n', '', text, count=1, flags=re.M)
                require(changed != text, 'actual copy-expiry completion marker removed')
                (scratch / row['log']).write_text(changed)
                reason = rejected(lambda: checked(scratch, row, args.input_root, libraries), 'missing-expiry-case',
                                  'exact restored stream and live companion verdict')
                observations.append(dict(profile=name, control='missing-expiry-case', reason=reason))
                changed = re.sub(r'^(TCP_RECOVERY_EXPIRY_RELEASE lane=0 elapsed_ms=)\d+', r'\g<1>4499', text, count=1, flags=re.M)
                require(changed != text, 'actual copy-expiry observation interval shortened')
                (scratch / row['log']).write_text(changed)
                reason = rejected(lambda: checked(scratch, row, args.input_root, libraries), 'shortened-expiry-wait',
                                  'both actual queue-expiry waits retain their full duration')
                observations.append(dict(profile=name, control='shortened-expiry-wait', reason=reason))
                (scratch / row['log']).write_text(text)
                route_controls = [
                    ('missing-route-case', r'^TCP_RECOVERY_ROUTE_PASS lane=0 mode=0 .*\n', '',
                     'all four exact route recoveries complete'),
                    ('missing-host-route-case', r'^TCP_RECOVERY_ROUTE_PASS lane=1 mode=1 .*\n', '',
                     'all four exact route recoveries complete'),
                    ('false-fresh-route', r'^(TCP_RECOVERY_ROUTE_FRESH lane=0 mode=0 errno=)101', r'\g<1>0',
                     'every withdrawn route rejects a fresh connect'),
                    ('hard-route-error', r'^(TCP_RECOVERY_ROUTE_ERROR lane=0 mode=0 error=)\d+', r'\g<1>110',
                     'both route mechanisms retain undelivered bytes without a hard socket failure'),
                    ('already-delivered-route', r'^(TCP_RECOVERY_ROUTE_ERROR lane=1 mode=1 error=\d+ available=)0', r'\g<1>512',
                     'both route mechanisms retain undelivered bytes without a hard socket failure'),
                    ('missing-mask-change', r'^TCP_RECOVERY_MASK lane=0 value=ffffffff\n', '',
                     'both connected and explicit host routes are changed and restored'),
                    ('missing-host-restoration', r'^TCP_RECOVERY_HOST_ROUTE lane=1 add=1\n', '',
                     'both connected and explicit host routes are changed and restored'),
                ]
                for label, expression, replacement, expected in route_controls:
                    changed = re.sub(expression, replacement, text, count=1, flags=re.M)
                    require(changed != text, f'actual {label} observation changed')
                    (scratch / row['log']).write_text(changed)
                    reason = rejected(lambda: checked(scratch, row, args.input_root, libraries), label, expected)
                    observations.append(dict(profile=name, control=label, reason=reason))
                error_line = re.search(r'^TCP_RECOVERY_ROUTE_ERROR lane=0 mode=0 .*\n', text, re.M).group()
                restore_line = 'TCP_RECOVERY_MASK lane=0 value=ffffff00\n'
                changed = text.replace(restore_line, '', 1).replace(error_line, restore_line + error_line, 1)
                require(changed != text, 'actual route restoration moved before retained-output observation')
                (scratch / row['log']).write_text(changed)
                reason = rejected(lambda: checked(scratch, row, args.input_root, libraries), 'route-order',
                                  'route withdrawal, retained output, live companion and restoration order')
                observations.append(dict(profile=name, control='route-order', reason=reason))
                (scratch / row['log']).write_text(text)
                for label in ('status', 'peer-result'):
                    changed = deepcopy(row)
                    if label == 'status':
                        changed['returncode'] = 99
                        expected = 'actual complete recovery producer status'
                    else:
                        changed['peers'][0]['flows'][0]['received'] = 5199
                        expected = 'peer result agrees with actual complete recovered stream'
                    reason = rejected(lambda: checked(scratch, changed, args.input_root, libraries), label, expected)
                    observations.append(dict(profile=name, control=label, reason=reason))
                metadata = row['peers'][0]['output_hold']['metadata']
                original_metadata = json.loads((root / metadata).read_text())
                for label in ('queue-confirmation', 'queue-physical-hold'):
                    changed = deepcopy(original_metadata)
                    if label == 'queue-confirmation':
                        changed['confirmed'] = False
                        expected = 'actual interface-scoped hold metadata'
                    elif native:
                        queues = json.loads(changed['events'][1]['stdout'])
                        for queue in queues:
                            queue['backlog'] = queue['qlen'] = 0
                        changed['events'][1]['stdout'] = json.dumps(queues)
                        expected = 'actual native payload remains queued before interface down'
                    else:
                        log = scratch / Path(metadata).with_suffix('.log')
                        log.write_text(log.read_text().replace('TCP_OUTPUT_HELD index=1', 'TCP_OUTPUT_NOT_HELD index=1'))
                        expected = 'actual guest output was held and later recovered at the same boundary'
                    (scratch / metadata).write_text(json.dumps(changed))
                    reason = rejected(lambda: checked(scratch, row, args.input_root, libraries), label, expected)
                    observations.append(dict(profile=name, control=label, reason=reason))
                shutil.copyfile(root / metadata, scratch / metadata)
                if not native:
                    shutil.copyfile(root / Path(metadata).with_suffix('.log'), scratch / Path(metadata).with_suffix('.log'))
                expiry_metadata = row['peers'][0]['expiry_hold']['metadata']
                if native:
                    changed = json.loads((root / expiry_metadata).read_text())
                    changed['events'][0]['command'][-1] = '1000ms'
                    (scratch / expiry_metadata).write_text(json.dumps(changed))
                    expected = 'exact interface and private namespace queue operations'
                else:
                    log = scratch / Path(expiry_metadata).with_suffix('.log')
                    log.write_text(log.read_text().replace('TCP_OUTPUT_EXPIRED index=1', 'TCP_OUTPUT_NOT_EXPIRED index=1'))
                    expected = 'actual owned IPv4 copy expiry is independently recorded'
                reason = rejected(lambda: checked(scratch, row, args.input_root, libraries), 'missing-expiry-proof', expected)
                observations.append(dict(profile=name, control='missing-expiry-proof', reason=reason))
                shutil.copyfile(root / expiry_metadata, scratch / expiry_metadata)
                if not native:
                    shutil.copyfile(root / Path(expiry_metadata).with_suffix('.log'), scratch / Path(expiry_metadata).with_suffix('.log'))
                metadata = row['peers'][0]['carrier']['metadata']
                original_carrier = json.loads((root / metadata).read_text())
                carrier_controls = {
                    'missing-carrier-event': 'ordered selected physical-carrier operations',
                    'duplicate-carrier-event': 'ordered selected physical-carrier operations',
                    'wrong-carrier-interface': ('only the selected physical veth port' if native else
                                                'actual selected QMP carrier operations'),
                    'changed-administrative-state': ('real carrier changes while' if native else
                                                     'real held carrier bytes preserve'),
                    'held-carrier-error': 'real held carrier bytes preserve',
                    'held-carrier-delivery': 'real held carrier bytes preserve',
                    'missing-carrier-held': 'real held carrier bytes preserve',
                    'backward-carrier-clock': 'actual ordered physical-carrier operation clocks',
                    'carrier-fingerprint': 'exact physical-carrier metadata fingerprint',
                    'different-carrier-controller': 'one shared physical-carrier controller'}
                if native:
                    carrier_controls['early-carrier-companion'] = 'independent native packets confirm'
                for label, expected in carrier_controls.items():
                    damaged = deepcopy(original_carrier)
                    changed = deepcopy(row)
                    if label == 'missing-carrier-event':
                        damaged['events'].pop()
                    elif label == 'duplicate-carrier-event':
                        damaged['events'][1] = deepcopy(damaged['events'][0])
                    elif label == 'wrong-carrier-interface':
                        if native:
                            damaged['events'][0]['commands'][0]['command'][3] = 'peer1'
                        else:
                            damaged['events'][0]['qmp']['name'] = 'carrier1'
                    elif label == 'changed-administrative-state':
                        if native:
                            event = damaged['events'][0]
                            event['state']['client']['flags'].remove('UP')
                            event['commands'][-1]['stdout'] = json.dumps([event['state']['client']])
                        else:
                            damaged['held'][0]['flags'] &= ~1
                    elif label == 'held-carrier-error':
                        damaged['held'][0]['error'] = 5
                    elif label == 'held-carrier-delivery':
                        damaged['held'][0]['available'] = 512
                    elif label == 'missing-carrier-held':
                        damaged['held'][0] = None
                    elif label == 'backward-carrier-clock':
                        damaged['events'][1]['start_monotonic_ns'] = damaged['events'][0]['start_monotonic_ns'] - 1
                    elif label == 'early-carrier-companion':
                        # Preserve internal event/held clock relationships,
                        # but place every claimed operation after the real
                        # packets. The independent packet-clock gate must fail.
                        for event in damaged['events']:
                            event['start_monotonic_ns'] += 1000000000000
                            event['end_monotonic_ns'] += 1000000000000
                        for held in damaged['held']:
                            held['monotonic_ns'] += 1000000000000
                    encoded = (json.dumps(damaged, indent=2) + '\n').encode()
                    (scratch / metadata).write_bytes(encoded)
                    digest = hashlib.sha256(encoded).hexdigest()
                    for peer in changed['peers']:
                        peer['carrier']['sha256'] = digest
                    if label == 'carrier-fingerprint':
                        for peer in changed['peers']:
                            peer['carrier']['sha256'] = '0' * 64
                    elif label == 'different-carrier-controller':
                        changed['peers'][1]['carrier']['metadata'] = 'different-carrier.json'
                    reason = rejected(lambda: checked(scratch, changed, args.input_root, libraries), label, expected)
                    artifact = destination / f'{name}-{label}.json'
                    artifact.write_text(json.dumps(dict(row=changed, metadata=damaged), indent=2) + '\n')
                    observations.append(dict(profile=name, control=label, reason=reason, artifact=artifact.name,
                                             sha256=hashlib.sha256(artifact.read_bytes()).hexdigest()))
                shutil.copyfile(root / metadata, scratch / metadata)
                inputs = json.loads((root / row['inputs']).read_text())
                inputs['sources']['userspace/tests/net/tcp_recovery.c'] = '0' * 64
                (scratch / row['inputs']).write_text(json.dumps(inputs))
                reason = rejected(lambda: checked(scratch, row, args.input_root, libraries), 'source-fingerprint',
                                  'actual sources input: userspace/tests/net/tcp_recovery.c')
                observations.append(dict(profile=name, control='source-fingerprint', reason=reason))
    value = dict(passed=True, rejected=len(observations), observations=observations)
    (destination / 'results.json').write_text(json.dumps(value, indent=2) + '\n')
    print(json.dumps(dict(passed=True, rejected=len(observations))), flush=True)


if __name__ == '__main__':
    main()
