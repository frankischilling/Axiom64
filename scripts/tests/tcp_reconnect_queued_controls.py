# SPDX-License-Identifier: GPL-3.0-or-later
"""Corrupt actual queued-copy packets and physical observations independently."""
from copy import deepcopy
import hashlib
import json
import re
import shutil
import struct
import zipfile
from tcp_icmp_capture import checksum, require

MASK = 0xffffffff


def packet_controls(native):
    values = {
        'queued-successor-data': 'exact independent queued old, successor and companion bytes',
        'queued-companion-data': 'exact independent queued old, successor and companion bytes',
        'queued-reset-sequence': 'queued disconnect reset owns only the abandoned old sequence',
        'missing-queued-reset': 'old abort and both fully acknowledged successor FINs complete',
        'queued-sequence-floor': 'queued successor excludes every old pending byte and advertised window',
        'missing-queued-close': 'queued ACK owns only actual captured bytes and FIN',
    }
    if native:
        values.update({'missing-late-old-copy': 'all exact queued old, successor and companion streams are captured',
                       'late-old-payload': 'exact independent queued old, successor and companion bytes'})
    return values


def mutate_packets(items, label, update):
    opening = [item for item in items if item['role'] == 4 and item['outgoing'] and item['flags'] & 2]
    old = opening[0]['sequence']
    new = next(item['sequence'] for item in opening if item['sequence'] != old)
    origin = (new + 1) & MASK
    position = lambda item: (item['sequence'] - origin) & MASK
    if label == 'queued-sequence-floor':
        old_end = (old + 1 + 16 + 512) & MASK
        shift = (old_end + 1 - new) & MASK
        for item in items:
            if item['role'] != 4:
                continue
            body = bytearray(item['body'])
            if item['outgoing'] and (item['sequence'] - new) & MASK <= 578:
                body[4:8] = ((item['sequence'] + shift) & MASK).to_bytes(4, 'big')
            elif not item['outgoing'] and item['flags'] & 16 and (item['acknowledgment'] - new) & MASK <= 578:
                body[8:12] = ((item['acknowledgment'] + shift) & MASK).to_bytes(4, 'big')
            else:
                continue
            update(item, body)
        return
    if label in ('missing-queued-reset', 'missing-queued-close', 'missing-late-old-copy'):
        def removed(item):
            if item['role'] != 4:
                return False
            if label == 'missing-queued-reset':
                return item['outgoing'] and item['flags'] & 4
            if label == 'missing-queued-close':
                return not item['outgoing'] and item['flags'] & 1
            return item['outgoing'] and item['data'] and 16 <= (item['sequence'] - old - 1) & MASK < 528
        changed = [item for item in items if not removed(item)]
        require(len(changed) < len(items), 'actual queued packet mutation removes observed evidence')
        items[:] = changed
        return
    if label == 'queued-reset-sequence':
        item = next(item for item in items if item['role'] == 4 and item['outgoing'] and item['flags'] & 4)
        body = bytearray(item['body'])
        body[4:8] = ((item['sequence'] - 1) & MASK).to_bytes(4, 'big')
    else:
        if label == 'late-old-payload':
            selected = lambda item: 16 <= (item['sequence'] - old - 1) & MASK < 528
        elif label == 'queued-companion-data':
            selected = lambda item: 528 <= position(item) < 576
        else:
            selected = lambda item: position(item) < 512
        item = next(item for item in items if item['role'] == 4 and item['outgoing'] and item['data'] and selected(item))
        body = bytearray(item['body'])
        body[(body[12] >> 4) * 4] ^= 1
    update(item, body)


def physical_controls(root, scratch, row, profile, checked, input_root, libraries, destination):
    native = 'client_namespace' in row
    claim = row['peers'][0]['queued_copy']
    names = {*row['captures'], row['log'], row['inputs'], claim['metadata']}
    for trace in claim['traces']:
        names.update((trace['log'], trace['script']))
    controls = {
        'missing-queue-event': 'ordered actual queued-copy cancellation and successor observations',
        'duplicate-queue-event': 'ordered actual queued-copy cancellation and successor observations',
        'missing-queue-confirmation': 'actual queued-copy hold remains confirmed through cancellation',
        'wrong-successor-frame': 'actual successor overlaps the old-copy lifetime on its original captured SYN',
        'late-successor-observation': 'actual successor overlaps the old-copy lifetime on its original captured SYN',
        'queue-fingerprint': 'exact physical queued-copy metadata fingerprint',
        'different-queue-controller': 'one shared actual queued-copy controller owns both NICs',
        'queued-peer-result': 'queued peer results agree with independently captured ownership and exact streams',
        'short-queue-wait': 'actual full queued-copy lifetime and successor wait',
        'missing-queue-barrier': 'every actual queued-copy application barrier completes in order',
    }
    if native:
        controls.update({'empty-old-queue': 'actual old native payload remains queued through cancellation and drains without drops',
                         'shifted-queue-clock': 'independent native packets observe the full real old-copy delay and successor recovery',
                         'wrong-queue-interface': 'exact successful native old-copy queue and future-packet classifier operations'})
    else:
        controls.update({'old-callback-owner': 'expired old copy has no callback owner that can reach its successor',
                         'missing-copy-expiry': 'expired old copy has no callback owner that can reach its successor',
                         'changed-expired-copy': 'actual held and expired copy owns the exact abandoned tuple, sequence and bytes',
                         'observer-return': 'observer holds only the selected old physical copy until its actual expiry',
                         'expiry-before-successor': 'actual guest successor is alive while its ownerless old copy expires',
                         'observer-fingerprint': 'exact original queued-copy observer script and trace fingerprint',
                         'wrong-queue-interface': 'observer holds only the selected old physical copy until its actual expiry'})
    observations = []
    for label, expected_reason in controls.items():
        for name in names:
            shutil.copyfile(root / name, scratch / name)
        candidate = deepcopy(row)
        metadata = json.loads((scratch / claim['metadata']).read_text())
        changed_metadata = False
        if label in ('missing-queue-event', 'duplicate-queue-event'):
            if label == 'missing-queue-event':
                metadata['events'].pop()
            else:
                metadata['events'].append(deepcopy(metadata['events'][-1]))
            changed_metadata = True
        elif label == 'missing-queue-confirmation':
            metadata['holds'][0] = [entry for entry in metadata['holds'][0] if entry.get('stage') != 'held_before_cancel']
            changed_metadata = True
        elif label in ('wrong-successor-frame', 'late-successor-observation'):
            if label == 'wrong-successor-frame':
                metadata['successors'][0]['syn_sha256'] = '0' * 64
            else:
                metadata['successors'][0]['monotonic_ns'] = metadata['events'][3]['monotonic_ns'] + 1
            changed_metadata = True
        elif label == 'queue-fingerprint':
            path = scratch / claim['metadata']
            path.write_bytes(path.read_bytes() + b' ')
        elif label == 'different-queue-controller':
            candidate['peers'][1]['queued_copy']['queued_each'] = 511
        elif label == 'queued-peer-result':
            candidate['peers'][0]['flows'][-1]['phases'][1]['initial'] ^= 1
        elif label in ('short-queue-wait', 'missing-queue-barrier'):
            path = scratch / row['log']
            text = path.read_text()
            if label == 'short-queue-wait':
                changed = re.sub(r'(TCP_RECONNECT_QUEUED_DONE lane=0 elapsed_ms=)\d+', r'\g<1>10999', text)
            else:
                changed = re.sub(r'^TCP_RECONNECT_QUEUED_HELD lane=0[^\n]*\n', '', text, flags=re.M)
            require(changed != text, 'actual queued application observation was damaged')
            path.write_text(changed)
        elif native:
            if label == 'empty-old-queue':
                query = next(entry for entry in metadata['holds'][0] if 'command' in entry and 'show' in entry['command'])
                rows = json.loads(query['stdout'])
                for entry in rows:
                    if entry.get('kind') == 'netem':
                        entry['backlog'] = entry['qlen'] = 0
                query['stdout'] = json.dumps(rows)
            elif label == 'wrong-queue-interface':
                metadata['holds'][0][0]['command'][8] = 'eth1'
            else:
                for event in metadata['events']:
                    event['monotonic_ns'] += 1000000000000
                for holds in metadata['holds']:
                    for entry in holds:
                        if 'monotonic_ns' in entry:
                            entry['monotonic_ns'] += 1000000000000
                for successor in metadata['successors']:
                    successor['monotonic_ns'] += 1000000000000
            changed_metadata = True
        else:
            trace = candidate['peers'][0]['queued_copy']['traces'][0]
            kind = 'script' if label in ('observer-return', 'wrong-queue-interface') else 'log'
            path = scratch / trace[kind]
            text = path.read_text()
            if label == 'old-callback-owner':
                changed = text.replace('owner=0 ', 'owner=0x1234 ')
            elif label == 'missing-copy-expiry':
                changed = re.sub(r'^TCP_RECONNECT_QUEUED_OLD_COPY_EXPIRED[^\n]*\n', '', text, flags=re.M)
            elif label == 'observer-return':
                changed = text.replace('return (int)-11', 'return (int)0')
            elif label == 'wrong-queue-interface':
                changed = text.replace('$rdi == 1', '$rdi == 2')
            elif label == 'expiry-before-successor':
                changed = re.sub(r'(TCP_RECONNECT_QUEUED_EXPIRED_MONOTONIC_NS )\d+',
                                 lambda match: match[1] + str(metadata['successors'][0]['monotonic_ns'] - 1), text)
            elif label == 'observer-fingerprint':
                changed = text + ' '
            else:
                original = re.search(r'TCP_RECONNECT_QUEUED_HELD_FRAME ([0-9a-f]+)', text)[1]
                frame = bytearray.fromhex(original)
                frame[-1] ^= 1
                body = frame[34:]
                body[16:18] = b'\0\0'
                body[16:18] = checksum(frame[26:34] + struct.pack('!BBH', 0, 6, len(body)) + body).to_bytes(2, 'big')
                frame[34:] = body
                changed = text.replace(original, frame.hex())
            require(changed != text, 'actual queued observer evidence was damaged')
            path.write_text(changed)
            if label != 'observer-fingerprint':
                for peer in candidate['peers']:
                    peer['queued_copy']['traces'][0][kind + '_sha256'] = hashlib.sha256(path.read_bytes()).hexdigest()
        if changed_metadata:
            path = scratch / claim['metadata']
            path.write_text(json.dumps(metadata, indent=2) + '\n')
            for peer in candidate['peers']:
                peer['queued_copy']['sha256'] = hashlib.sha256(path.read_bytes()).hexdigest()
        try:
            checked(scratch, candidate, input_root, libraries)
        except ValueError as error:
            require(expected_reason in str(error), f'{label}: wrong queued rejection: {error}')
            reason = str(error)
        else:
            raise ValueError(f'{label}: damaged queued-copy evidence was accepted')
        artifact = destination / (profile + '-' + label + '.zip')
        with zipfile.ZipFile(artifact, 'w', zipfile.ZIP_DEFLATED) as archive:
            archive.writestr('row.json', json.dumps(getattr(checked, 'last_row', candidate), indent=2) + '\n')
            for path in scratch.iterdir():
                if path.is_file():
                    archive.write(path, path.name)
        observations.append(dict(profile=profile, control=label, reason=reason,
                                 artifact=artifact.name, sha256=hashlib.sha256(artifact.read_bytes()).hexdigest()))
    for name in names:
        shutil.copyfile(root / name, scratch / name)
    return observations
