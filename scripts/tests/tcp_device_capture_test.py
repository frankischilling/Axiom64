# SPDX-License-Identifier: GPL-3.0-or-later
"""Reject changed copies of actual device-loss observations without rerunning producers."""
from copy import deepcopy
import json
from pathlib import Path
import re
import shutil
import sys
import tempfile
import zipfile

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from fetch import ROOT
from tcp_device.capture import observation, digest, require
from tcp_malformed.capture import raw_records
from tcp_fault_capture import decode
from tcp_malformed_capture_test import update, write

GUEST = {
    'wrong-physical-identity': 'actual PCI I/O confirms selected identity vanished',
    'healthy-PCI-missing': 'actual QMP enumeration independently confirms selected physical absence',
    'synthesized-EIO': 'observer holds actual selected output without synthesizing the device error',
    'callback-owner-remains': 'actual failure reclaims the owned copy',
    'changed-held-bytes': 'held copy owns exact abandoned tuple, sequence and bytes',
    'missing-copy-failure': 'actual failure reclaims the owned copy',
    'short-guest-lifetime': 'actual error readiness and full healthy lifetime complete',
    'short-host-lifetime': 'independent host monotonic observations retain the full healthy lifetime',
    'no-owned-pending-copy': 'actual failure reclaims the owned copy',
    'failed-observer-exit': 'actual successful owned physical observer exit',
    'unrelated-failure-entry': 'actual device failure is observed at the called owner boundary',
    'failure-owner-mismatch': 'actual device failure is observed at the called owner boundary',
}
NATIVE = {
    'selected-interface-remains': 'actual original Linux device inventory proves selected absence',
    'healthy-interface-missing': 'actual original Linux device inventory proves selected absence',
    'empty-pending-queue': 'actual native queue retains the selected pending output before deletion',
    'wrong-deleted-interface': 'actual comparison deletes only the selected private native interface',
    'short-host-lifetime': 'independent native host observations preserve the full healthy interval',
    'short-native-lifetime': 'actual error readiness and full healthy lifetime complete',
    'wrong-socket-error': 'actual scoped read, SO_ERROR, EOF and EPIPE syscall sequence',
    'broken-clock-fingerprint': 'exact original native clock receipt fingerprint',
}


def replace(path, data):
    if path.is_symlink():
        path.unlink()
    path.write_bytes(data)


def modify(directory, row, label):
    changed = set()
    if label.startswith('packet-data-lane'):
        lane = int(label[-1])
        path = directory / f'lane{lane}.pcap'
        items = list(raw_records(path))
        statistics = row['capture_statistics'][lane] if row['native'] else None
        if statistics is not None:
            receipts = [json.loads(line) for line in (directory / statistics['monotonic_receipts']).read_text().splitlines()]
            require(len(receipts) == len(items), 'candidate retains all original native clocks')
            for item, receipt in zip(items, receipts):
                item['receipt'] = receipt
        for item in items:
            decoded = decode(item['frame'], lane, (49600 + lane,))
            if decoded is not None and decoded['outgoing'] and decoded['data']:
                original = item['frame'].hex()
                data = decoded['data']
                item['frame'] = update(item['frame'], data=bytes([data[0] ^ 1]) + data[1:])
                altered = item['frame'].hex()
                break
        else:
            raise ValueError('actual data frame for negative packet control')
        peer_path = directory / 'peer-frames.json'
        peers = json.loads(peer_path.read_text())
        next(item for item in peers[lane]['frames'] if item['frame'] == original)['frame'] = altered
        replace(peer_path, (json.dumps(peers, indent=2) + '\n').encode())
        candidate, candidate_statistics = write(items, path, statistics, directory)
        replace(path, candidate.read_bytes())
        changed.update((path.name, peer_path.name))
        if statistics is not None:
            row['capture_statistics'][lane] = candidate_statistics
            changed.add(candidate_statistics['monotonic_receipts'])
        replace(directory / 'candidate-row.json', (json.dumps(row, indent=2) + '\n').encode())
        return changed | {'candidate-row.json'}
    if label == 'broken-clock-fingerprint':
        row['capture_statistics'][0]['monotonic_receipts_sha256'] = '0' * 64
        replace(directory / 'candidate-row.json', (json.dumps(row, indent=2) + '\n').encode())
        return {'candidate-row.json'}
    if label in ('short-guest-lifetime', 'short-native-lifetime', 'wrong-socket-error'):
        path = directory / ('client.log' if row['native'] else 'guest.log')
        original = path.read_text()
        altered = (original.replace('read_errno=101 so_error=101', 'read_errno=5 so_error=101')
                   if label == 'wrong-socket-error' else re.sub(
                   r'(TCP_DEVICE_HEALTHY_PASS lane=\d bytes=\d+ elapsed_ms=)\d+', r'\g<1>4999', original))
        require(altered != original, 'negative control changes the actual log')
        replace(path, altered.encode())
        return {path.name}
    if row['native']:
        path = directory / 'actual-device-operations.json'
        operations = json.loads(path.read_text())
        commands = [item for item in operations if 'command' in item]
        queries = [item for item in commands if item['command'][-4:] == ['ip', '-j', 'link', 'show']]
        if label in ('selected-interface-remains', 'healthy-interface-missing'):
            after = json.loads(queries[1]['stdout'])
            if label == 'selected-interface-remains':
                before = json.loads(queries[0]['stdout'])
                after.append(next(item for item in before if item['ifname'] == f'eth{row["affected"]}'))
            else:
                after[:] = [item for item in after if item['ifname'] != f'eth{1-row["affected"]}']
            queries[1]['stdout'] = json.dumps(after)
        elif label == 'empty-pending-queue':
            queue = next(item for item in commands if item['command'][-7:-1] == ['tc', '-j', '-s', 'qdisc', 'show', 'dev'])
            counters = json.loads(queue['stdout'])
            for item in counters:
                item['backlog'] = item['qlen'] = 0
            queue['stdout'] = json.dumps(counters)
        elif label == 'wrong-deleted-interface':
            next(item for item in commands if item['command'][-5:-1] == ['ip', 'link', 'delete', 'dev'])['command'][-1] = f'eth{1-row["affected"]}'
        elif label == 'short-host-lifetime':
            events = {item['operation']: item for item in operations if 'operation' in item}
            events['healthy_complete']['monotonic_ns'] = events['actual_native_error']['monotonic_ns'] + 4999999999
        else:
            raise ValueError(label)
        replace(path, (json.dumps(operations, indent=2) + '\n').encode())
        return {path.name}
    path = directory / 'physical-device-observations.json'
    physical = json.loads(path.read_text())
    removed = next(item for item in physical['hardware'] if item.get('operation') == 'remove')
    if label == 'wrong-physical-identity':
        removed['after'][row['affected']] = removed['before'][row['affected']]
    elif label == 'healthy-PCI-missing':
        for bus in removed['pci']:
            bus['devices'][:] = [item for item in bus['devices'] if item['slot'] != 5 - row['affected']]
    elif label == 'failed-observer-exit':
        physical['observer_returncode'] = 1
    elif label == 'short-host-lifetime':
        events = {item['stage']: item for item in physical['events']}
        events['healthy_complete']['monotonic_ns'] = events['actual_guest_failure']['monotonic_ns'] + 4999999999
    else:
        trace = directory / ('device-copy.gdb' if label in ('synthesized-EIO', 'unrelated-failure-entry') else 'device-copy.log')
        original = trace.read_text()
        if label == 'synthesized-EIO':
            altered = original.replace('return (int)-11', 'return (int)-5')
        elif label == 'unrelated-failure-entry':
            altered = original.replace('break *ax::inet_failed', 'break *ax::inet_icmp_error')
        elif label == 'failure-owner-mismatch':
            altered = re.sub(r'(TCP_DEVICE_QUEUE_FAILURE error=5 owner=)0x[0-9a-f]+', r'\g<1>0x1234', original)
        elif label == 'callback-owner-remains':
            altered = original.replace('TCP_DEVICE_COPY_CLEARED owner=0x0 ', 'TCP_DEVICE_COPY_CLEARED owner=0x1234 ')
        elif label == 'missing-copy-failure':
            altered = re.sub(r'^TCP_DEVICE_QUEUE_FAILURE[^\n]*\n', '', original, flags=re.M)
        elif label == 'no-owned-pending-copy':
            altered = re.sub(r'(TCP_DEVICE_QUEUE_PENDING index=\d owner=)0x[0-9a-f]+', r'\g<1>0x0', original)
        elif label == 'changed-held-bytes':
            frame = bytes.fromhex(re.search(r'TCP_DEVICE_HELD_FRAME ([0-9a-f]+)', original)[1])
            data = frame[54:]
            altered_frame = update(frame, data=data[:-1] + bytes([data[-1] ^ 1])).hex()
            altered = original.replace(frame.hex(), altered_frame)
        else:
            raise ValueError(label)
        require(altered != original, 'negative control changes the actual physical trace')
        replace(trace, altered.encode())
        physical['script_sha256' if trace.suffix == '.gdb' else 'log_sha256'] = digest(trace)
        changed.add(trace.name)
    replace(path, (json.dumps(physical, indent=2) + '\n').encode())
    return changed | {path.name}


def main():
    root = Path(sys.argv[1]) if len(sys.argv) > 1 else ROOT / 'build/tcp-device'
    output = root / 'damaged'
    output.mkdir(exist_ok=True)
    results, originals = [], {}
    for native in (True, False):
        report = root / ('native-results.json' if native else 'guest-results.json')
        originals[report] = digest(report)
        for row in json.loads(report.read_text()):
            baseline = root / row['directory']
            for path in baseline.iterdir():
                if path.is_file():
                    originals[path] = digest(path)
            observation(baseline, row)
            controls = dict(NATIVE if native else GUEST)
            controls.update({f'packet-data-lane{lane}': 'exact original unpoisoned device-comparison stream bytes'
                             for lane in range(2)})
            for label, reason in controls.items():
                with tempfile.TemporaryDirectory(prefix='axiom64-device-negative-') as temporary:
                    candidate = Path(temporary)
                    # Keep original captures read-only. Native receipt validation
                    # deliberately requires real files rather than symlink aliases.
                    for path in baseline.iterdir():
                        if path.is_file():
                            target = candidate / path.name
                            if path.name.endswith('.clocks.jsonl'):
                                shutil.copyfile(path, target)
                            else:
                                target.symlink_to(path.resolve())
                    candidate_row = deepcopy(row)
                    changed = modify(candidate, candidate_row, label)
                    try:
                        observation(candidate, candidate_row)
                    except ValueError as error:
                        require(reason in str(error), f'{label}: wrong physical rejection: {error}')
                        rejection = str(error)
                    else:
                        raise ValueError(f'{label}: damaged actual device evidence incorrectly accepted')
                    artifact = output / f'{row["directory"]}-{label}.zip'
                    with zipfile.ZipFile(artifact, 'w', zipfile.ZIP_DEFLATED) as archive:
                        archive.writestr('candidate.json', json.dumps(dict(baseline=row['directory'],
                            changed_files=sorted(changed), expected_rejection=reason,
                            auditor_sha256=digest(ROOT / 'scripts/tcp_device/capture.py'),
                            synthetic_negative_copy=True), indent=2) + '\n')
                        for name in sorted(changed):
                            archive.write(candidate / name, name)
                    results.append(dict(profile=row['directory'], control=label, rejection=rejection,
                                        artifact=artifact.name, sha256=digest(artifact)))
    require(all(digest(path) == value for path, value in originals.items()), 'all original device evidence stays unchanged')
    require(len(results) == 6 * (len(NATIVE) + 2) + 16 * (len(GUEST) + 2),
            'all six native and sixteen guest device controls run')
    (output / 'results.json').write_text(json.dumps(dict(passed=True, controls_rejected=len(results), results=results,
                                                       original_inputs_unchanged=True), indent=2) + '\n')
    print(f'TCP_DEVICE_DAMAGE_PASS controls={len(results)} originals_unchanged=1')


if __name__ == '__main__':
    main()
