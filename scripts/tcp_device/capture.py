# SPDX-License-Identifier: GPL-3.0-or-later
"""Independently audit complete TCP device-loss cohorts, packets and owned copies."""
import argparse
from collections import Counter
import hashlib
import itertools
import json
from pathlib import Path
import re
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from fetch import ROOT
from tcp_capture_clock import microseconds
from tcp_device.inputs import SOURCES
from tcp_fault_capture import packets, decode, require, MASK
from tcp_fixture_inputs import audit_image
from tcp_icmp_capture import audit_inputs
from tcp_native_inputs import provider_root


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def expected(lane, direction, offset, size):
    return bytes(((at * 29) ^ (at >> 7) ^ (lane * 53) ^ (direction * 41)) & 255
                 for at in range(offset, offset + size))


def stream(rows, lane, outgoing, size, origin):
    present = bytearray(size)
    for row in rows:
        if row['outgoing'] != outgoing or not row['data']:
            continue
        at = (row['seq'] - origin) & MASK
        require(at + len(row['data']) <= size and row['data'] == expected(lane, int(not outgoing), at, len(row['data'])),
                'exact original unpoisoned device-comparison stream bytes')
        present[at:at + len(row['data'])] = b'\1' * len(row['data'])
    require(all(present), 'every actual device-comparison application byte is captured')


def physical(directory, row, lanes):
    affected = row['affected']
    evidence = json.loads((directory / 'physical-device-observations.json').read_text())
    require(evidence['affected'] == affected and evidence['stage'] == 'complete' and
            evidence['observer_returncode'] == 0 and row['physical_observer_passed'],
            'actual successful owned physical observer exit for this selected adapter')
    removed = [entry for entry in evidence['hardware'] if entry.get('operation') == 'remove']
    require(len(removed) == 1, 'one actual selected PCI removal')
    removed = removed[0]
    before = [0x10411af4 if row['transport'] == 'modern' else 0x10001af4, 0x100e8086]
    after = before.copy()
    after[affected] = 0xffffffff
    require(removed['before'] == before and removed['pending'] == before[affected] and removed['after'] == after,
            'actual PCI I/O confirms selected identity vanished and the other stayed unchanged')
    slots = [device['slot'] for bus in removed['pci'] for device in bus['devices']]
    require(affected + 4 not in slots and 5 - affected in slots,
            'actual QMP enumeration independently confirms selected physical absence')
    commands = evidence['monitor']
    deletions = [entry for entry in commands if entry['command'] == 'device_del']
    require(len(deletions) == 1 and deletions[0]['arguments'] == dict(id=f'nic{affected}') and
            all(entry['command'] in ('qmp_capabilities', 'stop', 'device_del', 'query-pci', 'cont') for entry in commands),
            'exact selected physical deletion uses no guest clock advancement')
    require(any(entry.get('request') == f'outl 0xae08 {1 << (affected + 4):#x}' for entry in evidence['hardware']),
            'actual selected ACPI eject port operation is retained')
    io = [entry for entry in evidence['hardware'] if 'request' in entry]
    require(len(io) == 14 and all(entry['response'].startswith('OK') for entry in io),
            'complete successful original PCI port transactions')
    saved = int(io[0]['response'].split()[1], 0)
    identity = lambda lane: [f'outl 0xcf8 {0x80000000 | ((lane + 4) << 11):#x}', 'inl 0xcfc']
    requests = ['inl 0xcf8', *identity(0), *identity(1), *identity(affected),
                'outl 0xae0c 0', f'outl 0xae08 {1 << (affected + 4):#x}',
                *identity(0), *identity(1), f'outl 0xcf8 {saved:#x}']
    require([entry['request'] for entry in io] == requests and
            [int(io[index]['response'].split()[1], 0) for index in (2, 4, 6, 10, 12)] ==
            [*before, before[affected], *after], 'original port reads independently prove exact PCI identities and removal')
    queries = [entry for entry in commands if entry['command'] == 'query-pci']
    require(len(queries) == 1 and queries[0]['result'] == removed['pci'],
            'original QMP result agrees with the recorded device inventory')
    script, trace = directory / 'device-copy.gdb', directory / 'device-copy.log'
    require(digest(script) == evidence['script_sha256'] and digest(trace) == evidence['log_sha256'],
            'actual original physical observer fingerprints')
    script_text, trace_text = script.read_text(), trace.read_text()
    require('return (int)-11' in script_text and 'return (int)-5' not in script_text,
            'observer holds actual selected output without synthesizing the device error')
    held = re.findall(r'TCP_DEVICE_HELD_FRAME ([0-9a-f]+)', trace_text)
    queued = re.findall(r'TCP_DEVICE_QUEUED_FRAME ([0-9a-f]+)', trace_text)
    require(len(held) == len(queued) == 1 and held == queued,
            'actual pending copy equals the original held wire frame')
    held = decode(bytes.fromhex(held[0]), affected, (49600 + affected,))
    require(held is not None and held['outgoing'] and len(held['data']) == 512 and
            held['seq'] == (lanes[affected]['origin'] + 16) & MASK and
            held['data'] == expected(affected, 0, 16, 512),
            'held copy owns exact abandoned tuple, sequence and bytes')
    require(re.search(rf'TCP_DEVICE_QUEUE_PENDING index={affected+1} owner=0x[1-9a-f][0-9a-f]* transmitted=0 length=566', trace_text)
            and 'TCP_DEVICE_QUEUE_FAILURE error=5 ' in trace_text and
            'TCP_DEVICE_QUEUE_CLEARED owner=0x0 bytes=0x0 length=0 transmitted=0 remaining=0' in trace_text and
            'TCP_DEVICE_HEALTHY_FIN_AFTER_RECLAMATION' in trace_text,
            'actual failure reclaims the owned copy and leaves no queued callback or transmitted accounting')
    markers = ('TCP_DEVICE_QUEUE_PENDING', 'TCP_DEVICE_QUEUE_FAILURE', 'TCP_DEVICE_QUEUE_CLEARED',
               'TCP_DEVICE_HEALTHY_FIN_AFTER_RECLAMATION')
    require([trace_text.index(marker) for marker in markers] == sorted(trace_text.index(marker) for marker in markers),
            'owned queue failure and reclamation precede the surviving FIN')
    events = {entry['stage']: entry for entry in evidence['events']}
    require(events['healthy_complete']['monotonic_ns'] - events['actual_guest_failure']['monotonic_ns'] >= 5000000000,
            'independent host monotonic observations retain the full healthy lifetime')
    return dict(observer_returncode=evidence['observer_returncode'], actual_selected_PCI_removed=True,
                physical_observations_sha256=digest(directory / 'physical-device-observations.json'))


def native_operations(directory, row):
    affected = row['affected']
    interface, healthy = f'eth{affected}', f'eth{1-affected}'
    operations = json.loads((directory / 'actual-device-operations.json').read_text())
    commands = [item for item in operations if 'command' in item]
    require(all(item['returncode'] == 0 for item in commands), 'all actual private native device operations succeed')
    require(len([item for item in commands if item['command'][-5:] == ['ip', 'link', 'delete', 'dev', interface]]) == 1,
            'actual comparison deletes only the selected private native interface')
    queries = [json.loads(item['stdout']) for item in commands if item['command'][-4:] == ['ip', '-j', 'link', 'show']]
    require(len(queries) == 2 and {'eth0', 'eth1'} <= {item['ifname'] for item in queries[0]} and
            interface not in {item['ifname'] for item in queries[1]} and healthy in {item['ifname'] for item in queries[1]},
            'actual original Linux device inventory proves selected absence and other-interface survival')
    queues = [json.loads(item['stdout']) for item in commands
              if item['command'][-7:] == ['tc', '-j', '-s', 'qdisc', 'show', 'dev', interface]]
    require(len(queues) == 1 and any(item.get('kind') == 'netem' and item.get('backlog', 0) >= 512 and
            item.get('qlen', 0) >= 1 for item in queues[0]),
            'actual native queue retains the selected pending output before deletion')
    arm = ['tc', 'qdisc', 'add', 'dev', interface, 'root', 'netem', 'delay', '10000ms']
    require(len([item for item in commands if item['command'][-len(arm):] == arm]) == 1 and len(commands) == 5,
            'only the selected isolated netem queue and original device operations are used')
    expected_commands = [arm, ['tc', '-j', '-s', 'qdisc', 'show', 'dev', interface],
                         ['ip', '-j', 'link', 'show'], ['ip', 'link', 'delete', 'dev', interface],
                         ['ip', '-j', 'link', 'show']]
    require([item['command'][4:] for item in commands] == expected_commands and
            [item['monotonic_ns'] for item in operations] == sorted(item['monotonic_ns'] for item in operations),
            'actual queue confirmation precedes native deletion and socket error observations')
    events = {item['operation']: item for item in operations if 'operation' in item}
    require(events['healthy_complete']['monotonic_ns'] - events['actual_native_error']['monotonic_ns'] >= 5000000000,
            'independent native host observations preserve the full healthy interval')
    require(row['configured_TCP_USER_TIMEOUT_ms'] == 3000 and row['kernel_release'],
            'explicit configured native deadline and actual kernel remain recorded')
    return dict(actual_virtual_netdevice_deleted=True, configured_TCP_USER_TIMEOUT_ms=3000,
                operations_sha256=digest(directory / 'actual-device-operations.json'))


def observation(directory, row):
    affected, native = row['affected'], row['native']
    require(type(affected) is int and affected in (0, 1), 'known selected device identity')
    text = (directory / ('client.log' if native else 'guest.log')).read_text()
    require(row['passed'] and row['returncode'] == (0 if native else 1) and row['error'] is None and
            not any(marker in text for marker in ('TCP_DEVICE_FAIL line=', 'PANIC:', 'FAULT pid=')) and
            text.count(f'TCP_DEVICE_PASS affected={affected} queued=512') == 1,
            'actual original socket client succeeds independently of the coordinator verdict')
    code, cleared = (101, 101) if native else (5, 0)
    syscall = re.search(r'^TCP_DEVICE_SYSCALLS native=(\d) read_bytes=(-?\d+) read_errno=(\d+) so_error=(\d+) '
        r'second_read_bytes=(-?\d+) second_errno=(\d+) send_bytes=(-?\d+) send_errno=(\d+)$', text, re.M)
    require(syscall and list(map(int, syscall.groups())) == [int(native), -1, code, cleared, 0, 0, -1, 32],
            'actual scoped read, SO_ERROR, EOF and EPIPE syscall sequence')
    failed = re.search(rf'^TCP_DEVICE_FAILED lane={affected} revents=(\d+) read_errno={code} send_errno=32 cleared_error={cleared}$', text, re.M)
    healthy = re.search(rf'^TCP_DEVICE_HEALTHY_PASS lane={1-affected} bytes=(\d+) elapsed_ms=(\d+)$', text, re.M)
    require(failed and int(failed[1]) & 8 and healthy and int(healthy[2]) >= 5000 and 112 <= int(healthy[1]) <= 65536,
            'actual error readiness and full healthy lifetime complete')
    if native:
        require('TCP_FAULT_NATIVE_DONE status=0' in text and len(row['capture_statistics']) == 2 and
                len({row[key] for key in ('parent_namespace', 'peer_namespace', 'client_namespace')}) == 3,
                'actual native comparison completes in three distinct namespaces')
    else:
        require(all(marker in text for marker in ('AXIOM64_TESTS_PASS', 'AXIOM64_EXIT status=0',
                f'Firmware: {row["firmware"].upper()}', f'virtio-net: index=1 transport={row["transport"]}',
                'e1000: index=2 model=82540EM')), 'actual device-loss firmware and both NIC drivers')
    healthy_bytes = int(healthy[1])
    frames = json.loads((directory / 'peer-frames.json').read_text())
    require(len(frames) == 2 and [item['lane'] for item in frames] == [0, 1], 'both actual device-loss peer identities')
    lanes = []
    for lane in range(2):
        path = directory / f'lane{lane}.pcap'
        rows = packets(path, lane, (49600 + lane,), statistics=row['capture_statistics'][lane] if native else None)
        require(not any(item['flags'] & 4 for item in rows), 'real device comparison never resets its healthy stream')
        recorded = Counter()
        for frame in frames[lane]['frames']:
            item = decode(bytes.fromhex(frame['frame']), lane, (49600 + lane,))
            if item is not None:
                require(item['outgoing'] == (frame['direction'] == 'receive'), 'actual original peer frame direction')
                recorded[item['frame']] += 1
        require(recorded == Counter(item['frame'] for item in rows), 'actual original capture and peer frame multiset')
        syn = [item for item in rows if item['outgoing'] and item['flags'] & 2]
        synack = [item for item in rows if not item['outgoing'] and item['flags'] & 2]
        require(len(syn) == len(synack) == 1 and synack[0]['ack'] == (syn[0]['seq'] + 1) & MASK,
                'both actual original socket handshakes precede removal')
        origin, reverse = (syn[0]['seq'] + 1) & MASK, (synack[0]['seq'] + 1) & MASK
        stream(rows, lane, True, 16 if lane == affected else healthy_bytes, origin)
        stream(rows, lane, False, 17 if lane == affected else healthy_bytes, reverse)
        if lane == affected:
            require(not any(item['flags'] & 1 for item in rows), 'removed stream cannot emit a later FIN or pending payload')
        else:
            for outgoing, base in [(True, origin), (False, reverse)]:
                fins = [item for item in rows if item['outgoing'] == outgoing and item['flags'] & 1]
                require(fins and all(((item['seq'] + len(item['data']) - base) & MASK) == healthy_bytes for item in fins) and
                        any(item['outgoing'] != outgoing and item['flags'] & 16 and
                            item['ack'] == (base + healthy_bytes + 1) & MASK for item in rows),
                        'both surviving original FINs follow exact data and are acknowledged')
            progress = [item for item in rows if item['outgoing'] and item['data'] and ((item['seq'] - origin) & MASK) >= 48]
            finish = next(item for item in rows if item['outgoing'] and item['flags'] & 1)
            require(progress and microseconds(finish) - microseconds(progress[0]) >= 5000000,
                    'original packet clocks retain the full surviving-stream observation')
        lanes.append(dict(lane=lane, packets=len(rows), sha256=digest(path), origin=origin, reverse=reverse))
    result = native_operations(directory, row) if native else physical(directory, row, lanes)
    result.update(passed=True, affected=affected, healthy_bytes=healthy_bytes, healthy_ms=int(healthy[2]), captures=lanes)
    return result


def runtime(inputs, input_root):
    if inputs['native'] and inputs['linkage'] == 'native':
        require(set(inputs['host_libraries']) == {'libc.so.6', 'ld-linux-x86-64.so.2'} and all(
                'retained' in library and library['retained'] in inputs['products']
                for library in inputs['host_libraries'].values()), 'device native shared libraries are retained products')
    if inputs['linkage'] != 'native':
        require(set(inputs['providers']) == {'build', 'runtime'} and all(
                f'{provider_root(inputs, provider)}/{product}' in inputs['products']
                for provider in ('build', 'runtime') for product in
                ('manifest.json', 'COPYRIGHT', 'sysroot/lib/ld-musl-x86_64.so.1', 'sysroot/usr/lib/libc.a')),
                'device observations retain both complete musl providers')
        for provider, metadata in inputs['providers'].items():
            require(json.loads((input_root / provider_root(inputs, provider) / 'manifest.json').read_text()) == metadata,
                    'actual device musl metadata matches its retained manifest')
    audit_inputs(inputs, input_root)


def check_results(directory, input_root=None):
    input_root = input_root or ROOT
    checked, images = [], {}
    for native in (True, False):
        rows = json.loads((directory / ('native-results.json' if native else 'guest-results.json')).read_text())
        if native:
            expected_profiles = set(itertools.product(('native', 'static', 'dynamic'), (0, 1)))
            actual = [(row['linkage'], row['affected']) for row in rows]
        else:
            expected_profiles = set(itertools.product(('static', 'dynamic'), ('bios', 'uefi'), ('modern', 'legacy'), (0, 1)))
            actual = [(row['linkage'], row['firmware'], row['transport'], row['affected']) for row in rows]
        require(len(actual) == len(expected_profiles) and set(actual) == expected_profiles,
                'complete unique device-loss native and guest cohorts')
        for row in rows:
            name = row['directory']
            require(isinstance(name, str) and name and Path(name).name == name and '/' not in name and '\\' not in name,
                    'bounded actual device observation directory')
            profile = directory / name
            require(row == json.loads((profile / 'producer-result.json').read_text()) and row['native'] == native,
                    'complete actual device observation matches its cohort report')
            inputs = json.loads((profile / 'inputs.json').read_text())
            require(inputs['native'] == native and inputs['linkage'] == row['linkage'] and set(inputs['sources']) == set(SOURCES)
                    and f'build/tcp-device-{row["linkage"]}' in inputs['products'], 'complete actual device client and input contract')
            runtime(inputs, input_root)
            if not native:
                key = (row['linkage'], row['affected'])
                if key not in images:
                    images[key] = audit_image(inputs, input_root, 'tcp-device', f'tcp-device-{row["affected"]}',
                                              (str(row['affected']),))
            command = json.loads((profile / ('client-command.json' if native else 'command.json')).read_text())
            if native:
                require(command[-2:] == ['--native', str(row['affected'])] and
                        Path(command[-3]).name == f'tcp-device-{row["linkage"]}' and
                        len(command) == (4 if row['linkage'] == 'dynamic' else 3) and
                        (row['linkage'] != 'dynamic' or Path(command[0]).name == 'ld-musl-x86_64.so.1'),
                        'actual native device command executes the recorded client and explicit dynamic loader')
            else:
                require(Path(command[command.index('-cdrom') + 1]).name ==
                        f'axiom64-tcp-device-{row["affected"]}-{row["linkage"]}.iso', 'actual guest executes its selected device image')
            result = observation(profile, row)
            result.update(directory=name, linkage=row['linkage'], native=native, inputs_sha256=digest(profile / 'inputs.json'))
            checked.append(result)
    require(len(checked) == 22 and sum(len(row['captures']) for row in checked) == 44 and len(images) == 4,
            'all device-loss observations, original captures and actual images')
    return dict(passed=True, profiles=checked, images=list(images.values()), captures=44,
                native_virtual_netdevice_user_timeout_ms=3000, guest_PCI_default_TCP=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--directory', type=Path, default=ROOT / 'build/tcp-device')
    parser.add_argument('--input-root', type=Path)
    args = parser.parse_args()
    result = check_results(args.directory, args.input_root)
    (args.directory / 'capture-results.json').write_text(json.dumps(result, indent=2) + '\n')
    print('TCP_DEVICE_CAPTURE_PASS native_profiles=6 guest_profiles=16 captures=44 actual_images=4')


if __name__ == '__main__':
    main()
