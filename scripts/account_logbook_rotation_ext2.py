#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Observe actual ext2 rotation writes/flushes, interrupt them, and boot recovery.

Every target comes from an independently inspected baseline device trace.
Filesystem inconsistencies are failed prerequisites; this harness never repairs
an interrupted volume.  Writeback and writethrough are explicit test models.
"""
import argparse
import binascii
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import signal
import socket
import struct
import subprocess
import sys
import tempfile
import time
import traceback

from account_logbook_rotation_block import backend_command, trace_events
from account_logbook_rotation_guest import frames, state, projections
from account_logbook_test import SOURCES
from account_management_ext2 import working_disk
from account_storage_shards import partition_targets
from account_store_guest import fixture
from account_store_test import digest, environment
from console_prompt import KERNEL_RECORD
from ext2_recovery_inspection import deleted_allocation_findings
from ext2_counter_inspection import counter_findings
from ext2_named_retirement_inspection import named_retirement_findings
from build_musl import compiler_args, ensure
from ext2_test import create_volume, debugfs, SEED
from fetch import ROOT
from fixture_archive import archive_fixture
from random_snapshot_test import QMP

CLIENT = 'userspace/tests/security/account-logbook-rotation-ext2.c'
MARKER = b'AXIOM64_ROTATION_BLOCK_ARM_V1'
END_MARKER = b'AXIOM64_ROTATION_BLOCK_END_V1'
PATH = '/rotation/records'
ARCHIVE_FILES = ('journal', 'state', 'wtmp', 'btmp', 'auth.log')
MODES = {'lock': 0o600, 'journal': 0o600, 'state': 0o600,
         'utmp': 0o644, 'wtmp': 0o644, 'btmp': 0o600, 'auth.log': 0o600}
INPUTS = [*SOURCES, CLIENT, 'scripts/account_logbook_rotation_ext2.py',
          'scripts/account_logbook_rotation_block.py', 'scripts/account_logbook_rotation_guest.py',
          'scripts/account_logbook_test.py', 'scripts/account_store_guest.py',
          'scripts/account_store_test.py', 'scripts/build_musl.py', 'scripts/ext2_test.py',
          'scripts/fixture_archive.py', 'scripts/random_snapshot_test.py',
          'scripts/random_administration_test.py', 'scripts/image.py', 'scripts/fetch.py',
          'scripts/ports.py', 'scripts/sources.py', 'sources.lock.json', 'dependencies.json',
          'Makefile', 'userspace/init/main.c', 'userspace/init/console.c',
          'userspace/init/console.h', 'userspace/init/seed_records.h', 'boot/limine.conf']


def save(path, value):
    path.write_text(json.dumps(value, indent=2) + '\n')


def execute(command, log, timeout=90):
    started = time.monotonic_ns()
    with log.open('xb') as output:
        process = subprocess.Popen(command, cwd=ROOT, env=environment(), stdin=subprocess.DEVNULL,
                                   stdout=output, stderr=subprocess.STDOUT)
        timed_out = False
        try:
            process.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            timed_out = True
            process.kill()
            process.wait()
    return dict(command=command, returncode=process.returncode, timed_out=timed_out,
                elapsed_ns=time.monotonic_ns() - started, log_sha256=digest(log))


def start_backend(disk, directory, scratch, offset, *, model='writeback', operation='write',
                  request=0, mode='observe', marker=MARKER, end_marker=END_MARKER):
    socket = scratch / 'nbd.sock'
    trace = directory / 'block.jsonl'
    command = backend_command(disk, socket, trace, control_offset=offset, control_marker=marker,
                              control_end_marker=end_marker,
                              cache_model=model, fault_operation=operation, fault_request=request,
                              fault_mode=mode, gate=scratch / 'release')
    output = (directory / 'backend.log').open('xb')
    process = subprocess.Popen(command, stdout=output, stderr=subprocess.STDOUT)
    deadline = time.monotonic() + 5
    while not socket.exists():
        if process.poll() is not None or time.monotonic() > deadline:
            process.kill() if process.poll() is None else None
            process.wait()
            output.close()
            raise RuntimeError('bounded disposable NBD backend did not start')
        time.sleep(.01)
    return process, output, socket, trace, command


def stop_backend(process, output):
    if process.poll() is None:
        process.terminate()
        try:
            process.wait(timeout=2)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait()
    output.close()


def nbd_controls(path, operation):
    """Exchange bounded real protocol requests and inspect their error replies."""
    def receive(stream, length):
        result = bytearray()
        while len(result) < length:
            data = stream.recv(length - len(result))
            if not data:
                raise RuntimeError('actual NBD control connection ended early')
            result.extend(data)
        return bytes(result)

    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as stream:
        stream.settimeout(5)
        stream.connect(str(path))
        magic, option_magic, flags = struct.unpack('>QQH', receive(stream, 18))
        assert magic == 0x4e42444d41474943 and option_magic == 0x49484156454f5054 and flags & 1
        stream.sendall(struct.pack('>I', 1))
        stream.sendall(struct.pack('>QII', option_magic, 1, 0))
        size, transmission = struct.unpack('>QH', receive(stream, 10))
        assert size == 1024 * 1024 and transmission & 4
        assert receive(stream, 124) == bytes(124)
        replies = []

        def request(kind, offset=0, payload=b''):
            identifier = len(replies) + 1
            stream.sendall(struct.pack('>IHHQQI', 0x25609513, 0, kind, identifier, offset, len(payload)))
            if payload:
                stream.sendall(payload)
            magic, error, returned = struct.unpack('>IIQ', receive(stream, 16))
            assert magic == 0x67446698 and returned == identifier
            replies.append(dict(kind=kind, offset=offset, bytes=len(payload), errno=error))
            return error

        assert request(1, 0, b'A' * 512) == 0 and request(3) == 0
        assert request(1, 1024, b'Z' * 512) == (5 if operation == 'write' else 0)
        assert request(3) == (5 if operation == 'flush' else 0)
        assert request(1, 0, b'E' * 512) == 0 and request(3) == 0
        assert request(1, 2048, b'Q' * 512) == 0 and request(3) == 0
        stream.sendall(struct.pack('>IHHQQI', 0x25609513, 0, 2, len(replies) + 1, 0, 0))
        return replies


def backend_controls(directory):
    rows = []
    for model in ('writeback', 'writethrough'):
        for operation in ('none', 'write', 'flush'):
            case = directory / (model + '-' + operation)
            case.mkdir()
            disk = case / 'disk.raw'
            disk.write_bytes(bytes(1024 * 1024))
            with tempfile.TemporaryDirectory(prefix='axiom64-rotation-nbd-') as temporary:
                backend, output, socket, trace, command = start_backend(
                    disk, case, Path(temporary), 0, model=model,
                    operation='write' if operation == 'none' else operation,
                    request=int(operation != 'none'), mode='observe' if operation == 'none' else 'eio',
                    marker=b'A' * 16, end_marker=b'E' * 16)
                try:
                    replies = nbd_controls(socket, operation)
                    save(case / 'client-replies.json', replies)
                    row = dict(actual_protocol_replies=replies)
                finally:
                    stop_backend(backend, output)
            events = trace_events(trace)
            injected = [event for event in events if event['event'] == 'injected']
            armed = [event for event in events if event['event'] == 'armed']
            assert len(armed) == 1
            disarmed = [event for event in events if event['event'] == 'disarmed']
            assert len(disarmed) == 1 and disarmed[0]['requests']['write'] == 1
            assert not any(event['event'] == 'request' for event in events[events.index(disarmed[0]) + 1:])
            assert len(injected) == int(operation != 'none')
            assert all(event['operation'] == operation and event['index'] == 1 and
                       event['errno'] == 5 for event in injected)
            if operation == 'none':
                assert disk.read_bytes()[1024:1536] == b'Z' * 512
            else:
                assert sum(reply['errno'] == 5 for reply in replies) == 1
                if operation == 'write':
                    assert not any(disk.read_bytes()[1024:1536])
            row.update(case=case.name, cache_model=model, actual_nbd=True, backend_command=command,
                       actual_eio=len(injected), trace_sha256=digest(trace), passed=True)
            rows.append(row)
            save(directory / 'results.json', rows)
    return rows


def build(provider, linkage, directory):
    program = directory / 'observer'
    command = [*compiler_args(provider), '-std=c11', '-O2', '-g', '-Wall', '-Wextra', '-Werror',
               '-DACCOUNT_LOGIN_JOURNAL_LIMIT=3712', '-DACCOUNT_LOGIN_LIVE_LIMIT=4',
               *(str(ROOT / name) for name in SOURCES if name.endswith('.c')),
               str(ROOT / CLIENT), '-o', str(program), *(['-static'] if linkage == 'static' else [])]
    row = execute(command, directory / 'build.log')
    if row['returncode'] or row['timed_out']:
        raise RuntimeError('unwrapped ext2 observer failed to compile')
    headers = subprocess.check_output(['readelf', '-W', '-l', str(program)], text=True)
    dynamic = subprocess.check_output(['readelf', '-W', '-d', str(program)], text=True)
    assert ('INTERP' not in headers) == (linkage == 'static')
    assert 'RPATH' not in dynamic and 'RUNPATH' not in dynamic
    assert not any('--wrap' in argument for argument in command)
    return program, dict(command=command, binary_sha256=digest(program), headers=headers,
                         dynamic=dynamic, wrapped=False, journal_limit=3712, live_limit=4,
                         libc_manifest_sha256=digest(ensure(provider) / 'manifest.json'))


def native_observer(directory):
    program = directory / 'observer-native'
    command = ['gcc', '-std=c11', '-O2', '-g', '-Wall', '-Wextra', '-Werror',
               '-DACCOUNT_LOGIN_JOURNAL_LIMIT=3712', '-DACCOUNT_LOGIN_LIVE_LIMIT=4',
               *(str(ROOT / name) for name in SOURCES if name.endswith('.c')),
               str(ROOT / CLIENT), '-o', str(program)]
    row = execute(command, directory / 'build.log')
    assert not row['returncode'] and not row['timed_out']
    fixtures = Path('/tmp') / ('axiom64-rotation-ext2-observer-' + str(os.getpid()))
    fixtures.mkdir(mode=0o755)
    fixtures.chmod(0o755)
    save(directory / 'native-inputs.json', dict(command=command, binary_sha256=digest(program),
                                              retained_fixtures=str(fixtures)))
    rows = []
    for scenario in ('basic', 'expiry'):
        case = directory / scenario
        case.mkdir()
        root = fixtures / scenario
        root.mkdir(mode=0o755)
        control = root / 'control'
        control.write_bytes(bytes(512))
        records = root / 'records'
        run_log = case / 'run.log'
        run = execute([str(program), 'run', str(records), str(control), scenario], run_log)
        assert run['returncode'] == 0 and not run['timed_out']
        before = serial_files(run_log, 'before')
        recovery_log = case / 'recovery.log'
        recovered = execute([str(program), 'recover', str(records)], recovery_log)
        assert recovered['returncode'] == 0 and not recovered['timed_out']
        files = {path.relative_to(records).as_posix(): path.read_bytes()
                 for path in records.rglob('*') if path.is_file()}
        metadata = {}
        for path in [records, *records.rglob('*')]:
            value = path.stat()
            name = path.relative_to(records).as_posix() if path != records else '.'
            metadata[name] = dict(kind='directory' if path.is_dir() else 'regular',
                                  mode=value.st_mode & 0o7777, uid=value.st_uid, gid=value.st_gid,
                                  links=value.st_nlink, bytes=value.st_size)
        assert files == serial_files(recovery_log, 'recover') == serial_files(recovery_log, 'idempotent')
        proof = verify(files, metadata, before, recovered=True, trigger_expected=1)
        exports = case / 'exports'
        for name, data in files.items():
            path = exports / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(data)
        rows.append(dict(case=scenario, run=run, recovery=recovered, proof=proof,
                         retained_linux_fixtures=str(root), passed=True, power_loss=False))
        save(directory / 'results.json', rows)
    return rows


def images(provider, linkage, directory, *, journal=False):
    program, inputs = build(provider, linkage, directory)
    result = {}
    for phase in ('basic', 'expiry', 'recover'):
        case = directory / ('image-' + phase)
        case.mkdir()
        filename = 'account-rotation-ext2-' + phase
        invocation = ('/bin/' + filename + ' recover /mnt' + PATH if phase == 'recover' else
                      '/bin/' + filename + ' run /mnt' + PATH + ' /mnt/rotation/control ' + phase)
        policy = ' -o recovery=check' if phase == 'recover' and not journal else ''
        command = '/bin/busybox mkdir -p /mnt\n/bin/busybox mount -t ext2' + policy + ' /dev/vda /mnt\n' + invocation + \
                  '\n/bin/busybox umount /mnt'
        result[phase] = fixture(case, provider, linkage,
                               program_builder=lambda *unused: (program, inputs),
                               filename=filename, command=command)
        # Each profile image owns its filename; do not write a captured product.
    return result, inputs


def seed(directory, *, journal=False):
    disk = directory / 'seed.raw'
    create_volume(disk)
    if journal:
        result = subprocess.run(['tune2fs', '-j', str(disk)], capture_output=True, text=True)
        (directory / 'journal-created.log').write_text(result.stdout + result.stderr)
        assert result.returncode == 0
        raw = disk.read_bytes()
        assert struct.unpack_from('<I', raw, 1116)[0] & 4
        assert struct.unpack_from('<I', raw, 1248)[0] == 8
    control = directory / 'control.bin'
    # debugfs preserves all-zero source ranges as holes.  The sentinel needs a
    # real preallocated physical block whose offset is independently observed.
    control.write_bytes(b'AXIOM64_ROTATION_NOT_ARMED' + bytes(512 - 26))
    for command in ('mkdir /rotation', 'sif /rotation mode 040755',
                    'write ' + str(control) + ' /rotation/control',
                    'sif /rotation/control mode 0100600'):
        debugfs(disk, command, write=True)
    block = int(debugfs(disk, 'bmap /rotation/control 0').strip())
    assert block > 0
    fsck(disk, directory, 'seed')
    return disk, block * 1024


def fsck(disk, directory, label, *, pending_recovery=False):
    log = directory / (label + '-fsck.log')
    row = execute(['e2fsck', '-f', '-n', str(disk)], log)
    text = log.read_text()
    diagnostics = re.findall(r'^.*(?:\bwrong\b|Fix\?|\bIGNORED\b|UNEXPECTED INCONSISTENCY|'
                             r'still has errors|\bcorrupt\b|multiply.claimed|unattached inode).*$'
                             , text, re.MULTILINE | re.IGNORECASE)
    row['rejected_diagnostics'] = diagnostics
    row['passed'] = not row['returncode'] and not row['timed_out'] and not diagnostics
    if pending_recovery and not row['passed'] and row['returncode'] in (0, 4) and not row['timed_out']:
        data = disk.read_bytes()
        for classifier in (deleted_allocation_findings, counter_findings, named_retirement_findings):
            try:
                finding = classifier(data, text)
            except (ValueError, struct.error, IndexError):
                continue
            row['expected_checked_recovery'] = finding
            # This records a failed pre-recovery checker, not a passing volume.
            # Only actual guest recovery and the later strict checker can pass.
            save(directory / (label + '-fsck.json'), row)
            return row
    save(directory / (label + '-fsck.json'), row)
    # e2fsck can return0 while refusing incorrect superblock summary counts.
    # The dirty-volume kernel check rejects them, so those diagnostics are red.
    if row['returncode'] or row['timed_out'] or diagnostics:
        raise RuntimeError('unrepaired actual ext2 volume failed e2fsck: ' + str(log))
    return row


def disk_files(disk, *, metadata=False):
    with tempfile.TemporaryDirectory(prefix='axiom64-rotation-export-') as temporary:
        destination = Path(temporary)
        debugfs(disk, 'rdump ' + PATH + ' ' + str(destination))
        exported = destination / 'records'
        if not exported.exists():
            return {}, {}, []
        files = {path.relative_to(exported).as_posix(): path.read_bytes()
                 for path in exported.rglob('*') if path.is_file()}
        directories = ['.', *(path.relative_to(exported).as_posix()
                               for path in exported.rglob('*') if path.is_dir())]
        records = {}
        if metadata:
            for name in [*directories, *files]:
                text = debugfs(disk, 'stat ' + PATH + ('/' + name if name != '.' else ''))
                kind = re.search(r'Type:\s+(\S+)\s+Mode:\s+([0-7]+)', text)
                owners = re.search(r'User:\s+(\d+)\s+Group:\s+(\d+).*?Size:\s+(\d+)', text)
                links = re.search(r'Links:\s+(\d+)', text)
                assert kind and owners and links
                records[name] = dict(kind=kind[1], mode=int(kind[2], 8), uid=int(owners[1]),
                                     gid=int(owners[2]), bytes=int(owners[3]), links=int(links[1]))
        return files, records, directories


def serial_files(log, phase):
    # A complete kernel diagnostic can split separate userspace hex writes.
    # Preserve the capture; recognize exports in a view omitting only the
    # same known complete records used by the ordinary console reader.
    text = KERNEL_RECORD.sub(b'', log.read_bytes()).decode().replace('\r\n', '\n')
    result = {}
    for name, payload in re.findall(r'^ACCOUNT_ROTATION_EXT2_DATA phase=' + phase +
                                   r' name=(\S+) hex=([0-9a-f]*)$', text, re.MULTILINE):
        assert name not in result
        result[name] = bytes.fromhex(payload)
    assert result
    return result


def reseal(records):
    result = []
    for sequence, frame in enumerate(records, 1):
        raw = bytearray(frame['raw'])
        struct.pack_into('<Q', raw, 16, sequence)
        raw[12:16] = bytes(4)
        struct.pack_into('<I', raw, 12, binascii.crc32(raw))
        result.append(bytes(raw))
    return b''.join(result)


def summary(files):
    current = state(files['state']) if 'state' in files else dict(generation=1, carried=0, previous_events=0)
    return dict(state=current, sha256={name: hashlib.sha256(data).hexdigest()
                                      for name, data in sorted(files.items())})


def phase_labels(files, directories, before, scenario):
    old = state(before['state']) if 'state' in before else dict(generation=1, carried=0, previous_events=0)
    generation = old['generation']
    archive = f'archive-{generation:016x}'
    labels = []
    if archive in directories:
        labels.append('archive-created')
    if files.get(archive + '/journal') == before['journal']:
        labels.append('archive-journal')
        try:
            saved = state(files[archive + '/state'])
            records = frames(files[archive + '/journal'])
            if saved == old and all(files.get(archive + '/' + name) == value
                                    for name, value in projections(saved, records).items()):
                labels.append('archive-complete')
        except (KeyError, AssertionError, ValueError):
            pass
    if 'rotation' in files:
        marker = files['rotation']
        if len(marker) == 112 and struct.unpack_from('<III', marker) == (0x52423641, 1, 112):
            copy = bytearray(marker)
            crc, = struct.unpack_from('<I', copy, 12)
            copy[12:16] = bytes(4)
            if crc == binascii.crc32(copy):
                labels.append('marker')
    starts = [frame for frame in frames(before['journal']) if frame['kind'] == 1]
    if files.get('journal') == reseal(starts):
        labels.append('carried-current')
    try:
        saved = state(files['state'])
        records = frames(files['journal'])
        if saved['generation'] == generation + 1:
            labels.append('state-committed')
            if 'rotation' not in files:
                labels.append('marker-removed')
            triggers = sum(frame['kind'] == 5 and frame['status'] == 900
                           for frame in records[saved['carried']:])
            if triggers == 1:
                labels.append('trigger')
                if all(files.get(name) == value for name, value in projections(saved, records).items()):
                    labels.append('projections')
            if scenario == 'expiry':
                expired = 'archive-0000000000000001'
                if expired in directories and expired + '/journal' not in files:
                    labels.append('expiry-partial')
                if expired not in directories:
                    labels.append('expiry-complete')
    except (KeyError, AssertionError, ValueError):
        pass
    return labels


def targets(directory, trace, before, scenario):
    events = trace_events(trace)
    armed = [event for event in events if event['event'] == 'armed']
    assert len(armed) == 1 and digest(directory / 'armed.raw') == armed[0]['disk_sha256']
    observed = {}
    with tempfile.TemporaryDirectory(prefix='axiom64-rotation-replay-') as temporary:
        replay = Path(temporary) / 'replay.raw'
        shutil.copyfile(directory / 'armed.raw', replay)
        writes = []
        with replay.open('r+b', buffering=0) as output:
            for event in events:
                if event['event'] == 'write_complete':
                    data = bytes.fromhex(event['payload_hex'])
                    assert len(data) == event['bytes'] and hashlib.sha256(data).hexdigest() == event['payload_sha256']
                    output.seek(event['offset'])
                    output.write(data)
                    writes.append(event)
                elif event['event'] == 'flush_complete':
                    os.fsync(output.fileno())
                    assert digest(replay) == event['disk_sha256'], 'independent block replay differs'
                    files, _metadata, directories = disk_files(replay)
                    for label in phase_labels(files, directories, before, scenario):
                        if label not in observed and writes:
                            observed[label] = dict(flush=event['index'], first_write=writes[0]['index'],
                                                   last_write=writes[-1]['index'], proof=summary(files))
                    writes = []
    required = {'archive-created', 'archive-journal', 'archive-complete', 'marker',
                'carried-current', 'state-committed', 'marker-removed', 'trigger', 'projections'}
    if scenario == 'expiry':
        required |= {'expiry-partial', 'expiry-complete'}
    assert required <= set(observed), 'unobserved required rotation storage phases: ' + repr(required - set(observed))
    save(directory / 'observed-phases.json', observed)
    return observed


def verify(files, metadata, before, *, recovered, trigger_expected=None):
    current = state(files['state']) if 'state' in files else dict(generation=1, carried=0, previous_events=0)
    generation = current['generation']
    first = max(1, generation - 4)
    archives = [f'archive-{value:016x}' for value in range(first, generation)]
    leases = [name for name in files if re.fullmatch(r'l-[0-9a-f]{32}', name)]
    expected = set(MODES) | {archive + '/' + name for archive in archives for name in ARCHIVE_FILES} | set(leases)
    if 'state' not in files:
        assert generation == 1
        expected.remove('state')
    provisional_name = f'archive-{generation:016x}'
    directories = {name for name, record in metadata.items() if record['kind'] == 'directory'}
    provisional = provisional_name in directories
    assert directories == {'.', *archives, *([provisional_name] if provisional else [])}
    if provisional:
        # A failed copy can leave the selected generation's provisional archive.
        # Every published member must exactly reproduce that selected source;
        # unknown files and directories remain invalid.
        selected = frames(files['journal'])
        state_bytes = files.get('state')
        if state_bytes is None:
            raw = bytearray(struct.pack('<IIIIQQQ', 0x53423641, 1, 40, 0, 1, 0, 0))
            struct.pack_into('<I', raw, 12, binascii.crc32(raw))
            state_bytes = bytes(raw)
        selected_files = dict(journal=files['journal'], state=state_bytes,
                              **{name: data for name, data in projections(current, selected).items()
                                 if name in ARCHIVE_FILES})
        prefix = provisional_name + '/'
        for name, data in files.items():
            if name.startswith(prefix):
                member = name[len(prefix):]
                assert member in ARCHIVE_FILES and data == selected_files[member], \
                    'provisional archive differs from the complete selected source'
                expected.add(name)
    assert set(files) == expected
    assert set(metadata) == set(files) | directories
    assert len(leases) == (0 if recovered else 2) and files['lock'] == b''
    for name, record in metadata.items():
        assert record['uid'] == record['gid'] == 0
        if record['kind'] == 'directory':
            assert record['mode'] == 0o755
        else:
            mode = MODES.get(name, 0o644 if name.endswith('/wtmp') else 0o600)
            assert record['mode'] == mode and record['links'] == 1 and record['bytes'] == len(files[name])
    history, prior, prior_frames = [], None, None
    for archive in [*archives, '']:
        prefix = archive + '/' if archive else ''
        saved = state(files[prefix + 'state']) if prefix + 'state' in files else current
        records = frames(files[prefix + 'journal'])
        assert saved['generation'] == (int(archive[8:], 16) if archive else generation)
        assert saved['carried'] == (0 if saved['generation'] == 1 else 2)
        if prior:
            ended = {frame['token'] for frame in prior_frames if frame['kind'] in (2, 9)}
            carried = [frame for frame in prior_frames if frame['kind'] == 1 and frame['token'] not in ended]
            assert b''.join(frame['raw'] for frame in records[:saved['carried']]) == reseal(carried)
            assert saved['previous_events'] == prior['previous_events'] + len(prior_frames) - prior['carried']
        for name, data in projections(saved, records).items():
            assert files[prefix + name] == data
        history.extend(records[saved['carried']:])
        prior, prior_frames = saved, records
    expected_statuses = {frame['status'] for name, payload in before.items()
                         if name.endswith('journal')
                         for frame in frames(payload)
                         if frame['kind'] in (3, 5) and frame['status'] != 900}
    if generation == 6:
        expected_statuses -= set(range(100, 106))
    actual = [frame['status'] for frame in history if frame['kind'] in (3, 5) and frame['status'] != 900]
    assert set(actual) == expected_statuses and len(actual) == len(expected_statuses)
    trigger_count = sum(frame['kind'] == 5 and frame['status'] == 900 for frame in history)
    assert trigger_count in (0, 1) and (trigger_expected is None or trigger_count == trigger_expected)
    recovery = [frame for frame in history if frame['kind'] == 9]
    assert len(recovery) == (2 if recovered else 0)
    assert {frame['uid'] for frame in recovery} == ({70000, 70001} if recovered else set())
    expected_events = (32 if len(expected_statuses) > 6 else 8) + trigger_count + (2 if recovered else 0)
    assert current['previous_events'] + len(prior_frames) - current['carried'] == expected_events
    entries = files['utmp']
    assert len(entries) % 384 == 0
    assert sum(struct.unpack_from('<h', entries, offset)[0] == 7
               for offset in range(0, len(entries), 384)) == (0 if recovered else 2)
    for name, data in before.items():
        if name.startswith('archive-') and name in files:
            assert files[name] == data, 'retained closed archive changed'
    return dict(generation=generation, retained_archives=len(archives),
                provisional_archive=provisional, trigger=trigger_count,
                recovered=len(recovery), global_events=expected_events, exact_history=True)


def qemu(image, directory, firmware, transport, *, disk=None, socket=None, qmp=None):
    command = ['qemu-system-x86_64', '-machine', 'pc', '-cpu', 'max', '-m', '256M', '-nic', 'none',
               '-cdrom', str(image), '-display', 'none', '-serial', 'stdio', '-monitor', 'none',
               '-no-reboot', '-device', 'isa-debug-exit,iobase=0xf4,iosize=0x04',
               '-trace', 'enable=virtio_blk_req_complete,file=' + str(directory / 'virtio.trace')]
    if socket:
        command += ['-blockdev', 'driver=nbd,node-name=records,server.type=unix,server.path=' + str(socket)]
    else:
        command += ['-drive', 'if=none,id=records,format=raw,cache=writeback,file=' + str(disk)]
    command += ['-device', 'virtio-blk-pci,drive=records,rerror=report,werror=report,' +
                ('disable-legacy=on' if transport == 'modern' else 'disable-modern=on')]
    if qmp:
        command += ['-qmp', 'unix:' + str(qmp) + ',server=on,wait=off']
    if firmware == 'uefi':
        variables = directory / 'VARS.fd'
        shutil.copyfile('/usr/share/OVMF/OVMF_VARS_4M.fd', variables)
        command += ['-drive', 'if=pflash,format=raw,readonly=on,file=/usr/share/OVMF/OVMF_CODE_4M.fd',
                    '-drive', 'if=pflash,format=raw,file=' + str(variables)]
    return command


def accepted(row, log, phase, firmware, transport):
    text = log.read_text().replace('\r\n', '\n')
    assert not row['timed_out'] and row['returncode'] == 1
    assert text.count('ACCOUNT_ROTATION_EXT2_PASS phase=' + phase + ' ') == 1
    assert text.splitlines().count('AXIOM64_TESTS_PASS') == 1 and 'AXIOM64_EXIT status=0' in text
    assert 'Firmware: ' + firmware.upper() in text
    assert 'virtio-blk: disk=0 transport=' + transport + ' sectors=32768 readonly=0 flush=1' in text
    assert not any(marker in text for marker in ('ACCOUNT_ROTATION_EXT2_FAIL', 'PANIC:', 'FAULT pid='))


def cell(directory, iso, recovery_iso, base, offset, firmware, transport, scenario, *,
         model='writeback', operation='write', request=0, mode='observe', label=None, target_shape=None):
    directory.mkdir()
    disk = directory / 'disk.raw'
    shutil.copyfile(base, disk)
    row = dict(case=label or directory.name, firmware=firmware, transport=transport, scenario=scenario,
               cache_model=model, operation=operation, request=request, fault_mode=mode,
               wrapped=False, power_loss=mode.startswith('pause-'), passed=False)
    try:
        with tempfile.TemporaryDirectory(prefix='axiom64-rotation-vm-') as temporary, working_disk(disk) as device_disk:
            scratch = Path(temporary)
            backend, output, socket, trace, backend_args = start_backend(
                device_disk, directory, scratch, offset, model=model, operation=operation, request=request, mode=mode)
            monitor = None
            log = directory / 'guest.log'
            started = time.monotonic_ns()
            with log.open('xb') as serial:
                command = qemu(iso, directory, firmware, transport, socket=socket, qmp=scratch / 'qmp.sock')
                process = subprocess.Popen(command, cwd=ROOT, env=environment(), stdin=subprocess.DEVNULL,
                                           stdout=serial, stderr=subprocess.STDOUT)
                timed_out = False
                try:
                    monitor = QMP(scratch / 'qmp.sock', process, directory / 'qmp.jsonl', 5)
                    deadline = time.monotonic() + 90
                    if mode.startswith('pause-'):
                        while True:
                            paused = [event for event in trace_events(trace, complete=False)
                                      if event['event'] == 'paused']
                            if paused:
                                assert len(paused) == 1 and paused[0]['operation'] == operation and paused[0]['index'] == request
                                # QMP stop drains I/O and cannot acknowledge while
                                # this actual NBD callback remains blocked.  Log
                                # the real request, then freeze the whole host
                                # process without releasing its device action.
                                monitor.sequence += 1
                                stop = dict(execute='stop', id=monitor.sequence)
                                monitor.record('send', stop)
                                monitor.socket.sendall(json.dumps(stop).encode() + b'\n')
                                os.kill(process.pid, signal.SIGSTOP)
                                freeze_deadline = time.monotonic() + 1
                                while True:
                                    status = Path('/proc') / str(process.pid) / 'status'
                                    stopped = re.search(r'^State:\s+(\S+)', status.read_text(), re.MULTILINE)[1]
                                    if stopped in ('T', 't'):
                                        break
                                    if time.monotonic() > freeze_deadline:
                                        raise RuntimeError('QEMU did not enter an actual host stopped state')
                                    time.sleep(.001)
                                row['actual_pause'] = paused[0]
                                row['qmp_stop_requested'] = True
                                row['qmp_stop_acknowledged'] = False
                                row['host_stopped_state'] = stopped
                                row['discarded_volatile_bytes'] = paused[0]['pending_bytes']
                                process.kill()
                                break
                            if process.poll() is not None or time.monotonic() > deadline:
                                raise RuntimeError('VM never reached its observed actual block boundary')
                            time.sleep(.01)
                    try:
                        process.wait(timeout=max(.1, deadline - time.monotonic()))
                    except subprocess.TimeoutExpired:
                        timed_out = True
                        process.kill()
                        process.wait()
                finally:
                    if process.poll() is None:
                        process.kill()
                        process.wait()
                    if monitor:
                        monitor.close()
                    stop_backend(backend, output)
            run = dict(command=command, returncode=process.returncode, timed_out=timed_out,
                       elapsed_ns=time.monotonic_ns() - started, backend_command=backend_args,
                       log_sha256=digest(log), trace_sha256=digest(trace))
            row['run'] = run
        row['actual_device_disk_sha256'] = digest(disk)
        row['temporary_linux_device_disk'] = True
        before = serial_files(log, 'before')
        events = trace_events(trace)
        injected = [event for event in events if event['event'] == 'injected']
        if target_shape is not None:
            observed_shape = []
            for event in events:
                if event['event'] != 'request':
                    continue
                observed_shape.append([event['operation'], event.get('offset'), event.get('bytes')])
                if event['operation'] == operation and event['index'] == request:
                    break
            assert observed_shape == target_shape, 'fault case physical request prefix differs from observed baseline'
            row['baseline_request_prefix_verified'] = True
        if mode == 'eio':
            assert len(injected) == 1 and injected[0]['operation'] == operation and injected[0]['index'] == request
            accepted(run, log, 'run', firmware, transport)
            text = log.read_text()
            assert 'ACCOUNT_ROTATION_EXT2_ATTEMPT result=-1 errno=5' in text
            completion = (directory / 'virtio.trace').read_text()
            assert len(re.findall(r'virtio_blk_req_complete .*?status 1\b', completion)) == 1, \
                'device did not complete exactly one actual failed virtio request'
            row['failed_virtio_completions'] = 1
            row['virtio_trace_sha256'] = digest(directory / 'virtio.trace')
        elif mode == 'observe':
            accepted(run, log, 'run', firmware, transport)
            assert not injected and 'ACCOUNT_ROTATION_EXT2_ATTEMPT result=0 errno=0' in log.read_text()
            assert not re.search(r'virtio_blk_req_complete .*?status 1\b',
                                 (directory / 'virtio.trace').read_text())
        else:
            assert not run['timed_out'] and run['returncode'] == -signal.SIGKILL and not injected
            assert row['actual_pause']['disk_sha256'] == digest(disk), 'backend cleanup changed the paused durable bytes'
            row['paused_durable_bytes_unchanged_by_host_cleanup'] = True
        row['pre_recovery_fsck'] = fsck(disk, directory, 'interrupted',
                                      pending_recovery=mode.startswith('pause-'))
        row['interrupted_disk_sha256'] = digest(disk)
        interrupted = directory / 'interrupted.raw'
        shutil.copyfile(disk, interrupted)
        row['retained_interrupted'] = archive_fixture(interrupted, remove=True)
        if mode == 'observe':
            row['observed_phases'] = targets(directory, trace, before, scenario)
        if not mode.startswith('pause-'):
            files, metadata, _directories = disk_files(disk, metadata=True)
            assert files == serial_files(log, 'retry')
            row['live_proof'] = verify(files, metadata, before, recovered=False,
                                       trigger_expected=1 if mode == 'observe' else None)
        recovery = directory / 'recovery'
        recovery.mkdir()
        recovery_log = recovery / 'guest.log'
        with working_disk(disk) as device_disk:
            recovered = execute(qemu(recovery_iso, recovery, firmware, transport, disk=device_disk), recovery_log)
        recovered['actual_device_disk_sha256'] = digest(disk)
        recovered['temporary_linux_device_disk'] = True
        accepted(recovered, recovery_log, 'recover', firmware, transport)
        files, metadata, _directories = disk_files(disk, metadata=True)
        assert files == serial_files(recovery_log, 'recover') == serial_files(recovery_log, 'idempotent')
        row['recovery'] = recovered
        row['recovered_proof'] = verify(files, metadata, before, recovered=True,
                                      trigger_expected=1 if mode == 'observe' else None)
        row['post_recovery_fsck'] = fsck(disk, directory, 'recovered')
        row['retained_final'] = archive_fixture(disk, remove=True)
        row['retained_armed'] = archive_fixture(directory / 'armed.raw', remove=True)
        exports = directory / 'exports'
        for name, data in files.items():
            path = exports / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(data)
        save(directory / 'metadata.json', metadata)
        row['passed'] = True
    except BaseException as error:
        row['error'] = repr(error)
        (directory / 'error.txt').write_text(traceback.format_exc())
        for name in ('disk.raw', 'armed.raw'):
            if (directory / name).exists() and not (directory / (name + '.gz')).exists():
                row['retained_failed_' + name] = archive_fixture(directory / name, remove=True)
        raise
    finally:
        save(directory / 'result.json', row)
    print('ACCOUNT_ROTATION_EXT2_CELL_PASS ' + row['case'], flush=True)
    return row


def guest(args, rows):
    # Kernel/init/busybox products are frozen existing inputs.  Do not build them.
    products = [ROOT / 'build/axiom64.elf', ROOT / 'build/init']
    assert all(path.is_file() for path in products)
    product_hashes = {str(path): digest(path) for path in products}
    save(args.directory / 'frozen-products.json', product_hashes)
    base, offset = seed(args.directory, journal=args.journal)
    seed_hash = digest(base)
    for provider in ('build', 'runtime') if args.provider == 'both' else (args.provider,):
        for linkage in ('static', 'dynamic') if args.linkage == 'both' else (args.linkage,):
            profile = args.directory / (provider + '-' + linkage)
            profile.mkdir()
            image, inputs = images(provider, linkage, profile, journal=args.journal)
            save(profile / 'observer-inputs.json', inputs)
            for firmware in ('bios', 'uefi') if args.firmware == 'both' else (args.firmware,):
                for transport in ('modern', 'legacy') if args.transport == 'both' else (args.transport,):
                    for scenario in args.scenario:
                        prefix = profile / (firmware + '-' + transport + '-' + scenario)
                        prefix.mkdir()
                        baseline = cell(prefix / 'baseline', image[scenario], image['recover'],
                                        base, offset, firmware, transport, scenario)
                        rows.append(baseline)
                        save(args.directory / 'results.json', rows)
                        targets_by_phase = baseline['observed_phases']
                        targets = [dict(phase=phase, operation=operation, request=request)
                                   for phase, target in targets_by_phase.items()
                                   for operation, request in (('write', target['last_write']),
                                                              ('flush', target['flush']))]
                        selection = partition_targets(targets, args.shard_index, args.shard_count)
                        baseline['target_selection'] = selection
                        save(prefix / 'target-selection.json', selection)
                        save(prefix / 'baseline' / 'result.json', baseline)
                        save(args.directory / 'results.json', rows)
                        baseline_trace = trace_events(prefix / 'baseline' / 'block.jsonl')
                        for selected in selection['selected_targets']:
                            phase, operation, request = (selected[name] for name in
                                                         ('phase', 'operation', 'request'))
                            shape = []
                            for event in baseline_trace:
                                if event['event'] == 'request':
                                    shape.append([event['operation'], event.get('offset'), event.get('bytes')])
                                    if event['operation'] == operation and event['index'] == request:
                                        break
                            for model in args.cache_model:
                                for mode in args.fault_mode:
                                    label = '-'.join((phase, operation, str(request), model, mode))
                                    row = cell(prefix / label, image[scenario], image['recover'], base,
                                               offset, firmware, transport, scenario, model=model,
                                               operation=operation, request=request, mode=mode, label=label,
                                               target_shape=shape)
                                    rows.append(row)
                                    save(args.directory / 'results.json', rows)
    assert digest(base) == seed_hash
    assert all(digest(Path(name)) == value for name, value in product_hashes.items())
    save(args.directory / 'seed-retention.json', archive_fixture(base, remove=True))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--directory', type=Path, required=True)
    parser.add_argument('--backend-only', action='store_true')
    parser.add_argument('--native-observer', action='store_true')
    parser.add_argument('--journal', action='store_true',
                        help='use internal journals and ordinary automatic recovery on owned guest fixtures')
    parser.add_argument('--provider', choices=('build', 'runtime', 'both'), default='both')
    parser.add_argument('--linkage', choices=('static', 'dynamic', 'both'), default='both')
    parser.add_argument('--firmware', choices=('bios', 'uefi', 'both'), default='both')
    parser.add_argument('--transport', choices=('modern', 'legacy', 'both'), default='both')
    parser.add_argument('--scenario', choices=('basic', 'expiry'), nargs='+', default=['basic', 'expiry'])
    parser.add_argument('--cache-model', choices=('writeback', 'writethrough'), nargs='+', default=['writeback', 'writethrough'])
    parser.add_argument('--fault-mode', choices=('eio', 'pause-before', 'pause-after'), nargs='+', default=['eio', 'pause-before', 'pause-after'])
    parser.add_argument('--shard-index', type=int, default=0)
    parser.add_argument('--shard-count', type=int, default=1,
                        help='partition observed phase/write/flush targets; all shards are required')
    args = parser.parse_args()
    if args.shard_count < 1 or not 0 <= args.shard_index < args.shard_count:
        parser.error('use a positive shard count and an index within that count')
    if (args.backend_only or args.native_observer) and (args.shard_index or args.shard_count != 1):
        parser.error('storage shards select actual guest targets, not preliminary controls')
    if args.journal and (args.backend_only or args.native_observer):
        parser.error('--journal selects owned guest fixtures, not native/backend controls')
    if args.backend_only and args.native_observer:
        parser.error('choose one isolated preliminary control')
    if os.geteuid() or os.getegid():
        raise RuntimeError('disposable ext2 acceptance requires an explicit root build environment')
    args.directory = args.directory.resolve()
    if not args.directory.is_relative_to((ROOT / 'build').resolve()):
        raise RuntimeError('all disposable fixtures must stay in the owned build directory')
    args.directory.mkdir(parents=True, exist_ok=False)
    loaded_helpers = [Path(module.__file__).resolve().relative_to(ROOT).as_posix()
                      for module in list(sys.modules.values()) if getattr(module, '__file__', None)
                      and Path(module.__file__).resolve().is_relative_to(ROOT / 'scripts')]
    names = list(dict.fromkeys([*INPUTS, *loaded_helpers, *(path.relative_to(ROOT).as_posix() for path in (ROOT / 'kernel').rglob('*')
                       if path.is_file() and path.suffix in ('.cpp', '.hpp', '.asm'))]))
    source = {name: digest(ROOT / name) for name in names}
    save(args.directory / 'source-inputs.json', source)
    for name in source:
        path = args.directory / 'source' / name
        path.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(ROOT / name, path)
    tools = {}
    for name in ('qemu-system-x86_64', 'qemu-io', 'nbdkit', 'e2fsck', 'debugfs', 'mke2fs', 'gcc', 'readelf'):
        binary = Path(shutil.which(name))
        tools[name] = dict(path=str(binary), sha256=digest(binary))
    save(args.directory / 'tools.json', tools)
    rows, error = [], None
    try:
        if args.backend_only:
            rows = backend_controls(args.directory)
        elif args.native_observer:
            rows = native_observer(args.directory)
        else:
            guest(args, rows)
    except BaseException as problem:
        error = repr(problem)
        (args.directory / 'error.txt').write_text(traceback.format_exc())
    # Failed attempts remain part of the receipt's actual crash/error count.
    if not args.backend_only and not args.native_observer:
        attempts = [json.loads(path.read_text()) for path in args.directory.rglob('result.json')
                    if 'source' not in path.relative_to(args.directory).parts]
        if attempts:
            rows = attempts
            save(args.directory / 'results.json', rows)
    unchanged = source == {name: digest(ROOT / name) for name in source}
    frozen_products = args.directory / 'frozen-products.json'
    products_unchanged = (not frozen_products.exists() or
                          all(digest(Path(name)) == value for name, value in
                              json.loads(frozen_products.read_text()).items()))
    complete = (not args.backend_only and not args.native_observer and all(getattr(args, name) == 'both' for name in
                                             ('provider', 'linkage', 'firmware', 'transport')) and
                set(args.scenario) == {'basic', 'expiry'} and
                set(args.cache_model) == {'writeback', 'writethrough'} and
                set(args.fault_mode) == {'eio', 'pause-before', 'pause-after'} and
                args.shard_count == 1)
    passed = error is None and unchanged and products_unchanged and bool(rows) and all(row['passed'] for row in rows)
    receipt = dict(passed=passed,
                   terminal=True,
                   selection=dict(directory=str(args.directory), provider=args.provider, linkage=args.linkage,
                                  firmware=args.firmware, transport=args.transport, scenario=args.scenario,
                                  cache_model=args.cache_model, fault_mode=args.fault_mode,
                                  shard_index=args.shard_index, shard_count=args.shard_count),
                   journaled=args.journal,
                   matrix_complete=complete and passed, cells=len(rows), source_stable=unchanged,
                   wrapped=False, actual_nbd=not args.native_observer, repaired_filesystems=False,
                   actual_vm_crashes=sum(row.get('power_loss', False) for row in rows), error=error,
                   host_filesystem_repair=False,
                   frozen_products_unchanged=products_unchanged,
                   wsl_distribution=os.environ.get('WSL_DISTRO_NAME'),
                   recovery_mount_policy=('automatic journal recovery; strict kernel validation, no host repair' if args.journal else
                                          'recovery=check; strict kernel validation, no host repair'))
    save(args.directory / 'acceptance.json', receipt)
    if not receipt['passed']:
        raise RuntimeError(error or 'actual storage campaign source changed')
    print('ACCOUNT_ROTATION_EXT2_MATRIX_PASS cells=' + str(len(rows)) +
          ' complete=' + str(int(receipt['matrix_complete'])), flush=True)


if __name__ == '__main__':
    main()
