#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Verify real account commands, concurrency and failures on persistent ext2."""
import argparse
import binascii
from contextlib import contextmanager
import errno
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import signal
import stat
import struct
import subprocess
import sys
import tarfile
import tempfile
import time

from account_management_test import SOURCES, build as build_accountctl, crypt
from account_store_guest import fixture
from account_store_test import STORE_MODULES, digest, environment
from build_musl import compiler_args
from ext2_test import create_volume, debugfs
from fetch import ROOT
from fixture_archive import archive_fixture
from account_logbook_rotation_block import backend_command, trace_events
from account_journal_oracle import journal_observation
from ext2_counter_inspection import counter_findings
from ext2_named_retirement_inspection import directory_retirement_findings, named_retirement_findings
from ext2_recovery_inspection import deleted_allocation_findings
from random_snapshot_test import QMP
from nbd_startup import launch_backend

CLIENT = 'userspace/tests/security/account-management-ext2.c'
INPUTS = [*SOURCES, CLIENT, 'scripts/account_management_ext2.py',
          'scripts/account_store_guest.py', 'scripts/account_store_ext2.py',
          'scripts/ext2_test.py', 'scripts/fixture_archive.py', 'scripts/image.py',
          'Makefile', 'userspace/init/main.c', 'userspace/init/console.c',
          'userspace/init/console.h', 'userspace/init/seed_records.h', 'boot/limine.conf']
INPUTS += ['scripts/account_logbook_rotation_block.py', 'scripts/nbd_startup.py']
INPUTS += ['scripts/account_journal_oracle.py']
INPUTS += ['scripts/random_snapshot_test.py', 'scripts/account_store_test.py', 'scripts/build_musl.py',
           'scripts/fetch.py', 'scripts/ports.py', 'scripts/sources.py', 'sources.lock.json',
           'dependencies.json', 'ports.lock.json']
INPUTS += ['scripts/ext2_counter_inspection.py', 'scripts/ext2_recovery_inspection.py',
           'scripts/ext2_named_retirement_inspection.py']
PHASES = ('prepare', 'exercise', 'concurrent', 'verify')
ARM = b'AXIOM64_MANAGEMENT_ARM_v1'
END = b'AXIOM64_MANAGEMENT_END_v1'


def save(path, value):
    path.write_text(json.dumps(value, indent=2) + '\n')


def management_volume(disk, journal):
    create_volume(disk, capacity=32 * 1024 * 1024)
    if not journal:
        return
    command = ['tune2fs', '-j', str(disk)]
    result = subprocess.run(command, capture_output=True, text=True)
    disk.with_suffix('.journal.log').write_text(result.stdout + result.stderr)
    assert result.returncode == 0
    raw = disk.read_bytes()
    assert struct.unpack_from('<I', raw, 1116)[0] & 4
    assert struct.unpack_from('<I', raw, 1248)[0] == 8
    check_fs(disk, disk.parent, 'journal-created')


def copy_device_bytes(source, destination, expected):
    with source.open('rb') as incoming, destination.open('xb') as output:
        shutil.copyfileobj(incoming, output)
        output.flush()
        os.fsync(output.fileno())
    assert digest(destination) == expected


@contextmanager
def working_disk(retained, *, prefer_memory=False):
    # Keep per-request device I/O on the Linux filesystem. The complete actual
    # guest disk is copied back, including after timeout or rejection.
    original = retained.lstat()
    identity = lambda value: (value.st_dev, value.st_ino, value.st_size, value.st_mtime_ns)
    if not stat.S_ISREG(original.st_mode) or original.st_nlink != 1:
        raise ValueError('the retained fixture must be a single-link regular file')
    parent = Path('/tmp')
    # The NBD backend owns its separate volatile cache and flush model. A small
    # host-memory device file avoids unrelated physical-host sync latency while
    # retaining the same actual guest writes across emulator/backend termination.
    if prefer_memory and original.st_size <= 32 * 1024 * 1024:
        memory = Path('/dev/shm')
        try:
            if (memory.is_dir() and not memory.is_symlink() and
                    shutil.disk_usage(memory).free >= original.st_size + 16 * 1024 * 1024):
                parent = memory
        except OSError:
            pass
    temporary = Path(tempfile.mkdtemp(prefix='axiom64-management-disk-', dir=parent))
    disk = temporary / 'disk.raw'
    try:
        shutil.copyfile(retained, disk)
        assert digest(disk) == digest(retained)
        if identity(retained.lstat()) != identity(original):
            raise OSError(errno.ESTALE, 'the fixture source changed during staging')
    except BaseException:
        disk.unlink(missing_ok=True)
        temporary.rmdir()
        raise
    try:
        yield disk
    finally:
        try:
            expected = digest(disk)
            if temporary.parent == Path('/dev/shm'):
                checkpoint = Path(tempfile.mkdtemp(prefix='axiom64-management-disk-', dir='/tmp'))
                copy_device_bytes(disk, checkpoint / 'disk.raw', expected)
                disk.unlink()
                temporary.rmdir()
                disk, temporary = checkpoint / 'disk.raw', checkpoint
            pending = retained.with_name(retained.name + '.pending-copy')
            if identity(retained.lstat()) != identity(original):
                raise OSError(errno.ESTALE, 'the fixture destination changed')
            copy_device_bytes(disk, pending, expected)
            if identity(retained.lstat()) != identity(original):
                raise OSError(errno.ESTALE, 'the fixture destination changed')
            os.replace(pending, retained)
            assert digest(retained) == expected
        except BaseException:
            print('ACCOUNT_MANAGEMENT_DEVICE_DISK_RETAINED path=' + str(disk), file=sys.stderr, flush=True)
            raise
        disk.unlink()
        temporary.rmdir()


def archive_native(directory, destination):
    records = {}
    for path in [directory, *sorted(directory.rglob('*'))]:
        value = path.lstat()
        name = 'fixtures' + ('/' + path.relative_to(directory).as_posix() if path != directory else '')
        record = dict(mode=stat.S_IMODE(value.st_mode), uid=value.st_uid, gid=value.st_gid,
                      kind='symlink' if path.is_symlink() else 'directory' if path.is_dir() else 'file')
        if path.is_symlink():
            record['target'] = os.readlink(path)
        elif path.is_file():
            record.update(bytes=value.st_size, sha256=digest(path))
        records[name] = record
    with tarfile.open(destination, 'w:gz') as archive:
        archive.add(directory, arcname='fixtures')
    with tarfile.open(destination, 'r:gz') as archive:
        members = archive.getmembers()
        assert len(members) == len(records) and set(member.name for member in members) == set(records)
        for member in members:
            expected = records[member.name]
            assert (member.mode, member.uid, member.gid) == (expected['mode'], expected['uid'], expected['gid'])
            if expected['kind'] == 'directory':
                assert member.isdir()
            elif expected['kind'] == 'symlink':
                assert member.issym() and member.linkname == expected['target']
            else:
                assert member.isfile() and member.size == expected['bytes']
                with archive.extractfile(member) as stream:
                    assert hashlib.file_digest(stream, 'sha256').hexdigest() == expected['sha256']
    return dict(path=str(destination), sha256=digest(destination), verified_members=len(records),
                metadata_and_payloads_exact=True)


def serial_state(text, phase):
    records = {}
    for name, payload in re.findall(r'^ACCOUNT_MANAGEMENT_EXT2_DATA phase=' + phase +
                                   r' name=(passwd|group|shadow) hex=([0-9a-f]*)$', text, re.M):
        assert name not in records
        records[name] = bytes.fromhex(payload)
    assert set(records) == {'passwd', 'group', 'shadow'}
    revisions = re.findall(r'^ACCOUNT_MANAGEMENT_EXT2_REVISION phase=' + phase +
                           r' value=(g-[0-9a-f]{32})$', text, re.M)
    assert len(revisions) == 1
    return revisions[0], records


def fsck_observation(disk, directory, label):
    row, text = execute(['e2fsck', '-f', '-n', str(disk)], directory / (label + '-fsck.log'))
    diagnostics = re.findall(r'^.*(?:count wrong|bitmap differences|UNEXPECTED INCONSISTENCY|'
                             r'Filesystem still has errors|Fix\?|Clear\?|Salvage\?).*$', text,
                             re.MULTILINE | re.IGNORECASE)
    row['inconsistency_diagnostics'] = diagnostics
    row['passed'] = row['passed'] and not diagnostics
    return row, text


def check_fs(disk, directory, label, *, pending_recovery=False):
    row, text = fsck_observation(disk, directory, label)
    if pending_recovery and not row['passed'] and row['returncode'] in (0, 4) and not row['timed_out']:
        data = disk.read_bytes()
        for classifier in (deleted_allocation_findings, counter_findings, named_retirement_findings,
                           directory_retirement_findings):
            try:
                finding = classifier(data, text)
            except (ValueError, struct.error, IndexError):
                continue
            row['expected_checked_recovery'] = finding
            # A failed checker remains failed. Guest repair and strict post-checks
            # must establish a valid selected account generation on the actual disk.
            save(directory / (label + '-fsck.json'), row)
            return row
    if not row['passed']:
        save(directory / (label + '-fsck.json'), row)
        raise RuntimeError('unrepaired ext2 failed independent check: ' + str(directory))
    return row


def validate_records(records, phase):
    """Parse exported files independently of the production account reader."""
    parsed = {}
    for name, fields in (('passwd', 7), ('group', 4), ('shadow', 9)):
        text = records[name].decode('ascii')
        assert text.endswith('\n') and '\0' not in text
        entries = [line.split(':') for line in text.splitlines()]
        assert all(len(entry) == fields for entry in entries)
        assert len({entry[0] for entry in entries}) == len(entries)
        parsed[name] = {entry[0]: entry for entry in entries}
    users, groups, shadows = (parsed[name] for name in ('passwd', 'group', 'shadow'))
    assert set(users) == set(shadows)
    assert len({int(row[2]) for row in users.values()}) == len(users)
    assert len({int(row[2]) for row in groups.values()}) == len(groups)
    for user in users.values():
        assert user[1] == 'x' and 0 <= int(user[2]) < 0xffffffff
        assert int(user[3]) in {int(group[2]) for group in groups.values()}
    for group in groups.values():
        members = group[3].split(',') if group[3] else []
        assert len(members) == len(set(members)) and set(members) <= set(users)
    assert users['root'][2:4] == ['0', '0'] and shadows['root'][1] == '!'
    assert users['admin'][2:4] == ['1000', '1000']
    assert users['alice'][2:4] == ['70000', '80000'] and groups['staff'][2] == '80000'
    assert shadows['admin'][1].startswith('$y$') and shadows['alice'][1].startswith('$y$')
    if phase == 'prepare':
        assert set(users) == {'root', 'admin', 'alice', 'bob', 'locked'}
        assert users['bob'][2:4] == ['70001', '80000'] and shadows['locked'][1].startswith('!$y$')
    elif phase in ('exercise', 'concurrent', 'verify'):
        assert not {'bob', 'renamed-user'} & set(users)
        assert not {'spare', 'renamed-group'} & set(groups)
        assert users['charlie'][2:4] == ['70002', '80000']
        assert not shadows['locked'][1].startswith('!')
    if phase in ('concurrent', 'verify'):
        assert all(groups['batch' + str(index)][2] == str(82000 + index) for index in range(12))
        assert len({'winner-a', 'winner-b'} & set(groups)) == 1
        assert len({'racer-a', 'racer-b'} & set(users)) == 1
        assert len([user for user in users.values() if user[2] == '71000']) == 1
        assert groups['same-name'][2] in ('83001', '83002')
        assert users['charlie'][6] == '/bin/busybox' and users['charlie'][5].endswith('/charlie-updated')
        assert {'alice', 'charlie', 'locked'} <= set(groups['sudo'][3].split(','))
        assert 'killed-pending' not in groups and groups['retry-after-kill'][2] == '84001'
    return parsed


def inspect_disk(disk, directory, root, text, phase):
    exports = directory / 'exports'
    exports.mkdir()
    metadata = {}

    def stat(name, mode, kind, uid=0, gid=0):
        data = debugfs(disk, 'stat ' + name)
        record = re.search(r'Inode:\s+(\d+)\s+Type:\s+(\S+)\s+Mode:\s+([0-7]+)', data)
        owner = re.search(r'User:\s+(\d+)\s+Group:\s+(\d+).*?Size:\s+(\d+)', data)
        links = re.search(r'Links:\s+(\d+)', data)
        assert record and owner and links, 'missing host inode: ' + name
        value = dict(inode=int(record[1]), kind=record[2], mode=int(record[3], 8),
                     uid=int(owner[1]), gid=int(owner[2]), bytes=int(owner[3]), links=int(links[1]))
        assert (value['mode'], value['kind'], value['uid'], value['gid']) == (mode, kind, uid, gid), name
        assert kind == 'directory' or value['links'] == 1
        metadata[name] = value
        (exports / (str(len(metadata)) + '-stat.log')).write_text(data)
        return data

    stat(root, 0o755, 'directory')
    stat(root + '/db', 0o755, 'directory')
    stat(root + '/db/lock', 0o600, 'regular')
    current = stat(root + '/db/current', 0o777, 'symlink')
    target = re.search(r'Fast link dest:\s+"(g-[0-9a-f]{32})"', current)[1]
    stat(root + '/db/' + target, 0o755, 'directory')
    expected_target, expected = serial_state(text, phase)
    assert target == expected_target
    records = {}
    for name in ('passwd', 'group', 'shadow'):
        path = root + '/db/' + target + '/' + name
        stat(path, 0o600 if name == 'shadow' else 0o644, 'regular')
        output = exports / (name + '.bin')
        debugfs(disk, 'dump ' + path + ' ' + str(output))
        records[name] = output.read_bytes()
        assert records[name] == expected[name], 'serial/disk selected-generation mismatch: ' + name
    parsed = validate_records(records, phase)
    for name, uid, gid in (('admin', 1000, 1000), ('alice', 70000, 80000), ('bob', 70001, 80000),
                           ('bob-new', 70001, 80000), ('locked', 70003, 80000)):
        home = root + '/homes/' + name
        stat(home, 0o700, 'directory', uid, gid)
        stat(home + '/retained.txt', 0o600, 'regular', uid, gid)
        output = exports / ('home-' + name + '.bin')
        debugfs(disk, 'dump ' + home + '/retained.txt ' + str(output))
        assert output.read_bytes() == b'persistent private home data\n'
    if phase in ('exercise', 'concurrent', 'verify'):
        stat(root + '/homes/charlie', 0o700, 'directory', 70002, 80000)
    if phase in ('concurrent', 'verify'):
        stat(root + '/homes/charlie-updated', 0o700, 'directory', 70002, 80000)
        winner = next(name for name in ('racer-a', 'racer-b') if name in parsed['passwd'])
        loser = next(name for name in ('racer-a', 'racer-b') if name != winner)
        stat(root + '/homes/' + winner, 0o700, 'directory', 71000, 80000)
        assert 'Inode:' not in debugfs(disk, 'stat ' + root + '/homes/' + loser)
    if 'fault-user' in parsed['passwd']:
        assert parsed['passwd']['fault-user'][2:4] == ['72000', '80000']
        assert parsed['shadow']['fault-user'][1] == '!'
        stat(root + '/homes/fault-user', 0o700, 'directory', 72000, 80000)
    save(directory / 'metadata.json', metadata)
    return dict(current=target, files={name: hashlib.sha256(data).hexdigest() for name, data in records.items()},
                metadata=metadata, disk_sha256=digest(disk), serial_exact=True)


def probe(provider, linkage, directory, native_runtime=None):
    library = crypt(provider)
    stage = library / linkage / 'stage'
    compiler = ['gcc'] if provider == 'native' else compiler_args(provider)
    program = directory / 'management-ext2-driver'
    command = [*compiler, '-std=c11', '-O2', '-g', '-Wall', '-Wextra', '-Werror',
               '-I' + str(stage / 'usr/include'),
               *(str(ROOT / name) for name in STORE_MODULES),
               *(str(ROOT / 'userspace/accounts' / name) for name in
                 ('database.c', 'record.c', 'password.c')),
               str(ROOT / CLIENT), '-o', str(program)]
    if linkage == 'static':
        command += ['-static', str(stage / 'usr/lib/libcrypt.a')]
    else:
        command += ['-L' + str(stage / 'usr/lib'), '-lcrypt']
        if native_runtime:
            command += ['-Wl,-rpath=' + str(native_runtime)]
            if provider != 'native':
                command += ['-Wl,--dynamic-linker=' + str(native_runtime / 'libc.so')]
    with (directory / 'driver-build.log').open('xb') as log:
        subprocess.run(command, cwd=ROOT, env=environment(), stdout=log,
                       stderr=subprocess.STDOUT, check=True)
    headers = subprocess.check_output(['readelf', '-W', '-l', str(program)], text=True)
    dynamic = subprocess.check_output(['readelf', '-W', '-d', str(program)], text=True)
    assert ('INTERP' not in headers) == (linkage == 'static')
    if not native_runtime:
        assert 'RPATH' not in dynamic and 'RUNPATH' not in dynamic
    return program, dict(command=command, binary_sha256=digest(program), headers=headers,
                         dynamic=dynamic, password_manifest_sha256=digest(library / 'manifest.json'))


def execute(command, log, *, expected=0):
    started = time.monotonic_ns()
    timeout = False
    with log.open('xb') as output:
        process = subprocess.Popen(command, cwd=ROOT, env=environment(), stdin=subprocess.DEVNULL,
                                   stdout=output, stderr=subprocess.STDOUT, start_new_session=True)
        try:
            process.wait(timeout=120)
        except subprocess.TimeoutExpired:
            timeout = True
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            process.wait()
        except BaseException:
            if process.poll() is None:
                try:
                    os.killpg(process.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
            process.wait()
            raise
    text = log.read_text().replace('\r\n', '\n')
    row = dict(command=command, returncode=process.returncode, timed_out=timeout,
               elapsed_ns=time.monotonic_ns() - started, log=log.name, log_sha256=digest(log),
               passed=not timeout and process.returncode == expected and
               'ACCOUNT_MANAGEMENT_EXT2_FAIL' not in text and 'PANIC:' not in text)
    return row, text


def native_inside(args):
    # Only the namespace's /etc is replaced. The source/build tree and host
    # account database are never used as administration fixtures.
    subprocess.run(['mount', '--make-rprivate', '/'], check=True)
    subprocess.run(['mount', '-t', 'tmpfs', '-o', 'mode=0755', 'tmpfs', '/etc'], check=True)
    command = [str(args.driver), args.phase, str(args.fixture), str(args.accountctl)]
    raise SystemExit(subprocess.run(command, env=environment(), timeout=120).returncode)


def native(args, rows):
    if not args.fixtures or args.fixtures.exists() or not args.fixtures.is_absolute():
        raise RuntimeError('native controls require a fresh absolute Linux fixture directory')
    args.fixtures.mkdir(mode=0o755)
    try:
        for provider in ('build', 'runtime', 'native') if args.provider == 'both' else (args.provider,):
            for linkage in ('static', 'dynamic') if args.linkage == 'both' else (args.linkage,):
                name = provider + '-' + linkage
                case = args.directory / name
                case.mkdir()
                linux = args.fixtures / name
                linux.mkdir(mode=0o755)
                runtime = linux / 'runtime' if linkage == 'dynamic' else None
                ctl, library, ctl_inputs = build_accountctl(provider, linkage, case, runtime)
                driver, driver_inputs = probe(provider, linkage, case, runtime)
                for source, filename in ((ctl, 'accountctl'), (driver, 'driver')):
                    shutil.copyfile(source, linux / filename)
                    (linux / filename).chmod(0o755)
                for phase in (*PHASES, 'attempt', 'recover'):
                    command = ['unshare', '--mount', '--pid', '--fork', '--mount-proc',
                               sys.executable, str(Path(__file__).resolve()), '--native-inside',
                               '--phase', phase, '--fixture', str(linux / 'data'),
                               '--driver', str(linux / 'driver'), '--accountctl', str(linux / 'accountctl')]
                    row, text = execute(command, case / (phase + '.log'))
                    marker = 'ACCOUNT_MANAGEMENT_EXT2_PASS phase=' + phase + ' '
                    row.update(provider=provider, linkage=linkage, phase=phase,
                               accountctl_inputs=ctl_inputs, driver_inputs=driver_inputs,
                               command_observations=len(re.findall(r'^ACCOUNT_MANAGEMENT_EXT2_COMMAND ', text, re.M)))
                    row['passed'] = row['passed'] and len([line for line in text.splitlines() if line.startswith(marker)]) == 1
                    revision, records = serial_state(text, phase)
                    assert records == {name: (linux / 'data/db' / revision / name).read_bytes()
                                       for name in records}
                    validate_records(records, phase)
                    row.update(selected_revision=revision, independent_payload_checks=True)
                    rows.append(row)
                    (args.directory / 'results.json').write_text(json.dumps(rows, indent=2) + '\n')
                    if not row['passed']:
                        raise RuntimeError('native command phase failed: ' + name + '/' + phase)
                print('ACCOUNT_MANAGEMENT_EXT2_NATIVE_PASS ' + name, flush=True)
    finally:
        save(args.directory / 'native-fixtures.json',
             archive_native(args.fixtures, args.directory / 'native-fixtures.tar.gz'))


def guest(args, rows):
    # Root coordinates this initial shared build with other VM runners.
    subprocess.run(['make', '-s', '-j2', 'build/axiom64.elf', 'build/init', 'busybox'], cwd=ROOT, check=True)
    for provider in ('build', 'runtime') if args.provider == 'both' else (args.provider,):
        for linkage in ('static', 'dynamic') if args.linkage == 'both' else (args.linkage,):
            case = args.directory / (provider + '-' + linkage)
            case.mkdir()
            ctl, library, ctl_inputs = build_accountctl(provider, linkage, case)
            driver, driver_inputs = probe(provider, linkage, case)
            products = {'bin/accountctl': ctl}
            if linkage == 'dynamic':
                products['usr/lib/libcrypt.so.2'] = library / 'dynamic/stage/usr/lib/libcrypt.so.2.0.0'
            profile = case.name
            command = ('/bin/busybox mkdir -p /mnt/management\n'
                       '/bin/busybox mount -t ext2 /dev/vda /mnt/management\n'
                       f'root=/mnt/management/{profile}\n'
                       'if [ ! -d "$root/db" ]; then phase=prepare; '
                       'elif [ ! -f "$root/exercised" ]; then phase=exercise; '
                       'elif [ ! -f "$root/concurrent" ]; then phase=concurrent; else phase=verify; fi\n'
                       '/bin/management-ext2 "$phase" "$root" /bin/accountctl\n'
                       'if [ "$phase" = exercise ]; then /bin/busybox touch "$root/exercised"; fi\n'
                       'if [ "$phase" = concurrent ]; then /bin/busybox touch "$root/concurrent"; fi\n'
                       '/bin/busybox umount /mnt/management')
            image = fixture(case, provider, linkage, program_builder=lambda *unused: (driver, driver_inputs),
                            filename='management-ext2', command=command, extra_products=products)
            (case / 'accountctl-inputs.json').write_text(json.dumps(ctl_inputs, indent=2) + '\n')
            for firmware in ('bios', 'uefi') if args.firmware == 'both' else (args.firmware,):
                for transport in ('modern', 'legacy') if args.transport == 'both' else (args.transport,):
                    cell = case / (firmware + '-' + transport)
                    cell.mkdir()
                    disk = cell / 'disk.raw'
                    management_volume(disk, args.journal)
                    previous = None
                    for phase in PHASES:
                        directory = cell / phase
                        directory.mkdir()
                        log = directory / 'guest.log'
                        qemu = ['qemu-system-x86_64', '-machine', 'pc', '-cpu', 'max', '-m', '256M',
                                '-nic', 'none', '-cdrom', str(image), '-display', 'none', '-serial', 'stdio',
                                '-monitor', 'none', '-no-reboot', '-device', 'isa-debug-exit,iobase=0xf4,iosize=0x04',
                                '-drive', 'if=none,id=management,format=raw,file=' + str(disk),
                                '-device', 'virtio-blk-pci,drive=management,' +
                                ('disable-legacy=on' if transport == 'modern' else 'disable-modern=on')]
                        if firmware == 'uefi':
                            variables = directory / 'VARS.fd'
                            shutil.copyfile('/usr/share/OVMF/OVMF_VARS_4M.fd', variables)
                            qemu += ['-drive', 'if=pflash,format=raw,readonly=on,file=/usr/share/OVMF/OVMF_CODE_4M.fd',
                                     '-drive', 'if=pflash,format=raw,file=' + str(variables)]
                        with working_disk(disk) as device_disk:
                            actual_qemu = [argument.replace('file=' + str(disk), 'file=' + str(device_disk))
                                           for argument in qemu]
                            assert sum(a != b for a, b in zip(qemu, actual_qemu)) == 1
                            row, text = execute(actual_qemu, log, expected=1)
                        row['actual_device_disk_sha256'] = digest(disk)
                        row['temporary_linux_device_disk'] = True
                        row.update(provider=provider, linkage=linkage, firmware=firmware, transport=transport, phase=phase)
                        row['passed'] = row['passed'] and 'Firmware: ' + firmware.upper() in text and \
                            text.splitlines().count('AXIOM64_TESTS_PASS') == 1 and \
                            text.splitlines().count('AXIOM64_EXIT status=0') == 1 and \
                            sum(line.startswith('ACCOUNT_MANAGEMENT_EXT2_PASS phase=' + phase + ' ') for line in text.splitlines()) == 1
                        row['fsck'] = check_fs(disk, directory, 'clean')
                        rows.append(row)
                        (args.directory / 'results.json').write_text(json.dumps(rows, indent=2) + '\n')
                        if not row['passed']:
                            row['retained_failed_disk'] = archive_fixture(disk)
                            save(args.directory / 'results.json', rows)
                            raise RuntimeError('persistent management phase failed: ' + row['phase'])
                        row['host_state'] = inspect_disk(disk, directory, '/' + profile, text, phase)
                        if phase == 'verify':
                            assert previous['current'] == row['host_state']['current']
                            assert previous['files'] == row['host_state']['files']
                            assert previous['metadata'] == row['host_state']['metadata']
                            row['fresh_kernel_identical_generation_and_home_metadata'] = True
                        previous = row['host_state']
                        checkpoint = directory / 'disk.raw'
                        shutil.copyfile(disk, checkpoint)
                        row['retained_phase_disk'] = archive_fixture(checkpoint, remove=True)
                        save(args.directory / 'results.json', rows)
                    final = archive_fixture(disk, remove=True)
                    rows[-1]['retained_final_disk'] = final
                    save(args.directory / 'results.json', rows)
                    print('ACCOUNT_MANAGEMENT_EXT2_GUEST_PASS ' + profile + '/' + firmware + '/' + transport, flush=True)


def campaign_images(case, provider, linkage, *, journal=False):
    ctl, library, ctl_inputs = build_accountctl(provider, linkage, case)
    driver, driver_inputs = probe(provider, linkage, case)
    products = {'bin/accountctl': ctl}
    if linkage == 'dynamic':
        products['usr/lib/libcrypt.so.2'] = library / 'dynamic/stage/usr/lib/libcrypt.so.2.0.0'
    images = {}
    for phase in ('prepare', 'attempt', 'recover', 'crash-recover', 'full', 'readonly'):
        directory = case / ('image-' + phase)
        directory.mkdir()
        option = ' -o recovery=check' if phase == 'crash-recover' and not journal else ' -o ro' if phase == 'readonly' else ''
        action = 'recover' if phase == 'crash-recover' else phase
        command = ('/bin/busybox mkdir -p /mnt/management\n'
                   '/bin/busybox mount -t ext2' + option + ' /dev/vda /mnt/management\n'
                   f'/bin/management-ext2-{phase} {action} /mnt/management/{case.name} /bin/accountctl\n'
                   '/bin/busybox umount /mnt/management')
        images[phase] = fixture(directory, provider, linkage,
                               program_builder=lambda *unused: (driver, driver_inputs),
                               filename='management-ext2-' + phase, command=command, extra_products=products)
    save(case / 'accountctl-inputs.json', ctl_inputs)
    save(case / 'driver-inputs.json', driver_inputs)
    return images


def qemu_command(image, directory, firmware, transport, *, disk=None, socket=None, readonly=False, qmp=None):
    command = ['qemu-system-x86_64', '-machine', 'pc', '-cpu', 'max', '-m', '256M', '-nic', 'none',
               '-cdrom', str(image), '-display', 'none', '-serial', 'stdio', '-monitor', 'none',
               '-no-reboot', '-device', 'isa-debug-exit,iobase=0xf4,iosize=0x04',
               '-trace', 'enable=virtio_blk_req_complete,file=' + str(directory / 'virtio.trace')]
    if socket:
        command += ['-blockdev', 'driver=nbd,node-name=management,server.type=unix,server.path=' + str(socket)]
    else:
        command += ['-drive', 'if=none,id=management,format=raw,cache=writeback,file=' + str(disk) +
                    ',readonly=' + ('on' if readonly else 'off')]
    command += ['-device', 'virtio-blk-pci,drive=management,rerror=report,werror=report,' +
                ('disable-legacy=on' if transport == 'modern' else 'disable-modern=on')]
    if qmp:
        command += ['-qmp', 'unix:' + str(qmp) + ',server=on,wait=off']
    if firmware == 'uefi':
        variables = directory / 'VARS.fd'
        shutil.copyfile('/usr/share/OVMF/OVMF_VARS_4M.fd', variables)
        command += ['-drive', 'if=pflash,format=raw,readonly=on,file=/usr/share/OVMF/OVMF_CODE_4M.fd',
                    '-drive', 'if=pflash,format=raw,file=' + str(variables)]
    return command


def accepted(row, text, phase, firmware, transport, readonly=False):
    assert row['passed'] and text.splitlines().count('AXIOM64_TESTS_PASS') == 1
    assert text.splitlines().count('AXIOM64_EXIT status=0') == 1 and 'Firmware: ' + firmware.upper() in text
    assert sum(line.startswith('ACCOUNT_MANAGEMENT_EXT2_PASS phase=' + phase + ' ') for line in text.splitlines()) == 1
    assert 'virtio-blk: disk=0 transport=' + transport + ' sectors=65536 readonly=' + str(int(readonly)) + ' flush=1' in text
    assert not any(marker in text for marker in ('PANIC:', 'FAULT pid=', 'ACCOUNT_MANAGEMENT_EXT2_FAIL'))


def selected_files(disk, root):
    """Read an offline selection, including incomplete intermediate states."""
    current = debugfs(disk, 'stat ' + root + '/db/current')
    target = re.search(r'Fast link dest:\s+"(g-[0-9a-f]{32})"', current)
    if not target:
        return None, {}
    records = {}
    with tempfile.TemporaryDirectory(prefix='axiom64-management-export-') as temporary:
        for name in ('passwd', 'group', 'shadow'):
            destination = Path(temporary) / name
            debugfs(disk, 'dump ' + root + '/db/' + target[1] + '/' + name + ' ' + str(destination))
            if destination.exists():
                records[name] = destination.read_bytes()
    return target[1], records


def added_user_files(before, profile):
    result = dict(before)
    result['passwd'] += ('fault-user:x:72000:80000::/mnt/management/' + profile +
                         '/homes/fault-user:/bin/sh\n').encode()
    result['shadow'] += b'fault-user:!::0:::::\n'
    return result


def recovery_selection(disk, root, directory):
    _check, selected, proof = recovery_input(disk, root, directory, pending_recovery=True)
    return selected, proof


def recovery_input(disk, root, directory, *, pending_recovery):
    with disk.open('rb') as stream:
        stream.seek(1116)
        journaled = struct.unpack('<I', stream.read(4))[0] & 4
    if not journaled:
        check = check_fs(disk, directory, 'interrupted', pending_recovery=pending_recovery)
        return check, selected_files(disk, root), None
    if pending_recovery:
        raw_check, _text = fsck_observation(disk, directory, 'interrupted')
        if raw_check['timed_out'] or raw_check['returncode'] not in (0, 4):
            raise RuntimeError('native observation of the actual interrupted input failed')
        # Preserve a failed raw check as failed. Committed journal replay and
        # the existing bounded validator determine recovery eligibility below.
        save(directory / 'interrupted-fsck.json', raw_check)
    else:
        raw_check = check_fs(disk, directory, 'interrupted')
    with journal_observation(disk, directory) as (observation, proof):
        check = check_fs(observation, directory, 'journal-replayed', pending_recovery=pending_recovery)
        selected = selected_files(observation, root)
        proof['raw_filesystem_check'] = raw_check
        proof['filesystem_check'] = check
        proof['filesystem_view'] = 'Linux journal-only replay on an observation copy'
        proof['selected_revision'] = selected[0]
        proof['selected_files'] = {name: hashlib.sha256(value).hexdigest()
                                   for name, value in selected[1].items()}
    return check, selected, proof


def journal_frames(data):
    assert len(data) % 448 == 0, 'partial authoritative management journal frame'
    result = []
    for index in range(len(data) // 448):
        frame = data[index * 448:(index + 1) * 448]
        magic, version, size, crc, sequence = struct.unpack_from('<IIIIQ', frame)
        copy = bytearray(frame)
        copy[12:16] = bytes(4)
        assert (magic, version, size, sequence) == (0x4c363441, 1, 448, index + 1)
        assert crc == binascii.crc32(copy)
        uid, gid, kind, status = struct.unpack_from('<IIIi', frame, 416)
        target = frame[108:364].split(b'\0', 1)[0].decode('ascii')
        assert 1 <= kind <= 22 and 0 <= status <= 65535
        result.append(dict(raw=frame, kind=kind, status=status, uid=uid, gid=gid, target=target))
    return result


def disk_journal(disk, root, directory, label):
    destination = directory / (label + '-journal.bin')
    debugfs(disk, 'dump ' + root + '/records/journal ' + str(destination))
    data = destination.read_bytes()
    journal_frames(data)
    return data


def baseline_targets(directory, trace, root, before, expected, model):
    """Classify real device requests by independently replaying accepted bytes."""
    replay = directory / 'replay.raw'
    shutil.copyfile(directory / 'armed.raw', replay)
    events = trace_events(trace)
    requests = []
    phases = {}
    before_target, before_files = before
    expected_files = expected[1]
    older = set(re.findall(r'g-[0-9a-f]{32}', debugfs(replay, 'ls -p ' + root + '/db'))) - {before_target}
    assert older, 'prepared store lacks an actual previous generation control'
    with replay.open('r+b') as output:
        for event in events:
            if event['event'] == 'request':
                requests.append([event['operation'], event.get('offset'), event.get('bytes')])
            if event['event'] not in ('write_complete', 'flush_complete'):
                continue
            labels = []
            if event['event'] == 'write_complete':
                data = bytes.fromhex(event['payload_hex'])
                assert len(data) == event['bytes'] and hashlib.sha256(data).hexdigest() == event['payload_sha256']
                output.seek(event['offset'])
                output.write(data)
                output.flush()
                if b'fault-user:x:72000:80000:' in data:
                    labels.append('passwd-staged')
                if b'fault-user:!:' in data:
                    labels.append('shadow-staged')
                if b'fault-user' in data and b'fault-user:' not in data:
                    labels.append('intent-audit-data')
            if event['event'] == 'flush_complete' or model == 'writethrough':
                target, files = selected_files(replay, root)
                home = debugfs(replay, 'stat ' + root + '/homes/fault-user')
                if target == before_target and 'Inode:' in home:
                    labels.append('home-created-before-publication')
                if target and target != before_target and files == expected_files:
                    labels.append('complete-generation-published')
                    assert 'Inode:' in debugfs(replay, 'stat ' + root + '/db/' + before_target)
                    if all('Inode:' not in debugfs(replay, 'stat ' + root + '/db/' + old) for old in older):
                        labels.append('older-generation-collected')
                with tempfile.TemporaryDirectory(prefix='axiom64-management-journal-') as temporary:
                    journal = Path(temporary) / 'journal'
                    debugfs(replay, 'dump ' + root + '/records/journal ' + str(journal))
                    try:
                        frames = journal_frames(journal.read_bytes())
                    except (AssertionError, FileNotFoundError):
                        frames = []
                    if any(frame['kind'] == 10 and frame['target'] == 'fault-user' and frame['status'] == 0
                           for frame in frames):
                        labels.append('completion-audit-published')
                    if any(frame['kind'] == 10 and frame['target'] == 'fault-user' and frame['status'] == 115
                           for frame in frames):
                        labels.append('intent-audit-published')
                        if event['event'] == 'flush_complete':
                            labels.append('intent-audit-flushed')
            for label in labels:
                phases.setdefault(label, dict(operation=event['operation'], request=event['index'],
                                               prefix=list(requests)))
    required = {'intent-audit-data', 'intent-audit-published', 'intent-audit-flushed',
                'passwd-staged', 'shadow-staged',
                'home-created-before-publication', 'complete-generation-published',
                'older-generation-collected', 'completion-audit-published'}
    save(directory / 'observed-phases.json', phases)
    assert required <= set(phases), 'unobserved required actual storage phases: ' + repr(required - set(phases))
    replay.unlink()
    return phases


def backend_start(disk, directory, scratch, offset, model, operation, request, mode):
    socket = scratch / 'nbd.sock'
    trace = directory / 'block.jsonl'
    command = backend_command(disk, socket, trace, control_offset=offset, control_marker=ARM,
                              control_end_marker=END, cache_model=model, fault_operation=operation,
                              fault_request=request, fault_mode=mode, gate=scratch / 'release')
    process, output = launch_backend(command, socket, directory)
    return process, output, socket, trace, command


def backend_stop(process, output):
    if process.poll() is None:
        process.terminate()
        try:
            process.wait(timeout=2)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait()
    output.close()


def fault_cell(directory, images, base, offset, profile, firmware, transport, *, model='writeback',
               operation='write', request=0, mode='observe', target=None):
    directory.mkdir()
    disk = directory / 'disk.raw'
    shutil.copyfile(base, disk)
    root = '/' + profile
    row = dict(provider=profile.rsplit('-', 1)[0], linkage=profile.rsplit('-', 1)[1],
               firmware=firmware, transport=transport, phase=directory.name, cache_model=model,
               fault_operation=operation, fault_request=request, fault_mode=mode,
               actual_unmodified_command=True, wrapped=False, passed=False)
    try:
        before = selected_files(base, root)
        historical = disk_journal(base, root, directory, 'historical')
        with tempfile.TemporaryDirectory(prefix='axiom64-management-vm-') as temporary, working_disk(disk) as device_disk:
            scratch = Path(temporary)
            backend, output, socket, trace, backend_args = backend_start(
                device_disk, directory, scratch, offset, model, operation, request, mode)
            monitor = None
            started = time.monotonic_ns()
            log = directory / 'guest.log'
            command = qemu_command(images['attempt'], directory, firmware, transport,
                                   socket=socket, qmp=scratch / 'qmp.sock')
            with log.open('xb') as serial:
                process = subprocess.Popen(command, cwd=ROOT, env=environment(), stdin=subprocess.DEVNULL,
                                           stdout=serial, stderr=subprocess.STDOUT)
                timed_out = False
                try:
                    monitor = QMP(scratch / 'qmp.sock', process, directory / 'qmp.jsonl', 5)
                    deadline = time.monotonic() + 120
                    if mode.startswith('pause-'):
                        while True:
                            paused = [event for event in trace_events(trace, complete=False) if event['event'] == 'paused']
                            if paused:
                                assert len(paused) == 1 and paused[0]['operation'] == operation and paused[0]['index'] == request
                                monitor.sequence += 1
                                stop = dict(execute='stop', id=monitor.sequence)
                                monitor.record('send', stop)
                                monitor.socket.sendall(json.dumps(stop).encode() + b'\n')
                                os.kill(process.pid, signal.SIGSTOP)
                                freeze_deadline = time.monotonic() + 1
                                while True:
                                    state = re.search(r'^State:\s+(\S+)', (Path('/proc') / str(process.pid) / 'status').read_text(), re.M)[1]
                                    if state in ('T', 't'):
                                        break
                                    assert time.monotonic() < freeze_deadline
                                    time.sleep(.001)
                                row.update(actual_pause=paused[0], host_stopped_state=state,
                                           qmp_stop_requested=True, qmp_stop_acknowledged=False,
                                           actual_vm_sigkill=True)
                                process.kill()
                                break
                            if process.poll() is not None or time.monotonic() >= deadline:
                                raise RuntimeError('VM never reached its observed actual block request')
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
                    backend_stop(backend, output)
            text = log.read_text().replace('\r\n', '\n')
            run = dict(command=command, backend_command=backend_args, returncode=process.returncode,
                       timed_out=timed_out, elapsed_ns=time.monotonic_ns() - started,
                       log_sha256=digest(log), trace_sha256=digest(trace), passed=not timed_out and process.returncode == 1)
            row['run'] = run
        row['actual_device_disk_sha256'] = digest(disk)
        row['temporary_linux_device_disk'] = True
        events = trace_events(trace)
        assert len([event for event in events if event['event'] == 'armed']) == 1
        assert re.search(r'^exec pid=\d+ /bin/accountctl \(', text, re.M), 'fault occurred before the actual administration command'
        if target:
            observed_prefix = []
            for event in events:
                if event['event'] == 'request':
                    observed_prefix.append([event['operation'], event.get('offset'), event.get('bytes')])
                    if event['operation'] == operation and event['index'] == request:
                        break
            assert observed_prefix == target['prefix'], 'actual fault request prefix differs from observed baseline'
            row['baseline_request_prefix_exact'] = True
        injected = [event for event in events if event['event'] == 'injected']
        completions = (directory / 'virtio.trace').read_text()
        failed = len(re.findall(r'virtio_blk_req_complete .*?status 1\b', completions))
        row.update(failed_virtio_completions=failed, virtio_trace_sha256=digest(directory / 'virtio.trace'))
        if mode == 'eio':
            assert len(injected) == 1 and injected[0]['operation'] == operation and injected[0]['index'] == request
            assert failed == 1
            accepted(run, text, 'attempt', firmware, transport)
            assert 'ACCOUNT_MANAGEMENT_EXT2_ATTEMPT exit=1 ' in text
        elif mode == 'observe':
            assert not injected and failed == 0
            accepted(run, text, 'attempt', firmware, transport)
            assert 'ACCOUNT_MANAGEMENT_EXT2_ATTEMPT exit=0 visible=1' in text
        else:
            assert not run['timed_out'] and run['returncode'] == -signal.SIGKILL and not injected
            assert row['actual_pause']['disk_sha256'] == digest(disk), 'backend cleanup changed the paused durable bytes'
            row['paused_durable_bytes_unchanged_by_host_cleanup'] = True
        if not mode.startswith('pause-'):
            assert len([event for event in events if event['event'] == 'disarmed']) == 1
        interrupted = directory / 'interrupted.raw'
        shutil.copyfile(disk, interrupted)
        row['retained_interrupted'] = archive_fixture(interrupted, remove=True)
        row['pre_recovery_fsck'], selected, oracle = recovery_input(
            disk, root, directory, pending_recovery=mode.startswith('pause-'))
        if oracle is not None:
            row['native_journal_selection_oracle'] = oracle
            row['raw_pre_recovery_fsck'] = oracle['raw_filesystem_check']
        assert selected[1] in (before[1], added_user_files(before[1], profile)), 'selected generation is neither complete old nor complete new'
        if selected[1] != before[1]:
            with tempfile.TemporaryDirectory(prefix='axiom64-management-previous-') as temporary:
                previous = {}
                for name in before[1]:
                    output = Path(temporary) / name
                    debugfs(disk, 'dump ' + root + '/db/' + before[0] + '/' + name + ' ' + str(output))
                    previous[name] = output.read_bytes()
                assert previous == before[1], 'publication changed or discarded its complete previous generation'
            row['previous_generation_retained_exact'] = True
        if not mode.startswith('pause-'):
            row['live_proof'] = inspect_disk(disk, directory, root, text, 'attempt')
            history = disk_journal(disk, root, directory, 'completed')
            assert history.startswith(historical), 'acknowledged historical audit events changed'
            row['acknowledged_historical_events_preserved'] = len(historical) // 448
        if mode == 'observe':
            row['observed_phases'] = baseline_targets(directory, trace, root, before, selected, model)
        recovery = directory / 'recovery'
        recovery.mkdir()
        phase = 'crash-recover' if mode.startswith('pause-') else 'recover'
        with working_disk(disk) as device_disk:
            recovered, recovery_text = execute(qemu_command(images[phase], recovery, firmware, transport, disk=device_disk),
                                              recovery / 'guest.log', expected=1)
        recovered['actual_device_disk_sha256'] = digest(disk)
        recovered['temporary_linux_device_disk'] = True
        accepted(recovered, recovery_text, 'recover', firmware, transport)
        recovered_before = serial_state(recovery_text, 'recovered')[1]
        assert recovered_before == selected[1], 'fresh kernel replaced an already selected generation'
        row['recovery'] = recovered
        row['recovered_proof'] = inspect_disk(disk, recovery, root, recovery_text, 'recover')
        final_history = disk_journal(disk, root, recovery, 'final')
        assert final_history.startswith(historical)
        successful = [frame for frame in journal_frames(final_history)
                      if frame['kind'] == 10 and frame['target'] == 'fault-user' and frame['status'] == 0]
        # A crash or error after publication may leave only the durable intent;
        # it never acknowledged a completed command. A clean retry of an absent
        # user or an acknowledged successful command must have exactly one
        # completed-success record. Every case rejects duplicate successes.
        acknowledged = 'ACCOUNT_MANAGEMENT_EXT2_ATTEMPT exit=0 visible=1' in text
        assert len(successful) <= 1, 'user creation audit success duplicated across retry'
        if selected[1] == before[1] or acknowledged:
            assert len(successful) == 1, 'acknowledged user creation audit success lost'
        row.update(successful_user_creation_events=len(successful), command_success_acknowledged=acknowledged,
                   unacknowledged_visible_intent_only=selected[1] != before[1] and not successful)
        row['post_recovery_fsck'] = check_fs(disk, recovery, 'recovered')
        row['retained_final'] = archive_fixture(disk, remove=True)
        row['retained_armed'] = archive_fixture(directory / 'armed.raw', remove=True)
        row['passed'] = True
    except BaseException as error:
        row['error'] = repr(error)
        if disk.exists():
            try:
                row['failed_disk_fsck'] = check_fs(disk, directory, 'failed')
            except BaseException as failure:
                row['failed_disk_fsck_error'] = repr(failure)
            target_name, records = selected_files(disk, root)
            exports = directory / 'failed-exports'
            exports.mkdir()
            for name, data in records.items():
                (exports / (name + '.bin')).write_bytes(data)
            row['failed_selected_revision'] = target_name
        for name in ('disk.raw', 'armed.raw'):
            path = directory / name
            if path.exists() and not path.with_name(path.name + '.gz').exists():
                row['retained_failed_' + name] = archive_fixture(path, remove=True)
        raise
    finally:
        save(directory / 'result.json', row)
    print('ACCOUNT_MANAGEMENT_EXT2_FAULT_PASS ' + directory.name, flush=True)
    return row


def storage_campaign(args, rows):
    subprocess.run(['make', '-s', '-j2', 'build/axiom64.elf', 'build/init', 'busybox'], cwd=ROOT, check=True)
    for provider in ('build', 'runtime') if args.provider == 'both' else (args.provider,):
        for linkage in ('static', 'dynamic') if args.linkage == 'both' else (args.linkage,):
            profile = provider + '-' + linkage
            case = args.directory / profile
            case.mkdir()
            images = campaign_images(case, provider, linkage, journal=args.journal)
            for firmware in ('bios', 'uefi') if args.firmware == 'both' else (args.firmware,):
                for transport in ('modern', 'legacy') if args.transport == 'both' else (args.transport,):
                    cell = case / (firmware + '-' + transport)
                    cell.mkdir()
                    prepare = cell / 'prepare'
                    prepare.mkdir()
                    base = prepare / 'seed.raw'
                    management_volume(base, args.journal)
                    row, text = execute(qemu_command(images['prepare'], prepare, firmware, transport, disk=base),
                                        prepare / 'guest.log', expected=1)
                    accepted(row, text, 'prepare', firmware, transport)
                    row.update(provider=provider, linkage=linkage, firmware=firmware, transport=transport,
                               phase='prepare', host_state=inspect_disk(base, prepare, '/' + profile, text, 'prepare'))
                    row['fsck'] = check_fs(base, prepare, 'prepared')
                    rows.append(row)
                    save(args.directory / 'results.json', rows)
                    if args.campaign == 'storage':
                        for phase in ('readonly', 'full'):
                            directory = cell / phase
                            directory.mkdir()
                            disk = directory / 'disk.raw'
                            shutil.copyfile(base, disk)
                            before_hash = digest(disk)
                            with working_disk(disk) as device_disk:
                                run, log = execute(qemu_command(images[phase], directory, firmware, transport,
                                                               disk=device_disk, readonly=phase == 'readonly'),
                                                   directory / 'guest.log', expected=1)
                            run['actual_device_disk_sha256'] = digest(disk)
                            run['temporary_linux_device_disk'] = True
                            run.update(provider=provider, linkage=linkage, firmware=firmware,
                                       transport=transport, phase=phase)
                            rows.append(run)
                            save(args.directory / 'results.json', rows)
                            accepted(run, log, phase, firmware, transport, readonly=phase == 'readonly')
                            if phase == 'readonly':
                                assert digest(disk) == before_hash and 'Read-only file system' in log
                                run['readonly_bytes_unchanged'] = True
                            else:
                                assert 'ACCOUNT_MANAGEMENT_EXT2_ENOSPC written=' in log and 'errno=28' in log
                                assert 'No space left on device' in log
                            run['fsck'] = check_fs(disk, directory, 'storage')
                            run['host_state'] = inspect_disk(disk, directory, '/' + profile, log, phase)
                            run['retained_disk'] = archive_fixture(disk, remove=True)
                            save(args.directory / 'results.json', rows)
                    else:
                        block = int(debugfs(base, 'bmap /' + profile + '/control 0').strip())
                        assert block > 0
                        offset = block * 1024
                        for model in ('writeback', 'writethrough') if args.cache_model == 'both' else (args.cache_model,):
                            baseline = fault_cell(cell / ('baseline-' + model), images, base, offset, profile,
                                                  firmware, transport, model=model)
                            rows.append(baseline)
                            save(args.directory / 'results.json', rows)
                            unique = {}
                            for label, target in baseline['observed_phases'].items():
                                unique.setdefault((target['operation'], target['request']), (label, target))
                            targets = list(unique.values())
                            if args.fault_limit:
                                targets = targets[:args.fault_limit]
                            for label, target in targets:
                                for mode in args.fault_modes.split(','):
                                    name = '-'.join((label, target['operation'], str(target['request']), model, mode))
                                    failed = fault_cell(cell / name, images, base, offset, profile, firmware, transport,
                                                        model=model, operation=target['operation'], request=target['request'],
                                                        mode=mode, target=target)
                                    rows.append(failed)
                                    save(args.directory / 'results.json', rows)
                    rows[-1]['retained_seed'] = archive_fixture(base, remove=True)
                    save(args.directory / 'results.json', rows)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--directory', type=Path)
    parser.add_argument('--native', action='store_true')
    parser.add_argument('--fixtures', type=Path)
    parser.add_argument('--firmware', choices=('bios', 'uefi', 'both'), default='both')
    parser.add_argument('--transport', choices=('modern', 'legacy', 'both'), default='both')
    parser.add_argument('--provider', choices=('build', 'runtime', 'native', 'both'), default='both')
    parser.add_argument('--linkage', choices=('static', 'dynamic', 'both'), default='both')
    parser.add_argument('--campaign', choices=('clean', 'storage', 'fault'), default='clean')
    parser.add_argument('--journal', action='store_true',
                        help='create classic internal journals on the owned guest fixtures')
    parser.add_argument('--cache-model', choices=('writeback', 'writethrough', 'both'), default='both')
    parser.add_argument('--fault-modes', default='eio,pause-before,pause-after')
    parser.add_argument('--fault-limit', type=int, default=0,
                        help='explicit preliminary target limit; zero covers all observed targets')
    parser.add_argument('--native-inside', action='store_true')
    parser.add_argument('--phase')
    parser.add_argument('--fixture', type=Path)
    parser.add_argument('--driver', type=Path)
    parser.add_argument('--accountctl', type=Path)
    args = parser.parse_args()
    if args.journal and (args.native or args.native_inside):
        parser.error('--journal selects guest fixtures, not native filesystem controls')
    if args.fault_limit < 0 or not args.fault_modes or any(mode not in ('eio', 'pause-before', 'pause-after')
                                                       for mode in args.fault_modes.split(',')):
        parser.error('use nonnegative target limit and exact comma-separated fault modes')
    if args.native_inside:
        native_inside(args)
    if not args.directory or os.geteuid() or os.getegid():
        raise RuntimeError('use root and an explicit owned result directory')
    args.directory = args.directory.resolve()
    assert args.directory.is_relative_to((ROOT / 'build').resolve())
    args.directory.mkdir(parents=True, exist_ok=False)
    names = [*INPUTS, *(path.relative_to(ROOT).as_posix() for path in (ROOT / 'kernel').rglob('*')
                       if path.is_file() and path.suffix in ('.cpp', '.hpp', '.asm'))]
    source = {name: digest(ROOT / name) for name in names}
    (args.directory / 'source-inputs.json').write_text(json.dumps(source, indent=2) + '\n')
    rows = []
    error = None
    try:
        if args.native:
            native(args, rows)
        else:
            assert args.provider != 'native', 'native libc is a Linux control, not an Axiom64 port'
            if args.campaign == 'clean':
                guest(args, rows)
            else:
                storage_campaign(args, rows)
    except BaseException as failure:
        error = repr(failure)
        raise
    finally:
        stable = source == {name: digest(ROOT / name) for name in source}
        fault_results = [json.loads(path.read_text()) for path in args.directory.rglob('result.json')]
        save(args.directory / 'fault-results.json', fault_results)
        complete = args.provider == args.linkage == args.firmware == args.transport == 'both' and \
            not args.fault_limit and args.cache_model == 'both' and \
            set(args.fault_modes.split(',')) == {'eio', 'pause-before', 'pause-after'}
        save(args.directory / 'receipt.json', dict(passed=error is None and stable,
             terminal=True, source_stable=stable, phases=len(rows), error=error,
             actual_commands=True, wrapped=False, timeout_seconds=120,
             campaign='native' if args.native else args.campaign, journaled=args.journal,
             matrix_complete=complete and error is None and stable,
             fault_cells=len(fault_results), failed_fault_cells=sum(not row['passed'] for row in fault_results),
             actual_vm_crashes=sum(row.get('actual_vm_sigkill', False) for row in fault_results),
             profiles=sorted({row['provider'] + '-' + row['linkage'] for row in rows}),
             original_source_manifest_sha256=digest(args.directory / 'source-inputs.json')))
    assert stable, 'source changed during validation'
    print('ACCOUNT_MANAGEMENT_EXT2_MATRIX_PASS phases=' + str(len(rows)), flush=True)


if __name__ == '__main__':
    main()
