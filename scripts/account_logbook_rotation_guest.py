#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Verify real guest journal rotation, protected projections and clean reboot recovery."""
import argparse
import binascii
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import signal
import struct
import subprocess
import tarfile
import tempfile
import time

from account_logbook_test import SOURCES
from account_store_guest import fixture
from account_store_test import digest, environment
from build_musl import compiler_args, ensure, loader
from ext2_test import create_volume, debugfs, SEED
from fetch import ROOT
from fixture_archive import archive_fixture

CLIENT = 'userspace/tests/security/account-logbook-rotation-guest.c'
INPUTS = [*SOURCES, CLIENT, 'scripts/account_logbook_rotation_guest.py',
          'scripts/account_logbook_test.py', 'scripts/account_store_guest.py',
          'scripts/account_store_test.py', 'scripts/build_musl.py', 'scripts/ext2_test.py',
          'scripts/fixture_archive.py', 'scripts/image.py', 'sources.lock.json',
          'dependencies.json', 'Makefile', 'userspace/init/main.c',
          'userspace/init/console.c', 'userspace/init/console.h',
          'userspace/init/seed_records.h', 'boot/limine.conf']
MODES = {'lock': 0o600, 'journal': 0o600, 'state': 0o600, 'utmp': 0o644,
         'wtmp': 0o644, 'btmp': 0o600, 'auth.log': 0o600}
ARCHIVE_FILES = ('journal', 'state', 'wtmp', 'btmp', 'auth.log')
KINDS = {1: 'login', 2: 'logout', 3: 'denied', 5: 'sudo', 9: 'recovered'}


def build(provider, linkage, directory, *, default=False):
    compiler = ['gcc'] if provider == 'native' else compiler_args(provider)
    program = directory / ('rotation-' + ('default' if default else 'small'))
    command = [*compiler, '-std=c11', '-O2', '-g', '-Wall', '-Wextra', '-Werror',
               *([] if default else ['-DACCOUNT_LOGIN_JOURNAL_LIMIT=3584',
                                     '-DACCOUNT_LOGIN_LIVE_LIMIT=4']),
               *(str(ROOT / name) for name in SOURCES if name.endswith('.c')),
               str(ROOT / CLIENT), '-o', str(program),
               *(['-static'] if linkage == 'static' else [])]
    with (directory / 'build.log').open('xb') as log:
        subprocess.run(command, cwd=ROOT, env=environment(), check=True,
                       stdout=log, stderr=subprocess.STDOUT)
    headers = subprocess.check_output(['readelf', '-W', '-l', str(program)], text=True)
    dynamic = subprocess.check_output(['readelf', '-W', '-d', str(program)], text=True)
    assert ('INTERP' not in headers) == (linkage == 'static')
    assert not any('--wrap' in value for value in command)
    assert 'RPATH' not in dynamic and 'RUNPATH' not in dynamic
    return program, dict(command=command, binary_sha256=digest(program), headers=headers,
                         dynamic=dynamic, wrapped=False,
                         journal_limit=33554432 if default else 3584,
                         live_limit=1024 if default else 4,
                         libc_manifest_sha256=(digest(ensure(provider) / 'manifest.json')
                                               if provider != 'native' else None))


def execute(command, log, timeout=180):
    started = time.monotonic_ns()
    timed_out = False
    with log.open('xb') as output:
        process = subprocess.Popen(command, cwd=ROOT, env=environment(), stdin=subprocess.DEVNULL,
                                   stdout=output, stderr=subprocess.STDOUT, start_new_session=True)
        try:
            process.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            timed_out = True
            os.killpg(process.pid, signal.SIGKILL)
            process.wait()
    return dict(command=command, returncode=process.returncode, timed_out=timed_out,
                elapsed_ns=time.monotonic_ns() - started, log=str(log), log_sha256=digest(log))


def wire_crc(data):
    copy = bytearray(data)
    saved, = struct.unpack_from('<I', copy, 12)
    copy[12:16] = bytes(4)
    assert saved == binascii.crc32(copy), 'wire checksum differs'


def state(data):
    assert len(data) == 40
    magic, version, size, _crc, generation, carried, previous = struct.unpack('<IIIIQQQ', data)
    assert (magic, version, size) == (0x53423641, 1, 40)
    wire_crc(data)
    return dict(generation=generation, carried=carried, previous_events=previous)


def cstring(data):
    zero = data.index(0)
    assert not any(data[zero:]), 'nonzero string padding'
    return data[:zero].decode('ascii')


def frames(data):
    assert len(data) % 448 == 0
    result = []
    for index in range(len(data) // 448):
        raw = data[index * 448:(index + 1) * 448]
        wire_crc(raw)
        magic, version, size, _crc, sequence, seconds = struct.unpack_from('<IIIIQq', raw)
        assert (magic, version, size, sequence) == (0x4c363441, 1, 448, index + 1)
        entry = raw[32:416]
        uid, gid, kind, status = struct.unpack_from('<IIIi', raw, 416)
        pid, = struct.unpack_from('<i', entry, 4)
        entry_type, = struct.unpack_from('<h', entry)
        session, sec32, microseconds = struct.unpack_from('<iii', entry, 336)
        assert session == pid and sec32 == seconds and 0 <= microseconds < 1000000
        assert kind in KINDS and entry_type == {1: 7, 2: 8, 3: 6, 5: 0, 9: 8}[kind]
        assert 0 <= status <= 65535 and pid > 0
        result.append(dict(raw=raw, entry=entry, uid=uid, gid=gid, kind=kind, status=status,
                           pid=pid, seconds=seconds, microseconds=microseconds,
                           user=cstring(entry[44:76]), terminal=cstring(entry[8:40]),
                           target=cstring(entry[76:332]), token=raw[432:448]))
    return result


def dead_entry(frame):
    entry = bytearray(frame['entry'])
    if frame['kind'] in (2, 9):
        entry[44:76] = bytes(32)
    return bytes(entry)


def projections(saved, records):
    wtmp, btmp, auth = bytearray(), bytearray(), bytearray()
    for index, frame in enumerate(records[saved['carried']:]):
        if frame['kind'] in (1, 2, 9):
            wtmp.extend(dead_entry(frame))
        if frame['kind'] == 3:
            btmp.extend(frame['entry'])
        auth.extend((f"{frame['seconds']}.{frame['microseconds']:06d} "
                     f"seq={saved['previous_events'] + index + 1} event={KINDS[frame['kind']]} "
                     f"user={frame['user']} uid={frame['uid']} gid={frame['gid']} "
                     f"pid={frame['pid']} tty={frame['terminal']} target={frame['target']} "
                     f"status={frame['status']}\n").encode())
    return {'wtmp': bytes(wtmp), 'btmp': bytes(btmp), 'auth.log': bytes(auth)}


def verify_files(files, metadata, phase):
    archives = [f'archive-{generation:016x}' for generation in range(6, 10)]
    leases = [name for name in files if re.fullmatch(r'l-[0-9a-f]{32}', name)]
    expected = set(MODES) | {name + '/' + item for name in archives for item in ARCHIVE_FILES} | set(leases)
    assert set(files) == set(metadata) == expected and len(leases) == int(phase == 'prepare')
    assert files['lock'] == b'' and all(files[name] == b'' for name in leases)
    summaries = {}
    history = []
    previous = None
    previous_records = None
    for name in [*archives, '']:
        prefix = name + '/' if name else ''
        saved = state(files[prefix + 'state'])
        records = frames(files[prefix + 'journal'])
        assert saved['generation'] == (int(name[8:], 16) if name else 10)
        assert saved['carried'] == (2 if name else 1)
        assert len(records) == (8 if name else 2 + int(phase == 'recover'))
        assert all(frame['kind'] == 1 for frame in records[:saved['carried']])
        assert all((frame['uid'], frame['gid']) == (70000, 80000)
                   for frame in records if frame['kind'] in (1, 2, 9))
        if previous is not None:
            ended = {frame['token'] for frame in previous_records if frame['kind'] in (2, 9)}
            carried = [frame for frame in previous_records if frame['kind'] == 1 and frame['token'] not in ended]
            assert len(carried) == saved['carried']
            for index, frame in enumerate(carried):
                current = records[index]
                assert frame['raw'][:12] == current['raw'][:12]
                assert frame['raw'][24:] == current['raw'][24:]
            assert saved['previous_events'] == (previous['previous_events'] +
                                                 len(previous_records) - previous['carried'])
        for projection, expected_bytes in projections(saved, records).items():
            assert files[prefix + projection] == expected_bytes, prefix + projection
        history += records[saved['carried']:]
        summaries[name or 'current'] = dict(**saved, frames=len(records))
        previous, previous_records = saved, records
    current = previous_records
    assert previous['previous_events'] == 56
    assert current[0]['kind'] == 1 and current[1]['kind'] == 3 and current[1]['status'] == 53
    assert [frame['status'] for frame in history if frame['kind'] in (3, 5)] == list(range(30, 54))
    assert sum(frame['kind'] == 2 for frame in history) == 1
    assert sum(frame['kind'] == 9 for frame in history) == int(phase == 'recover')
    assert not any(frame['kind'] == 1 for frame in history), 'carried START duplicated in history'
    latest = current[0]
    if phase == 'recover':
        assert current[2]['kind'] == 9 and current[2]['token'] == latest['token']
        latest = current[2]
    assert files['utmp'] == dead_entry(latest)
    for name, value in metadata.items():
        base = name.rsplit('/', 1)[-1]
        expected_mode = 0o600 if name in leases else MODES[base]
        assert (value['mode'], value['uid'], value['gid'], value['links'], value['bytes']) == (
            expected_mode, 0, 0, 1, len(files[name])), name
    return dict(generations=summaries, retained_audits=24, historical_starts=0,
                ended=1, recovered=int(phase == 'recover'), active=int(phase == 'prepare'),
                files=len(files), full_width_identity=True, independent_projections=True)


def serial_files(log, phase, directory):
    text = log.read_text().replace('\r\n', '\n')
    values = re.findall(r'^ACCOUNT_ROTATION_GUEST_FILE phase=' + phase +
                        r' name=(\S+) mode=([0-7]{4}) uid=(\d+) gid=(\d+) links=(\d+) bytes=(\d+)$',
                        text, re.MULTILINE)
    metadata = {name: dict(mode=int(mode, 8), uid=int(uid), gid=int(gid), links=int(links), bytes=int(size))
                for name, mode, uid, gid, links, size in values}
    raw = re.findall(r'^ACCOUNT_ROTATION_GUEST_DATA phase=' + phase + r' name=(\S+) hex=([0-9a-f]*)$',
                     text, re.MULTILINE)
    files = {name: bytes.fromhex(data) for name, data in raw}
    assert len(values) == len(metadata) == len(raw) == len(files)
    proof = verify_files(files, metadata, phase)
    directory.mkdir(exist_ok=False)
    for name, data in files.items():
        destination = directory / name
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_bytes(data)
    proof['metadata'] = metadata
    proof['sha256'] = {name: hashlib.sha256(data).hexdigest() for name, data in files.items()}
    (directory / 'proof.json').write_text(json.dumps(proof, indent=2) + '\n')
    return files, proof


def disk_files(disk, directory, profile, expected, serial_metadata):
    checked = subprocess.run(['e2fsck', '-f', '-n', str(disk)], capture_output=True)
    (directory / 'fsck.log').write_bytes(checked.stdout + checked.stderr)
    assert checked.returncode == 0, 'independent ext2 filesystem check failed'
    # List real directory entries before extracting the known projection tree.
    for suffix, names in [('', set(MODES) | {f'archive-{g:016x}' for g in range(6, 10)} |
                                  {name for name in expected if name.startswith('l-')}),
                          *[(f'/archive-{g:016x}', set(ARCHIVE_FILES)) for g in range(6, 10)]]:
        listing = debugfs(disk, 'ls -p /' + profile + suffix)
        actual = {line.split('/')[5] for line in listing.splitlines() if line.startswith('/')}
        assert actual - {'.', '..'} == names
    exports = directory / 'disk-exports'
    exports.mkdir()
    files, metadata = {}, {}
    for name in expected:
        guest_path = '/' + profile + '/' + name
        value = debugfs(disk, 'stat ' + guest_path)
        (directory / ('stat-' + name.replace('/', '-') + '.log')).write_text(value)
        mode = re.search(r'Inode:\s+(\d+)\s+Type:\s+regular\s+Mode:\s+([0-7]+)', value)
        owner = re.search(r'User:\s+(\d+)\s+Group:\s+(\d+).*?Size:\s+(\d+)', value)
        links = re.search(r'Links:\s+(\d+)', value)
        assert mode and owner and links
        destination = exports / name
        destination.parent.mkdir(parents=True, exist_ok=True)
        debugfs(disk, 'dump ' + guest_path + ' ' + str(destination))
        files[name] = destination.read_bytes()
        metadata[name] = dict(mode=int(mode[2], 8), uid=int(owner[1]), gid=int(owner[2]),
                              links=int(links[1]), bytes=int(owner[3]))
        assert files[name] == expected[name] and metadata[name] == serial_metadata[name]
    seed = directory / 'seed.bin'
    debugfs(disk, 'dump /seed.txt ' + str(seed))
    assert seed.read_bytes() == SEED
    return dict(fsck_returncode=0, fsck_log_sha256=digest(directory / 'fsck.log'),
                disk_sha256=digest(disk), exported_files=len(files), serial_bytes_match=True)


def verify_default(log):
    text = log.read_text().replace('\r\n', '\n')
    captured = re.findall(r'^ACCOUNT_ROTATION_GUEST_DEFAULT_BASE ([0-9a-f]{896})$', text, re.MULTILINE)
    archive = re.findall(r'^ACCOUNT_ROTATION_GUEST_DEFAULT_ARCHIVE frames=(\d+) bytes=(\d+) '
                         r'crc32=([0-9a-f]{8})$', text, re.MULTILINE)
    assert len(captured) == len(archive) == 1
    base = bytes.fromhex(captured[0])
    first = frames(base)[0]
    assert first['kind'] == 5 and first['uid'] == 70000 and not first['status']
    count, size, actual = archive[0]
    count, size, actual = int(count), int(size), int(actual, 16)
    assert count == 33554432 // 448 and size == count * 448
    crc = 0
    for sequence in range(1, count + 1):
        raw = bytearray(base)
        struct.pack_into('<Q', raw, 16, sequence)
        raw[12:16] = bytes(4)
        struct.pack_into('<I', raw, 12, binascii.crc32(raw))
        crc = binascii.crc32(raw, crc)
    assert actual == crc
    return dict(production_journal_limit=33554432, production_live_limit=1024,
                override=False, preloaded_valid_frames=count, archived_bytes=size,
                real_guest_audited_append=True, independent_archive_crc32=f'{crc:08x}')


def accepted(row, log, phases, firmware=None):
    text = log.read_text().replace('\r\n', '\n')
    lines = text.splitlines()
    markers = [('ACCOUNT_ROTATION_GUEST_PASS phase=default policy=33554432 generation=2 archives=1'
                if phase == 'default' else
                'ACCOUNT_ROTATION_GUEST_PASS phase=' + phase + ' policy=small generation=10 archives=4')
               for phase in phases]
    passed = (not row['timed_out'] and row['returncode'] == int(firmware is not None) and
              all(lines.count(marker) == 1 for marker in markers) and
              not any(word in text for word in ('ACCOUNT_ROTATION_GUEST_FAIL', 'PANIC:', 'FAULT pid=')))
    if firmware:
        passed = (passed and lines.count('AXIOM64_TESTS_PASS') == 1 and
                  lines.count('AXIOM64_EXIT status=0') == 1 and 'Firmware: ' + firmware.upper() in text)
    row['passed'] = passed
    return passed


def qemu(image, phase_directory, firmware, transport, disk=None, memory=256):
    command = ['qemu-system-x86_64', '-machine', 'pc', '-cpu', 'max', '-m', str(memory) + 'M',
               '-nic', 'none', '-cdrom', str(image), '-display', 'none', '-serial', 'stdio',
               '-monitor', 'none', '-no-reboot', '-device', 'isa-debug-exit,iobase=0xf4,iosize=0x04']
    if disk:
        command += ['-drive', 'if=none,id=records,format=raw,file=' + str(disk),
                    '-device', 'virtio-blk-pci,drive=records,' +
                    ('disable-legacy=on' if transport == 'modern' else 'disable-modern=on')]
    if firmware == 'uefi':
        variables = phase_directory / 'VARS.fd'
        shutil.copyfile('/usr/share/OVMF/OVMF_VARS_4M.fd', variables)
        command += ['-drive', 'if=pflash,format=raw,readonly=on,file=/usr/share/OVMF/OVMF_CODE_4M.fd',
                    '-drive', 'if=pflash,format=raw,file=' + str(variables)]
    return command


def guest(args, rows):
    subprocess.run(['make', '-s', '-j2', 'build/axiom64.elf', 'build/init', 'busybox'], cwd=ROOT, check=True)

    def retain(row):
        rows.append(row)
        (args.directory / 'results.json').write_text(json.dumps(rows, indent=2) + '\n')
        if not row['passed']:
            raise RuntimeError('guest rotation profile failed: ' + row['case'])

    for provider in ('build', 'runtime') if args.provider == 'both' else (args.provider,):
        for linkage in ('static', 'dynamic') if args.linkage == 'both' else (args.linkage,):
            case = args.directory / (provider + '-' + linkage)
            case.mkdir()
            program, inputs = build(provider, linkage, case)
            profile = case.name
            command = (f'if [ -b /dev/vda ]; then\n'
                       f' /bin/busybox mkdir -p /mnt\n /bin/busybox mount -t ext2 /dev/vda /mnt\n'
                       f' if [ -f /mnt/{profile}/state ]; then\n'
                       f'  /bin/account-rotation recover /mnt/{profile}\n'
                       f' else\n  /bin/account-rotation prepare /mnt/{profile}\n fi\n'
                       f' /bin/busybox umount /mnt\nelse\n'
                       f' /bin/account-rotation prepare /run/{profile}\n'
                       f' /bin/account-rotation recover /run/{profile}\nfi')
            image = fixture(case, provider, linkage,
                            program_builder=lambda *unused: (program, inputs),
                            filename='account-rotation', command=command)
            for firmware in ('bios', 'uefi') if args.firmware == 'both' else (args.firmware,):
                for transport in ('modern', 'legacy') if args.transport == 'both' else (args.transport,):
                    for storage in ('ram', 'ext2') if args.root == 'both' else (args.root,):
                        cell = case / (firmware + '-' + transport + '-' + storage)
                        cell.mkdir()
                        disk = cell / 'volume.raw' if storage == 'ext2' else None
                        if disk:
                            create_volume(disk)
                        original_archives = None
                        for boot in range(2 if disk else 1):
                            phase_directory = cell / ('boot-' + str(boot))
                            phase_directory.mkdir()
                            phases = ['prepare', 'recover'] if not disk else ['recover' if boot else 'prepare']
                            log = phase_directory / 'guest.log'
                            row = execute(qemu(image, phase_directory, firmware, transport, disk), log)
                            row.update(case=phase_directory.relative_to(args.directory).as_posix(),
                                       provider=provider, linkage=linkage, firmware=firmware,
                                       transport=transport, storage=storage, boot=boot,
                                       storage_driver_exercised=bool(disk), inputs=inputs,
                                       image_sha256=digest(image), phases=phases,
                                       clean_reboot=bool(disk), power_loss=False, wrapped=False)
                            accepted(row, log, phases, firmware)
                            try:
                                if not row['passed']:
                                    raise RuntimeError('guest observer failed')
                                row['proof'] = {}
                                for phase in phases:
                                    files, proof = serial_files(log, phase, phase_directory / ('serial-' + phase))
                                    archive_hashes = {name: value for name, value in proof['sha256'].items()
                                                      if name.startswith('archive-')}
                                    if original_archives is None:
                                        original_archives = archive_hashes
                                    else:
                                        assert original_archives == archive_hashes, 'closed archive changed on recovery'
                                    proof['closed_archives_unchanged'] = True
                                    row['proof'][phase] = proof
                                    if disk:
                                        proof['disk'] = disk_files(disk, phase_directory, profile, files, proof['metadata'])
                                if disk:
                                    text = log.read_text()
                                    assert 'virtio-blk: disk=0 transport=' + transport in text
                                    if not boot:
                                        before = phase_directory / 'before-reboot.raw'
                                        shutil.copyfile(disk, before)
                                        row['retained_disk'] = archive_fixture(before, remove=True)
                                    else:
                                        row['retained_disk'] = archive_fixture(disk, remove=True)
                            except Exception as error:
                                row.update(passed=False, error=str(error))
                            retain(row)
                            print('ACCOUNT_ROTATION_GUEST_PASS ' + row['case'], flush=True)
    if not args.skip_default:
        case = args.directory / 'default-32mib-build-static-bios-ram'
        case.mkdir()
        program, inputs = build('build', 'static', case, default=True)
        image = fixture(case, 'build', 'static', program_builder=lambda *unused: (program, inputs),
                        filename='account-rotation-default',
                        command='/bin/account-rotation-default default /run/default-records')
        log = case / 'guest.log'
        row = execute(qemu(image, case, 'bios', 'modern', memory=512), log, timeout=600)
        row.update(case=case.name, provider='build', linkage='static', firmware='bios',
                   transport=None, storage='ram', inputs=inputs, image_sha256=digest(image),
                   phases=['default'], default_policy=True, wrapped=False, power_loss=False)
        accepted(row, log, ['default'], 'bios')
        try:
            assert row['passed']
            row['proof'] = verify_default(log)
        except Exception as error:
            row.update(passed=False, error=str(error))
        retain(row)
        print('ACCOUNT_ROTATION_GUEST_DEFAULT_32MIB_PASS', flush=True)


def native(args, rows):
    with tempfile.TemporaryDirectory(prefix='axiom64-account-rotation-observer-') as temporary:
        parent = Path(temporary)
        parent.chmod(0o755)
        try:
            for provider in ('build', 'runtime', 'native'):
                for linkage in ('static', 'dynamic'):
                    case = args.directory / (provider + '-' + linkage)
                    case.mkdir()
                    program, inputs = build(provider, linkage, case)
                    directory = parent / case.name
                    original = None
                    for phase in ('prepare', 'recover'):
                        command = [str(program), phase, str(directory)]
                        if linkage == 'dynamic' and provider != 'native':
                            command.insert(0, str(loader(provider)))
                        log = case / (phase + '.log')
                        row = execute(command, log)
                        row.update(case=case.name + '/' + phase, provider=provider, linkage=linkage,
                                   inputs=inputs, power_loss=False, wrapped=False)
                        accepted(row, log, [phase])
                        try:
                            assert row['passed']
                            files, proof = serial_files(log, phase, case / ('serial-' + phase))
                            for name, data in files.items():
                                current = directory / name
                                value = current.stat()
                                assert current.read_bytes() == data
                                assert (value.st_mode & 0o7777, value.st_uid, value.st_gid, value.st_nlink) == (
                                    proof['metadata'][name]['mode'], 0, 0, 1)
                            closed = {name: value for name, value in proof['sha256'].items() if name.startswith('archive-')}
                            if original is None:
                                original = closed
                            else:
                                assert original == closed
                            proof['closed_archives_unchanged'] = True
                            row['proof'] = proof
                        except Exception as error:
                            row.update(passed=False, error=str(error))
                        rows.append(row)
                        (args.directory / 'results.json').write_text(json.dumps(rows, indent=2) + '\n')
                        if not row['passed']:
                            raise RuntimeError('native rotation observer failed: ' + row['case'])
                    print('ACCOUNT_ROTATION_OBSERVER_NATIVE_PASS ' + case.name, flush=True)
        finally:
            archived = args.directory / 'native-fixtures.tar.gz'
            with tarfile.open(archived, 'w:gz') as stream:
                stream.add(parent, arcname='fixtures')
            with tarfile.open(archived, 'r:gz') as stream:
                for member in stream:
                    if member.isfile():
                        actual = stream.extractfile(member).read()
                        expected = (parent / member.name.removeprefix('fixtures/')).read_bytes()
                        assert actual == expected
            (args.directory / 'native-retention.json').write_text(json.dumps(dict(
                archive_sha256=digest(archived), verified=True), indent=2) + '\n')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--directory', type=Path, required=True)
    parser.add_argument('--native', action='store_true')
    parser.add_argument('--provider', choices=('build', 'runtime', 'both'), default='both')
    parser.add_argument('--linkage', choices=('static', 'dynamic', 'both'), default='both')
    parser.add_argument('--firmware', choices=('bios', 'uefi', 'both'), default='both')
    parser.add_argument('--transport', choices=('modern', 'legacy', 'both'), default='both')
    parser.add_argument('--root', choices=('ram', 'ext2', 'both'), default='both')
    parser.add_argument('--skip-default', action='store_true')
    args = parser.parse_args()
    if os.geteuid() or os.getegid():
        raise RuntimeError('the isolated journal observer requires root')
    args.directory = args.directory.resolve()
    if not args.directory.is_relative_to((ROOT / 'build').resolve()):
        raise RuntimeError('rotation receipts must be inside the owned build directory')
    args.directory.mkdir(parents=True, exist_ok=False)
    names = [*INPUTS, *(path.relative_to(ROOT).as_posix() for path in (ROOT / 'kernel').rglob('*')
                       if path.is_file() and path.suffix in ('.cpp', '.hpp', '.asm'))]
    source = {name: digest(ROOT / name) for name in names}
    (args.directory / 'source-inputs.json').write_text(json.dumps(source, indent=2) + '\n')
    for name in source:
        destination = args.directory / 'source' / name
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_bytes((ROOT / name).read_bytes())
    rows = []
    error = None
    try:
        (native if args.native else guest)(args, rows)
    except Exception as problem:
        error = str(problem)
    unchanged = source == {name: digest(ROOT / name) for name in source}
    full = (args.native or all(getattr(args, name) == 'both' for name in
                              ('provider', 'linkage', 'firmware', 'transport', 'root')) and
            not args.skip_default)
    receipt = dict(passed=error is None and unchanged and all(row['passed'] for row in rows),
                   matrix_complete=full and len(rows) == (12 if args.native else 49),
                   profiles=len(rows), clean_reboot_pairs=0 if args.native else
                   sum(row.get('storage') == 'ext2' and row.get('boot') == 1 for row in rows),
                   source_stable=unchanged, power_loss=False, wrapped_faults=False, error=error)
    (args.directory / 'acceptance.json').write_text(json.dumps(receipt, indent=2) + '\n')
    if not receipt['passed']:
        raise RuntimeError(error or 'rotation source changed during validation')
    print('ACCOUNT_ROTATION_OBSERVER_MATRIX_PASS profiles=' + str(len(rows)) +
          ' complete=' + str(int(receipt['matrix_complete'])), flush=True)


if __name__ == '__main__':
    main()
