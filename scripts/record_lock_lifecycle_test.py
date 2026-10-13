#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Compare actual blocked record-lock lifecycle on Linux and fresh RAM/ext2 guests."""
import argparse
import json
import os
from pathlib import Path
import signal
import shutil
import subprocess
import time

from account_store_guest import fixture
from account_store_test import digest, environment
from build_musl import compiler_args, ensure, loader
from ext2_test import create_volume, debugfs, SEED
from fetch import ROOT

SOURCE = 'userspace/tests/security/record-lock-lifecycle.c'
INPUTS = [SOURCE, 'scripts/record_lock_lifecycle_test.py', 'scripts/account_store_guest.py',
          'scripts/account_store_test.py', 'scripts/build_musl.py', 'scripts/ext2_test.py',
          'scripts/image.py', 'sources.lock.json', 'dependencies.json', 'Makefile']
OBSERVATIONS = 14


def build(provider, linkage, directory):
    compiler = ['gcc'] if provider == 'native' else compiler_args(provider)
    program = directory / ('record-lifecycle-' + provider + '-' + linkage)
    observer = directory / ('record-lifecycle-exec-' + provider)
    common = [*compiler, '-std=c11', '-O2', '-g', '-Wall', '-Wextra', '-Werror', '-pthread',
              str(ROOT / SOURCE)]
    commands = [[*common, '-o', str(program), *(['-static'] if linkage == 'static' else [])],
                [*common, '-static', '-o', str(observer)]]
    with (directory / 'build.log').open('wb') as log:
        for command in commands:
            subprocess.run(command, cwd=ROOT, env=environment(), stdout=log,
                           stderr=subprocess.STDOUT, check=True)
    headers = subprocess.check_output(['readelf', '-W', '-l', str(program)], text=True)
    dynamic = subprocess.check_output(['readelf', '-W', '-d', str(program)], text=True)
    if linkage == 'static':
        assert 'INTERP' not in headers and '(NEEDED)' not in dynamic
    else:
        assert '(NEEDED)' in dynamic and 'RPATH' not in dynamic and 'RUNPATH' not in dynamic
        if provider != 'native':
            assert '/lib/ld-musl-x86_64.so.1' in headers and 'libc.so.6' not in dynamic
    inputs = dict(commands=commands, program_sha256=digest(program), observer_sha256=digest(observer),
                  headers=headers, dynamic=dynamic)
    if provider != 'native':
        inputs['libc_manifest_sha256'] = digest(ensure(provider) / 'manifest.json')
    return program, observer, inputs


def execute(command, log):
    started = time.monotonic_ns()
    timed_out = False
    with log.open('xb') as output:
        process = subprocess.Popen(command, cwd=ROOT, env=environment(), stdin=subprocess.DEVNULL,
                                   stdout=output, stderr=subprocess.STDOUT, start_new_session=True)
        try:
            process.wait(timeout=90)
        except subprocess.TimeoutExpired:
            timed_out = True
            os.killpg(process.pid, signal.SIGKILL)
            process.wait()
    return dict(command=command, returncode=process.returncode, timed_out=timed_out,
                elapsed_ns=time.monotonic_ns() - started, log=str(log), log_sha256=digest(log))


def accepted(row, log, *, guest=False, quota=False, suites=1, persisted=False):
    lines = log.read_text().replace('\r\n', '\n').splitlines()
    count = OBSERVATIONS + int(quota)
    marker = f'RECORD_LIFECYCLE_PASS observations={count} quota={int(quota)}'
    passed = (not row['timed_out'] and row['returncode'] == int(guest) and
              lines.count(marker) == suites and
              sum(line.startswith('RECORD_LIFECYCLE_OBSERVATION ') for line in lines) == count * suites and
              not any(word in '\n'.join(lines) for word in
                      ('RECORD_LIFECYCLE_FAIL', 'PANIC:', 'FAULT pid=', 'FILESYSTEM_SHUTDOWN_FAIL')))
    if guest:
        passed = passed and lines.count('AXIOM64_TESTS_PASS') == 1 and 'AXIOM64_EXIT status=0' in lines
    if suites:
        expected = {(0, 0, -1, 9): 2, (1, 0, 0, 0): 2, (0, 1, 0, 0): 1, (1, 1, 0, 0): 1}
        for (ofd, restart, result, error), total in expected.items():
            evidence = (f'RECORD_LIFECYCLE_WAIT_RESULT ofd={ofd} restart={restart} '
                        f'result={result} error={error}')
            passed = passed and lines.count(evidence) == total * suites
        passed = passed and sum(line.startswith('RECORD_LIFECYCLE_BLOCKED ') for line in lines) == 18 * suites
    if persisted:
        passed = passed and lines.count('RECORD_LIFECYCLE_PERSIST_PASS bytes=new locks=absent') == 1
    row.update(passed=passed,
               observations=sum(line.startswith('RECORD_LIFECYCLE_OBSERVATION ') for line in lines),
               expected_observations=count * suites,
               actual_blocked_observations=sum(line.startswith('RECORD_LIFECYCLE_BLOCKED ') for line in lines))
    return passed


def invocation(program, provider, linkage):
    if linkage == 'static':
        return [str(program)]
    if provider == 'native':
        return ['/lib64/ld-linux-x86-64.so.2', str(program)]
    directory = ensure(provider)
    return [str(loader(provider)), '--library-path',
            ':'.join(str(directory / name) for name in ('sysroot/lib', 'sysroot/usr/lib')), str(program)]


def native(args, source):
    if not args.fixtures or not args.fixtures.is_absolute() or args.fixtures.exists():
        raise RuntimeError('native profiles require fresh absolute Linux filesystem fixtures')
    args.fixtures.mkdir(mode=0o700)
    rows = []
    for provider in ('build', 'runtime', 'native'):
        for linkage in ('static', 'dynamic'):
            case = args.directory / (provider + '-' + linkage)
            case.mkdir()
            program, observer, inputs = build(provider, linkage, case)
            command = [*invocation(program, provider, linkage), str(args.fixtures / case.name), str(observer)]
            row = execute(command, case / 'native.log')
            row.update(provider=provider, linkage=linkage, inputs=inputs,
                       host_kernel=subprocess.check_output(['uname', '-a'], text=True).strip())
            fixture_path = args.fixtures / case.name
            preserved = case / 'native-files'
            preserved.mkdir()
            files = {}
            if fixture_path.exists():
                for path in fixture_path.iterdir():
                    value = path.stat()
                    if not path.is_file() or path.is_symlink():
                        raise RuntimeError('unexpected native lifecycle fixture entry')
                    shutil.copy2(path, preserved / path.name)
                    files[path.name] = dict(mode=value.st_mode, uid=value.st_uid, gid=value.st_gid,
                                           inode=value.st_ino, device=value.st_dev, links=value.st_nlink,
                                           bytes=value.st_size, sha256=digest(path))
            row['native_fixture'] = files
            accepted(row, case / 'native.log')
            rows.append(row)
            (args.directory / 'results.json').write_text(json.dumps(rows, indent=2) + '\n')
            if not row['passed']:
                raise RuntimeError('native record-lock lifecycle failed: ' + case.name)
            for path in fixture_path.iterdir():
                path.unlink()
            fixture_path.rmdir()
            print('RECORD_LIFECYCLE_NATIVE_PASS ' + case.name, flush=True)
    if source != {name: digest(ROOT / name) for name in source}:
        raise RuntimeError('native record-lock lifecycle inputs changed')
    args.fixtures.rmdir()


def disk_check(disk, case, profile):
    fsck = subprocess.run(['e2fsck', '-f', '-n', str(disk)], capture_output=True)
    log = case / 'fsck.log'
    log.write_bytes(fsck.stdout + fsck.stderr)
    if fsck.returncode:
        raise RuntimeError('record-lock lifecycle disk failed independent filesystem inspection')
    exported = {}
    for name, expected in [('seed.txt', SEED), (profile + '/original', b'new')]:
        destination = case / ('export-' + name.replace('/', '-'))
        debugfs(disk, 'dump /' + name + ' ' + str(destination))
        if destination.read_bytes() != expected:
            raise RuntimeError('record-lock lifecycle persisted bytes differ: ' + name)
        exported[name] = digest(destination)
    return dict(disk_sha256=digest(disk), fsck_returncode=fsck.returncode,
                fsck_sha256=digest(log), exported=exported)


def guest(args, source):
    subprocess.run(['make', '-s', '-j2', 'build/axiom64.elf', 'build/init', 'busybox'], cwd=ROOT, check=True)
    rows = []
    for provider in ('build', 'runtime'):
        for linkage in ('static', 'dynamic'):
            case = args.directory / (provider + '-' + linkage)
            case.mkdir()
            program, observer, inputs = build(provider, linkage, case)
            def builder(_provider, _linkage, _directory):
                return program, inputs
            profile = case.name
            command = (f'if [ -b /dev/vda ]; then\n'
                       f' /bin/busybox mkdir -p /mnt\n /bin/busybox mount -t ext2 /dev/vda /mnt\n'
                       f' if [ -f /mnt/{profile}/original ]; then\n'
                       f'  /bin/record-lifecycle --persist-check /mnt/{profile}\n'
                       f' else\n  /bin/record-lifecycle /mnt/{profile} /bin/record-lifecycle-exec --guest-quota\n fi\n'
                       f' /bin/busybox umount /mnt\nelse\n'
                       f' /bin/record-lifecycle /run/{profile} /bin/record-lifecycle-exec --guest-quota\nfi')
            image = fixture(case, provider, linkage, program_builder=builder, filename='record-lifecycle',
                            command=command, extra_products={'bin/record-lifecycle-exec': observer})
            for firmware in ('bios', 'uefi') if args.firmware == 'both' else (args.firmware,):
                for transport in ('modern', 'legacy') if args.transport == 'both' else (args.transport,):
                    for root in ('ram', 'ext2') if args.root == 'both' else (args.root,):
                        cell = case / (firmware + '-' + transport + '-' + root)
                        cell.mkdir()
                        disk = cell / 'volume.raw'
                        if root == 'ext2':
                            create_volume(disk)
                        for phase in range(2 if root == 'ext2' else 1):
                            phase_dir = cell / ('boot-' + str(phase))
                            phase_dir.mkdir()
                            qemu = ['qemu-system-x86_64', '-machine', 'pc', '-cpu', 'max', '-m', '256M', '-nic', 'none',
                                    '-cdrom', str(image), '-display', 'none', '-serial', 'stdio', '-monitor', 'none',
                                    '-no-reboot', '-device', 'isa-debug-exit,iobase=0xf4,iosize=0x04']
                            if root == 'ext2':
                                qemu += ['-drive', 'if=none,id=root,format=raw,file=' + str(disk),
                                         '-device', 'virtio-blk-pci,drive=root,' +
                                         ('disable-legacy=on' if transport == 'modern' else 'disable-modern=on')]
                            if firmware == 'uefi':
                                variables = phase_dir / 'VARS.fd'
                                shutil.copyfile('/usr/share/OVMF/OVMF_VARS_4M.fd', variables)
                                qemu += ['-drive', 'if=pflash,format=raw,readonly=on,file=/usr/share/OVMF/OVMF_CODE_4M.fd',
                                         '-drive', 'if=pflash,format=raw,file=' + str(variables)]
                            log = phase_dir / 'guest.log'
                            row = execute(qemu, log)
                            accepted(row, log, guest=True, quota=True, suites=int(phase == 0), persisted=bool(phase))
                            row.update(provider=provider, linkage=linkage, firmware=firmware, transport=transport,
                                       root=root, phase=phase, inputs=inputs, image_sha256=digest(image))
                            text = log.read_text()
                            row['passed'] = row['passed'] and 'Firmware: ' + firmware.upper() in text
                            if root == 'ext2':
                                row['passed'] = row['passed'] and 'virtio-blk: disk=0 transport=' + transport in text
                            if root == 'ext2' and row['passed']:
                                try:
                                    row['disk'] = disk_check(disk, phase_dir, profile)
                                except Exception as error:
                                    row.update(passed=False, error=str(error))
                            rows.append(row)
                            (args.directory / 'results.json').write_text(json.dumps(rows, indent=2) + '\n')
                            if not row['passed']:
                                raise RuntimeError('guest record-lock lifecycle failed: ' + str(phase_dir))
                            print('RECORD_LIFECYCLE_GUEST_PASS ' + str(phase_dir), flush=True)
    if source != {name: digest(ROOT / name) for name in source}:
        raise RuntimeError('guest record-lock lifecycle inputs changed')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--directory', type=Path, required=True)
    parser.add_argument('--native', action='store_true')
    parser.add_argument('--fixtures', type=Path)
    parser.add_argument('--firmware', choices=('bios', 'uefi', 'both'), default='both')
    parser.add_argument('--transport', choices=('modern', 'legacy', 'both'), default='both')
    parser.add_argument('--root', choices=('ram', 'ext2', 'both'), default='both')
    args = parser.parse_args()
    args.directory = args.directory.resolve()
    args.directory.mkdir(parents=True, exist_ok=False)
    names = list(INPUTS)
    if args.native:
        names = [SOURCE, 'scripts/record_lock_lifecycle_test.py', 'scripts/account_store_test.py',
                 'scripts/build_musl.py', 'scripts/fetch.py', 'sources.lock.json', 'dependencies.json']
    else:
        names += [path.relative_to(ROOT).as_posix() for path in (ROOT / 'kernel').rglob('*')
                  if path.is_file() and path.suffix in ('.cpp', '.hpp', '.asm')]
        names += [path.relative_to(ROOT).as_posix() for path in (ROOT / 'userspace/init').glob('*') if path.is_file()]
    source = {name: digest(ROOT / name) for name in names}
    (args.directory / 'source-inputs.json').write_text(json.dumps(source, indent=2) + '\n')
    (native if args.native else guest)(args, source)


if __name__ == '__main__':
    main()
