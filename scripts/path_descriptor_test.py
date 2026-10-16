# SPDX-License-Identifier: GPL-3.0-or-later
"""Compare real Linux path-descriptor lifetime and access restrictions on RAM and ext2."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import signal
import subprocess
import sys
import time

from account_store_guest import fixture
from account_store_test import environment
from account_session_test import retain_native
from build_musl import compiler_args, loader
from ext2_test import create_volume
from fetch import ROOT
from fixture_archive import archive_fixture

CLIENT = 'userspace/tests/fs/path-descriptors.c'


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def save(path, value):
    path.write_text(json.dumps(value, indent=2)+'\n')


def build(directory, provider, linkage, native):
    binary = directory / 'path-descriptors'
    command = ['gcc'] if provider == 'native' else list(compiler_args(provider))
    command += ['-std=c11', '-O2', '-g', '-Wall', '-Wextra', '-Werror']
    if linkage == 'static':
        command += ['-static']
    elif native and provider != 'native':
        command += ['-Wl,--dynamic-linker=' + str(loader(provider))]
    command += [str(ROOT / CLIENT), '-o', str(binary)]
    subprocess.run(command, cwd=ROOT, env=environment(), check=True)
    inputs = dict(command=command, binary_sha256=digest(binary))
    if provider != 'native':
        inputs['selected_loader'] = dict(path=str(loader(provider)), sha256=digest(loader(provider)))
    save(directory / 'compiler-inputs.json', inputs)
    return binary, inputs


def execute(command, directory, native, observations=71):
    started = time.monotonic_ns()
    log = directory / 'execution.log'
    timed_out = False
    with log.open('xb') as output:
        process = subprocess.Popen(command, cwd=ROOT, stdin=subprocess.DEVNULL,
                                   stdout=output, stderr=subprocess.STDOUT, start_new_session=True)
        try:
            process.wait(timeout=90)
        except subprocess.TimeoutExpired:
            timed_out = True
            os.killpg(process.pid, signal.SIGKILL)
            process.wait()
        except BaseException:
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            process.wait()
            raise
    text = log.read_text().replace('\r\n', '\n')
    marker = f'PATH_DESCRIPTOR_PASS root_observations={observations-8} ordinary_permission_checks=6 record_lock_child_checks=2'
    passed = (not timed_out and process.returncode == (0 if native else 1) and
              text.splitlines().count(marker) == 1 and
              text.splitlines().count('PATH_DESCRIPTOR_SELECT result=1 requested_bit=1') == 1 and
              text.splitlines().count('PATH_DESCRIPTOR_RECORD_CLOSE_PASS path_preserved=1 ordinary_released=1') == 1 and
              'PATH_DESCRIPTOR_FAIL' not in text and 'PANIC:' not in text)
    if not native:
        passed &= text.splitlines().count('AXIOM64_TESTS_PASS') == 1 and 'AXIOM64_EXIT status=0' in text
    return dict(passed=bool(passed), command=command, returncode=process.returncode,
                timed_out=timed_out, elapsed_ns=time.monotonic_ns()-started, log_sha256=digest(log),
                observations=observations if passed else 0)


def inspect_native_fixture(path):
    assert {entry.name for entry in path.iterdir()} == {'data', 'current', 'dangling'}
    data = path / 'data'
    metadata = data.stat()
    assert data.read_bytes() == b'fixture' and metadata.st_mode & 0o7777 == 0
    assert metadata.st_uid == metadata.st_gid == 0 and metadata.st_nlink == 1
    assert os.readlink(path / 'current') == 'replacement'
    assert os.readlink(path / 'dangling') == 'missing'
    return dict(data_sha256=digest(data), data_mode=metadata.st_mode & 0o7777,
                data_uid=metadata.st_uid, data_gid=metadata.st_gid,
                data_links=metadata.st_nlink, current_target='replacement', dangling_target='missing')


def qemu(image, directory, firmware, transport, disk=None):
    command = ['qemu-system-x86_64', '-machine', 'pc', '-cpu', 'max', '-m', '256M', '-nic', 'none',
               '-cdrom', str(image), '-display', 'none', '-serial', 'stdio', '-monitor', 'none',
               '-no-reboot', '-device', 'isa-debug-exit,iobase=0xf4,iosize=0x04']
    if disk:
        command += ['-drive', 'if=none,id=data,format=raw,file=' + str(disk), '-device',
                    'virtio-blk-pci,drive=data,' + ('disable-legacy=on' if transport == 'modern' else 'disable-modern=on')]
    if firmware == 'uefi':
        variables = directory / 'VARS.fd'
        shutil.copyfile('/usr/share/OVMF/OVMF_VARS_4M.fd', variables)
        command += ['-drive', 'if=pflash,format=raw,readonly=on,file=/usr/share/OVMF/OVMF_CODE_4M.fd',
                    '-drive', 'if=pflash,format=raw,file=' + str(variables)]
    return command


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--directory', type=Path, required=True)
    parser.add_argument('--native', action='store_true')
    parser.add_argument('--fixtures', type=Path, help='fresh absolute Linux filesystem directory for native clients')
    parser.add_argument('--provider', choices=('build', 'runtime', 'native', 'both'), default='both')
    parser.add_argument('--linkage', choices=('static', 'dynamic', 'both'), default='both')
    parser.add_argument('--filesystem', choices=('ram', 'ext2', 'both'), default='both')
    parser.add_argument('--firmware', choices=('bios', 'uefi', 'both'), default='both')
    parser.add_argument('--transport', choices=('modern', 'legacy', 'both'), default='both')
    args = parser.parse_args()
    directory = args.directory.resolve()
    if not directory.is_relative_to((ROOT / 'build').resolve()) or os.geteuid() or os.getegid():
        raise RuntimeError('use root and a fresh owned build directory')
    if not args.native and args.provider == 'native':
        parser.error('native libc is a Linux comparison, not a target provider')
    if args.native:
        if not args.fixtures or not args.fixtures.is_absolute() or args.fixtures.exists():
            parser.error('native clients require --fixtures with a fresh absolute Linux filesystem directory')
        args.fixtures.mkdir(mode=0o755)
        args.fixtures.chmod(0o755)
    directory.mkdir(parents=True, exist_ok=False)
    names = [CLIENT, 'scripts/path_descriptor_test.py', 'Makefile', 'dependencies.json',
             'sources.lock.json', 'ports.lock.json', 'boot/limine.conf', 'vendor/limine.h',
             'userspace/init/main.c', 'userspace/init/console.c', 'userspace/init/console.h',
             'userspace/init/seed_records.h', 'scripts/build_busybox.py']
    names += [Path(module.__file__).resolve().relative_to(ROOT).as_posix()
              for module in list(sys.modules.values()) if getattr(module, '__file__', None)
              and Path(module.__file__).resolve().is_relative_to(ROOT / 'scripts')]
    names += [path.relative_to(ROOT).as_posix() for path in (ROOT / 'kernel').rglob('*')
              if path.is_file() and path.suffix in ('.cpp', '.hpp', '.asm')]
    source = {name:digest(ROOT / name) for name in dict.fromkeys(names)}
    save(directory / 'source-inputs.json', source)
    for name in source:
        destination = directory / 'source' / name
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(ROOT / name, destination)
    rows, error = [], None
    try:
        if not args.native:
            subprocess.run(['make', '-s', '-j2', 'build/axiom64.elf', 'build/init', 'busybox'], cwd=ROOT, check=True)
        providers = ('build', 'runtime', 'native') if args.native else ('build', 'runtime')
        if args.provider != 'both':
            providers = (args.provider,)
        for provider in providers:
            for linkage in ('static', 'dynamic') if args.linkage == 'both' else (args.linkage,):
                profile = directory / (provider + '-' + linkage)
                profile.mkdir()
                program, product = build(profile, provider, linkage, args.native)
                if args.native:
                    native_fixture = args.fixtures / profile.name
                    native_fixture.mkdir(mode=0o755)
                    native_fixture.chmod(0o755)
                    row = execute([str(program), str(native_fixture / 'case')], profile, True)
                    row.update(provider=provider, linkage=linkage, product=product)
                    rows.append(row)
                    save(directory / 'results.json', rows)
                    row['exports'] = retain_native(profile, native_fixture)
                    save(directory / 'results.json', rows)
                    assert row['passed'], 'native path descriptor comparison failed'
                    row['retained_native_fixture'] = inspect_native_fixture(native_fixture / 'case')
                    save(directory / 'results.json', rows)
                    print('PATH_DESCRIPTOR_NATIVE_PASS ' + profile.name, flush=True)
                    continue
                for filesystem in ('ram', 'ext2') if args.filesystem == 'both' else (args.filesystem,):
                    case = profile / filesystem
                    case.mkdir()
                    filename = 'path-descriptors-' + filesystem
                    command = '/bin/' + filename + ' /tmp/path-descriptors'
                    if filesystem == 'ext2':
                        command = ('/bin/busybox mkdir -p /mnt/path && '
                                   '/bin/busybox mount -t ext2 /dev/vda /mnt/path && '
                                   '/bin/' + filename + ' /mnt/path/case mounted-block && /bin/busybox umount /mnt/path')
                    image = fixture(case, provider, linkage, program_builder=lambda *unused:(program, product),
                                    filename=filename, command=command)
                    for firmware in ('bios', 'uefi') if args.firmware == 'both' else (args.firmware,):
                        for transport in ('modern', 'legacy') if args.transport == 'both' else (args.transport,):
                            phase = case / (firmware + '-' + transport)
                            phase.mkdir()
                            disk = phase / 'disk.raw' if filesystem == 'ext2' else None
                            if disk:
                                create_volume(disk)
                            row = execute(qemu(image, phase, firmware, transport, disk), phase, False,
                                          observations=75 if filesystem == 'ext2' else 71)
                            row.update(provider=provider, linkage=linkage, firmware=firmware,
                                       transport=transport, filesystem=filesystem)
                            rows.append(row)
                            if disk:
                                check = subprocess.run(['e2fsck', '-f', '-n', str(disk)], capture_output=True, timeout=60)
                                (phase / 'fsck.log').write_bytes(check.stdout + check.stderr)
                                row['fsck_returncode'] = check.returncode
                                row['passed'] &= check.returncode == 0 and not re.search(
                                    rb'count wrong|Fix\?|Clear\?|still has errors|corrupt',
                                    check.stdout + check.stderr, re.IGNORECASE)
                                row['retained_disk'] = archive_fixture(disk, remove=True)
                            save(directory / 'results.json', rows)
                            assert row['passed'], 'guest path descriptor comparison failed: ' + str(phase)
                            print('PATH_DESCRIPTOR_GUEST_PASS ' + '/'.join(phase.relative_to(directory).parts), flush=True)
    except BaseException as problem:
        error = repr(problem)
    stable = source == {name:digest(ROOT / name) for name in source}
    complete = args.provider == args.linkage == 'both' and (args.native or
               args.filesystem == args.firmware == args.transport == 'both')
    receipt = dict(passed=error is None and stable and bool(rows) and all(row['passed'] for row in rows),
                   terminal=True, source_stable=stable, matrix_complete=complete and error is None,
                   native=args.native, cells=len(rows), observations=sum(row['observations'] for row in rows), error=error,
                   host_filesystem_repair=False)
    save(directory / 'receipt.json', receipt)
    assert receipt['passed'], error or 'path descriptor source changed'
    print('PATH_DESCRIPTOR_MATRIX_PASS cells=' + str(len(rows)), flush=True)


if __name__ == '__main__':
    main()
