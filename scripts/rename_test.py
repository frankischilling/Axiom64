#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Compare atomic rename publication on Linux and generated RAM/ext2 guest fixtures."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import tarfile
import time

from account_store_guest import fixture
from account_store_test import digest, environment
from build_musl import compiler_args, loader
from ext2_test import create_volume
from fetch import ROOT
from fixture_archive import archive_fixture
from random_seed_crash_test import qemu_command

CLIENT = 'userspace/tests/fs/rename.c'
INPUTS = [CLIENT, 'scripts/rename_test.py', 'scripts/account_store_guest.py',
          'scripts/account_store_test.py', 'scripts/build_musl.py', 'scripts/ext2_test.py',
          'scripts/fixture_archive.py', 'scripts/random_seed_crash_test.py', 'scripts/image.py',
          'Makefile', 'dependencies.json', 'sources.lock.json', 'ports.lock.json', 'boot/limine.conf',
          'userspace/init/main.c', 'userspace/init/console.c', 'userspace/init/console.h',
          'userspace/init/seed_records.h']


def build(provider, linkage, directory, native_runtime=None):
    compiler = ['gcc'] if provider == 'native' else compiler_args(provider)
    program = directory / 'rename-test'
    command = [*compiler, '-std=c11', '-O2', '-g', '-Wall', '-Wextra', '-Werror',
               str(ROOT / CLIENT), '-o', str(program)]
    runtime = {}
    if linkage == 'static':
        command += ['-static']
    elif native_runtime is not None and provider != 'native':
        native_runtime.mkdir()
        source = loader(provider)
        destination = native_runtime / 'libc.so'
        shutil.copyfile(source, destination)
        destination.chmod(0o755)
        assert digest(destination) == digest(source)
        runtime['libc.so'] = dict(source=str(source), sha256=digest(destination))
        command += ['-Wl,--dynamic-linker=' + str(destination)]
    with (directory / 'compile.log').open('xb') as output:
        subprocess.run(command, cwd=ROOT, env=environment(), stdout=output,
                       stderr=subprocess.STDOUT, check=True)
    headers = subprocess.check_output(['readelf', '-W', '-l', str(program)], text=True)
    dynamic = subprocess.check_output(['readelf', '-W', '-d', str(program)], text=True)
    assert ('INTERP' not in headers) == (linkage == 'static')
    assert 'RPATH' not in dynamic and 'RUNPATH' not in dynamic
    return program, dict(command=command, binary_sha256=digest(program),
                         headers=headers, dynamic=dynamic, runtime=runtime)


def execute(command, logfile, expected):
    started = time.monotonic_ns()
    with logfile.open('xb') as output:
        result = subprocess.run(command, cwd=ROOT, env=environment(), stdout=output,
                                stderr=subprocess.STDOUT, timeout=90)
    text = logfile.read_text()
    return dict(command=command, returncode=result.returncode,
                elapsed_ns=time.monotonic_ns() - started, log=str(logfile),
                log_sha256=digest(logfile), passed=result.returncode == expected and
                text.splitlines().count('RENAME_PASS observations=10 concurrent_publications=32') == 1 and
                not any(marker in text for marker in ('RENAME_FAIL', 'PANIC:', 'FAULT pid=')) and
                (expected == 0 or (text.splitlines().count('AXIOM64_TESTS_PASS') == 1 and
                                   'AXIOM64_EXIT status=0' in text)))


def native(args, rows):
    assert args.fixtures and args.fixtures.is_absolute() and not args.fixtures.exists()
    args.fixtures.mkdir(mode=0o755)
    try:
        for provider in ('build', 'runtime', 'native') if args.provider == 'both' else (args.provider,):
            for linkage in ('static', 'dynamic') if args.linkage == 'both' else (args.linkage,):
                name = provider + '-' + linkage
                case = args.directory / name
                case.mkdir()
                linux = args.fixtures / name
                linux.mkdir(mode=0o755)
                program, inputs = build(provider, linkage, case, native_runtime=linux / 'runtime')
                copied = linux / 'rename-test'
                shutil.copyfile(program, copied)
                copied.chmod(0o755)
                assert digest(copied) == inputs['binary_sha256']
                row = execute([str(copied), str(linux / 'data')], case / 'guest.log', 0)
                row.update(provider=provider, linkage=linkage, inputs=inputs)
                rows.append(row)
                (args.directory / 'results.json').write_text(json.dumps(rows, indent=2) + '\n')
                if not row['passed']:
                    raise RuntimeError('native rename failed: ' + name)
                print('RENAME_NATIVE_PASS ' + name, flush=True)
    finally:
        archive = args.directory / 'native-fixtures.tar.gz'
        with tarfile.open(archive, 'w:gz') as output:
            output.add(args.fixtures, arcname='fixtures')
        with tarfile.open(archive, 'r:gz') as data:
            members = data.getmembers()
            for member in members:
                if member.isfile():
                    original = args.fixtures / member.name.removeprefix('fixtures/')
                    assert hashlib.file_digest(data.extractfile(member), 'sha256').hexdigest() == digest(original)
        (args.directory / 'native-fixtures.json').write_text(json.dumps(dict(
            sha256=digest(archive), verified_members=len(members)), indent=2) + '\n')


def guest(args, rows):
    subprocess.run(['make', '-s', '-j2', 'build/axiom64.elf', 'build/init', 'busybox'], cwd=ROOT, check=True)
    for provider in ('build', 'runtime') if args.provider == 'both' else (args.provider,):
        assert provider != 'native'
        for linkage in ('static', 'dynamic') if args.linkage == 'both' else (args.linkage,):
            for filesystem in ('ram', 'ext2') if args.filesystem == 'both' else (args.filesystem,):
                profile = provider + '-' + linkage + '-' + filesystem
                case = args.directory / profile
                case.mkdir()
                command = '/bin/rename-test /run/rename-fixture'
                if filesystem == 'ext2':
                    command = ('/bin/busybox mkdir -p /mnt/rename\n'
                               '/bin/busybox mount -t ext2 /dev/vda /mnt/rename\n'
                               '/bin/rename-test /mnt/rename/fixture\n'
                               '/bin/busybox umount /mnt/rename')
                image = fixture(case, provider, linkage, program_builder=build,
                                filename='rename-test', command=command)
                for firmware in ('bios', 'uefi') if args.firmware == 'both' else (args.firmware,):
                    for transport in ('modern', 'legacy') if args.transport == 'both' else (args.transport,):
                        cell = case / (firmware + '-' + transport)
                        cell.mkdir()
                        disk = cell / 'disk.raw'
                        if filesystem == 'ext2':
                            create_volume(disk)
                        command = qemu_command(cell, image, disk, firmware, transport)
                        if filesystem == 'ram':
                            device = command.index('-drive')
                            del command[device:device + 4]
                        row = execute(command, cell / 'guest.log', 1)
                        row.update(provider=provider, linkage=linkage, filesystem=filesystem,
                                   firmware=firmware, transport=transport)
                        rows.append(row)
                        (args.directory / 'results.json').write_text(json.dumps(rows, indent=2) + '\n')
                        if not row['passed']:
                            raise RuntimeError('guest rename failed: ' + profile + '/' + cell.name)
                        if filesystem == 'ext2':
                            with (cell / 'fsck.log').open('xb') as output:
                                checked = subprocess.run(['e2fsck', '-f', '-n', str(disk)],
                                                         stdout=output, stderr=subprocess.STDOUT)
                            if checked.returncode or re.search(
                                    r'count wrong|UNEXPECTED INCONSISTENCY|FILESYSTEM STILL HAS ERRORS',
                                    (cell / 'fsck.log').read_text(), re.I):
                                raise RuntimeError('rename left an inconsistent filesystem')
                            row['retained_disk'] = archive_fixture(disk, remove=True)
                            row['fsck_log_sha256'] = digest(cell / 'fsck.log')
                        print('RENAME_GUEST_PASS ' + profile + '/' + cell.name, flush=True)
                        (args.directory / 'results.json').write_text(json.dumps(rows, indent=2) + '\n')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--directory', type=Path, required=True)
    parser.add_argument('--native', action='store_true')
    parser.add_argument('--fixtures', type=Path)
    parser.add_argument('--provider', choices=('build', 'runtime', 'native', 'both'), default='both')
    parser.add_argument('--linkage', choices=('static', 'dynamic', 'both'), default='both')
    parser.add_argument('--filesystem', choices=('ram', 'ext2', 'both'), default='both')
    parser.add_argument('--firmware', choices=('bios', 'uefi', 'both'), default='both')
    parser.add_argument('--transport', choices=('modern', 'legacy', 'both'), default='both')
    args = parser.parse_args()
    assert not args.native or (not os.geteuid() and not os.getegid())
    args.directory = args.directory.resolve()
    assert args.directory.is_relative_to((ROOT / 'build').resolve())
    args.directory.mkdir(parents=True, exist_ok=False)
    names = [*INPUTS, *(path.relative_to(ROOT).as_posix() for path in (ROOT / 'kernel').rglob('*')
                        if path.is_file() and path.suffix in ('.cpp', '.hpp', '.asm'))]
    sources = {name: digest(ROOT / name) for name in names}
    (args.directory / 'source-inputs.json').write_text(json.dumps(sources, indent=2) + '\n')
    for name in sources:
        copied = args.directory / 'sources' / name
        copied.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(ROOT / name, copied)
        assert digest(copied) == sources[name]
    rows, error = [], None
    try:
        (native if args.native else guest)(args, rows)
    except BaseException as failure:
        error = repr(failure)
        raise
    finally:
        stable = sources == {name: digest(ROOT / name) for name in sources}
        (args.directory / 'receipt.json').write_text(json.dumps(dict(
            passed=error is None and stable, terminal=True, source_stable=stable, error=error,
            native=args.native, rows=len(rows), timeout_seconds=90), indent=2) + '\n')
    assert stable


if __name__ == '__main__':
    main()
