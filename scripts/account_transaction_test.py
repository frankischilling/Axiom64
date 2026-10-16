#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Verify generation/home intent at actual process and publication boundaries."""
import argparse
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import time

from account_session_test import retain_native
from account_store_guest import fixture
from account_store_test import STORE_INPUTS, STORE_MODULES, digest, environment
from build_musl import compiler_args, loader
from ext2_test import create_volume
from fetch import ROOT
from fixture_archive import archive_fixture
from random_seed_crash_test import qemu_command

CLIENT = 'userspace/tests/security/account-transaction.c'
SOURCES = [*STORE_INPUTS, CLIENT, 'scripts/account_transaction_test.py',
           'scripts/account_session_test.py', 'scripts/account_store_guest.py',
           'scripts/account_store_test.py', 'scripts/build_musl.py', 'scripts/ext2_test.py',
           'scripts/fixture_archive.py', 'scripts/random_seed_crash_test.py', 'scripts/image.py',
           'Makefile', 'dependencies.json', 'sources.lock.json', 'ports.lock.json', 'boot/limine.conf',
           'userspace/init/main.c', 'userspace/init/console.c', 'userspace/init/console.h',
           'userspace/init/seed_records.h']


def build(provider, linkage, directory, runtime=None, sanitize=False):
    compiler = ['gcc'] if provider == 'native' else compiler_args(provider)
    program = directory / 'account-transaction'
    command = [*compiler, '-std=c11', '-O2', '-g', '-Wall', '-Wextra', '-Werror',
               *(str(ROOT / name) for name in STORE_MODULES), str(ROOT / CLIENT),
               '-Wl,--wrap=openat,--wrap=mkdirat,--wrap=fsync,--wrap=fsetxattr,--wrap=write,--wrap=renameat,--wrap=syscall',
               '-o', str(program)]
    if linkage == 'static':
        command += ['-static']
    elif runtime is not None and provider != 'native':
        runtime.mkdir()
        destination = runtime / 'libc.so'
        shutil.copyfile(loader(provider), destination)
        destination.chmod(0o755)
        assert digest(destination) == digest(loader(provider))
        command += ['-Wl,--dynamic-linker=' + str(destination)]
    if sanitize:
        command += ['-fsanitize=address,undefined', '-fno-omit-frame-pointer']
    with (directory / 'compile.log').open('xb') as output:
        subprocess.run(command, cwd=ROOT, env=environment(), stdout=output,
                       stderr=subprocess.STDOUT, check=True)
    headers = subprocess.check_output(['readelf', '-W', '-l', str(program)], text=True)
    assert ('INTERP' not in headers) == (linkage == 'static')
    return program, dict(command=command, binary_sha256=digest(program), headers=headers)


def execute(command, log, firmware=None):
    started = time.monotonic_ns()
    with log.open('xb') as output:
        result = subprocess.run(command, cwd=ROOT, env=environment(), stdin=subprocess.DEVNULL,
                                stdout=output, stderr=subprocess.STDOUT, timeout=90)
    text = log.read_text().replace('\r\n', '\n')
    lines = text.splitlines()
    observations = sum(line.startswith('ACCOUNT_TRANSACTION_OBSERVATION ') for line in lines)
    passed = (result.returncode == (1 if firmware else 0) and observations == 18
              and lines.count('ACCOUNT_TRANSACTION_PASS observations=18') == 1
              and not any(value in text for value in ('ACCOUNT_TRANSACTION_FAIL', 'PANIC:', 'FAULT pid=',
                                                     'AddressSanitizer', 'runtime error:')))
    if firmware:
        passed = passed and lines.count('AXIOM64_TESTS_PASS') == 1 and 'AXIOM64_EXIT status=0' in lines
        passed = passed and 'Firmware: ' + firmware.upper() in lines
    return dict(command=command, returncode=result.returncode, elapsed_ns=time.monotonic_ns() - started,
                log=str(log), log_sha256=digest(log), observations=observations, passed=passed)


def native(args, rows):
    assert args.fixtures and args.fixtures.is_absolute() and not args.fixtures.exists()
    args.fixtures.mkdir(mode=0o755)
    profiles = [('native', 'dynamic')] if args.sanitize else [
        (provider, linkage) for provider in ('build', 'runtime', 'native') for linkage in ('static', 'dynamic')]
    for provider, linkage in profiles:
        case = args.directory / (provider + '-' + linkage)
        case.mkdir()
        linux = args.fixtures / case.name
        linux.mkdir(mode=0o755)
        program, inputs = build(provider, linkage, case, linux / 'runtime', args.sanitize)
        copied = linux / 'account-transaction'
        shutil.copyfile(program, copied)
        copied.chmod(0o755)
        assert digest(copied) == inputs['binary_sha256']
        row = execute([str(copied), str(linux / 'data')], case / 'native.log')
        row.update(provider=provider, linkage=linkage, inputs=inputs, exports=retain_native(case, linux))
        rows.append(row)
        (args.directory / 'results.json').write_text(json.dumps(rows, indent=2) + '\n')
        if not row['passed']:
            raise RuntimeError('native transaction failed: ' + case.name)
        print('ACCOUNT_TRANSACTION_NATIVE_PASS ' + case.name, flush=True)


def guest(args, rows):
    subprocess.run(['make', '-s', '-j2', 'build/axiom64.elf', 'build/init', 'busybox'], cwd=ROOT, check=True)
    for provider in ('build', 'runtime'):
        for linkage in ('static', 'dynamic'):
            for filesystem in ('ram', 'ext2') if args.filesystem == 'both' else (args.filesystem,):
                case = args.directory / (provider + '-' + linkage + '-' + filesystem)
                case.mkdir()
                command = '/bin/account-transaction /run/transaction-fixture'
                if filesystem == 'ext2':
                    command = ('/bin/busybox mkdir -p /mnt/transaction-test\n'
                               '/bin/busybox mount -t ext2 /dev/vda /mnt/transaction-test\n'
                               '/bin/account-transaction /mnt/transaction-test/fixture\n'
                               '/bin/busybox umount /mnt/transaction-test')
                image = fixture(case, provider, linkage, program_builder=build,
                                filename='account-transaction', command=command)
                for firmware in ('bios', 'uefi') if args.firmware == 'both' else (args.firmware,):
                    for transport in ('modern', 'legacy') if args.transport == 'both' else (args.transport,):
                        cell = case / (firmware + '-' + transport)
                        cell.mkdir()
                        disk = cell / 'disk.raw'
                        if filesystem == 'ext2':
                            create_volume(disk)
                        command = qemu_command(cell, image, disk, firmware, transport)
                        if filesystem == 'ram':
                            drive = command.index('-drive')
                            del command[drive:drive + 4]
                        row = execute(command, cell / 'guest.log', firmware)
                        row.update(provider=provider, linkage=linkage, filesystem=filesystem,
                                   firmware=firmware, transport=transport)
                        rows.append(row)
                        (args.directory / 'results.json').write_text(json.dumps(rows, indent=2) + '\n')
                        if not row['passed']:
                            raise RuntimeError('guest transaction failed: ' + case.name + '/' + cell.name)
                        if filesystem == 'ext2':
                            log = cell / 'fsck.log'
                            with log.open('xb') as output:
                                checked = subprocess.run(['e2fsck', '-f', '-n', str(disk)],
                                                         stdout=output, stderr=subprocess.STDOUT)
                            if checked.returncode or re.search(
                                    r'count wrong|UNEXPECTED INCONSISTENCY|FILESYSTEM STILL HAS ERRORS',
                                    log.read_text(), re.I):
                                raise RuntimeError('transaction fixture filesystem is inconsistent')
                            row.update(retained_disk=archive_fixture(disk, remove=True),
                                       fsck_returncode=checked.returncode, fsck_log_sha256=digest(log))
                        print('ACCOUNT_TRANSACTION_GUEST_PASS ' + case.name + '/' + cell.name, flush=True)
                        (args.directory / 'results.json').write_text(json.dumps(rows, indent=2) + '\n')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--directory', type=Path, required=True)
    parser.add_argument('--native', action='store_true')
    parser.add_argument('--sanitize', action='store_true')
    parser.add_argument('--fixtures', type=Path)
    parser.add_argument('--filesystem', choices=('ram', 'ext2', 'both'), default='both')
    parser.add_argument('--firmware', choices=('bios', 'uefi', 'both'), default='both')
    parser.add_argument('--transport', choices=('modern', 'legacy', 'both'), default='both')
    args = parser.parse_args()
    assert (not args.native or (not os.geteuid() and not os.getegid())) and (not args.sanitize or args.native)
    args.directory = args.directory.resolve()
    assert args.directory.is_relative_to((ROOT / 'build').resolve())
    args.directory.mkdir(parents=True, exist_ok=False)
    names = [*SOURCES, *(path.relative_to(ROOT).as_posix() for path in (ROOT / 'kernel').rglob('*')
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
    except BaseException as caught:
        error = repr(caught)
        raise
    finally:
        stable = sources == {name: digest(ROOT / name) for name in sources}
        (args.directory / 'receipt.json').write_text(json.dumps(dict(
            passed=error is None and stable, terminal=True, source_stable=stable, error=error,
            native=args.native, sanitize=args.sanitize, rows=len(rows), timeout_seconds=90), indent=2) + '\n')
    assert stable


if __name__ == '__main__':
    main()
