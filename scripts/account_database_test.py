#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Run actual account record validation through native libc and fresh guest kernels."""
import argparse
import json
import os
from pathlib import Path
import shutil
import subprocess
import time

from account_store_guest import fixture
from account_store_test import digest, environment
from build_musl import compiler_args, ensure, loader
from fetch import ROOT

SOURCES = ['userspace/accounts/store.c', 'userspace/accounts/store.h',
           'userspace/accounts/database.c', 'userspace/accounts/database.h',
           'userspace/accounts/record.c', 'userspace/accounts/record.h', 'userspace/accounts/password.h',
           'userspace/tests/security/account-database.c', 'scripts/account_database_test.py',
           'scripts/account_store_test.py', 'scripts/account_store_guest.py', 'scripts/build_musl.py',
           'sources.lock.json', 'Makefile', 'scripts/image.py', 'userspace/init/main.c',
           'userspace/init/console.c', 'userspace/init/console.h',
           'userspace/init/seed_records.h', 'boot/limine.conf']


def build(provider, linkage, directory):
    command = ['gcc'] if provider == 'native' else compiler_args(provider)
    program = directory / ('account-database-' + provider + '-' + linkage)
    command += ['-std=c11', '-O2', '-g', '-Wall', '-Wextra', '-Werror',
                *(str(ROOT / name) for name in ('userspace/accounts/store.c', 'userspace/accounts/database.c',
                  'userspace/accounts/record.c', 'userspace/tests/security/account-database.c')),
                '-o', str(program)]
    if linkage == 'static':
        command += ['-static']
    subprocess.run(command, env=environment(), check=True)
    headers = subprocess.check_output(['readelf', '-W', '-l', str(program)], text=True)
    dynamic = subprocess.check_output(['readelf', '-W', '-d', str(program)], text=True)
    if linkage == 'static':
        assert 'INTERP' not in headers and '(NEEDED)' not in dynamic
    else:
        assert '(NEEDED)' in dynamic and 'RPATH' not in dynamic and 'RUNPATH' not in dynamic
        if provider != 'native':
            assert '/lib/ld-musl-x86_64.so.1' in headers
    inputs = dict(command=command, binary_sha256=digest(program), headers=headers, dynamic=dynamic)
    if provider != 'native':
        inputs['libc_manifest_sha256'] = digest(ensure(provider) / 'manifest.json')
    return program, inputs


def result(command, log, firmware=None):
    started = time.monotonic_ns()
    timed_out = False
    with log.open('wb') as output:
        process = subprocess.Popen(command, cwd=ROOT, env=environment(), stdin=subprocess.DEVNULL,
                                   stdout=output, stderr=subprocess.STDOUT)
        try:
            process.wait(timeout=90)
        except subprocess.TimeoutExpired:
            timed_out = True
            process.kill()
            process.wait()
    text = log.read_text().replace('\r\n', '\n')
    lines = text.splitlines()
    observations = sum(line.startswith('ACCOUNT_DATABASE_OBSERVATION ') for line in lines)
    passed = (not timed_out and process.returncode == (1 if firmware else 0) and observations == 21
              and lines.count('ACCOUNT_DATABASE_PASS observations=21') == 1
              and not any(marker in text for marker in ('ACCOUNT_DATABASE_FAIL', 'PANIC:', 'FAULT pid=')))
    if firmware:
        passed = passed and lines.count('AXIOM64_TESTS_PASS') == 1 and 'AXIOM64_EXIT status=0' in text
        passed = passed and 'Firmware: ' + firmware.upper() in text
    return dict(command=command, returncode=process.returncode, timed_out=timed_out,
                elapsed_ns=time.monotonic_ns() - started, observations=observations,
                log=str(log), log_sha256=digest(log), passed=passed)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--directory', type=Path, default=ROOT / 'build/account-database')
    parser.add_argument('--native', action='store_true')
    parser.add_argument('--fixtures', type=Path)
    args = parser.parse_args()
    if args.native and (os.geteuid() or os.getegid() or not args.fixtures or not args.fixtures.is_absolute() or args.fixtures.exists()):
        raise RuntimeError('native account controls require root and a fresh absolute fixture directory')
    args.directory.mkdir(parents=True, exist_ok=False)
    if args.native:
        args.fixtures.mkdir(mode=0o755)
        args.fixtures.chmod(0o755)
    names = [*SOURCES, *(path.relative_to(ROOT).as_posix() for path in (ROOT / 'kernel').rglob('*')
                        if path.is_file() and path.suffix in ('.cpp', '.hpp', '.asm'))]
    source = {name: digest(ROOT / name) for name in names}
    (args.directory / 'source-inputs.json').write_text(json.dumps(source, indent=2) + '\n')
    if not args.native:
        subprocess.run(['make', '-s', '-j2', 'build/axiom64.elf', 'build/init', 'busybox'], cwd=ROOT, check=True)
    rows = []
    for provider in ('build', 'runtime', 'native') if args.native else ('build', 'runtime'):
        for linkage in ('static', 'dynamic'):
            case = args.directory / (provider + '-' + linkage)
            case.mkdir()
            if args.native:
                program, inputs = build(provider, linkage, case)
                command = [str(program), str(args.fixtures / case.name)]
                if linkage == 'dynamic':
                    interpreter = Path('/lib64/ld-linux-x86-64.so.2') if provider == 'native' else loader(provider)
                    paths = '/lib/x86_64-linux-gnu' if provider == 'native' else ':'.join(
                        str(ensure(provider) / name) for name in ('sysroot/lib', 'sysroot/usr/lib'))
                    command = [str(interpreter), '--library-path', paths, *command]
                    inputs['loader_sha256'] = digest(interpreter)
                row = result(command, case / 'native.log')
                row.update(provider=provider, linkage=linkage, inputs=inputs)
                rows.append(row)
            else:
                image = fixture(case, provider, linkage, program_builder=build, filename='account-database',
                                command='/bin/account-database /run/account-database')
                for firmware in ('bios', 'uefi'):
                    command = ['qemu-system-x86_64', '-machine', 'pc', '-cpu', 'max', '-m', '256M', '-nic', 'none',
                               '-cdrom', str(image), '-display', 'none', '-serial', 'stdio', '-monitor', 'none',
                               '-no-reboot', '-device', 'isa-debug-exit,iobase=0xf4,iosize=0x04']
                    if firmware == 'uefi':
                        variables = case / 'OVMF_VARS.fd'
                        shutil.copyfile('/usr/share/OVMF/OVMF_VARS_4M.fd', variables)
                        command += ['-drive', 'if=pflash,format=raw,readonly=on,file=/usr/share/OVMF/OVMF_CODE_4M.fd',
                                    '-drive', 'if=pflash,format=raw,file=' + str(variables)]
                    row = result(command, case / (firmware + '.log'), firmware)
                    row.update(provider=provider, linkage=linkage, firmware=firmware)
                    rows.append(row)
                    if not row['passed']:
                        break
            (args.directory / 'results.json').write_text(json.dumps(rows, indent=2) + '\n')
            if not rows[-1]['passed']:
                raise RuntimeError('account database profile failed: ' + case.name)
            print('ACCOUNT_DATABASE_PROFILE_PASS ' + case.name, flush=True)
    assert source == {name: digest(ROOT / name) for name in source}
    expected = 6 if args.native else 8
    assert len(rows) == expected and all(row['passed'] for row in rows)
    print('ACCOUNT_DATABASE_MATRIX_PASS profiles=' + str(expected) +
          ' observations=' + str(sum(row['observations'] for row in rows)), flush=True)


if __name__ == '__main__':
    main()
