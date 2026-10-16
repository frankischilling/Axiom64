#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Verify password decisions and actual irreversible privilege transitions."""
import argparse
import json
import os
from pathlib import Path
import shutil
import subprocess
import time

from account_management_test import SOURCES, crypt, invocation
from account_store_guest import fixture
from account_store_test import digest, environment
from build_musl import compiler_args
from fetch import ROOT

INPUTS = [*SOURCES, 'userspace/accounts/auth.c', 'userspace/accounts/auth.h',
          'userspace/accounts/protected.c', 'userspace/accounts/protected.h',
          'userspace/tests/security/account-auth.c', 'userspace/tests/security/account-observe.c',
          'scripts/account_auth_test.py', 'scripts/account_store_guest.py', 'Makefile',
          'scripts/image.py', 'userspace/init/main.c', 'userspace/init/console.c',
          'userspace/init/console.h', 'userspace/init/seed_records.h', 'boot/limine.conf']


def build(provider, linkage, directory):
    library = crypt(provider)
    stage = library / linkage / 'stage'
    compiler = ['gcc'] if provider == 'native' else compiler_args(provider)
    program = directory / ('account-auth-' + provider + '-' + linkage)
    command = [*compiler, '-std=c11', '-O2', '-g', '-Wall', '-Wextra', '-Werror',
               '-I' + str(stage / 'usr/include'),
               *(str(ROOT / 'userspace/accounts' / name) for name in
                 ('store.c', 'transaction.c', 'database.c', 'record.c', 'password.c', 'home.c', 'auth.c', 'protected.c')),
               str(ROOT / 'userspace/tests/security/account-auth.c'), '-o', str(program)]
    if linkage == 'static':
        command += ['-static', str(stage / 'usr/lib/libcrypt.a')]
    else:
        command += ['-L' + str(stage / 'usr/lib'), '-lcrypt']
    subprocess.run(command, env=environment(), check=True)
    observer = directory / ('account-observe-' + provider)
    observe_command = [*compiler, '-std=c11', '-O2', '-g', '-Wall', '-Wextra', '-Werror', '-static',
                       str(ROOT / 'userspace/tests/security/account-observe.c'), '-o', str(observer)]
    subprocess.run(observe_command, env=environment(), check=True)
    headers = subprocess.check_output(['readelf', '-W', '-l', str(program)], text=True)
    dynamic = subprocess.check_output(['readelf', '-W', '-d', str(program)], text=True)
    if linkage == 'static':
        assert 'INTERP' not in headers and '(NEEDED)' not in dynamic
    else:
        assert 'libcrypt.so.2' in dynamic and 'RPATH' not in dynamic and 'RUNPATH' not in dynamic
        if provider != 'native':
            assert '/lib/ld-musl-x86_64.so.1' in headers
    observer_headers = subprocess.check_output(['readelf', '-W', '-l', str(observer)], text=True)
    assert 'INTERP' not in observer_headers
    inputs = dict(command=command, binary_sha256=digest(program), headers=headers, dynamic=dynamic,
                  observer_command=observe_command, observer_sha256=digest(observer),
                  observer_headers=observer_headers, library_manifest_sha256=digest(library / 'manifest.json'))
    return program, observer, library, inputs


def execute(command, log, firmware=None):
    started = time.monotonic_ns()
    timed_out = False
    with log.open('wb') as output:
        process = subprocess.Popen(command, cwd=ROOT, env=environment(), stdin=subprocess.DEVNULL,
                                   stdout=output, stderr=subprocess.STDOUT)
        try:
            process.wait(timeout=120)
        except subprocess.TimeoutExpired:
            timed_out = True
            process.kill()
            process.wait()
    text = log.read_text().replace('\r\n', '\n')
    lines = text.splitlines()
    count = sum(line.startswith('ACCOUNT_AUTH_OBSERVATION ') for line in lines)
    passed = (not timed_out and process.returncode == (1 if firmware else 0) and count == 9 and
              lines.count('ACCOUNT_AUTH_PASS observations=9') == 1 and
              lines.count('ACCOUNT_SETUID_CONTROL_PASS real=1001 effective=0 saved=0') == 1 and
              lines.count('ACCOUNT_SERVICE_EXEC_PASS uid=1001 gid=1001 no_new_privileges=1 private_file_denied=1') == 1 and
              not any(marker in text for marker in ('ACCOUNT_AUTH_FAIL', 'PANIC:', 'FAULT pid=')))
    if firmware:
        passed = passed and lines.count('AXIOM64_TESTS_PASS') == 1 and 'AXIOM64_EXIT status=0' in text
        passed = passed and 'Firmware: ' + firmware.upper() in text
    return dict(command=command, returncode=process.returncode, timed_out=timed_out,
                elapsed_ns=time.monotonic_ns() - started, observations=count,
                log=str(log), log_sha256=digest(log), passed=passed)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--directory', type=Path, default=ROOT / 'build/account-auth')
    parser.add_argument('--native', action='store_true')
    parser.add_argument('--fixtures', type=Path)
    args = parser.parse_args()
    args.directory.mkdir(parents=True, exist_ok=False)
    if args.native:
        if os.geteuid() or os.getegid() or not args.fixtures or not args.fixtures.is_absolute() or args.fixtures.exists():
            raise RuntimeError('native set-ID controls require root and fresh native filesystem fixtures')
        args.fixtures.mkdir(mode=0o755)
        args.fixtures.chmod(0o755)
    names = [*INPUTS, *(path.relative_to(ROOT).as_posix() for path in (ROOT / 'kernel').rglob('*')
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
            program, observer, library, inputs = build(provider, linkage, case)
            if args.native:
                native_case = args.fixtures / case.name
                native_case.mkdir(mode=0o755)
                native_case.chmod(0o755)
                native_observer = native_case / 'account-observe'
                shutil.copyfile(observer, native_observer)
                native_observer.chmod(0o755)
                assert digest(native_observer) == inputs['observer_sha256']
                command = invocation(program, library, provider, linkage) + [str(native_case / 'data'), str(native_observer)]
                row = execute(command, case / 'native.log')
                row.update(provider=provider, linkage=linkage, inputs=inputs)
                rows.append(row)
            else:
                def builder(_provider, _linkage, _directory):
                    return program, inputs
                products = {'bin/account-observe': observer}
                if linkage == 'dynamic':
                    products['usr/lib/libcrypt.so.2'] = library / 'dynamic/stage/usr/lib/libcrypt.so.2.0.0'
                image = fixture(case, provider, linkage, program_builder=builder, filename='account-auth',
                                command='/bin/account-auth /run/account-auth /bin/account-observe', extra_products=products)
                for firmware in ('bios', 'uefi'):
                    command = ['qemu-system-x86_64', '-machine', 'pc', '-cpu', 'max', '-m', '256M', '-nic', 'none',
                               '-cdrom', str(image), '-display', 'none', '-serial', 'stdio', '-monitor', 'none',
                               '-no-reboot', '-device', 'isa-debug-exit,iobase=0xf4,iosize=0x04']
                    if firmware == 'uefi':
                        variables = case / 'OVMF_VARS.fd'
                        shutil.copyfile('/usr/share/OVMF/OVMF_VARS_4M.fd', variables)
                        command += ['-drive', 'if=pflash,format=raw,readonly=on,file=/usr/share/OVMF/OVMF_CODE_4M.fd',
                                    '-drive', 'if=pflash,format=raw,file=' + str(variables)]
                    row = execute(command, case / (firmware + '.log'), firmware)
                    row.update(provider=provider, linkage=linkage, firmware=firmware, inputs=inputs)
                    rows.append(row)
                    if not row['passed']:
                        break
            (args.directory / 'results.json').write_text(json.dumps(rows, indent=2) + '\n')
            if not rows[-1]['passed']:
                raise RuntimeError('account authentication profile failed: ' + case.name)
            print('ACCOUNT_AUTH_PROFILE_PASS ' + case.name, flush=True)
    assert source == {name: digest(ROOT / name) for name in source}
    count = 6 if args.native else 8
    assert len(rows) == count and all(row['passed'] for row in rows)
    print('ACCOUNT_AUTH_MATRIX_PASS profiles=' + str(count) + ' observations=' + str(sum(row['observations'] for row in rows)), flush=True)


if __name__ == '__main__':
    main()
