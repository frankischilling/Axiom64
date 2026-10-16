#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Verify actual private terminal entry, cancellation and complete echo restoration."""
import argparse
import json
import os
from pathlib import Path
import shutil
import subprocess
import time

from account_management_test import crypt, invocation
from account_store_guest import fixture
from account_store_test import digest, environment
from build_musl import compiler_args
from fetch import ROOT

INPUTS = ['userspace/accounts/' + name for name in ('password.c', 'password.h', 'secret.c', 'secret.h')]
INPUTS += ['userspace/tests/security/account-secret.c', 'scripts/account_secret_test.py',
           'scripts/account_management_test.py', 'scripts/account_store_guest.py', 'scripts/account_store_test.py',
           'scripts/build_libxcrypt.py', 'scripts/build_musl.py', 'scripts/linux_uapi.py', 'Makefile',
           'dependencies.json', 'sources.lock.json', 'scripts/image.py', 'userspace/init/main.c',
           'userspace/init/console.c', 'userspace/init/console.h',
           'userspace/init/seed_records.h', 'boot/limine.conf']


def build(provider, linkage, directory):
    library = crypt(provider)
    stage = library / linkage / 'stage'
    compiler = ['gcc'] if provider == 'native' else compiler_args(provider)
    program = directory / ('account-secret-' + provider + '-' + linkage)
    command = [*compiler, '-std=c11', '-O2', '-g', '-Wall', '-Wextra', '-Werror',
               '-I' + str(stage / 'usr/include'),
               str(ROOT / 'userspace/accounts/password.c'), str(ROOT / 'userspace/accounts/secret.c'),
               str(ROOT / 'userspace/tests/security/account-secret.c'),
               '-Wl,--wrap=read', '-Wl,--wrap=pselect', '-o', str(program)]
    if linkage == 'static':
        command += ['-static', str(stage / 'usr/lib/libcrypt.a')]
    else:
        command += ['-L' + str(stage / 'usr/lib'), '-lcrypt']
    subprocess.run(command, env=environment(), check=True)
    headers = subprocess.check_output(['readelf', '-W', '-l', str(program)], text=True)
    dynamic = subprocess.check_output(['readelf', '-W', '-d', str(program)], text=True)
    if linkage == 'static':
        assert 'INTERP' not in headers and '(NEEDED)' not in dynamic
    else:
        assert 'libcrypt.so.2' in dynamic and 'RPATH' not in dynamic and 'RUNPATH' not in dynamic
        if provider != 'native':
            assert '/lib/ld-musl-x86_64.so.1' in headers
    inputs = dict(command=command, binary_sha256=digest(program), headers=headers, dynamic=dynamic,
                  library_manifest_sha256=digest(library / 'manifest.json'))
    return program, library, inputs


def execute(command, log, firmware=None):
    start = time.monotonic_ns()
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
    count = sum(line.startswith('ACCOUNT_SECRET_OBSERVATION ') for line in lines)
    passed = (not timed_out and process.returncode == (1 if firmware else 0) and count == 10 and
              lines.count('ACCOUNT_SECRET_PASS observations=10') == 1 and
              not any(marker in text for marker in ('ACCOUNT_SECRET_FAIL', 'PANIC:', 'FAULT pid=')))
    if firmware:
        passed = passed and lines.count('AXIOM64_TESTS_PASS') == 1 and 'AXIOM64_EXIT status=0' in text
        passed = passed and 'Firmware: ' + firmware.upper() in text
    return dict(command=command, returncode=process.returncode, timed_out=timed_out,
                elapsed_ns=time.monotonic_ns() - start, observations=count,
                log=str(log), log_sha256=digest(log), passed=passed)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--directory', type=Path, default=ROOT / 'build/account-secret')
    parser.add_argument('--native', action='store_true')
    args = parser.parse_args()
    if args.native and (os.geteuid() or os.getegid()):
        raise RuntimeError('native terminal and identity controls require root')
    args.directory.mkdir(parents=True, exist_ok=False)
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
            program, library, inputs = build(provider, linkage, case)
            if args.native:
                row = execute(invocation(program, library, provider, linkage), case / 'native.log')
                row.update(provider=provider, linkage=linkage, inputs=inputs)
                rows.append(row)
                (args.directory / 'results.json').write_text(json.dumps(rows, indent=2) + '\n')
                if not row['passed']:
                    raise RuntimeError('native secret profile failed: ' + case.name)
                print('ACCOUNT_SECRET_NATIVE_PASS ' + case.name, flush=True)
            else:
                def builder(_provider, _linkage, _directory):
                    return program, inputs
                products = {} if linkage == 'static' else {
                    'usr/lib/libcrypt.so.2': library / 'dynamic/stage/usr/lib/libcrypt.so.2.0.0'}
                image = fixture(case, provider, linkage, program_builder=builder, filename='account-secret',
                                command='/bin/account-secret', extra_products=products)
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
                    (args.directory / 'results.json').write_text(json.dumps(rows, indent=2) + '\n')
                    if not row['passed']:
                        raise RuntimeError('guest secret profile failed: ' + case.name + '/' + firmware)
                    print('ACCOUNT_SECRET_GUEST_PASS ' + case.name + '/' + firmware, flush=True)
    if source != {name: digest(ROOT / name) for name in source}:
        raise RuntimeError('account secret source changed during validation')
    print('ACCOUNT_SECRET_MATRIX_PASS profiles=' + str(len(rows)) + ' observations=' + str(len(rows) * 10), flush=True)


if __name__ == '__main__':
    main()
