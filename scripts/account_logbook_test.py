#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Exercise real login journals, process leases, recovery and protected projections."""
import argparse
import json
import os
from pathlib import Path
import shutil
import subprocess
import time

from account_store_guest import fixture
from account_store_test import digest, environment
from account_session_test import retain_native
from build_musl import compiler_args, ensure, loader
from fetch import ROOT

SOURCES = ['userspace/accounts/' + name for name in ('store.c', 'store.h', 'database.c', 'database.h',
           'record.c', 'record.h', 'protected.c', 'protected.h', 'login_record.c', 'login_record.h',
           'logbook.c', 'logbook.h', 'auth.h')]
INPUTS = [*SOURCES, 'userspace/tests/security/account-logbook.c', 'scripts/account_logbook_test.py',
          'userspace/tests/security/account-login-libc.c',
          'scripts/account_session_test.py', 'scripts/account_store_guest.py', 'scripts/account_store_test.py',
          'scripts/build_musl.py', 'Makefile', 'sources.lock.json', 'dependencies.json', 'scripts/image.py',
          'userspace/init/main.c', 'userspace/init/console.c', 'userspace/init/console.h',
          'userspace/init/seed_records.h', 'boot/limine.conf']


def build(provider, linkage, directory):
    compiler = ['gcc'] if provider == 'native' else compiler_args(provider)
    program = directory / ('account-logbook-' + provider + '-' + linkage)
    command = [*compiler, '-std=c11', '-O2', '-g', '-Wall', '-Wextra', '-Werror',
               *(str(ROOT / name) for name in SOURCES if name.endswith('.c')),
               str(ROOT / 'userspace/tests/security/account-logbook.c'), '-o', str(program)]
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


def execute(command, log, firmware=None):
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
    count = sum(line.startswith('ACCOUNT_LOGBOOK_OBSERVATION ') for line in lines)
    passed = (not timed_out and process.returncode == (1 if firmware else 0) and count == 8 and
              lines.count('ACCOUNT_LOGBOOK_PASS observations=8 damaged_bits=3584') == 1 and
              not any(marker in text for marker in ('ACCOUNT_LOGBOOK_FAIL', 'PANIC:', 'FAULT pid=')))
    if firmware:
        passed = passed and lines.count('AXIOM64_TESTS_PASS') == 1 and 'AXIOM64_EXIT status=0' in text
        passed = passed and 'Firmware: ' + firmware.upper() in text
    return dict(command=command, returncode=process.returncode, timed_out=timed_out,
                elapsed_ns=time.monotonic_ns() - started, observations=count,
                log=str(log), log_sha256=digest(log), passed=passed)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--directory', type=Path, default=ROOT / 'build/account-logbook')
    parser.add_argument('--native', action='store_true')
    parser.add_argument('--fixtures', type=Path)
    args = parser.parse_args()
    if args.native:
        if os.geteuid() or os.getegid() or not args.fixtures or not args.fixtures.is_absolute() or args.fixtures.exists():
            raise RuntimeError('native logbook controls require root and fresh Linux filesystem fixtures')
        args.fixtures.mkdir(mode=0o755)
        args.fixtures.chmod(0o755)
    args.directory.mkdir(parents=True, exist_ok=False)
    names = [*INPUTS, *(path.relative_to(ROOT).as_posix() for path in (ROOT / 'kernel').rglob('*')
                       if path.is_file() and path.suffix in ('.cpp', '.hpp', '.asm'))]
    source = {name: digest(ROOT / name) for name in names}
    (args.directory / 'source-inputs.json').write_text(json.dumps(source, indent=2) + '\n')
    if not args.native:
        subprocess.run(['make', '-s', '-j2', 'build/axiom64.elf', 'build/init', 'busybox'], cwd=ROOT, check=True)
    rows = []
    reader = args.directory / 'account-login-libc'
    reader_command = ['gcc', '-std=c11', '-O2', '-g', '-Wall', '-Wextra', '-Werror', '-static',
                      str(ROOT / 'userspace/tests/security/account-login-libc.c'), '-o', str(reader)]
    subprocess.run(reader_command, env=environment(), check=True)
    reader_inputs = dict(command=reader_command, sha256=digest(reader),
                         headers=subprocess.check_output(['readelf', '-W', '-l', str(reader)], text=True))
    assert 'INTERP' not in reader_inputs['headers']
    (args.directory / 'reader-inputs.json').write_text(json.dumps(reader_inputs, indent=2) + '\n')
    for provider in ('build', 'runtime', 'native') if args.native else ('build', 'runtime'):
        for linkage in ('static', 'dynamic'):
            case = args.directory / (provider + '-' + linkage)
            case.mkdir()
            program, inputs = build(provider, linkage, case)
            if args.native:
                native_case = args.fixtures / case.name
                native_case.mkdir(mode=0o755)
                native_case.chmod(0o755)
                command = [str(program), str(native_case / 'data')]
                if linkage == 'dynamic':
                    interpreter = Path('/lib64/ld-linux-x86-64.so.2') if provider == 'native' else loader(provider)
                    command = [str(interpreter), *command]
                row = execute(command, case / 'native.log')
                reference_log = case / 'libc-reader.log'
                with reference_log.open('wb') as output:
                    reference = subprocess.run([str(reader), str(native_case / 'data/records')],
                                               stdout=output, stderr=subprocess.STDOUT, timeout=30)
                reference_text = reference_log.read_text()
                row['libc_reader'] = dict(returncode=reference.returncode,
                                          log_sha256=digest(reference_log), binary_sha256=digest(reader))
                row['passed'] = row['passed'] and reference.returncode == 0 and \
                    any(line.startswith('ACCOUNT_LOGIN_LIBC_PASS ') for line in reference_text.splitlines())
                row.update(provider=provider, linkage=linkage, inputs=inputs)
                row['native_exports'] = retain_native(case, native_case)
                rows.append(row)
                (args.directory / 'results.json').write_text(json.dumps(rows, indent=2) + '\n')
                if not row['passed']:
                    raise RuntimeError('native logbook profile failed: ' + case.name)
                print('ACCOUNT_LOGBOOK_NATIVE_PASS ' + case.name, flush=True)
            else:
                def builder(_provider, _linkage, _directory):
                    return program, inputs
                image = fixture(case, provider, linkage, program_builder=builder, filename='account-logbook',
                                command='/bin/account-logbook /run/account-logbook\n/bin/account-login-libc /run/account-logbook/records',
                                extra_products={'bin/account-login-libc': reader})
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
                    text = (case / (firmware + '.log')).read_text()
                    row['passed'] = row['passed'] and \
                        any(line.startswith('ACCOUNT_LOGIN_LIBC_PASS ') for line in text.splitlines())
                    row.update(provider=provider, linkage=linkage, firmware=firmware, inputs=inputs)
                    rows.append(row)
                    (args.directory / 'results.json').write_text(json.dumps(rows, indent=2) + '\n')
                    if not row['passed']:
                        raise RuntimeError('guest logbook profile failed: ' + case.name + '/' + firmware)
                    print('ACCOUNT_LOGBOOK_GUEST_PASS ' + case.name + '/' + firmware, flush=True)
    if source != {name: digest(ROOT / name) for name in source}:
        raise RuntimeError('account logbook source changed during validation')
    print('ACCOUNT_LOGBOOK_MATRIX_PASS profiles=' + str(len(rows)) + ' observations=' + str(len(rows) * 8), flush=True)


if __name__ == '__main__':
    main()
