#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Compare POSIX/OFD byte-range ownership and blocked calls with native Linux."""
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

INPUTS = ['userspace/tests/security/record-locks.c', 'scripts/record_lock_test.py',
          'userspace/tests/security/record-lock-exec.c',
          'scripts/account_store_guest.py', 'scripts/account_store_test.py', 'scripts/build_musl.py',
          'Makefile', 'sources.lock.json', 'dependencies.json', 'scripts/image.py',
          'userspace/init/main.c', 'userspace/init/console.c', 'userspace/init/console.h',
          'userspace/init/seed_records.h', 'boot/limine.conf']


def build(provider, linkage, directory):
    compiler = ['gcc'] if provider == 'native' else compiler_args(provider)
    program = directory / ('record-locks-' + provider + '-' + linkage)
    command = [*compiler, '-std=c11', '-O2', '-g', '-Wall', '-Wextra', '-Werror', '-pthread',
               str(ROOT / INPUTS[0]), '-o', str(program)]
    if linkage == 'static':
        command += ['-static']
    subprocess.run(command, env=environment(), check=True)
    observer = directory / ('record-lock-exec-' + provider)
    observer_command = [*compiler, '-std=c11', '-O2', '-g', '-Wall', '-Wextra', '-Werror', '-static',
                        str(ROOT / 'userspace/tests/security/record-lock-exec.c'), '-o', str(observer)]
    subprocess.run(observer_command, env=environment(), check=True)
    headers = subprocess.check_output(['readelf', '-W', '-l', str(program)], text=True)
    dynamic = subprocess.check_output(['readelf', '-W', '-d', str(program)], text=True)
    if linkage == 'static':
        assert 'INTERP' not in headers and '(NEEDED)' not in dynamic
    else:
        assert '(NEEDED)' in dynamic and 'RPATH' not in dynamic and 'RUNPATH' not in dynamic
        if provider != 'native':
            assert '/lib/ld-musl-x86_64.so.1' in headers
    return program, observer, dict(command=command, binary_sha256=digest(program), headers=headers, dynamic=dynamic,
                                  observer_command=observer_command, observer_sha256=digest(observer))


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
    count = sum(line.startswith('RECORD_LOCK_OBSERVATION ') for line in lines)
    passed = (not timed_out and process.returncode == (1 if firmware else 0) and count == 8 and
              lines.count('RECORD_LOCK_PASS observations=8') == 1 and
              not any(marker in text for marker in ('RECORD_LOCK_FAIL', 'PANIC:', 'FAULT pid=')))
    if firmware:
        passed = passed and lines.count('AXIOM64_TESTS_PASS') == 1 and 'AXIOM64_EXIT status=0' in text
        passed = passed and 'Firmware: ' + firmware.upper() in text
    return dict(command=command, returncode=process.returncode, timed_out=timed_out,
                elapsed_ns=time.monotonic_ns() - start, observations=count,
                log=str(log), log_sha256=digest(log), passed=passed)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--directory', type=Path, default=ROOT / 'build/record-locks')
    parser.add_argument('--native', action='store_true')
    parser.add_argument('--fixtures', type=Path)
    args = parser.parse_args()
    if args.native:
        if not args.fixtures or not args.fixtures.is_absolute() or args.fixtures.exists():
            raise RuntimeError('use fresh absolute native fixtures')
        args.fixtures.mkdir()
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
            program, observer, inputs = build(provider, linkage, case)
            if args.native:
                command = [str(program), str(args.fixtures / case.name), str(observer)]
                if linkage == 'dynamic':
                    interpreter = Path('/lib64/ld-linux-x86-64.so.2') if provider == 'native' else loader(provider)
                    command = [str(interpreter), *command]
                row = execute(command, case / 'native.log')
                row.update(provider=provider, linkage=linkage, inputs=inputs)
                rows.append(row)
                (args.directory / 'results.json').write_text(json.dumps(rows, indent=2) + '\n')
                if not row['passed']:
                    raise RuntimeError('native record lock profile failed: ' + case.name)
                print('RECORD_LOCK_NATIVE_PASS ' + case.name, flush=True)
            else:
                def builder(_provider, _linkage, _directory):
                    return program, inputs
                image = fixture(case, provider, linkage, program_builder=builder, filename='record-locks',
                                command='/bin/record-locks /run/record-locks /bin/record-lock-exec',
                                extra_products={'bin/record-lock-exec': observer})
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
                        raise RuntimeError('guest record lock profile failed: ' + case.name + '/' + firmware)
                    print('RECORD_LOCK_GUEST_PASS ' + case.name + '/' + firmware, flush=True)
    if source != {name: digest(ROOT / name) for name in source}:
        raise RuntimeError('record lock source changed during validation')
    print('RECORD_LOCK_MATRIX_PASS profiles=' + str(len(rows)) + ' observations=' + str(len(rows) * 8), flush=True)


if __name__ == '__main__':
    main()
