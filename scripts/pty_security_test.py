#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Compare private PTY ownership, session access, hangup and lifetime with Linux."""
import argparse
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import time

from account_store_guest import fixture
from account_store_test import digest, environment
from build_musl import compiler_args, ensure, loader
from fetch import ROOT

INPUTS = ['userspace/tests/security/pty-security.c', 'scripts/pty_security_test.py',
          'scripts/account_store_guest.py', 'scripts/account_store_test.py', 'scripts/build_musl.py',
          'Makefile', 'sources.lock.json', 'dependencies.json', 'scripts/image.py',
          'userspace/init/main.c', 'userspace/init/console.c', 'userspace/init/console.h',
          'userspace/init/seed_records.h', 'boot/limine.conf']
MARKER = 'PTY_SECURITY_PASS observations=9 recycled_pairs=512'


def build(provider, linkage, directory):
    compiler = ['gcc'] if provider == 'native' else compiler_args(provider)
    program = directory / ('pty-security-' + provider + '-' + linkage)
    command = [*compiler, '-std=c11', '-O2', '-g', '-Wall', '-Wextra', '-Werror',
               str(ROOT / INPUTS[0]), '-o', str(program)]
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
    count = sum(line.startswith('PTY_SECURITY_OBSERVATION ') for line in lines)
    expected = 10 if firmware else 9
    marker = 'PTY_SECURITY_PASS observations=' + str(expected) + ' recycled_pairs=512'
    passed = (not timed_out and process.returncode == (1 if firmware else 0) and count == expected and
              lines.count(marker) == 1 and
              not any(marker in text for marker in ('PTY_SECURITY_FAIL', 'PANIC:', 'FAULT pid=')))
    if firmware:
        passed = passed and lines.count('AXIOM64_TESTS_PASS') == 1 and 'AXIOM64_EXIT status=0' in text
        passed = passed and 'Firmware: ' + firmware.upper() in text
    return dict(command=command, returncode=process.returncode, timed_out=timed_out,
                elapsed_ns=time.monotonic_ns() - started, observations=count,
                log=str(log), log_sha256=digest(log), passed=passed)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--directory', type=Path, default=ROOT / 'build/pty-security')
    parser.add_argument('--native', action='store_true')
    parser.add_argument('--namespace-internal', action='store_true', help=argparse.SUPPRESS)
    args = parser.parse_args()
    if args.native:
        if os.geteuid() or os.getegid():
            raise RuntimeError('native identity and mount controls require root')
        if not args.namespace_internal:
            command = ['unshare', '--mount', '--propagation', 'private', sys.executable,
                       str(Path(__file__).resolve()), '--native', '--namespace-internal',
                       '--directory', str(args.directory)]
            raise SystemExit(subprocess.run(command, env=environment()).returncode)
        subprocess.run(['mount', '-t', 'devpts', '-o', 'newinstance,mode=0600,ptmxmode=0666',
                        'devpts', '/dev/pts'], check=True)
    elif args.namespace_internal:
        raise RuntimeError('namespace flag requires native mode')
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
            program, inputs = build(provider, linkage, case)
            if args.native:
                command = [str(program)]
                if linkage == 'dynamic':
                    interpreter = Path('/lib64/ld-linux-x86-64.so.2') if provider == 'native' else loader(provider)
                    command = [str(interpreter), str(program)]
                row = execute(command, case / 'native.log')
                row.update(provider=provider, linkage=linkage, inputs=inputs)
                rows.append(row)
                (args.directory / 'results.json').write_text(json.dumps(rows, indent=2) + '\n')
                if not row['passed']:
                    raise RuntimeError('native PTY security profile failed: ' + case.name)
                print('PTY_SECURITY_NATIVE_PASS ' + case.name, flush=True)
            else:
                def builder(_provider, _linkage, _directory):
                    return program, inputs
                image = fixture(case, provider, linkage, program_builder=builder, filename='pty-security',
                                command='/bin/pty-security guest')
                for firmware in ('bios', 'uefi'):
                    command = ['qemu-system-x86_64', '-machine', 'pc', '-cpu', 'max', '-m', '256M',
                               '-nic', 'none', '-cdrom', str(image), '-display', 'none', '-serial', 'stdio',
                               '-monitor', 'none', '-no-reboot', '-device', 'isa-debug-exit,iobase=0xf4,iosize=0x04']
                    if firmware == 'uefi':
                        variables = case / 'OVMF_VARS.fd'
                        shutil.copy2('/usr/share/OVMF/OVMF_VARS_4M.fd', variables)
                        command += ['-drive', 'if=pflash,format=raw,readonly=on,file=/usr/share/OVMF/OVMF_CODE_4M.fd',
                                    '-drive', 'if=pflash,format=raw,file=' + str(variables)]
                    row = execute(command, case / (firmware + '.log'), firmware)
                    row.update(provider=provider, linkage=linkage, firmware=firmware, root='ram', inputs=inputs)
                    rows.append(row)
                    (args.directory / 'results.json').write_text(json.dumps(rows, indent=2) + '\n')
                    if not row['passed']:
                        raise RuntimeError('guest PTY security profile failed: ' + case.name + '/' + firmware)
                    print('PTY_SECURITY_GUEST_PASS ' + case.name + '/' + firmware, flush=True)
    if source != {name: digest(ROOT / name) for name in source}:
        raise RuntimeError('PTY security source changed during validation')
    print('PTY_SECURITY_MATRIX_PASS profiles=' + str(len(rows)) +
          ' observations=' + str(sum(row['observations'] for row in rows)), flush=True)


if __name__ == '__main__':
    main()
