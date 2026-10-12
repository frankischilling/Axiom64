#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Compare real PTY input flushing, received-output ownership and error atomicity."""
import argparse
import json
from pathlib import Path
import shutil
import subprocess
import time

from account_store_guest import fixture
from account_store_test import digest, environment
from build_musl import compiler_args, loader
from fetch import ROOT

INPUTS = ['userspace/tests/process/terminal-flush.c', 'scripts/terminal_flush_test.py',
          'scripts/account_store_guest.py', 'scripts/account_store_test.py', 'scripts/build_musl.py',
          'scripts/image.py', 'Makefile', 'sources.lock.json', 'dependencies.json',
          'userspace/init/main.c', 'userspace/init/seed_records.h', 'boot/limine.conf']


def build(provider, linkage, directory, sanitize=False):
    compiler = ['gcc'] if provider == 'native' else compiler_args(provider)
    program = directory / ('terminal-flush-' + provider + '-' + linkage)
    command = [*compiler, '-std=c11', '-O2', '-g', '-Wall', '-Wextra', '-Werror',
               str(ROOT / INPUTS[0]), '-o', str(program)]
    if linkage == 'static':
        command.append('-static')
    if sanitize:
        command += ['-fsanitize=address,undefined', '-fno-omit-frame-pointer']
    subprocess.run(command, cwd=ROOT, env=environment(), check=True)
    headers = subprocess.check_output(['readelf', '-W', '-l', str(program)], text=True)
    dynamic = subprocess.check_output(['readelf', '-W', '-d', str(program)], text=True)
    assert ('INTERP' not in headers) == (linkage == 'static')
    assert 'RPATH' not in dynamic and 'RUNPATH' not in dynamic
    return program, dict(command=command, binary_sha256=digest(program), headers=headers, dynamic=dynamic)


def execute(command, log, firmware=None):
    started = time.monotonic_ns()
    timed_out = False
    with log.open('wb') as output:
        process = subprocess.Popen(command, cwd=ROOT, env=environment(), stdin=subprocess.DEVNULL,
                                   stdout=output, stderr=subprocess.STDOUT)
        try:
            process.wait(timeout=30)
        except subprocess.TimeoutExpired:
            timed_out = True
            process.kill()
            process.wait()
    text = log.read_text().replace('\r\n', '\n')
    lines = text.splitlines()
    count = sum(line.startswith('TERMINAL_FLUSH_RESULT ') and 'passed=1' in line for line in lines)
    passed = not timed_out and process.returncode == (1 if firmware else 0) and count == 6 and \
        lines.count('TERMINAL_FLUSH_PASS cases=6') == 1 and not any(marker in text for marker in (
            'passed=0', 'PANIC:', 'FAULT pid=', 'AddressSanitizer', 'runtime error:'))
    if firmware:
        passed = passed and lines.count('AXIOM64_TESTS_PASS') == 1 and \
            'AXIOM64_EXIT status=0' in text and 'Firmware: ' + firmware.upper() in text
    return dict(command=command, returncode=process.returncode, timed_out=timed_out,
                elapsed_ns=time.monotonic_ns() - started, observations=count,
                log=str(log), log_sha256=digest(log), passed=passed)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--directory', type=Path, default=ROOT / 'build/terminal-flush')
    parser.add_argument('--native', action='store_true')
    parser.add_argument('--sanitize', action='store_true')
    args = parser.parse_args()
    if args.sanitize and not args.native:
        raise RuntimeError('sanitizers use the native GNU client')
    args.directory.mkdir(parents=True, exist_ok=False)
    names = [*INPUTS, *(path.relative_to(ROOT).as_posix() for path in (ROOT / 'kernel').rglob('*')
                       if path.is_file() and path.suffix in ('.cpp', '.hpp', '.asm'))]
    source = {name: digest(ROOT / name) for name in names}
    (args.directory / 'source-inputs.json').write_text(json.dumps(source, indent=2) + '\n')
    if not args.native:
        subprocess.run(['make', '-s', '-j2', 'build/axiom64.elf', 'build/init', 'busybox'], cwd=ROOT, check=True)
    rows = []
    profiles = [('native', 'dynamic')] if args.sanitize else [
        (provider, linkage) for provider in (('build', 'runtime', 'native') if args.native else ('build', 'runtime'))
        for linkage in ('static', 'dynamic')]
    for provider, linkage in profiles:
        case = args.directory / (provider + '-' + linkage)
        case.mkdir()
        program, inputs = build(provider, linkage, case, args.sanitize)
        if args.native:
            command = [str(program)] if provider == 'native' or linkage == 'static' else [str(loader(provider)), str(program)]
            row = execute(command, case / 'native.log')
            row.update(provider=provider, linkage=linkage, inputs=inputs)
            rows.append(row)
        else:
            def builder(_provider, _linkage, _directory):
                return program, inputs
            image = fixture(case, provider, linkage, program_builder=builder, filename='terminal-flush',
                            command='/bin/terminal-flush')
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
                    raise RuntimeError('guest terminal flush profile failed: ' + case.name + '/' + firmware)
                print('TERMINAL_FLUSH_GUEST_PASS ' + case.name + '/' + firmware, flush=True)
        (args.directory / 'results.json').write_text(json.dumps(rows, indent=2) + '\n')
        if not rows[-1]['passed']:
            raise RuntimeError('native terminal flush profile failed: ' + case.name)
        if args.native:
            print('TERMINAL_FLUSH_NATIVE_PASS ' + case.name, flush=True)
    if source != {name: digest(ROOT / name) for name in source}:
        raise RuntimeError('terminal flush source changed during validation')
    print('TERMINAL_FLUSH_MATRIX_PASS profiles=' + str(len(rows)) + ' observations=' + str(len(rows) * 6), flush=True)


if __name__ == '__main__':
    main()
