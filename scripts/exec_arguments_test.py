#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Compare exec argument capture, limits and retained process state with actual Linux."""
import argparse
import json
import os
from pathlib import Path
import platform
import shutil
import subprocess
import tempfile
import time

from account_store_guest import fixture
from account_store_test import digest, environment
from build_musl import compiler_args, loader
from fetch import ROOT

INPUTS = ['userspace/tests/process/exec-arguments.c', 'scripts/exec_arguments_test.py',
          'scripts/account_store_guest.py', 'scripts/account_store_test.py',
          'scripts/build_musl.py', 'scripts/image.py', 'Makefile', 'sources.lock.json',
          'dependencies.json', 'userspace/init/main.c', 'userspace/init/console.c',
          'userspace/init/console.h', 'userspace/init/seed_records.h', 'boot/limine.conf']


def build(provider, linkage, directory, native_runtime=None):
    compiler = ['gcc'] if provider == 'native' else compiler_args(provider)
    program = directory / 'exec-arguments-test'
    command = [*compiler, '-std=c11', '-O2', '-g', '-Wall', '-Wextra', '-Werror', '-pthread',
               str(ROOT / INPUTS[0]), '-o', str(program)]
    runtime = None
    if linkage == 'static':
        command += ['-static']
    elif native_runtime and provider != 'native':
        native_runtime.mkdir()
        runtime = native_runtime / 'libc.so'
        shutil.copyfile(loader(provider), runtime)
        runtime.chmod(0o755)
        command += ['-Wl,--dynamic-linker=' + str(runtime)]
    with (directory / 'build.log').open('wb') as output:
        subprocess.run(command, cwd=ROOT, env=environment(), stdout=output,
                       stderr=subprocess.STDOUT, check=True)
    headers = subprocess.check_output(['readelf', '-W', '-l', str(program)], text=True)
    dynamic = subprocess.check_output(['readelf', '-W', '-d', str(program)], text=True)
    assert ('INTERP' not in headers) == (linkage == 'static')
    assert 'RPATH' not in dynamic and 'RUNPATH' not in dynamic
    provenance = dict(command=command, binary_sha256=digest(program), headers=headers, dynamic=dynamic)
    if runtime:
        shutil.copyfile(runtime, directory / 'native-libc.so')
        provenance['native_loader_sha256'] = digest(runtime)
    return program, provenance


def execute(command, log, firmware=None):
    started = time.monotonic_ns()
    timed_out = False
    with log.open('wb') as output:
        process = subprocess.Popen(command, cwd=ROOT, env=environment(), stdin=subprocess.DEVNULL,
                                   stdout=output, stderr=subprocess.STDOUT)
        try:
            process.wait(timeout=60)
        except subprocess.TimeoutExpired:
            timed_out = True
            process.kill()
            process.wait()
    text = log.read_text().replace('\r\n', '\n')
    lines = text.splitlines()
    count = sum(line.startswith('EXEC_ARGUMENTS_OBSERVATION ') for line in lines)
    passed = not timed_out and process.returncode == (1 if firmware else 0) and count == 9 and \
        lines.count('EXEC_ARGUMENTS_PASS observations=9') == 1 and not any(
        marker in text for marker in ('EXEC_ARGUMENTS_FAIL', 'PANIC:', 'FAULT pid='))
    if firmware:
        passed = passed and lines.count('AXIOM64_TESTS_PASS') == 1 and \
            'AXIOM64_EXIT status=0' in text and 'Firmware: ' + firmware.upper() in text
    return dict(command=command, returncode=process.returncode, timed_out=timed_out,
                elapsed_ns=time.monotonic_ns() - started, observations=count,
                log=str(log), log_sha256=digest(log), passed=passed)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--directory', type=Path, default=ROOT / 'build/exec-arguments')
    parser.add_argument('--native', action='store_true')
    args = parser.parse_args()
    if args.native and (os.geteuid() or os.getegid()):
        raise RuntimeError('the Linux exec comparison requires root')
    args.directory.mkdir(parents=True, exist_ok=False)
    names = [*INPUTS, *(path.relative_to(ROOT).as_posix() for path in (ROOT / 'kernel').rglob('*')
                       if path.is_file() and path.suffix in ('.cpp', '.hpp', '.asm'))]
    source = {name: digest(ROOT / name) for name in names}
    (args.directory / 'source-inputs.json').write_text(json.dumps(source, indent=2) + '\n')
    (args.directory / 'native-kernel.json').write_text(json.dumps(platform.uname()._asdict(), indent=2) + '\n')
    if not args.native:
        subprocess.run(['make', '-s', '-j2', 'build/axiom64.elf', 'build/init', 'busybox'], cwd=ROOT, check=True)
    rows = []
    with tempfile.TemporaryDirectory(prefix='axiom64-exec-arguments-') as temporary:
        native_root = Path(temporary)
        for provider in ('build', 'runtime', 'native') if args.native else ('build', 'runtime'):
            for linkage in ('static', 'dynamic'):
                case = args.directory / (provider + '-' + linkage)
                case.mkdir()
                program, inputs = build(provider, linkage, case,
                    native_root / case.name if args.native else None)
                if args.native:
                    command = ['unshare', '--mount', '--pid', '--fork', '--mount-proc', str(program), '--native']
                    row = execute(command, case / 'native.log')
                    row.update(provider=provider, linkage=linkage, inputs=inputs)
                    rows.append(row)
                else:
                    def builder(_provider, _linkage, _directory):
                        return program, inputs
                    iso = fixture(case, provider, linkage, program_builder=builder,
                                  filename='exec-arguments-test', command='/bin/exec-arguments-test')
                    for firmware in ('bios', 'uefi'):
                        command = ['qemu-system-x86_64', '-machine', 'pc', '-cpu', 'max', '-m', '256M',
                                   '-nic', 'none', '-cdrom', str(iso), '-display', 'none', '-serial', 'stdio',
                                   '-monitor', 'none', '-no-reboot',
                                   '-device', 'isa-debug-exit,iobase=0xf4,iosize=0x04']
                        if firmware == 'uefi':
                            variables = case / 'VARS.fd'
                            shutil.copyfile('/usr/share/OVMF/OVMF_VARS_4M.fd', variables)
                            command += ['-drive', 'if=pflash,format=raw,readonly=on,file=/usr/share/OVMF/OVMF_CODE_4M.fd',
                                        '-drive', 'if=pflash,format=raw,file=' + str(variables)]
                        row = execute(command, case / (firmware + '.log'), firmware)
                        row.update(provider=provider, linkage=linkage, firmware=firmware, inputs=inputs)
                        rows.append(row)
                        (args.directory / 'results.json').write_text(json.dumps(rows, indent=2) + '\n')
                        if not row['passed']:
                            raise RuntimeError('guest exec-arguments profile failed: ' + case.name + '/' + firmware)
                        print('EXEC_ARGUMENTS_GUEST_PASS ' + case.name + '/' + firmware, flush=True)
                (args.directory / 'results.json').write_text(json.dumps(rows, indent=2) + '\n')
                if not rows[-1]['passed']:
                    raise RuntimeError('native exec-arguments profile failed: ' + case.name)
                if args.native:
                    print('EXEC_ARGUMENTS_NATIVE_PASS ' + case.name, flush=True)
    assert source == {name: digest(ROOT / name) for name in source}, 'source changed during validation'
    print('EXEC_ARGUMENTS_MATRIX_PASS profiles=' + str(len(rows)) + ' observations=' + str(len(rows) * 9), flush=True)


if __name__ == '__main__':
    main()
