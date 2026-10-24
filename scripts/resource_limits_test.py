#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Compare Linux limit-table and descriptor contracts with actual Linux."""
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

INPUTS = ['userspace/tests/process/resource-limits.c', 'scripts/resource_limits_test.py',
          'scripts/tests/resource_thread_retirement_test.py', 'scripts/http_download/native_process.py',
          'scripts/http_download/audit.py',
          'scripts/account_store_guest.py', 'scripts/account_store_test.py',
          'scripts/build_musl.py', 'scripts/image.py', 'Makefile', 'sources.lock.json',
          'scripts/file_capabilities/host_sources.py', 'vendor/limine.h',
          'dependencies.json', 'ports.lock.json', 'userspace/init/main.c', 'userspace/init/console.c',
          'userspace/init/console.h', 'userspace/init/seed_records.h', 'boot/limine.conf']


def snapshot_inputs(directory, extra=()):
    names = sorted(set([*INPUTS, *extra,
        *(path.relative_to(ROOT).as_posix() for path in (ROOT / 'kernel').rglob('*')
          if path.is_file() and path.suffix in ('.cpp', '.hpp', '.asm', '.ld'))]))
    source = {}
    for name in names:
        target = directory / 'inputs' / name
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(ROOT / name, target)
        source[name] = digest(ROOT / name)
        assert digest(target) == source[name], 'source changed during capture: ' + name
    (directory / 'source-inputs.json').write_text(json.dumps(source, indent=2) + '\n')
    return source


def build(provider, linkage, directory, native_runtime=None):
    compiler = ['gcc'] if provider == 'native' else compiler_args(provider)
    program = directory / 'resource-limits-test'
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


def execute(command, log, firmware=None, expected_exec_order='filename-first'):
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
    count = sum(line.startswith('RESOURCE_LIMIT_OBSERVATION ') for line in lines)
    models = [line for line in lines if line.startswith('RESOURCE_EXEC_MODEL ')]
    passed = not timed_out and process.returncode == (1 if firmware else 0) and count == 11 and \
        models == ['RESOURCE_EXEC_MODEL order=' + expected_exec_order] and \
        lines.count('RESOURCE_LIMIT_PASS observations=11 scope=interface-descriptors-files-processes-exec-memory-cpu-data-stack-isolation') == 1 and not any(
        marker in text for marker in ('RESOURCE_LIMIT_FAIL', 'PANIC:', 'FAULT pid='))
    if firmware:
        passed = passed and lines.count('AXIOM64_TESTS_PASS') == 1 and \
            'AXIOM64_EXIT status=0' in text and 'Firmware: ' + firmware.upper() in text
    return dict(command=command, returncode=process.returncode, timed_out=timed_out,
                elapsed_ns=time.monotonic_ns() - started, observations=count,
                log=str(log), log_sha256=digest(log), expected_exec_order=expected_exec_order, passed=passed)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--directory', type=Path, default=ROOT / 'build/resource-limits')
    parser.add_argument('--native', action='store_true')
    parser.add_argument('--retain-host-source', action='store_true',
                        help='retain authenticated Ubuntu glibc source for published native binaries')
    args = parser.parse_args()
    if args.retain_host_source and not args.native:
        parser.error('--retain-host-source requires --native')
    if args.native and (os.geteuid() or os.getegid()):
        raise RuntimeError('the Linux resource-limit comparison requires root')
    args.directory.mkdir(parents=True, exist_ok=False)
    source = snapshot_inputs(args.directory)
    kernel = platform.uname()._asdict()
    (args.directory / 'host-kernel.json').write_text(json.dumps(kernel, indent=2) + '\n')
    exec_order = 'filename-first'
    if args.native:
        major = kernel['release'].split('.')[0]
        if not major.isdecimal():
            raise RuntimeError('native kernel has no numeric release major')
        exec_order = 'quota-first' if int(major) >= 7 else 'filename-first'
    (args.directory / 'exec-model.json').write_text(json.dumps(dict(
        native=args.native, expected_exec_order=exec_order, kernel=kernel), indent=2) + '\n')
    if args.retain_host_source:
        from file_capabilities.host_sources import capture
        corresponding_source = capture(args.directory / 'inputs')
        (args.directory / 'native-glibc-source.json').write_text(json.dumps(corresponding_source, indent=2) + '\n')
    if not args.native:
        subprocess.run(['make', '-s', '-j2', 'build/axiom64.elf', 'build/init', 'busybox'], cwd=ROOT, check=True)
    rows = []
    with tempfile.TemporaryDirectory(prefix='axiom64-resource-limits-') as temporary:
        native_root = Path(temporary)
        # Ordinary UID exec controls must reach their real native interpreter.
        native_root.chmod(0o755)
        for provider in ('build', 'runtime', 'native') if args.native else ('build', 'runtime'):
            for linkage in ('static', 'dynamic'):
                case = args.directory / (provider + '-' + linkage)
                case.mkdir()
                program, inputs = build(provider, linkage, case,
                    native_root / case.name if args.native else None)
                if args.native:
                    accessible = native_root / case.name / program.name
                    accessible.parent.mkdir(exist_ok=True)
                    shutil.copy2(program, accessible)
                    assert digest(accessible) == inputs['binary_sha256']
                    command = ['unshare', '--mount', '--pid', '--ipc', '--fork', '--kill-child',
                               '--mount-proc', str(accessible), '--native']
                    row = execute(command, case / 'native.log', expected_exec_order=exec_order)
                    row.update(provider=provider, linkage=linkage, inputs=inputs)
                    rows.append(row)
                else:
                    def builder(_provider, _linkage, _directory):
                        return program, inputs
                    iso = fixture(case, provider, linkage, program_builder=builder,
                                  filename='resource-limits-test', command='/bin/resource-limits-test')
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
                            raise RuntimeError('guest resource-limits profile failed: ' + case.name + '/' + firmware)
                        print('RESOURCE_LIMIT_GUEST_PASS ' + case.name + '/' + firmware, flush=True)
                (args.directory / 'results.json').write_text(json.dumps(rows, indent=2) + '\n')
                if not rows[-1]['passed']:
                    raise RuntimeError('native resource-limits profile failed: ' + case.name)
                if args.native:
                    print('RESOURCE_LIMIT_NATIVE_PASS ' + case.name, flush=True)
    assert source == {name: digest(ROOT / name) for name in source}, 'source changed during validation'
    print('RESOURCE_LIMIT_MATRIX_PASS profiles=' + str(len(rows)) + ' observations=' +
          str(sum(row['observations'] for row in rows)), flush=True)


if __name__ == '__main__':
    main()
