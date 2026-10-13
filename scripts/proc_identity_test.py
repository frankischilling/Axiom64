#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Compare process creation identity and per-boot UUID lifetime with Linux."""
import argparse
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import time

from account_store_guest import fixture
from account_store_test import digest, environment
from build_musl import compiler_args, loader
from fetch import ROOT

INPUTS = ['userspace/tests/process/proc-identity.c', 'kernel/tests/fs/proc_identity.cpp',
          'scripts/proc_identity_test.py', 'scripts/account_store_guest.py',
          'scripts/account_store_test.py', 'scripts/build_musl.py', 'scripts/image.py',
          'Makefile', 'sources.lock.json', 'dependencies.json', 'userspace/init/main.c',
          'userspace/init/console.c', 'userspace/init/console.h',
          'userspace/init/seed_records.h', 'boot/limine.conf']
OBSERVATIONS = [
    'boot_uuid_v4_partial_reads_rewind_and_multiple_mounts_are_stable',
    'self_pid_and_leader_stat_have_actual_clock_ticks_and_fixed_52_fields',
    'fork_zombie_buffered_stat_and_reaped_fresh_or_rewound_reads',
    'thread_birth_direct_tid_and_retained_snapshot_are_independent',
    'leader_exec_preserves_process_boot_and_start_ticks',
    'nonleader_exec_preserves_process_boot_and_start_ticks',
    '256_task_slot_recycles_keep_current_pid_and_creation_time',
]
UNREADY = 'uninitialized_boot_id_fails_eagain_without_output'


def build(provider, linkage, directory, guest):
    compiler = ['gcc'] if provider == 'native' else compiler_args(provider)
    program = (directory / ('proc-identity-' + provider + '-' + linkage)).resolve()
    command = [*compiler, '-std=c11', '-O2', '-g', '-Wall', '-Wextra', '-Werror', '-pthread',
               str(ROOT / INPUTS[0]), '-o', str(program)]
    runtime = None
    if linkage == 'static':
        command.append('-static')
    elif not guest and provider != 'native':
        runtime = (directory / 'libc.so').resolve()
        shutil.copy2(loader(provider), runtime)
        command.append('-Wl,--dynamic-linker=' + str(runtime))
    subprocess.run(command, cwd=ROOT, env=environment(), check=True)
    headers = subprocess.check_output(['readelf', '-W', '-l', str(program)], text=True)
    dynamic = subprocess.check_output(['readelf', '-W', '-d', str(program)], text=True)
    assert ('INTERP' not in headers) == (linkage == 'static')
    assert 'RPATH' not in dynamic and 'RUNPATH' not in dynamic
    if runtime:
        assert '[Requesting program interpreter: ' + str(runtime) + ']' in headers
    return program, dict(command=command, binary_sha256=digest(program), headers=headers,
                         dynamic=dynamic, runtime=(dict(path=str(runtime), sha256=digest(runtime))
                                                  if runtime else None))


def execute(command, log, firmware=None, unready=False):
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
    observations = [line.removeprefix('PROC_IDENTITY_OBSERVATION ')
                    for line in lines if line.startswith('PROC_IDENTITY_OBSERVATION ')]
    expected = [UNREADY] if unready else OBSERVATIONS
    marker = 'PROC_IDENTITY_PASS observations=' + str(len(expected)) + (' unready=1' if unready else '')
    identifiers = re.findall(r'^PROC_IDENTITY_BOOT ([0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-'
                             r'[89ab][0-9a-f]{3}-[0-9a-f]{12})$', text, re.MULTILINE)
    passed = (not timed_out and process.returncode == (1 if firmware else 0) and
              observations == expected and lines.count(marker) == 1 and
              len(identifiers) == (0 if unready else 1) and
              not any(marker in text for marker in ('PROC_IDENTITY_FAIL', 'PANIC:', 'FAULT pid=')))
    if firmware:
        passed = passed and lines.count('AXIOM64_TESTS_PASS') == 1 and 'AXIOM64_EXIT status=0' in text
        passed = passed and 'Firmware: ' + firmware.upper() in text
    return dict(command=command, returncode=process.returncode, timed_out=timed_out,
                elapsed_ns=time.monotonic_ns() - started, observations=observations,
                boot_id=identifiers[0] if identifiers else None, unready=unready,
                log=str(log), log_sha256=digest(log), passed=passed)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--directory', type=Path, default=ROOT / 'build/proc-identity')
    parser.add_argument('--native', action='store_true')
    args = parser.parse_args()
    args.directory = args.directory.resolve()
    if args.native and (os.geteuid() or os.getegid()):
        raise RuntimeError('the isolated Linux procfs comparison requires root')
    args.directory.mkdir(parents=True, exist_ok=False)
    names = [*INPUTS, *(path.relative_to(ROOT).as_posix() for path in (ROOT / 'kernel').rglob('*')
                       if path.is_file() and path.suffix in ('.cpp', '.hpp', '.asm'))]
    source = {name: digest(ROOT / name) for name in names}
    (args.directory / 'source-inputs.json').write_text(json.dumps(source, indent=2) + '\n')
    if not args.native:
        subprocess.run(['make', '-s', '-j2', 'build/axiom64.elf', 'build/init', 'busybox'],
                       cwd=ROOT, check=True)
    rows = []
    identifiers = set()

    def retain(row):
        rows.append(row)
        (args.directory / 'results.json').write_text(json.dumps(rows, indent=2) + '\n')
        if not row['passed']:
            raise RuntimeError('proc identity profile failed: ' + row['case'])

    for provider in ('build', 'runtime', 'native') if args.native else ('build', 'runtime'):
        for linkage in ('static', 'dynamic'):
            case = args.directory / (provider + '-' + linkage)
            case.mkdir()
            program, inputs = build(provider, linkage, case, not args.native)
            if args.native:
                command = ['unshare', '--mount', '--pid', '--fork', '--kill-child=SIGKILL',
                           '--mount-proc', str(program)]
                row = execute(command, case / 'native.log')
                row.update(case=case.name, provider=provider, linkage=linkage, inputs=inputs)
                retain(row)
                identifiers.add(row['boot_id'])
                print('PROC_IDENTITY_NATIVE_PASS ' + case.name, flush=True)
                continue

            def builder(_provider, _linkage, _directory):
                return program, inputs

            for unready in (False, True):
                profile = case / ('unready' if unready else 'ready')
                profile.mkdir()
                image = fixture(profile, provider, linkage, program_builder=builder,
                                filename='proc-identity-' + profile.name,
                                command='/bin/proc-identity-' + profile.name + (' --unready' if unready else ''),
                                kernel_options=('random.trust_cpu=off',) if unready else ())
                for firmware in ('bios', 'uefi'):
                    for repeat in range(1 if unready else 2):
                        name = firmware + '-' + str(repeat)
                        command = ['qemu-system-x86_64', '-machine', 'pc', '-cpu', 'max', '-m', '256M',
                                   '-nic', 'none', '-cdrom', str(image), '-display', 'none', '-serial', 'stdio',
                                   '-monitor', 'none', '-no-reboot', '-device', 'isa-debug-exit,iobase=0xf4,iosize=0x04']
                        if firmware == 'uefi':
                            variables = profile / (name + '-OVMF_VARS.fd')
                            shutil.copyfile('/usr/share/OVMF/OVMF_VARS_4M.fd', variables)
                            command += ['-drive', 'if=pflash,format=raw,readonly=on,file=/usr/share/OVMF/OVMF_CODE_4M.fd',
                                        '-drive', 'if=pflash,format=raw,file=' + str(variables)]
                        row = execute(command, profile / (name + '.log'), firmware, unready)
                        row.update(case=case.name + '/' + profile.name + '/' + name, provider=provider,
                                   linkage=linkage, firmware=firmware, repeat=repeat, inputs=inputs,
                                   image_sha256=digest(image))
                        if not unready:
                            row['boot_unique'] = row['boot_id'] not in identifiers
                            row['passed'] = row['passed'] and row['boot_unique']
                            identifiers.add(row['boot_id'])
                        retain(row)
                        print('PROC_IDENTITY_GUEST_PASS ' + row['case'], flush=True)
    if source != {name: digest(ROOT / name) for name in source}:
        raise RuntimeError('proc identity source changed during validation')
    expected_profiles = 6 if args.native else 24
    assert len(rows) == expected_profiles and len(identifiers) == (1 if args.native else 16)
    (args.directory / 'acceptance.json').write_text(json.dumps(dict(
        profiles=len(rows), observations=sum(len(row['observations']) for row in rows),
        ready_boots=0 if args.native else 16, unready_boots=0 if args.native else 8,
        distinct_boots=len(identifiers), source_stable=True, passed=True), indent=2) + '\n')
    print('PROC_IDENTITY_MATRIX_PASS profiles=' + str(len(rows)), flush=True)


if __name__ == '__main__':
    main()
