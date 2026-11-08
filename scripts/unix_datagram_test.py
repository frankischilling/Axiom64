#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Run all public Unix datagram clients on both musl providers and firmware modes."""
import argparse
import json
import os
from pathlib import Path
import shlex
import shutil
import subprocess
import sys
import time

from account_store_guest import fixture
from build_musl import compiler_args
from build_openssl import uapi_headers
from fetch import ROOT
from tcp_fixture_inputs import audit_fixture, digest
from unix_datagram_contract import CLIENTS, boot_body, check_log


def snapshot(directory):
    names = {'Makefile', 'dependencies.json', 'sources.lock.json', 'ports.lock.json',
             'boot/limine.conf', 'vendor/limine.h'}
    for folder, extensions in [('kernel', ('.cpp', '.hpp', '.asm', '.ld')),
                               ('scripts', ('.py', '.sh')), ('userspace/init', ('.c', '.h'))]:
        names.update(path.relative_to(ROOT).as_posix() for path in (ROOT / folder).rglob('*')
                     if path.is_file() and path.suffix in extensions)
    names.update('userspace/tests/ipc/' + name + '.c' for name in CLIENTS)
    records = {}
    for name in sorted(names):
        target = directory / 'inputs' / name
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(ROOT / name, target)
        records[name] = digest(target)
        if digest(ROOT / name) != records[name]:
            raise ValueError('Unix source changed while being captured: ' + name)
    (directory / 'source-inputs.json').write_text(json.dumps(records, indent=2) + '\n')
    return records


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--directory', type=Path, default=ROOT / 'build/unix-datagram-guest')
    args = parser.parse_args()
    directory = args.directory.resolve()
    directory.mkdir(parents=True, exist_ok=False)
    source = snapshot(directory)
    os.chdir(ROOT)
    with (directory / 'kernel-build.log').open('xb') as log:
        subprocess.run(['make', '-j2', 'build/axiom64.elf', 'build/init', 'busybox'],
                       stdout=log, stderr=subprocess.STDOUT, check=True)
    kernel = ROOT / 'build/axiom64.elf'
    headers, sdk = uapi_headers()
    for name, value in sdk['products'].items():
        target = directory / 'sdk' / name
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(headers.parent.parent / name, target)
        if digest(target) != value:
            raise ValueError('SDK changed during capture: ' + name)
    (directory / 'sdk.json').write_text(json.dumps(sdk, indent=2) + '\n')
    rows = []
    body = boot_body()
    script = ('#!/bin/sh\nset -e\n' + body + '\necho AXIOM64_TESTS_PASS\n').encode()
    for provider in ('build', 'runtime'):
        for linkage in ('static', 'dynamic'):
            case = directory / (provider + '-' + linkage)
            case.mkdir()
            programs = {}
            for name in CLIENTS:
                program = case / name
                command = [sys.executable, '-B', 'scripts/compile_uapi_client.py',
                           '--compiler', shlex.join(compiler_args(provider)), '--output', str(program),
                           '--', '-std=c11', '-O2', '-g', '-Wall', '-Wextra', '-Werror',
                           *(['-static'] if linkage == 'static' else []),
                           'userspace/tests/ipc/' + name + '.c']
                with (case / (name + '-build.log')).open('xb') as log:
                    subprocess.run(command, stdout=log, stderr=subprocess.STDOUT, check=True)
                inputs = json.loads(program.with_suffix('.inputs.json').read_text())
                if inputs['product']['sha256'] != digest(program) or inputs['uapi'] != sdk:
                    raise ValueError('Unix client executable or SDK differs from recorded compilation')
                if any(source.get(path) != value for path, value in inputs['sources'].items()):
                    raise ValueError('Unix client source differs from captured source')
                programs[name] = program, inputs
            extra = {'bin/' + name.replace('_', '-'): program for name, (program, _) in programs.items()
                     if name != 'unix_messages'}
            extra.update({'source/' + name + '.inputs.json': program.with_suffix('.inputs.json')
                          for name, (program, _) in programs.items()})
            image = fixture(case, provider, linkage, program_builder=lambda *args: programs['unix_messages'],
                            filename='unix-messages', command=body, extra_products=extra)
            products = json.loads((case / 'products.json').read_text())
            audit_fixture(image, digest(kernel), {name: value['sha256'] for name, value in products.items()
                          if name not in ('image.iso', 'root.cpio', 'kernel.elf')}, script,
                          initramfs_sha256=digest(case / 'root.cpio'))
            for firmware in ('bios', 'uefi'):
                command = ['qemu-system-x86_64', '-machine', 'pc', '-cpu', 'max', '-m', '256M',
                           '-nic', 'none', '-cdrom', str(image), '-display', 'none', '-serial', 'stdio',
                           '-monitor', 'none', '-no-reboot', '-device', 'isa-debug-exit,iobase=0xf4,iosize=0x04']
                if firmware == 'uefi':
                    variables = case / 'OVMF_VARS.fd'
                    shutil.copyfile('/usr/share/OVMF/OVMF_VARS_4M.fd', variables)
                    command += ['-drive', 'if=pflash,format=raw,readonly=on,file=/usr/share/OVMF/OVMF_CODE_4M.fd',
                                '-drive', 'if=pflash,format=raw,file=' + str(variables)]
                log = case / (firmware + '.log')
                start = time.monotonic_ns()
                with log.open('xb') as out:
                    process = subprocess.run(command, stdin=subprocess.DEVNULL, stdout=out,
                                             stderr=subprocess.STDOUT, timeout=90)
                check_log(log.read_text(), firmware, process.returncode)
                rows.append(dict(provider=provider, linkage=linkage, firmware=firmware, case=case.name,
                                 command=command, returncode=process.returncode,
                                 elapsed_ns=time.monotonic_ns() - start,
                                 log_sha256=digest(log), kernel_sha256=digest(kernel)))
                (directory / 'results.json').write_text(json.dumps(rows, indent=2) + '\n')
                print('UNIX_DATAGRAM_GUEST_PASS ' + case.name + '/' + firmware, flush=True)
    if any(digest(ROOT / name) != value for name, value in source.items()):
        raise ValueError('Unix sources changed during guest validation')
    from unix_datagram_proof import verify
    verify(directory)
    print('UNIX_DATAGRAM_GUEST_MATRIX_PASS profiles=8 executions=96', flush=True)


if __name__ == '__main__':
    main()
