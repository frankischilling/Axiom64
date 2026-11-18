#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Compare real Linux and Axiom64 System V semaphore operations."""
import argparse
from itertools import product
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile

from account_store_guest import fixture
from build_musl import compiler_args
from fetch import ROOT
from tcp_fixture_inputs import audit_fixture, digest
from timerfd_test import compile_client
from unix_datagram_proof import binary_linkage


CLIENT = ROOT / 'userspace/tests/ipc/sysv-semaphores.c'
BOOT = '/bin/sysv-semaphores-test\n/bin/sysv-semaphores-test --ordinary'


def execute(command, log, expected_exit, uids, firmware=None):
    with log.open('xb') as output:
        child = subprocess.run(command, stdin=subprocess.DEVNULL, stdout=output,
                               stderr=subprocess.STDOUT, timeout=90)
    lines = log.read_text().splitlines()
    completion = [line for line in lines if line.startswith('SYSV_SEM_PASS ')]
    expected = [f'SYSV_SEM_PASS uid={uid}' for uid in uids]
    markers = [] if firmware is None else [
        f'Firmware: {firmware.upper()}', 'AXIOM64_TESTS_PASS', 'AXIOM64_EXIT status=0']
    if (child.returncode != expected_exit or completion != expected or
            any(lines.count(marker) != 1 for marker in markers) or
            any(marker in line for marker in ('SYSV_SEM_FAIL', 'PANIC:', 'FAULT pid=')
                for line in lines)):
        raise RuntimeError(f'semaphore workload failed in {log}')
    return dict(returncode=child.returncode, uids=uids, log_sha256=digest(log))


def native(directory):
    rows = []
    for linkage in ('static', 'dynamic'):
        case = directory / linkage
        case.mkdir()
        program, inputs = compile_client(case, ['gcc'], ['-static'] if linkage == 'static' else [],
                                         'sysv-semaphores')
        headers = subprocess.check_output(['readelf', '-lW', str(program)], text=True)
        if ('INTERP' in headers) != (linkage == 'dynamic'):
            raise RuntimeError('native semaphore executable linkage differs')
        # The ordinary caller reexecutes the test. Its executable must remain
        # reachable even when the build lives under a root-only directory.
        with tempfile.TemporaryDirectory(prefix='axiom-sem-native-', dir='/var/tmp') as scratch:
            public = Path(scratch)
            public.chmod(0o755)
            executable = public / program.name
            shutil.copy2(program, executable)
            program_hash = inputs['product']['sha256']
            if digest(executable) != program_hash:
                raise RuntimeError('native executable copy differs from the compiled client')
            for uid, flags in ((0, []), (65534, ['--ordinary'])):
                row = execute(['unshare', '--ipc', '--', str(executable), *flags],
                              case / f'{uid}.log', 0, [uid])
                rows.append(dict(linkage=linkage, kernel=os.uname().release,
                                 program_sha256=program_hash, **row))
                print(f'SYSV_SEM_NATIVE_PASS {linkage} uid={uid}', flush=True)
    return rows


def guest(directory):
    with (directory / 'kernel-build.log').open('xb') as output:
        subprocess.run(['make', '-j2', 'build/axiom64.elf', 'build/init', 'busybox'],
                       cwd=ROOT, stdout=output, stderr=subprocess.STDOUT, check=True)
    kernel = digest(ROOT / 'build/axiom64.elf')
    rows = []
    for provider, linkage in product(('build', 'runtime'), ('static', 'dynamic')):
        case = directory / f'{provider}-{linkage}'
        case.mkdir()
        program, inputs = compile_client(case, compiler_args(provider),
                                         ['-static'] if linkage == 'static' else [],
                                         'sysv-semaphores')
        if binary_linkage(program) != linkage:
            raise RuntimeError('guest semaphore executable linkage differs')
        image = fixture(case, provider, linkage, program_builder=lambda *args: (program, inputs),
                        filename=program.name, command=BOOT,
                        extra_products={'source/sysv-semaphores.c': CLIENT,
                                        'source/compiler-inputs.json': program.with_suffix('.inputs.json')})
        products = json.loads((case / 'products.json').read_text())
        script = ('#!/bin/sh\nset -e\n'+BOOT+'\necho AXIOM64_TESTS_PASS\n').encode()
        audit_fixture(image, kernel, {name: entry['sha256'] for name, entry in products.items()
                      if name not in ('image.iso', 'root.cpio', 'kernel.elf')}, script,
                      initramfs_sha256=products['root.cpio']['sha256'])
        for firmware in ('bios', 'uefi'):
            command = ['qemu-system-x86_64', '-machine', 'pc', '-cpu', 'max', '-m', '256M',
                       '-nic', 'none', '-cdrom', str(image), '-display', 'none', '-serial',
                       'stdio', '-monitor', 'none', '-no-reboot', '-device',
                       'isa-debug-exit,iobase=0xf4,iosize=0x04']
            if firmware == 'uefi':
                store = case / 'OVMF_VARS.fd'
                shutil.copyfile('/usr/share/OVMF/OVMF_VARS_4M.fd', store)
                command += ['-drive', 'if=pflash,format=raw,readonly=on,file=/usr/share/OVMF/OVMF_CODE_4M.fd',
                            '-drive', f'if=pflash,format=raw,file={store}']
            row = execute(command, case / f'{firmware}.log', 1, [0, 65534], firmware)
            rows.append(dict(provider=provider, linkage=linkage, firmware=firmware,
                             kernel_sha256=kernel, program_sha256=digest(program),
                             image_sha256=digest(image), **row))
            print(f'SYSV_SEM_GUEST_PASS {provider}/{linkage}/{firmware}', flush=True)
    return rows


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--directory', type=Path, required=True)
    parser.add_argument('--native', action='store_true')
    args = parser.parse_args()
    if args.native and os.geteuid():
        parser.error('native matrix uses root and ordinary credentials')
    directory = args.directory.resolve()
    directory.mkdir(parents=True, exist_ok=False)
    source = digest(CLIENT)
    rows = native(directory) if args.native else guest(directory)
    if digest(CLIENT) != source:
        raise RuntimeError('client source changed during the workload')
    (directory / 'results.json').write_text(json.dumps(
        dict(passed=True, source_sha256=source, profiles=rows), indent=2)+'\n')


if __name__ == '__main__':
    main()
