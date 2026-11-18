#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Compare native timerfd and run the same client against the guest kernel."""
import argparse
import json
import os
from pathlib import Path
import shlex
import shutil
import subprocess
import sys
import tempfile

from account_store_guest import fixture
from build_musl import compiler_args
from compile_uapi_client import audit_compile
from fetch import ROOT
from tcp_fixture_inputs import audit_fixture, digest
from unix_datagram_proof import binary_linkage

SOURCE = 'userspace/tests/ipc/timerfd.c'
GROUPS = ('creation', 'expiration', 'read-contract', 'edge-readiness', 'lifetime')
BOOT_BODY = '/bin/timerfd-test\n/bin/timerfd-test --ordinary'


def compile_client(directory, compiler, flags):
    program = directory / 'timerfd-test'
    with (directory / 'compile.log').open('xb') as output:
        subprocess.run([sys.executable, '-B', 'scripts/compile_uapi_client.py', '--compiler',
                        shlex.join(compiler), '--output', str(program), '--', '-std=c11', '-O2',
                        '-g', '-Wall', '-Wextra', '-Werror', '-pthread', *flags, SOURCE],
                       cwd=ROOT, stdout=output, stderr=subprocess.STDOUT, check=True)
    return program, audit_compile(program, ROOT)


def check_log(log, uids, guest):
    lines = log.read_text().splitlines()
    identities = [line for line in lines if line.startswith('TIMERFD_BEGIN ')]
    prefix = 'TIMERFD_GROUP_PASS '
    received = [line[len(prefix):].split()[0] for line in lines if line.startswith(prefix)]
    expected = [f'TIMERFD_BEGIN uid={uid} guest={int(guest)}' for uid in uids]
    if (identities != expected or received != list(GROUPS) * len(uids) or
            lines.count('TIMERFD_PASS groups=5') != len(uids) or
            any('TIMERFD_FAIL' in line for line in lines)):
        raise RuntimeError(f'incomplete timerfd contract in {log}')
    return [line for line in lines if line.startswith(prefix + 'read-contract ')]


def native(directory):
    program, inputs = compile_client(directory, ['gcc'], [])
    records = []
    with tempfile.TemporaryDirectory(prefix='axiom-timerfd-native-', dir='/var/tmp') as scratch:
        public = Path(scratch)
        public.chmod(0o755)
        executable = public / program.name
        shutil.copy2(program, executable)
        if digest(executable) != inputs['product']['sha256']:
            raise RuntimeError('native execution copy differs from the compiled client')
        for name, args, uid in (('root', [], 0), ('drop', ['--ordinary'], 0), ('ordinary', [], 65534)):
            log = directory / (name + '.log')
            with log.open('xb') as output:
                subprocess.run([str(executable), *args], stdout=output, stderr=subprocess.STDOUT,
                               user=uid, group=uid, extra_groups=[], timeout=30, check=True)
            expected = 0 if name == 'root' else 65534
            records.append(dict(profile=name, observed=check_log(log, [expected], False),
                                log_sha256=digest(log), program_sha256=digest(executable)))
    return records


def guest(directory):
    with (directory / 'kernel-build.log').open('xb') as output:
        subprocess.run(['make', '-j2', 'build/axiom64.elf', 'build/init', 'busybox'], cwd=ROOT,
                       stdout=output, stderr=subprocess.STDOUT, check=True)
    kernel = digest(ROOT / 'build/axiom64.elf')
    script = ('#!/bin/sh\nset -e\n' + BOOT_BODY + '\necho AXIOM64_TESTS_PASS\n').encode()
    rows = []
    for provider in ('build', 'runtime'):
        for linkage in ('static', 'dynamic'):
            case = directory / (provider + '-' + linkage)
            case.mkdir()
            program, inputs = compile_client(case, compiler_args(provider),
                                             ['-static'] if linkage == 'static' else [])
            if binary_linkage(program) != linkage:
                raise RuntimeError('timerfd client ELF differs from its requested linkage')
            image = fixture(case, provider, linkage, program_builder=lambda *args: (program, inputs),
                            filename=program.name, command=BOOT_BODY,
                            extra_products={'source/timerfd-test.inputs.json':
                                            program.with_suffix('.inputs.json')})
            products = json.loads((case / 'products.json').read_text())
            audit_fixture(image, kernel, {name: item['sha256'] for name, item in products.items()
                          if name not in ('image.iso', 'root.cpio', 'kernel.elf')}, script,
                          initramfs_sha256=products['root.cpio']['sha256'])
            if products['bin/timerfd-test']['sha256'] != inputs['product']['sha256']:
                raise RuntimeError('timerfd boot did not select the compiled client')
            for firmware in ('bios', 'uefi'):
                command = ['qemu-system-x86_64', '-machine', 'pc', '-cpu', 'max', '-m', '256M',
                           '-nic', 'none', '-cdrom', str(image), '-display', 'none', '-serial',
                           'stdio', '-monitor', 'none', '-no-reboot', '-device',
                           'isa-debug-exit,iobase=0xf4,iosize=0x04']
                if firmware == 'uefi':
                    vars_image = case / 'OVMF_VARS.fd'
                    shutil.copyfile('/usr/share/OVMF/OVMF_VARS_4M.fd', vars_image)
                    command += ['-drive', 'if=pflash,format=raw,readonly=on,file=/usr/share/OVMF/OVMF_CODE_4M.fd',
                                '-drive', f'if=pflash,format=raw,file={vars_image}']
                log = case / (firmware + '.log')
                with log.open('xb') as output:
                    done = subprocess.run(command, stdin=subprocess.DEVNULL, stdout=output,
                                          stderr=subprocess.STDOUT, timeout=90)
                lines = log.read_text().splitlines()
                if done.returncode != 1 or any(lines.count(marker) != 1 for marker in (
                        'Firmware: ' + firmware.upper(), 'AXIOM64_TESTS_PASS', 'AXIOM64_EXIT status=0')):
                    raise RuntimeError(f'timerfd guest did not complete in {log}')
                rows.append(dict(provider=provider, linkage=linkage, firmware=firmware,
                                 observed=check_log(log, [0, 65534], True),
                                 log_sha256=digest(log), image_sha256=digest(image),
                                 program_sha256=digest(program), kernel_sha256=kernel))
                (directory / 'partial-results.json').write_text(json.dumps(rows, indent=2) + '\n')
                print(f'TIMERFD_GUEST_PASS {provider}/{linkage}/{firmware}', flush=True)
    return rows


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--directory', type=Path, required=True)
    parser.add_argument('--native', action='store_true')
    args = parser.parse_args()
    if args.native and os.geteuid() != 0:
        parser.error('native comparison needs root to test all three caller profiles')
    directory = args.directory.resolve()
    directory.mkdir(parents=True, exist_ok=False)
    os.chdir(ROOT)
    shutil.copyfile(ROOT / SOURCE, directory / 'timerfd.c')
    source = digest(directory / 'timerfd.c')
    rows = (native if args.native else guest)(directory)
    if digest(ROOT / SOURCE) != source:
        raise RuntimeError('timerfd source changed during the comparison')
    (directory / 'results.json').write_text(json.dumps(dict(passed=True, native=args.native,
        source_sha256=source, cases=rows), indent=2) + '\n')
    print(f'TIMERFD_MATRIX_PASS native={int(args.native)} profiles={len(rows)}')


if __name__ == '__main__':
    main()
