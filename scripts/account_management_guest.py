#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Run administrator provisioning, actual commands and libc lookup in fresh kernels."""
import argparse
import json
from pathlib import Path
import shutil
import subprocess
import time

from account_management_test import SOURCES, build, crypt
from account_store_guest import fixture
from account_store_test import digest, environment
from build_musl import compiler_args
from fetch import ROOT


def probe(provider, linkage, directory):
    library = crypt(provider)
    stage = library / linkage / 'stage'
    program = directory / ('account-management-' + provider + '-' + linkage)
    command = [*compiler_args(provider), '-std=c11', '-O2', '-g', '-Wall', '-Wextra', '-Werror',
               '-I' + str(stage / 'usr/include'),
               *(str(ROOT / 'userspace/accounts' / name) for name in ('store.c', 'database.c', 'record.c', 'password.c')),
               str(ROOT / 'userspace/tests/security/account-management.c'), '-o', str(program)]
    if linkage == 'static':
        command += ['-static', str(stage / 'usr/lib/libcrypt.a')]
    else:
        command += ['-L' + str(stage / 'usr/lib'), '-lcrypt']
    subprocess.run(command, env=environment(), check=True)
    return program, dict(command=command, binary_sha256=digest(program),
                         library_manifest_sha256=digest(library / 'manifest.json'))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--directory', type=Path, default=ROOT / 'build/account-management-guest')
    args = parser.parse_args()
    args.directory.mkdir(parents=True, exist_ok=False)
    names = [*SOURCES, 'scripts/account_management_guest.py', 'userspace/tests/security/account-management.c',
             'scripts/account_store_guest.py', 'scripts/image.py', 'Makefile', 'userspace/init/main.c',
             'userspace/init/seed_records.h', 'boot/limine.conf']
    names += [path.relative_to(ROOT).as_posix() for path in (ROOT / 'kernel').rglob('*')
              if path.is_file() and path.suffix in ('.cpp', '.hpp', '.asm')]
    source = {name: digest(ROOT / name) for name in names}
    (args.directory / 'source-inputs.json').write_text(json.dumps(source, indent=2) + '\n')
    subprocess.run(['make', '-s', '-j2', 'build/axiom64.elf', 'build/init', 'busybox'], cwd=ROOT, check=True)
    rows = []
    for provider in ('build', 'runtime'):
        for linkage in ('static', 'dynamic'):
            case = args.directory / (provider + '-' + linkage)
            case.mkdir()
            program, library, provenance = build(provider, linkage, case)
            products = {'bin/accountctl': program}
            if linkage == 'dynamic':
                products['usr/lib/libcrypt.so.2'] = library / 'dynamic/stage/usr/lib/libcrypt.so.2.0.0'
            image = fixture(case, provider, linkage, program_builder=probe, filename='account-management',
                            command='/bin/account-management', extra_products=products)
            (case / 'manager-compiler-inputs.json').write_text(json.dumps(provenance, indent=2) + '\n')
            for firmware in ('bios', 'uefi'):
                command = ['qemu-system-x86_64', '-machine', 'pc', '-cpu', 'max', '-m', '256M', '-nic', 'none',
                           '-cdrom', str(image), '-display', 'none', '-serial', 'stdio', '-monitor', 'none',
                           '-no-reboot', '-device', 'isa-debug-exit,iobase=0xf4,iosize=0x04']
                if firmware == 'uefi':
                    variables = case / 'OVMF_VARS.fd'
                    shutil.copyfile('/usr/share/OVMF/OVMF_VARS_4M.fd', variables)
                    command += ['-drive', 'if=pflash,format=raw,readonly=on,file=/usr/share/OVMF/OVMF_CODE_4M.fd',
                                '-drive', 'if=pflash,format=raw,file=' + str(variables)]
                started = time.monotonic_ns()
                log = case / (firmware + '.log')
                timed_out = False
                with log.open('wb') as output:
                    process = subprocess.Popen(command, cwd=ROOT, stdin=subprocess.DEVNULL,
                                               stdout=output, stderr=subprocess.STDOUT)
                    try:
                        process.wait(timeout=120)
                    except subprocess.TimeoutExpired:
                        timed_out = True
                        process.kill()
                        process.wait()
                text = log.read_text().replace('\r\n', '\n')
                observations = sum(line.startswith('ACCOUNT_MANAGEMENT_OBSERVATION ') for line in text.splitlines())
                passed = (process.returncode == 1 and not timed_out and observations == 11 and
                          text.splitlines().count('ACCOUNT_MANAGEMENT_PASS observations=11') == 1 and
                          text.splitlines().count('AXIOM64_TESTS_PASS') == 1 and 'AXIOM64_EXIT status=0' in text and
                          'Firmware: ' + firmware.upper() in text and
                          not any(marker in text for marker in ('ACCOUNT_MANAGEMENT_FAIL', 'PANIC:', 'FAULT pid=')))
                rows.append(dict(provider=provider, linkage=linkage, firmware=firmware, command=command,
                                 returncode=process.returncode, timed_out=timed_out, observations=observations,
                                 elapsed_ns=time.monotonic_ns() - started, log=str(log), log_sha256=digest(log), passed=passed))
                (args.directory / 'results.json').write_text(json.dumps(rows, indent=2) + '\n')
                if not passed:
                    raise RuntimeError('account administration guest failed: ' + case.name + '/' + firmware)
                print('ACCOUNT_MANAGEMENT_GUEST_PASS ' + case.name + '/' + firmware, flush=True)
    assert source == {name: digest(ROOT / name) for name in source}
    print('ACCOUNT_MANAGEMENT_GUEST_MATRIX_PASS profiles=8 observations=88', flush=True)


if __name__ == '__main__':
    main()
