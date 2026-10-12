#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Verify password publication, authenticated races and update failure ownership."""
import argparse
import json
import os
from pathlib import Path
import shutil
import subprocess
import time

from account_access_test import INPUTS, MODULES
from account_management_test import crypt, invocation
from account_session_test import retain_native
from account_store_guest import fixture
from account_store_test import digest, environment
from build_musl import compiler_args
from fetch import ROOT

SOURCES = [*INPUTS, 'userspace/tests/security/account-update.c', 'scripts/account_update_test.py']


def build(provider, linkage, directory, sanitizer=False):
    library = crypt(provider)
    stage = library / linkage / 'stage'
    compiler = ['gcc'] if provider == 'native' else compiler_args(provider)
    program = directory / ('account-update-' + provider + '-' + linkage)
    command = [*compiler, '-std=c11', '-O2', '-g', '-Wall', '-Wextra', '-Werror',
               '-I' + str(stage / 'usr/include'),
               *(str(ROOT / f'userspace/accounts/{name}.c') for name in MODULES),
               str(ROOT / 'userspace/tests/security/account-update.c'), '-o', str(program)]
    if sanitizer:
        command += ['-fsanitize=address,undefined', '-fno-omit-frame-pointer']
    command += ['-static', str(stage / 'usr/lib/libcrypt.a')] if linkage == 'static' else [
        '-L' + str(stage / 'usr/lib'), '-lcrypt']
    subprocess.run(command, cwd=ROOT, env=environment(), check=True)
    return program, library, dict(command=command, binary_sha256=digest(program),
                                  library_manifest_sha256=digest(library / 'manifest.json'),
                                  headers=subprocess.check_output(['readelf', '-W', '-l', str(program)], text=True),
                                  dynamic=subprocess.check_output(['readelf', '-W', '-d', str(program)], text=True))


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
    count = sum(line.startswith('ACCOUNT_UPDATE_OBSERVATION ') for line in lines)
    passed = (not timed_out and process.returncode == (1 if firmware else 0) and count == 6 and
              lines.count('ACCOUNT_UPDATE_PASS observations=6') == 1 and
              not any(marker in text for marker in ('ACCOUNT_UPDATE_FAIL', 'PANIC:', 'FAULT pid=',
                                                    'AddressSanitizer', 'runtime error:')))
    if firmware:
        passed = passed and lines.count('AXIOM64_TESTS_PASS') == 1 and 'AXIOM64_EXIT status=0' in text
        passed = passed and 'Firmware: ' + firmware.upper() in text
    return dict(command=command, returncode=process.returncode, timed_out=timed_out,
                elapsed_ns=time.monotonic_ns() - started, observations=count,
                log=str(log), log_sha256=digest(log), passed=passed)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--directory', type=Path, default=ROOT / 'build/account-update')
    parser.add_argument('--native', action='store_true')
    parser.add_argument('--sanitize', action='store_true')
    parser.add_argument('--fixtures', type=Path)
    args = parser.parse_args()
    if args.sanitize and not args.native:
        raise RuntimeError('sanitizers run on the native GNU client')
    if args.native:
        if os.geteuid() or os.getegid() or not args.fixtures or not args.fixtures.is_absolute() or args.fixtures.exists():
            raise RuntimeError('use root and fresh absolute native Linux fixtures')
        args.fixtures.mkdir(mode=0o755)
        args.fixtures.chmod(0o755)
    args.directory.mkdir(parents=True, exist_ok=False)
    names = [*SOURCES, *(path.relative_to(ROOT).as_posix() for path in (ROOT / 'kernel').rglob('*')
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
        program, library, inputs = build(provider, linkage, case, args.sanitize)
        if args.native:
            native_case = args.fixtures / case.name
            native_case.mkdir(mode=0o755)
            native_case.chmod(0o755)
            row = execute(invocation(program, library, provider, linkage) + [str(native_case / 'data')], case / 'native.log')
            row.update(provider=provider, linkage=linkage, inputs=inputs)
            row['native_exports'] = retain_native(case, native_case)
            rows.append(row)
        else:
            def builder(_provider, _linkage, _directory):
                return program, inputs
            products = {}
            if linkage == 'dynamic':
                products['usr/lib/libcrypt.so.2'] = library / 'dynamic/stage/usr/lib/libcrypt.so.2.0.0'
            image = fixture(case, provider, linkage, program_builder=builder, filename='account-update',
                            command='/bin/account-update /run/account-update', extra_products=products)
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
                    raise RuntimeError('guest update profile failed: ' + case.name + '/' + firmware)
                print('ACCOUNT_UPDATE_GUEST_PASS ' + case.name + '/' + firmware, flush=True)
        (args.directory / 'results.json').write_text(json.dumps(rows, indent=2) + '\n')
        if not rows[-1]['passed']:
            raise RuntimeError('native update profile failed: ' + case.name)
        if args.native:
            print('ACCOUNT_UPDATE_NATIVE_PASS ' + case.name, flush=True)
    if source != {name: digest(ROOT / name) for name in source}:
        raise RuntimeError('account update source changed during validation')
    print('ACCOUNT_UPDATE_MATRIX_PASS profiles=' + str(len(rows)) + ' observations=' + str(len(rows) * 6), flush=True)


if __name__ == '__main__':
    main()
