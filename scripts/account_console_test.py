#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Exercise the real first-boot console and private login workers on Linux and in VMs."""
import argparse
import json
import os
from pathlib import Path
import shutil
import subprocess
import time

from account_access_test import INPUTS, MODULES, build as access_build
from build_accounts import DESKTOP_INPUTS
from account_management_test import crypt, invocation
from account_session_test import retain_native
from account_store_guest import fixture
from account_store_test import digest, environment
from build_musl import compiler_args
from fetch import LOCK, ROOT

SOURCES = [*INPUTS, 'userspace/accounts/console.c', 'scripts/build_accounts.py',
           'userspace/tests/security/account-console.c', 'scripts/account_console_test.py']


def build(provider, linkage, directory, data, native_runtime=None):
    _, access, observer, library, inputs = access_build(provider, linkage, directory, data,
                                                       native_runtime)
    stage = library / linkage / 'stage'
    compiler = ['gcc'] if provider == 'native' else compiler_args(provider)
    common = [*compiler, '-std=c11', '-O2', '-g', '-Wall', '-Wextra', '-Werror',
              '-I' + str(stage / 'usr/include'),
              *(str(ROOT / f'userspace/accounts/{name}.c') for name in MODULES),
              str(ROOT / 'userspace/accounts/logbook_rotation.c')]
    link = ['-static', str(stage / 'usr/lib/libcrypt.a')] if linkage == 'static' else [
        '-L' + str(stage / 'usr/lib'), '-lcrypt']
    service, driver = directory / 'account-console', directory / 'account-console-test'
    desktop = [str(ROOT / name) for name in DESKTOP_INPUTS if name.endswith('.c')]
    commands = [[*common, *desktop, str(ROOT / 'userspace/accounts/console.c'), '-o', str(service), *link],
                [*common, str(ROOT / 'userspace/tests/security/account-console.c'), '-o', str(driver), *link]]
    if native_runtime and linkage == 'dynamic':
        commands[0].append('-Wl,-rpath=' + str(native_runtime))
        if provider != 'native':
            commands[0].append('-Wl,--dynamic-linker=' + str(native_runtime / 'libc.so'))
    for command in commands:
        subprocess.run(command, cwd=ROOT, env=environment(), check=True)
    inputs['products'].update({name: dict(command=command, sha256=digest(path),
        headers=subprocess.check_output(['readelf', '-W', '-l', str(path)], text=True),
        dynamic=subprocess.check_output(['readelf', '-W', '-d', str(path)], text=True))
        for name, command, path in zip(('account-console', 'account-console-test'), commands, (service, driver))})
    return driver, service, access, observer, library, inputs


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
    count = sum(line.startswith('ACCOUNT_CONSOLE_OBSERVATION ') for line in lines)
    passed = not timed_out and process.returncode == (1 if firmware else 0) and count == 10 and \
        lines.count('ACCOUNT_CONSOLE_PASS observations=10') == 1 and \
        not any(marker in text for marker in ('ACCOUNT_CONSOLE_FAIL', 'PANIC:', 'FAULT pid=',
                                              'Console-pri', 'AddressSanitizer', 'runtime error:'))
    if firmware:
        passed = passed and lines.count('AXIOM64_TESTS_PASS') == 1 and \
            'AXIOM64_EXIT status=0' in text and 'Firmware: ' + firmware.upper() in text
    return dict(command=command, returncode=process.returncode, timed_out=timed_out,
                elapsed_ns=time.monotonic_ns() - started, observations=count, log=str(log),
                log_sha256=digest(log), passed=passed)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--directory', type=Path, default=ROOT / 'build/account-console')
    parser.add_argument('--native', action='store_true')
    parser.add_argument('--fixtures', type=Path)
    args = parser.parse_args()
    if args.native:
        if os.geteuid() or os.getegid() or not args.fixtures or not args.fixtures.is_absolute() or args.fixtures.exists():
            raise RuntimeError('use root and fresh absolute native fixtures')
        args.fixtures.mkdir(mode=0o755)
        args.fixtures.chmod(0o755)
    args.directory.mkdir(parents=True, exist_ok=False)
    names = [*SOURCES, *(path.relative_to(ROOT).as_posix() for path in (ROOT / 'kernel').rglob('*')
                       if path.is_file() and path.suffix in ('.cpp', '.hpp', '.asm'))]
    source = {name: digest(ROOT / name) for name in names}
    (args.directory / 'source-inputs.json').write_text(json.dumps(source, indent=2) + '\n')
    subprocess.run(['make', '-s', '-j2', 'busybox', *([] if args.native else ['build/axiom64.elf', 'build/init'])],
                   cwd=ROOT, check=True)
    busybox = ROOT / ('build/busybox-' + LOCK['busybox']['version']) / 'busybox'
    rows = []
    for provider in ('build', 'runtime', 'native') if args.native else ('build', 'runtime'):
        for linkage in ('static', 'dynamic'):
            case = args.directory / (provider + '-' + linkage)
            case.mkdir()
            native_case = args.fixtures / case.name if args.native else None
            if native_case:
                native_case.mkdir(mode=0o755)
                native_case.chmod(0o755)
            data = native_case / 'data' if args.native else Path('/run/account-console-test')
            driver, service, access, observer, library, inputs = build(provider, linkage, case, data,
                                            native_case / 'lib' if native_case else None)
            inputs['busybox_sha256'] = digest(busybox)
            if args.native:
                native_busybox = native_case / 'busybox'
                shutil.copyfile(busybox, native_busybox)
                native_busybox.chmod(0o755)
                assert digest(native_busybox) == inputs['busybox_sha256']
                inputs['native_busybox'] = dict(path=str(native_busybox), source=str(busybox),
                                                sha256=digest(native_busybox))
                installed = []
                for product in (service, access, observer):
                    destination = native_case / product.name
                    shutil.copyfile(product, destination)
                    destination.chmod(0o755)
                    assert digest(destination) == digest(product)
                    installed.append(str(destination))
                command = ['unshare', '--mount', '--pid', '--fork', '--mount-proc',
                           *invocation(driver, library, provider, linkage), str(data),
                           installed[0], installed[1], str(native_busybox), installed[2]]
                row = execute(command, case / 'native.log')
                row.update(provider=provider, linkage=linkage, inputs=inputs,
                           native_exports=retain_native(case, native_case))
                rows.append(row)
            else:
                def builder(_provider, _linkage, _directory):
                    return driver, inputs
                products = {'bin/account-console': service, 'bin/account-access': access,
                            'bin/account-access-observe': observer}
                if linkage == 'dynamic':
                    products['usr/lib/libcrypt.so.2'] = library / 'dynamic/stage/usr/lib/libcrypt.so.2.0.0'
                image = fixture(case, provider, linkage, program_builder=builder, filename='account-console-test',
                    command='/bin/account-console-test /run/account-console-test /bin/account-console '
                            '/bin/account-access /bin/busybox /bin/account-access-observe', extra_products=products)
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
                        raise RuntimeError('guest console profile failed: ' + case.name + '/' + firmware)
                    print('ACCOUNT_CONSOLE_GUEST_PASS ' + case.name + '/' + firmware, flush=True)
            (args.directory / 'results.json').write_text(json.dumps(rows, indent=2) + '\n')
            if not rows[-1]['passed']:
                raise RuntimeError('native console profile failed: ' + case.name)
            if args.native:
                print('ACCOUNT_CONSOLE_NATIVE_PASS ' + case.name, flush=True)
    if source != {name: digest(ROOT / name) for name in source}:
        raise RuntimeError('account console source changed during validation')
    print('ACCOUNT_CONSOLE_MATRIX_PASS profiles=' + str(len(rows)) + ' observations=' + str(len(rows) * 10), flush=True)


if __name__ == '__main__':
    main()
