#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Exercise private interactive account frontends and real set-UID elevation."""
import argparse
import json
import os
from pathlib import Path
import shutil
import subprocess
import time

from account_management_test import SOURCES, crypt, invocation
from account_session_test import retain_native
from account_store_guest import fixture
from account_store_test import digest, environment
from build_musl import compiler_args, loader
from fetch import LOCK, ROOT
from build_accounts import DESKTOP_INPUTS

MODULES = ('store', 'database', 'record', 'password', 'home', 'auth', 'secret', 'session',
           'protected', 'login_record', 'logbook', 'recorded', 'update', 'busy', 'guard')
INPUTS = [*SOURCES, *DESKTOP_INPUTS, *(f'userspace/accounts/{name}.{suffix}' for name in MODULES for suffix in ('c', 'h')),
          'userspace/accounts/access.c', 'userspace/tests/security/account-access.c',
          'userspace/tests/security/account-access-observe.c', 'scripts/account_access_test.py',
          'scripts/account_session_test.py', 'scripts/account_store_guest.py', 'scripts/account_store_test.py',
          'Makefile', 'scripts/image.py', 'userspace/init/main.c', 'userspace/init/console.c',
          'userspace/init/console.h', 'userspace/init/seed_records.h', 'boot/limine.conf']


def build(provider, linkage, directory, data, native_runtime=None):
    directory.mkdir(parents=True, exist_ok=True)
    library = crypt(provider)
    stage = library / linkage / 'stage'
    compiler = ['gcc'] if provider == 'native' else compiler_args(provider)
    common = [*compiler, '-std=c11', '-O2', '-g', '-Wall', '-Wextra', '-Werror',
              '-I' + str(stage / 'usr/include')]
    modules = [str(ROOT / f'userspace/accounts/{name}.c') for name in MODULES]
    modules += [str(ROOT / name) for name in DESKTOP_INPUTS if name.endswith('.c')]
    link = ['-static', str(stage / 'usr/lib/libcrypt.a')] if linkage == 'static' else [
        '-L' + str(stage / 'usr/lib'), '-lcrypt']
    access, driver, observer = (directory / name for name in ('account-access', 'account-access-test', 'account-access-observe'))
    commands = [
        [*common, *modules, '-DACCOUNT_DATABASE_PATH="' + str(data / 'db') + '"',
         '-DACCOUNT_RECORDS_PATH="' + str(data / 'records') + '"',
         str(ROOT / 'userspace/accounts/access.c'), '-o', str(access), *link],
        [*common, *modules, str(ROOT / 'userspace/tests/security/account-access.c'), '-o', str(driver), *link],
        [*common, '-static', str(ROOT / 'userspace/tests/security/account-access-observe.c'), '-o', str(observer)]]
    runtime_inputs = {}
    if native_runtime and linkage == 'dynamic':
        native_runtime.mkdir(mode=0o755)
        native_runtime.chmod(0o755)
        libraries = {'libcrypt.so.2': stage / 'usr/lib/libcrypt.so.2.0.0'}
        if provider != 'native':
            libraries['libc.so'] = loader(provider)
        for name, source in libraries.items():
            destination = native_runtime / name
            shutil.copyfile(source, destination)
            destination.chmod(0o755)
            runtime_inputs[name] = dict(source=str(source), sha256=digest(destination))
        commands[0].append('-Wl,-rpath=' + str(native_runtime))
        if provider != 'native':
            commands[0].append('-Wl,--dynamic-linker=' + str(native_runtime / 'libc.so'))
    products = {}
    for command, product in zip(commands, (access, driver, observer)):
        subprocess.run(command, cwd=ROOT, env=environment(), check=True)
        headers = subprocess.check_output(['readelf', '-W', '-l', str(product)], text=True)
        dynamic = subprocess.check_output(['readelf', '-W', '-d', str(product)], text=True)
        static = product == observer or linkage == 'static'
        assert ('INTERP' not in headers) == static
        if product != access or not native_runtime:
            assert 'RPATH' not in dynamic and 'RUNPATH' not in dynamic
        if not static:
            assert 'libcrypt.so.2' in dynamic
            if provider != 'native' and (product != access or not native_runtime):
                assert '/lib/ld-musl-x86_64.so.1' in headers
        products[product.name] = dict(command=command, sha256=digest(product), headers=headers, dynamic=dynamic)
    return driver, access, observer, library, dict(products=products, native_runtime=runtime_inputs,
                                                library_manifest_sha256=digest(library / 'manifest.json'))


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
    count = sum(line.startswith('ACCOUNT_ACCESS_OBSERVATION ') for line in lines)
    passed = (not timed_out and process.returncode == (1 if firmware else 0) and count == 16 and
              lines.count('ACCOUNT_ACCESS_PASS observations=16') == 1 and
              not any(marker in text for marker in ('ACCOUNT_ACCESS_FAIL', 'PANIC:', 'FAULT pid=',
                                                    'Fixture-Access-Password-82', 'Fixture-Access-Changed-93')))
    if firmware:
        passed = passed and lines.count('AXIOM64_TESTS_PASS') == 1 and 'AXIOM64_EXIT status=0' in text
        passed = passed and 'Firmware: ' + firmware.upper() in text
    return dict(command=command, returncode=process.returncode, timed_out=timed_out,
                elapsed_ns=time.monotonic_ns() - started, observations=count,
                log=str(log), log_sha256=digest(log), passed=passed)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--directory', type=Path, default=ROOT / 'build/account-access')
    parser.add_argument('--native', action='store_true')
    parser.add_argument('--fixtures', type=Path)
    args = parser.parse_args()
    if args.native:
        if os.geteuid() or os.getegid() or not args.fixtures or not args.fixtures.is_absolute() or args.fixtures.exists():
            raise RuntimeError('use root and fresh absolute native Linux fixtures')
        args.fixtures.mkdir(mode=0o755)
        args.fixtures.chmod(0o755)
    args.directory.mkdir(parents=True, exist_ok=False)
    names = [*INPUTS, *(path.relative_to(ROOT).as_posix() for path in (ROOT / 'kernel').rglob('*')
                       if path.is_file() and path.suffix in ('.cpp', '.hpp', '.asm'))]
    source = {name: digest(ROOT / name) for name in names}
    (args.directory / 'source-inputs.json').write_text(json.dumps(source, indent=2) + '\n')
    subprocess.run(['make', '-s', '-j2', *(['busybox'] if args.native else ['build/axiom64.elf', 'build/init', 'busybox'])],
                   cwd=ROOT, check=True)
    busybox = ROOT / ('build/busybox-' + LOCK['busybox']['version']) / 'busybox'
    rows = []
    for provider in ('build', 'runtime', 'native') if args.native else ('build', 'runtime'):
        for linkage in ('static', 'dynamic'):
            case = args.directory / (provider + '-' + linkage)
            case.mkdir()
            native_case = args.fixtures / case.name if args.native else None
            data = native_case / 'data' if args.native else Path('/run/account-access')
            if args.native:
                native_case.mkdir(mode=0o755)
                native_case.chmod(0o755)
            program, access, observer, library, inputs = build(provider, linkage, case, data,
                                                              native_case / 'lib' if args.native else None)
            inputs['busybox_sha256'] = digest(busybox)
            if args.native:
                for binary in (access, observer):
                    destination = native_case / binary.name
                    shutil.copyfile(binary, destination)
                    destination.chmod(0o755)
                    assert digest(destination) == digest(binary)
                command = invocation(program, library, provider, linkage) + [str(data),
                    str(native_case / access.name), str(busybox), str(native_case / observer.name)]
                command = ['unshare', '--mount', '--pid', '--fork', '--mount-proc', *command]
                row = execute(command, case / 'native.log')
                row.update(provider=provider, linkage=linkage, inputs=inputs)
                row['native_exports'] = retain_native(case, native_case)
                rows.append(row)
            else:
                def builder(_provider, _linkage, _directory):
                    return program, inputs
                products = {'bin/account-access': access, 'bin/account-access-observe': observer}
                if linkage == 'dynamic':
                    products['usr/lib/libcrypt.so.2'] = library / 'dynamic/stage/usr/lib/libcrypt.so.2.0.0'
                image = fixture(case, provider, linkage, program_builder=builder, filename='account-access-test',
                                command='/bin/account-access-test /run/account-access /bin/account-access /bin/busybox /bin/account-access-observe',
                                extra_products=products)
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
                        raise RuntimeError('guest access profile failed: ' + case.name + '/' + firmware)
                    print('ACCOUNT_ACCESS_GUEST_PASS ' + case.name + '/' + firmware, flush=True)
            (args.directory / 'results.json').write_text(json.dumps(rows, indent=2) + '\n')
            if not rows[-1]['passed']:
                raise RuntimeError('native access profile failed: ' + case.name)
            if args.native:
                print('ACCOUNT_ACCESS_NATIVE_PASS ' + case.name, flush=True)
    if source != {name: digest(ROOT / name) for name in source}:
        raise RuntimeError('account access source changed during validation')
    print('ACCOUNT_ACCESS_MATRIX_PASS profiles=' + str(len(rows)) + ' observations=' + str(len(rows) * 16), flush=True)


if __name__ == '__main__':
    main()
