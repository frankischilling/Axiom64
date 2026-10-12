#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Run two authenticated ordinary shells and private session cleanup controls."""
import argparse
import json
import os
from pathlib import Path
import shutil
import subprocess
import tarfile
import time

from account_management_test import SOURCES, crypt, invocation
from account_management_test import build as management_build
from account_store_guest import fixture
from account_store_test import digest, environment
from build_musl import compiler_args
from fetch import LOCK, ROOT

INPUTS = [*SOURCES, 'userspace/accounts/auth.c', 'userspace/accounts/auth.h',
          'userspace/accounts/session.c', 'userspace/accounts/session.h',
          *(f'userspace/accounts/{name}.{suffix}' for name in
            ('protected', 'login_record', 'logbook', 'recorded') for suffix in ('c', 'h')),
          'userspace/tests/security/account-session.c', 'userspace/tests/security/account-session-observe.c',
          'scripts/account_session_test.py', 'scripts/account_store_guest.py', 'Makefile',
          'scripts/image.py', 'userspace/init/main.c', 'userspace/init/seed_records.h', 'boot/limine.conf']


def build(provider, linkage, directory):
    library = crypt(provider)
    stage = library / linkage / 'stage'
    compiler = ['gcc'] if provider == 'native' else compiler_args(provider)
    program = directory / ('account-session-' + provider + '-' + linkage)
    command = [*compiler, '-std=c11', '-O2', '-g', '-Wall', '-Wextra', '-Werror',
               '-I' + str(stage / 'usr/include'),
               *(str(ROOT / 'userspace/accounts' / name) for name in
                 ('store.c', 'database.c', 'record.c', 'password.c', 'home.c', 'auth.c', 'session.c',
                  'protected.c', 'login_record.c', 'logbook.c', 'recorded.c', 'busy.c')),
               str(ROOT / 'userspace/tests/security/account-session.c'), '-o', str(program)]
    if linkage == 'static':
        command += ['-static', str(stage / 'usr/lib/libcrypt.a')]
    else:
        command += ['-L' + str(stage / 'usr/lib'), '-lcrypt']
    subprocess.run(command, env=environment(), check=True)
    observer = directory / ('account-session-observe-' + provider)
    observer_command = [*compiler, '-std=c11', '-O2', '-g', '-Wall', '-Wextra', '-Werror', '-static',
                        str(ROOT / 'userspace/tests/security/account-session-observe.c'), '-o', str(observer)]
    subprocess.run(observer_command, env=environment(), check=True)
    headers = subprocess.check_output(['readelf', '-W', '-l', str(program)], text=True)
    dynamic = subprocess.check_output(['readelf', '-W', '-d', str(program)], text=True)
    if linkage == 'static':
        assert 'INTERP' not in headers and '(NEEDED)' not in dynamic
    else:
        assert 'libcrypt.so.2' in dynamic and 'RPATH' not in dynamic and 'RUNPATH' not in dynamic
        if provider != 'native':
            assert '/lib/ld-musl-x86_64.so.1' in headers
    observer_headers = subprocess.check_output(['readelf', '-W', '-l', str(observer)], text=True)
    assert 'INTERP' not in observer_headers
    inputs = dict(command=command, binary_sha256=digest(program), headers=headers, dynamic=dynamic,
                  observer_command=observer_command, observer_sha256=digest(observer),
                  observer_headers=observer_headers, library_manifest_sha256=digest(library / 'manifest.json'))
    return program, observer, library, inputs


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
    count = sum(line.startswith('ACCOUNT_SESSION_OBSERVATION ') for line in lines)
    shells = [line for line in lines if line.startswith('ACCOUNT_SHELL_SESSION_PASS ')]
    passed = (not timed_out and process.returncode == (1 if firmware else 0) and count == 15 and
              lines.count('ACCOUNT_SESSION_PASS observations=15 authenticated_shells=2') == 1 and len(shells) == 2 and
              any('user=alice uid=1000 gid=1000' in line for line in shells) and
              any('user=bob uid=1001 gid=1001' in line for line in shells) and
              all('foreground=1 private_tty=1 cross_user_denied=1' in line for line in shells) and
              not any(marker in text for marker in ('ACCOUNT_SESSION_FAIL', 'FORBIDDEN_SESSION_EXEC', 'PANIC:', 'FAULT pid=')))
    if firmware:
        passed = passed and lines.count('AXIOM64_TESTS_PASS') == 1 and 'AXIOM64_EXIT status=0' in text
        passed = passed and 'Firmware: ' + firmware.upper() in text
    return dict(command=command, returncode=process.returncode, timed_out=timed_out,
                elapsed_ns=time.monotonic_ns() - started, observations=count,
                log=str(log), log_sha256=digest(log), passed=passed)


def retain_native(directory, fixture):
    metadata = []
    for path in [fixture, *sorted(fixture.rglob('*'))]:
        value = path.lstat()
        row = dict(path=path.relative_to(fixture).as_posix(), mode=value.st_mode,
                   uid=value.st_uid, gid=value.st_gid, nlink=value.st_nlink, bytes=value.st_size)
        if path.is_symlink():
            row['target'] = os.readlink(path)
        elif path.is_file():
            row['sha256'] = digest(path)
        metadata.append(row)
    manifest = directory / 'native-metadata.json'
    manifest.write_text(json.dumps(metadata, indent=2) + '\n')
    archive = directory / 'native-fixture.tar'
    def names(info):
        info.uname = info.gname = ''
        return info
    with tarfile.open(archive, 'w') as output:
        output.add(fixture, arcname='native-fixture', filter=names)
    return dict(metadata_sha256=digest(manifest), archive_sha256=digest(archive))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--directory', type=Path, default=ROOT / 'build/account-session')
    parser.add_argument('--native', action='store_true')
    parser.add_argument('--fixtures', type=Path)
    args = parser.parse_args()
    if args.native:
        if os.geteuid() or os.getegid() or not args.fixtures or not args.fixtures.is_absolute() or args.fixtures.exists():
            raise RuntimeError('native session controls require root and fresh Linux filesystem fixtures')
        args.fixtures.mkdir(mode=0o755)
        args.fixtures.chmod(0o755)
    args.directory.mkdir(parents=True, exist_ok=False)
    names = [*INPUTS, *(path.relative_to(ROOT).as_posix() for path in (ROOT / 'kernel').rglob('*')
                       if path.is_file() and path.suffix in ('.cpp', '.hpp', '.asm'))]
    source = {name: digest(ROOT / name) for name in names}
    (args.directory / 'source-inputs.json').write_text(json.dumps(source, indent=2) + '\n')
    targets = ['busybox'] if args.native else ['build/axiom64.elf', 'build/init', 'busybox']
    subprocess.run(['make', '-s', '-j2', *targets], cwd=ROOT, check=True)
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
            program, observer, library, inputs = build(provider, linkage, case)
            management_directory = case / 'management'
            management_directory.mkdir()
            manager, _, management_inputs = management_build(provider, linkage, management_directory,
                                native_case / 'lib' if native_case else None)
            inputs['management'] = management_inputs
            inputs['busybox_sha256'] = digest(busybox)
            if args.native:
                native_observer = native_case / 'account-session-observe'
                shutil.copyfile(observer, native_observer)
                native_observer.chmod(0o755)
                assert digest(native_observer) == inputs['observer_sha256']
                native_manager = native_case / 'accountctl'
                shutil.copyfile(manager, native_manager)
                native_manager.chmod(0o755)
                assert digest(native_manager) == management_inputs['binary_sha256']
                command = invocation(program, library, provider, linkage) + [str(native_case / 'data'),
                            str(busybox), str(native_observer), str(native_manager)]
                command = ['unshare', '--mount', '--pid', '--fork', '--mount-proc', *command]
                row = execute(command, case / 'native.log')
                row.update(provider=provider, linkage=linkage, inputs=inputs)
                row['native_exports'] = retain_native(case, native_case)
                rows.append(row)
                (args.directory / 'results.json').write_text(json.dumps(rows, indent=2) + '\n')
                if not row['passed']:
                    raise RuntimeError('native session profile failed: ' + case.name)
                print('ACCOUNT_SESSION_NATIVE_PASS ' + case.name, flush=True)
            else:
                def builder(_provider, _linkage, _directory):
                    return program, inputs
                products = {'bin/account-session-observe': observer, 'bin/accountctl': manager}
                if linkage == 'dynamic':
                    products['usr/lib/libcrypt.so.2'] = library / 'dynamic/stage/usr/lib/libcrypt.so.2.0.0'
                image = fixture(case, provider, linkage, program_builder=builder, filename='account-session',
                                command='/bin/account-session /run/account-session /bin/busybox /bin/account-session-observe /bin/accountctl',
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
                        raise RuntimeError('guest session profile failed: ' + case.name + '/' + firmware)
                    print('ACCOUNT_SESSION_GUEST_PASS ' + case.name + '/' + firmware, flush=True)
    if source != {name: digest(ROOT / name) for name in source}:
        raise RuntimeError('account session source changed during validation')
    print('ACCOUNT_SESSION_MATRIX_PASS profiles=' + str(len(rows)) + ' observations=' + str(len(rows) * 15), flush=True)


if __name__ == '__main__':
    main()
