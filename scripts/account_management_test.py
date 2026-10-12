#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Exercise account administration with real executables, passwords and native metadata."""
import argparse
import json
import os
from pathlib import Path
import shutil
import subprocess
import time

from account_store_test import digest, environment
from build_libxcrypt import ensure as crypt
from build_musl import compiler_args, ensure as musl, loader
from fetch import ROOT

SOURCES = ['userspace/accounts/' + name for name in ('store.c', 'store.h', 'database.c', 'database.h',
           'record.c', 'record.h', 'password.c', 'password.h', 'home.c', 'home.h', 'manage.c',
           'protected.c', 'protected.h', 'login_record.c', 'login_record.h', 'logbook.c', 'logbook.h',
           'busy.c', 'busy.h', 'guard.c', 'guard.h', 'auth.h')]
SOURCES += ['scripts/account_management_test.py', 'scripts/account_store_test.py', 'scripts/build_libxcrypt.py',
            'scripts/build_musl.py', 'scripts/linux_uapi.py', 'dependencies.json', 'sources.lock.json']
SECRET = b'Fixture-only-Administrator-42\n'


def build(provider, linkage, directory, native_runtime=None):
    library = crypt(provider)
    stage = library / linkage / 'stage'
    program = directory / ('accountctl-' + provider + '-' + linkage)
    command = ['gcc'] if provider == 'native' else compiler_args(provider)
    command += ['-std=c11', '-O2', '-g', '-Wall', '-Wextra', '-Werror', '-I' + str(stage / 'usr/include'),
                *(str(ROOT / 'userspace/accounts' / name) for name in
                  ('store.c', 'database.c', 'record.c', 'password.c', 'home.c', 'manage.c',
                   'protected.c', 'login_record.c', 'logbook.c', 'busy.c', 'guard.c')),
                '-o', str(program)]
    if linkage == 'static':
        command += ['-static', str(stage / 'usr/lib/libcrypt.a')]
    else:
        command += ['-L' + str(stage / 'usr/lib'), '-lcrypt']
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
        command += ['-Wl,-rpath=' + str(native_runtime)]
        if provider != 'native':
            command += ['-Wl,--dynamic-linker=' + str(native_runtime / 'libc.so')]
    subprocess.run(command, env=environment(), check=True)
    headers = subprocess.check_output(['readelf', '-W', '-l', str(program)], text=True)
    dynamic = subprocess.check_output(['readelf', '-W', '-d', str(program)], text=True)
    if linkage == 'static':
        assert 'INTERP' not in headers and '(NEEDED)' not in dynamic
    else:
        assert 'libcrypt.so.2' in dynamic
        if not native_runtime:
            assert 'RPATH' not in dynamic and 'RUNPATH' not in dynamic
        if provider != 'native' and not native_runtime:
            assert '/lib/ld-musl-x86_64.so.1' in headers
    provenance = dict(command=command, binary_sha256=digest(program), headers=headers, dynamic=dynamic,
                      password_library_manifest_sha256=digest(library / 'manifest.json'), native_runtime=runtime_inputs)
    return program, library, provenance


def invocation(program, library, provider, linkage):
    if linkage == 'static':
        return [str(program)]
    manifest = json.loads((library / 'manifest.json').read_text())
    interpreter = (Path(manifest['identity_inputs']['native_inputs']['ld-linux-x86-64.so.2']['path'])
                   if provider == 'native' else loader(provider))
    paths = [str(library / 'dynamic/stage/usr/lib')]
    if provider != 'native':
        paths += [str(musl(provider) / 'sysroot/lib'), str(musl(provider) / 'sysroot/usr/lib')]
    return [str(interpreter), '--library-path', ':'.join(paths), str(program)]


def payloads(database):
    directory = database / 'current'
    return {name: (directory / name).read_bytes() for name in ('passwd', 'group', 'shadow')}


def native(directory, fixtures):
    directory.mkdir(parents=True, exist_ok=False)
    if fixtures.exists() or not fixtures.is_absolute() or os.geteuid() or os.getegid():
        raise RuntimeError('use root and a fresh absolute native filesystem fixture directory')
    fixtures.mkdir(mode=0o755)
    fixtures.chmod(0o755)
    source = {name: digest(ROOT / name) for name in SOURCES}
    (directory / 'source-inputs.json').write_text(json.dumps(source, indent=2) + '\n')
    rows = []
    for provider in ('build', 'runtime', 'native'):
        for linkage in ('static', 'dynamic'):
            name = provider + '-' + linkage
            case = directory / name
            case.mkdir()
            root = fixtures / name
            root.mkdir(mode=0o755)
            root.chmod(0o755)
            database = root / 'db'
            home = root / 'home/admin'
            program, library, inputs = build(provider, linkage, case)
            prefix = ['unshare', '--mount', '--pid', '--fork', '--mount-proc',
                      *invocation(program, library, provider, linkage), '--database', str(database),
                      '--records', str(root / 'records')]
            cases = []

            def run(label, arguments, *, expected=0, secret=None, ordinary=False, unchanged=False):
                before = payloads(database) if unchanged else None
                started = time.monotonic_ns()
                command = [*prefix, *arguments]
                if ordinary:
                    command[5:5] = ['setpriv', '--reuid=1000', '--regid=1000', '--clear-groups']
                result = subprocess.run(command, input=secret, capture_output=True,
                                        env=environment(), timeout=60)
                log = case / (label + '.log')
                log.write_bytes(result.stdout + result.stderr)
                assert result.returncode == expected, (label, result.returncode, log.read_text())
                assert SECRET.strip() not in log.read_bytes() and b'$y$' not in log.read_bytes()
                if unchanged:
                    assert before == payloads(database)
                cases.append(dict(label=label, arguments=arguments, command=command, returncode=result.returncode,
                                  elapsed_ns=time.monotonic_ns() - started, log=log.name,
                                  log_sha256=digest(log), ordinary=ordinary, unchanged=unchanged, passed=True))
                return result.stdout.decode()

            run('bootstrap', ['bootstrap', 'admin', str(home), '/bin/sh', '--password-fd', '0'], secret=SECRET)
            state = payloads(database)
            assert b'admin:x:1000:1000:Administrator:' in state['passwd']
            assert b'sudo:x:27:admin\n' in state['group'] and b'root:!:' in state['shadow']
            assert b'admin:$y$' in state['shadow']
            for path, mode, uid, gid in ((home, 0o700, 1000, 1000), (database, 0o755, 0, 0),
                                       (database / 'current/passwd', 0o644, 0, 0),
                                       (database / 'current/shadow', 0o600, 0, 0)):
                value = path.stat()
                assert value.st_mode & 0o7777 == mode and value.st_uid == uid and value.st_gid == gid
            run('bootstrap-again', ['bootstrap', 'other', str(root / 'home/other'), '/bin/sh', '--password-fd', '0'],
                expected=1, secret=SECRET, unchanged=True)
            run('group-add', ['group-add', 'bob', '1001'])
            bob_home = root / 'home/bob'
            run('user-add', ['user-add', 'bob', '1001', 'bob', str(bob_home), '/bin/sh'])
            run('duplicate-user', ['user-add', 'bob', '2000', 'bob', str(root / 'home/other'), '/bin/sh'],
                expected=1, unchanged=True)
            run('duplicate-id', ['user-add', 'other', '1001', 'bob', str(root / 'home/other'), '/bin/sh'],
                expected=1, unchanged=True)
            run('invalid-id', ['group-add', 'invalid', '4294967295'], expected=1, unchanged=True)
            run('invalid-name', ['group-add', 'bad:name', '2000'], expected=2, unchanged=True)
            run('primary-group', ['group-delete', 'bob'], expected=1, unchanged=True)
            run('member-add', ['member-add', 'sudo', 'bob'])
            run('rename-user', ['user-rename', 'bob', 'carol'])
            assert b'sudo:x:27:admin,carol\n' in payloads(database)['group']
            run('rename-group', ['group-rename', 'bob', 'staff'])
            run('password-change', ['password', 'carol', '--password-fd', '0'], secret=SECRET)
            assert b'carol:$y$' in payloads(database)['shadow']
            run('lock', ['lock', 'carol'])
            assert b'carol:!$y$' in payloads(database)['shadow']
            run('unlock', ['unlock', 'carol'])
            assert b'carol:$y$' in payloads(database)['shadow']
            run('empty-password', ['password', 'carol', '--password-fd', '0'], expected=2, secret=b'\n', unchanged=True)
            run('member-delete', ['member-delete', 'sudo', 'carol'])
            run('ordinary-denied', ['group-add', 'attack', '2000'], expected=1, ordinary=True, unchanged=True)
            run('root-delete-denied', ['user-delete', 'root'], expected=1, unchanged=True)
            run('user-delete', ['user-delete', 'carol'])
            run('group-delete', ['group-delete', 'staff'])
            assert bob_home.stat().st_uid == 1001
            run('symlink-group', ['group-add', 'unsafe', '2000'])
            linked = root / 'home/linked'
            linked.symlink_to(home, target_is_directory=True)
            run('existing-home', ['user-add', 'unsafe', '2000', 'unsafe', str(linked), '/bin/sh'],
                expected=1, unchanged=True)
            assert home.stat().st_uid == 1000 and not (database / 'current/passwd').read_text().count('unsafe:')
            rows.append(dict(provider=provider, linkage=linkage, inputs=inputs, cases=cases, passed=True))
            (directory / 'results.json').write_text(json.dumps(rows, indent=2) + '\n')
            print('ACCOUNT_MANAGEMENT_NATIVE_PASS ' + name + ' cases=' + str(len(cases)), flush=True)
    assert source == {name: digest(ROOT / name) for name in source}
    print('ACCOUNT_MANAGEMENT_NATIVE_MATRIX_PASS profiles=6 cases=' + str(sum(len(row['cases']) for row in rows)), flush=True)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--directory', type=Path, default=ROOT / 'build/account-management-native')
    parser.add_argument('--fixtures', type=Path, required=True)
    args = parser.parse_args()
    native(args.directory, args.fixtures)
