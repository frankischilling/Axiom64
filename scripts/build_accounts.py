#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Build the production account administrator, access frontend and console service."""
import argparse
import fcntl
import hashlib
import json
import os
from pathlib import Path
import subprocess

from build_libxcrypt import ensure as password_library
from build_musl import compiler_args
from fetch import ROOT

MODULES = ('store', 'transaction', 'database', 'record', 'password', 'home', 'auth', 'secret', 'session',
           'protected', 'login_record', 'logbook', 'recorded', 'update', 'busy', 'guard')
PROGRAMS = {'accountctl': 'manage', 'account-access': 'access', 'account-console': 'console'}
DESKTOP_INPUTS = [f'userspace/desktop/{name}.{suffix}' for name in ('seat', 'authority') for suffix in ('c', 'h')]
INPUTS = [*(f'userspace/accounts/{name}.{suffix}' for name in MODULES for suffix in ('c', 'h')),
          'userspace/accounts/logbook_rotation.c', 'userspace/accounts/logbook_internal.h',
          *(f'userspace/accounts/{name}.c' for name in PROGRAMS.values()),
          'scripts/build_accounts.py', 'scripts/build_libxcrypt.py', 'scripts/build_musl.py',
          'scripts/linux_uapi.py', 'dependencies.json', 'sources.lock.json', *DESKTOP_INPUTS]


def digest(path):
    with Path(path).open('rb') as file:
        return hashlib.file_digest(file, 'sha256').hexdigest()


def environment():
    value = os.environ.copy()
    for name in ('CC', 'CFLAGS', 'CPPFLAGS', 'LDFLAGS', 'CPATH', 'C_INCLUDE_PATH',
                 'CPLUS_INCLUDE_PATH', 'LIBRARY_PATH', 'GCC_EXEC_PREFIX', 'LD_LIBRARY_PATH',
                 'LD_PRELOAD', 'CONFIG_SITE'):
        value.pop(name, None)
    value['LC_ALL'] = 'C'
    return value


def ensure(provider='build', linkage='static'):
    if provider not in ('build', 'runtime', 'native') or linkage not in ('static', 'dynamic'):
        raise ValueError('unknown account build profile')
    library = password_library(provider)
    stage = library / linkage / 'stage'
    compiler = ['gcc'] if provider == 'native' else compiler_args(provider)
    source = {name: digest(ROOT / name) for name in INPUTS}
    identity_inputs = dict(provider=provider, linkage=linkage, source=source,
        password_manifest_sha256=digest(library / 'manifest.json'),
        compiler=subprocess.check_output([*compiler, '--version'], text=True, env=environment()),
        target=subprocess.check_output([*compiler, '-dumpmachine'], text=True, env=environment()))
    identity = hashlib.sha256(json.dumps(identity_inputs, sort_keys=True).encode()).hexdigest()
    parent = ROOT / 'build/accounts' / provider
    parent.mkdir(parents=True, exist_ok=True)
    destination = parent / identity
    with (parent / 'build.lock').open('w') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        manifest = destination / 'manifest.json'
        if manifest.exists():
            record = json.loads(manifest.read_text())
            if record['identity_inputs'] != identity_inputs:
                raise RuntimeError('account build identity changed')
            for name, expected in record['products'].items():
                if digest(destination / name) != expected:
                    raise RuntimeError('account cached product changed: ' + name)
            return destination
        if destination.exists():
            raise RuntimeError('incomplete account build retained: ' + str(destination))
        destination.mkdir()
        commands, products = {}, {}
        for program, main in PROGRAMS.items():
            output = destination / program
            command = [*compiler, '-std=c11', '-O2', '-g', '-Wall', '-Wextra', '-Werror',
                       '-I' + str(stage / 'usr/include'),
                       '-ffile-prefix-map=' + str(ROOT) + '=/usr/src/axiom64',
                       *(str(ROOT / f'userspace/accounts/{name}.c') for name in MODULES),
                       str(ROOT / 'userspace/accounts/logbook_rotation.c'),
                       *(str(ROOT / name) for name in DESKTOP_INPUTS if name.endswith('.c')),
                       str(ROOT / f'userspace/accounts/{main}.c'), '-o', str(output)]
            command += ['-static', str(stage / 'usr/lib/libcrypt.a')] if linkage == 'static' else [
                '-L' + str(stage / 'usr/lib'), '-lcrypt']
            with (destination / (program + '-build.log')).open('wb') as log:
                subprocess.run(command, cwd=ROOT, env=environment(), stdin=subprocess.DEVNULL,
                               stdout=log, stderr=subprocess.STDOUT, check=True)
            headers = subprocess.check_output(['readelf', '-W', '-l', str(output)], text=True)
            dynamic = subprocess.check_output(['readelf', '-W', '-d', str(output)], text=True)
            if linkage == 'static':
                assert 'INTERP' not in headers and '(NEEDED)' not in dynamic
            else:
                assert 'libcrypt.so.2' in dynamic and 'RPATH' not in dynamic and 'RUNPATH' not in dynamic
                if provider != 'native':
                    assert '/lib/ld-musl-x86_64.so.1' in headers
            commands[program] = dict(command=command, headers=headers, dynamic=dynamic)
            products[program] = digest(output)
        if source != {name: digest(ROOT / name) for name in source}:
            raise RuntimeError('account source changed during build')
        manifest.write_text(json.dumps(dict(identity=identity, identity_inputs=identity_inputs,
            commands=commands, products=products), indent=2) + '\n')
    print('ACCOUNTS_BUILD_PASS provider=' + provider + ' linkage=' + linkage, flush=True)
    return destination


def runtime_files():
    destination = ensure()
    result = {name: (0o100755, (destination / name).read_bytes()) for name in PROGRAMS}
    result['usr/bin/accountctl'] = result.pop('accountctl')
    result['usr/bin/account-access'] = (0o104755, result.pop('account-access')[1])
    result['sbin/account-console'] = (0o100700, result.pop('account-console')[1])
    for name in ('login', 'su', 'sudo', 'passwd'):
        result['usr/bin/' + name] = (0o120777, b'/usr/bin/account-access')
        result['bin/' + name] = (0o120777, b'/usr/bin/account-access')
    for name in ('passwd', 'group', 'shadow'):
        result['etc/' + name] = (0o120777, ('/etc/axiom64/accounts/current/' + name).encode())
    result['var/run'] = (0o40755, b'')
    result['var/run/utmp'] = (0o120777, b'/var/log/axiom64/login/utmp')
    for name in ('wtmp', 'btmp'):
        result['var/log/' + name] = (0o120777, ('/var/log/axiom64/login/' + name).encode())
    result['usr/share/licenses/Axiom64/accounts-build.json'] = (0o100644, (destination / 'manifest.json').read_bytes())
    return result


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--provider', choices=('build', 'runtime', 'native', 'all'), default='build')
    parser.add_argument('--linkage', choices=('static', 'dynamic', 'all'), default='static')
    args = parser.parse_args()
    for provider in ('build', 'runtime', 'native') if args.provider == 'all' else (args.provider,):
        for linkage in ('static', 'dynamic') if args.linkage == 'all' else (args.linkage,):
            ensure(provider, linkage)
