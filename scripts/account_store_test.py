#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Exercise immutable account generations with actual libc and filesystem operations."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import time

from build_musl import compiler_args, ensure, loader
from fetch import ROOT

STORE_MODULES = tuple('userspace/accounts/' + name + '.c' for name in
                      ('store', 'transaction', 'home', 'protected'))
STORE_INPUTS = tuple('userspace/accounts/' + name + '.' + suffix for name in
                     ('store', 'transaction', 'home', 'protected') for suffix in ('c', 'h'))
SOURCES = ('userspace/accounts/store.c', 'userspace/accounts/store.h',
           'userspace/tests/security/account-store.c', 'scripts/account_store_test.py',
           'scripts/build_musl.py', 'sources.lock.json') + STORE_INPUTS
MARKER = 'ACCOUNT_STORE_PASS generations=2 concurrent_updates=12 epoch=13 ordinary_denials=3 protected_rejections=5 fixture='


def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def environment():
    result = os.environ.copy()
    for name in ('CFLAGS', 'CPPFLAGS', 'LDFLAGS', 'CPATH', 'C_INCLUDE_PATH', 'CPLUS_INCLUDE_PATH',
                 'LIBRARY_PATH', 'GCC_EXEC_PREFIX', 'LD_LIBRARY_PATH', 'LD_PRELOAD'):
        result.pop(name, None)
    return result


def build(provider, linkage, directory):
    compiler = ['gcc'] if provider == 'native' else compiler_args(provider)
    program = directory / ('account-store-' + provider + '-' + linkage)
    command = [*compiler, '-std=c11', '-O2', '-g', '-Wall', '-Wextra', '-Werror',
               *(str(ROOT / name) for name in STORE_MODULES), str(ROOT / SOURCES[2]), '-o', str(program)]
    if linkage == 'static':
        command += ['-static']
    subprocess.run(command, env=environment(), check=True)
    headers = subprocess.check_output(['readelf', '-W', '-l', str(program)], text=True)
    dynamic = subprocess.check_output(['readelf', '-W', '-d', str(program)], text=True)
    if linkage == 'static':
        if 'INTERP' in headers or '(NEEDED)' in dynamic:
            raise RuntimeError('static account store unexpectedly depends on a dynamic library')
    elif 'RPATH' in dynamic or 'RUNPATH' in dynamic or '(NEEDED)' not in dynamic:
        raise RuntimeError('dynamic account store library selection is not explicit')
    elif provider != 'native' and '/lib/ld-musl-x86_64.so.1' not in headers:
        raise RuntimeError('target account store uses an unexpected interpreter')
    provenance = dict(command=command, binary_sha256=digest(program), headers=headers, dynamic=dynamic,
                      sources={name: digest(ROOT / name) for name in SOURCES})
    if provider != 'native':
        provenance['libc_manifest_sha256'] = digest(ensure(provider) / 'manifest.json')
    return program, provenance


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--directory', type=Path, default=ROOT / 'build/account-store-native')
    parser.add_argument('--fixtures', type=Path, required=True)
    args = parser.parse_args()
    if os.geteuid() != 0 or os.getegid() != 0:
        raise RuntimeError('native ownership and ordinary-user controls require root credentials')
    if not args.fixtures.is_absolute() or args.fixtures.exists():
        raise RuntimeError('use a fresh absolute native filesystem fixture directory')
    args.directory.mkdir(parents=True, exist_ok=False)
    args.fixtures.mkdir(mode=0o755)
    args.fixtures.chmod(0o755)
    source = {name: digest(ROOT / name) for name in SOURCES}
    (args.directory / 'source-inputs.json').write_text(json.dumps(source, indent=2) + '\n')
    rows = []
    for provider in ('build', 'runtime', 'native'):
        for linkage in ('static', 'dynamic'):
            name = provider + '-' + linkage
            program, provenance = build(provider, linkage, args.directory)
            command = [str(program), str(args.fixtures / name)]
            if linkage == 'dynamic':
                interpreter = Path('/lib64/ld-linux-x86-64.so.2') if provider == 'native' else loader(provider)
                library = ('/lib/x86_64-linux-gnu' if provider == 'native' else
                           ':'.join(str(ensure(provider) / path) for path in ('sysroot/lib', 'sysroot/usr/lib')))
                command = [str(interpreter), '--library-path', library, *command]
                provenance['loader_sha256'] = digest(interpreter)
                provenance['libc_sha256'] = digest(Path(library) / 'libc.so.6' if provider == 'native' else interpreter)
            start = time.monotonic_ns()
            result = subprocess.run(command, env=environment(), capture_output=True, timeout=60)
            log = args.directory / (name + '.log')
            log.write_bytes(result.stdout + result.stderr)
            text = log.read_text()
            passed = (result.returncode == 0 and text.splitlines().count(MARKER + str(args.fixtures / name)) == 1
                      and 'ACCOUNT_STORE_FAIL' not in text)
            rows.append(dict(provider=provider, linkage=linkage, inputs=provenance, command=command,
                             returncode=result.returncode, elapsed_ns=time.monotonic_ns() - start,
                             log=log.name, log_sha256=digest(log), passed=passed))
            (args.directory / 'results.json').write_text(json.dumps(rows, indent=2) + '\n')
            if not passed:
                raise RuntimeError('account store native profile failed: ' + name)
            print('ACCOUNT_STORE_NATIVE_PROFILE_PASS ' + name, flush=True)
    if source != {name: digest(ROOT / name) for name in source}:
        raise RuntimeError('account store inputs changed during the native comparisons')
    print('ACCOUNT_STORE_NATIVE_MATRIX_PASS profiles=6 concurrent_updates=72', flush=True)


if __name__ == '__main__':
    main()
