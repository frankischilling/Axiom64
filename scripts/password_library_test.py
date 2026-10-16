#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Exercise actual maintained password hashing through all three libc providers."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import time

from build_libxcrypt import ensure, digest
from build_musl import compiler_args, ensure as musl, loader
from fetch import ROOT


def build(provider, linkage, destination):
    library = ensure(provider)
    compiler = ['gcc'] if provider == 'native' else compiler_args(provider)
    stage = library / linkage / 'stage'
    program = destination / ('password-' + provider + '-' + linkage)
    command = [*compiler, '-std=c11', '-O2', '-g', '-Wall', '-Wextra', '-Werror',
               '-I' + str(ROOT / 'userspace'), '-I' + str(stage / 'usr/include'),
               str(ROOT / 'userspace/accounts/password.c'),
               str(ROOT / 'userspace/tests/security/password.c')]
    if linkage == 'static':
        command += ['-static', str(stage / 'usr/lib/libcrypt.a')]
    else:
        command += ['-L' + str(stage / 'usr/lib'), '-lcrypt']
    command += ['-o', str(program)]
    environment = os.environ.copy()
    for name in ('CFLAGS', 'CPPFLAGS', 'LDFLAGS', 'CPATH', 'C_INCLUDE_PATH',
                 'CPLUS_INCLUDE_PATH', 'LIBRARY_PATH', 'GCC_EXEC_PREFIX', 'LD_LIBRARY_PATH', 'LD_PRELOAD'):
        environment.pop(name, None)
    subprocess.run(command, env=environment, check=True)
    headers = subprocess.check_output(['readelf', '-W', '-l', str(program)], text=True)
    dynamic = subprocess.check_output(['readelf', '-W', '-d', str(program)], text=True)
    if linkage == 'static':
        if 'INTERP' in headers or '(NEEDED)' in dynamic:
            raise RuntimeError('static password client has dynamic dependencies')
    else:
        if 'libcrypt.so.2' not in dynamic or 'RPATH' in dynamic or 'RUNPATH' in dynamic:
            raise RuntimeError('dynamic password client has unexpected library provenance')
        if provider != 'native' and '/lib/ld-musl-x86_64.so.1' not in headers:
            raise RuntimeError('target password client uses another interpreter')
    return program, library, dict(command=command, binary_sha256=digest(program),
                                  library_manifest_sha256=digest(library / 'manifest.json'),
                                  program_headers=headers, dynamic=dynamic)


def native(destination):
    destination.mkdir(parents=True, exist_ok=False)
    rows = []
    for provider in ('build', 'runtime', 'native'):
        for linkage in ('static', 'dynamic'):
            program, library, inputs = build(provider, linkage, destination)
            command = [str(program)]
            if linkage == 'dynamic':
                manifest = json.loads((library / 'manifest.json').read_text())
                interpreter = (Path(manifest['identity_inputs']['native_inputs']['ld-linux-x86-64.so.2']['path'])
                               if provider == 'native' else loader(provider))
                paths = [str(library / 'dynamic/stage/usr/lib')]
                if provider != 'native':
                    paths += [str(musl(provider) / 'sysroot/lib'), str(musl(provider) / 'sysroot/usr/lib')]
                command = [str(interpreter), '--library-path', ':'.join(paths), str(program)]
                inputs['actual_loader_sha256'] = digest(interpreter)
                inputs['shared_library_sha256'] = digest(library / 'dynamic/stage/usr/lib/libcrypt.so.2.0.0')
            environment = os.environ.copy()
            for name in ('LD_LIBRARY_PATH', 'LD_PRELOAD'):
                environment.pop(name, None)
            start = time.monotonic_ns()
            result = subprocess.run(command, env=environment, capture_output=True, timeout=60)
            log = destination / (program.name + '.log')
            log.write_bytes(result.stdout + result.stderr)
            text = result.stdout.decode()
            observations = len([line for line in text.splitlines() if line.startswith('PASSWORD_LIBRARY_OBSERVATION ')])
            passed = (result.returncode == 0 and observations == 22 and
                      text.splitlines().count('PASSWORD_LIBRARY_PASS observations=22') == 1 and
                      'PASSWORD_LIBRARY_FAIL' not in text)
            row = dict(provider=provider, linkage=linkage, inputs=inputs, command=command,
                       returncode=result.returncode, elapsed_ns=time.monotonic_ns()-start,
                       observations=observations, log=log.name, log_sha256=digest(log), passed=passed)
            rows.append(row)
            (destination / 'results.json').write_text(json.dumps(rows, indent=2) + '\n')
            if not passed:
                raise RuntimeError('password-library native profile failed: ' + program.name)
            print('PASSWORD_LIBRARY_NATIVE_PASS provider=' + provider + ' linkage=' + linkage, flush=True)
    source = {name: digest(ROOT / name) for name in ('userspace/accounts/password.c',
              'userspace/accounts/password.h', 'userspace/tests/security/password.c',
              'scripts/password_library_test.py', 'scripts/build_libxcrypt.py', 'scripts/linux_uapi.py',
              'dependencies.json', 'ports.lock.json', 'sources.lock.json')}
    (destination / 'source-inputs.json').write_text(json.dumps(source, indent=2) + '\n')
    print('PASSWORD_LIBRARY_NATIVE_MATRIX_PASS profiles=6 observations=132', flush=True)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--directory', type=Path, default=ROOT / 'build/password-library-native')
    args = parser.parse_args()
    native(args.directory)
