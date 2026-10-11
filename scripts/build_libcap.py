# SPDX-License-Identifier: GPL-3.0-or-later
"""Build the pinned upstream getcap/setcap tools with an explicit libc provider."""
import argparse
import fcntl
import hashlib
import json
import os
from pathlib import Path
import shlex
import subprocess
import tarfile
from fetch import ROOT, LOCK, fetch
from build_musl import compiler_args, ensure as musl

OUTPUT = ROOT / 'build/libcap'


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def ensure(provider='build'):
    if provider not in ('build', 'runtime', 'native'):
        raise ValueError(provider)
    dependency = LOCK['libcap']
    compiler = ['gcc'] if provider == 'native' else compiler_args(provider)
    libc = None if provider == 'native' else json.loads((musl(provider) / 'manifest.json').read_text())
    version = subprocess.check_output(['gcc', '-dumpfullversion'], text=True).strip()
    target = subprocess.check_output(['gcc', '-dumpmachine'], text=True).strip()
    if target != 'x86_64-linux-gnu':
        raise RuntimeError('libcap requires the pinned x86-64 Linux build host')
    native_inputs = {}
    if provider == 'native':
        for name in ('libc.so.6', 'ld-linux-x86-64.so.2', 'libc.a', 'libc_nonshared.a',
                     'crt1.o', 'Scrt1.o', 'crti.o', 'crtn.o', 'libgcc.a', 'crtbegin.o', 'crtend.o'):
            path = Path(subprocess.check_output(['gcc', '-print-file-name=' + name], text=True).strip()).resolve()
            if not path.is_file():
                raise RuntimeError('native libcap linker input is missing: ' + name)
            native_inputs[name] = dict(path=str(path), sha256=digest(path))
        for name in ('capability.h', 'xattr.h'):
            path = Path('/usr/include/linux') / name
            native_inputs['linux/' + name] = dict(path=str(path), sha256=digest(path))
    identity = hashlib.sha256(json.dumps(dependency, sort_keys=True).encode() +
        Path(__file__).read_bytes() + (version + target + provider).encode() +
        (libc['identity'].encode() if libc else json.dumps(native_inputs, sort_keys=True).encode())).hexdigest()
    destination = OUTPUT / provider / identity
    manifest = destination / 'manifest.json'
    OUTPUT.mkdir(parents=True, exist_ok=True)
    with (OUTPUT / '.lock').open('a') as guard:
        fcntl.flock(guard, fcntl.LOCK_EX)
        if manifest.exists():
            record = json.loads(manifest.read_text())
            if record['identity'] != identity:
                raise RuntimeError('libcap cache identity differs')
            for name, expected in record['products'].items():
                if digest(destination / name) != expected:
                    raise RuntimeError('cached libcap product changed: ' + name)
            return destination
        archive = fetch('libcap')
        source_root = destination / 'source'
        source_root.mkdir(parents=True, exist_ok=True)
        with tarfile.open(archive) as stream:
            stream.extractall(source_root, filter='data')
        source = source_root / ('libcap-' + dependency['version'])
        environment = os.environ.copy()
        for name in ('CFLAGS', 'CPPFLAGS', 'LDFLAGS', 'CPATH', 'C_INCLUDE_PATH',
                     'CPLUS_INCLUDE_PATH', 'LIBRARY_PATH', 'GCC_EXEC_PREFIX'):
            environment.pop(name, None)
        commands = []
        # The provider's libc headers take priority; Linux UAPI is a fallback.
        cc = [*compiler, '-idirafter', '/usr/include', '-idirafter', '/usr/include/x86_64-linux-gnu']
        command = ['make', '-j2', '-C', str(source / 'libcap'), 'libcap.a',
                   'CC=' + shlex.join(cc), 'BUILD_CC=gcc', 'SHARED=no', 'PTHREADS=no',
                   'GOLANG=no', 'USE_GPERF=no', 'COPTS=-O2 -g']
        with (destination / 'build.log').open('w') as output:
            subprocess.run(command, env=environment, check=True, stdout=output, stderr=subprocess.STDOUT)
            commands.append(command)
            for linkage in ('static', 'dynamic'):
                for name in ('getcap', 'setcap'):
                    binary = destination / (name + '-' + linkage)
                    command = [*cc, '-std=gnu11', '-O2', '-g',
                               '-I' + str(source / 'libcap/include'),
                               '-I' + str(source / 'libcap/include/uapi')]
                    if linkage == 'static':
                        command += ['-static']
                    command += [str(source / 'progs' / (name + '.c')), str(source / 'libcap/libcap.a'),
                                '-o', str(binary)]
                    subprocess.run(command, env=environment, check=True, stdout=output, stderr=subprocess.STDOUT)
                    commands.append(command)
        products = {path.relative_to(destination).as_posix(): digest(path)
                    for path in [*(destination / (name + '-' + linkage) for name in ('getcap', 'setcap')
                                   for linkage in ('static', 'dynamic')),
                                 source / 'License', source / 'libcap/libcap.a']}
        record = dict(identity=identity, provider=provider, version=dependency['version'],
                      source=dict(url=dependency['url'], archive=dependency['archive'], sha256=digest(archive)),
                      license=dependency['license'], upstream_license=dependency['upstream_license'],
                      compiler=version, target=target, libc_identity=libc['identity'] if libc else None,
                      native_inputs=native_inputs, commands=commands, products=products)
        manifest.write_text(json.dumps(record, indent=2) + '\n')
        print('Built pinned libcap tools provider=' + provider + ' identity=' + identity, flush=True)
        return destination


def runtime_files():
    destination = ensure('runtime')
    source = destination / 'source' / ('libcap-' + LOCK['libcap']['version'])
    return {**{f'usr/sbin/{name}': (0o100755, (destination / (name + '-dynamic')).read_bytes())
               for name in ('getcap', 'setcap')},
            'usr/share/licenses/libcap/License': (0o100644, (source / 'License').read_bytes()),
            'usr/share/licenses/libcap/Axiom64-build.json': (0o100644, (destination / 'manifest.json').read_bytes())}


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--provider', choices=('build', 'runtime', 'native', 'all'), default='build')
    args = parser.parse_args()
    for provider in ('build', 'runtime', 'native') if args.provider == 'all' else (args.provider,):
        ensure(provider)
