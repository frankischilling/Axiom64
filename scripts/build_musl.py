#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Build patched, pinned musl libraries without modifying the host toolchain."""
import argparse
import fcntl
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import tarfile
import tempfile
from fetch import ROOT
from ports import download
from sources import CACHE, port_sources, verify

OUTPUT = ROOT / 'build/musl'


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def checked_patches(lock):
    patches = []
    for row in lock['musl_local_patches']:
        path = (ROOT / row['path']).resolve()
        if not path.is_relative_to((ROOT / 'vendor/musl').resolve()):
            raise RuntimeError('local musl patch escapes its vendor folder')
        patches.append(verify(path, row['sha256'], 'sha256'))
    return patches


def inputs(provider, lock):
    if provider == 'build':
        paths = [verify(download(row['url'], CACHE / 'build-musl' / row['name']),
                        row['sha256'], 'sha256') for row in lock['build_musl']['files']]
        archive = next(path for path in paths if path.name.endswith('.orig.tar.gz'))
        packaging = next(path for path in paths if path.name.endswith('.debian.tar.xz'))
        return archive, packaging, paths
    row = next(row for row in lock['ports'] if row['origin'] == 'musl')
    _, paths = port_sources(row)
    archive = next(path for path in paths if path.name == 'musl-1.2.5.tar.gz')
    return archive, None, paths


def ensure(provider='build'):
    if provider not in ('build', 'runtime'):
        raise ValueError(provider)
    OUTPUT.mkdir(parents=True, exist_ok=True)
    lock = json.loads((ROOT / 'sources.lock.json').read_text())
    patches = checked_patches(lock)
    compiler = subprocess.check_output(['gcc', '-dumpfullversion'], text=True).strip()
    target = subprocess.check_output(['gcc', '-dumpmachine'], text=True).strip()
    if target != 'x86_64-linux-gnu':
        raise RuntimeError(f'musl build requires the pinned x86-64 Linux host; found {target}')
    identity = hashlib.sha256((ROOT / 'sources.lock.json').read_bytes() +
        Path(__file__).read_bytes() + b''.join(path.read_bytes() for path in patches) +
        (compiler + target + provider).encode()).hexdigest()
    # Keep completed libraries immutable while a changed input builds separately.
    destination = OUTPUT / provider / identity
    manifest = destination / 'manifest.json'
    with (OUTPUT / '.lock').open('a') as guard:
        fcntl.flock(guard, fcntl.LOCK_EX)
        if manifest.exists():
            saved = json.loads(manifest.read_text())
            if saved['identity'] == identity:
                for name, expected in saved['products'].items():
                    if digest(destination / name) != expected:
                        raise RuntimeError(f'cached musl product changed: {provider}/{name}')
                return destination
        archive, packaging, verified = inputs(provider, lock)
        destination.mkdir(parents=True, exist_ok=True)
        logfile = destination / 'build.log'
        with tempfile.TemporaryDirectory(prefix=f'axiom64-musl-{provider}-') as temporary:
            scratch = Path(temporary)
            with tarfile.open(archive) as stream:
                stream.extractall(scratch, filter='data')
            source = scratch / ('musl-1.2.4' if provider == 'build' else 'musl-1.2.5')
            ordered = []
            if packaging:
                with tarfile.open(packaging) as stream:
                    stream.extractall(source, filter='data')
                series = source / 'debian/patches/series'
                if series.exists():
                    for line in series.read_text().splitlines():
                        name = line.split('#', 1)[0].strip()
                        if name:
                            ordered.append(source / 'debian/patches' / name)
            else:
                ordered.extend(path for path in verified if path.suffix == '.patch')
            ordered.extend(patches)
            environment = os.environ.copy()
            # Explicit source-built libc uses its own headers and startup files.
            for name in ('CFLAGS', 'CPPFLAGS', 'LDFLAGS', 'CPATH', 'C_INCLUDE_PATH',
                         'CPLUS_INCLUDE_PATH', 'LIBRARY_PATH', 'GCC_EXEC_PREFIX'):
                environment.pop(name, None)
            commands = []
            with logfile.open('w') as output:
                def run(command):
                    commands.append(command)
                    subprocess.run(command, cwd=source, env=environment, stdin=subprocess.DEVNULL,
                                   stdout=output, stderr=subprocess.STDOUT, check=True)
                for patch in ordered:
                    run(['patch', '-p1', '--fuzz=0', '--batch', '-i', str(patch)])
                configure = ['./configure', '--prefix=/usr', '--syslibdir=/lib',
                             '--target=x86_64-linux-musl', '--enable-debug', 'CC=gcc',
                             'AR=ar', 'RANLIB=ranlib',
                             f'CFLAGS=-ffile-prefix-map={source}=/usr/src/musl-{provider}']
                if provider == 'runtime':
                    configure.append('LDFLAGS=-Wl,-soname,libc.musl-x86_64.so.1')
                run(configure)
                run(['make', f'-j{min(os.cpu_count() or 2, 8)}'])
                stage = scratch / 'stage'
                run(['make', f'DESTDIR={stage}', 'install'])
            # Keep the real interpreter file and relative development symlinks.
            interpreter = stage / 'lib/ld-musl-x86_64.so.1'
            interpreter.unlink()
            shutil.move(stage / 'usr/lib/libc.so', interpreter)
            (stage / 'usr/lib/libc.so').symlink_to('../../lib/ld-musl-x86_64.so.1')
            shutil.copytree(stage, destination / 'sysroot', dirs_exist_ok=True, symlinks=True)
            shutil.copyfile(source / 'COPYRIGHT', destination / 'COPYRIGHT')
            shutil.copyfile(source / 'src/network/res_msend.c', destination / 'res_msend.c')
            products = {path.relative_to(destination).as_posix(): digest(path)
                        for path in (destination / 'sysroot').rglob('*')
                        if path.is_file() and not path.is_symlink()}
            products['COPYRIGHT'] = digest(destination / 'COPYRIGHT')
            products['res_msend.c'] = digest(destination / 'res_msend.c')
            saved = dict(identity=identity, provider=provider, compiler=compiler, target=target,
                         inputs={path.name: digest(path) for path in verified},
                         patches=[dict(name=path.name, sha256=digest(path)) for path in ordered],
                         commands=commands, products=products)
            manifest.write_text(json.dumps(saved, indent=2) + '\n')
    print(f'MUSL_BUILD_PASS provider={provider} identity={identity}', flush=True)
    return destination


def loader(provider='build'):
    return ensure(provider) / 'sysroot/lib/ld-musl-x86_64.so.1'


def compiler_args(provider='build'):
    destination = ensure(provider)
    template = (destination / 'sysroot/usr/lib/musl-gcc.specs').read_text()
    text = template.replace('/usr/', str(destination / 'sysroot/usr') + '/')
    specs = OUTPUT / provider / 'compiler.specs'
    if not specs.exists() or specs.read_text() != text:
        specs.write_text(text)
    return ['gcc', '-specs=' + str(specs)]


def runtime_files():
    destination = ensure('runtime')
    result = {}
    for base in ('usr/include', 'usr/lib'):
        for path in (destination / 'sysroot' / base).rglob('*'):
            name = path.relative_to(destination / 'sysroot').as_posix()
            if name.endswith('musl-gcc.specs'):
                continue
            if path.is_symlink():
                result[name] = (0o120777, os.readlink(path).encode())
            elif path.is_file():
                result[name] = (0o100644, path.read_bytes())
    result['lib/ld-musl-x86_64.so.1'] = (0o100755, loader('runtime').read_bytes())
    result['lib/libc.musl-x86_64.so.1'] = (0o120777, b'ld-musl-x86_64.so.1')
    result['usr/share/licenses/musl/axiom64-build.json'] = (0o100644,
        (destination / 'manifest.json').read_bytes())
    result['usr/share/licenses/musl/COPYRIGHT'] = (0o100644,
        (destination / 'COPYRIGHT').read_bytes())
    return result


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--provider', choices=['build', 'runtime', 'both'], default='both')
    parser.add_argument('--compiler-specs', action='store_true')
    args = parser.parse_args()
    for provider in ('build', 'runtime') if args.provider == 'both' else [args.provider]:
        ensure(provider)
        if args.compiler_specs:
            compiler_args(provider)
