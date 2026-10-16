#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Key completed crypto products by their source and actual Linux build inputs."""
import argparse
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import shutil
import subprocess
import time

ROOT = Path(__file__).resolve().parents[2]
PROVIDERS = ('build', 'runtime', 'native')


def digest(path):
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def cache_paths():
    paths = ['build/musl/build/*', 'build/musl/runtime/*']
    for provider in PROVIDERS:
        base = 'build/openssl/' + provider + '/*/'
        paths.extend(base + name for name in (
            'manifest.json', 'LICENSE.txt', 'AUTHORS.md', 'INSTALL.md',
            'static-build.log', 'dynamic-build.log',
            'static/stage', 'dynamic/stage',
            'static/build/include/openssl/configuration.h',
            'dynamic/build/include/openssl/configuration.h'))
    return paths


def covered(relative, paths):
    path = PurePosixPath(relative)
    return any(candidate.match(pattern) for pattern in paths
               for candidate in (path, *path.parents) if str(candidate) != '.')


def source_inputs(root):
    names = ['dependencies.json', 'ports.lock.json', 'sources.lock.json',
             'scripts/build_openssl.py', 'scripts/build_musl.py',
             'scripts/linux_uapi.py', 'scripts/fetch.py', 'scripts/ports.py',
             'scripts/sources.py', 'scripts/ci/crypto_cache.py']
    lock = json.loads((root / 'sources.lock.json').read_text())
    names.extend(row['path'] for row in lock['musl_local_patches'])
    result = {}
    for name in names:
        path = (root / name).resolve()
        if not path.is_relative_to(root.resolve()):
            raise RuntimeError('crypto cache source escapes the checkout: ' + name)
        result[name] = digest(path)
    return result


def output(command):
    return subprocess.check_output(command, text=True).strip()


def host_inputs():
    tools = {}
    names = ['gcc', 'as', 'ld', 'ar', 'ranlib', 'perl', 'make', 'patch', 'readelf']
    names.extend(output(['gcc', '-print-prog-name=' + name]) for name in ('cc1', 'collect2'))
    for name in names:
        located = shutil.which(name)
        if located is None:
            raise RuntimeError('missing crypto build tool: ' + name)
        path = Path(located).resolve()
        tools[name] = dict(path=str(path), sha256=digest(path))
    libraries = {}
    for name in ('libc.so.6', 'ld-linux-x86-64.so.2', 'libc.a', 'libc_nonshared.a',
                 'crt1.o', 'Scrt1.o', 'crti.o', 'crtn.o', 'libgcc.a', 'crtbegin.o', 'crtend.o'):
        path = Path(output(['gcc', '-print-file-name=' + name])).resolve()
        libraries[name] = dict(path=str(path), sha256=digest(path))
    # Hash the host C header search trees as well as the native linker inputs.
    probe = subprocess.run(['gcc', '-E', '-Wp,-v', '-xc', '-'], input='', text=True,
                           capture_output=True, check=True)
    search = probe.stderr.split('#include <...> search starts here:\n', 1)[1]
    directories = [Path(line.strip()) for line in search.split('End of search list.', 1)[0].splitlines()]
    headers = {}
    for directory in directories:
        for path in sorted(directory.rglob('*')):
            if path.is_file():
                headers[str(path)] = digest(path)
            elif path.is_symlink():
                headers[str(path)] = dict(link=os.readlink(path))
    packages = output(['dpkg-query', '-W', '-f=${binary:Package}\t${Version}\n'])
    packages = [line for line in packages.splitlines() if line.split('\t')[0].startswith(
        ('gcc', 'cpp', 'binutils', 'libc6', 'libgcc', 'libperl', 'perl', 'make', 'linux-libc-dev'))]
    return dict(compiler=output(['gcc', '-dumpfullversion']),
                target=output(['gcc', '-dumpmachine']), tools=tools, libraries=libraries,
                headers=headers, packages=sorted(packages), os_release=Path('/etc/os-release').read_text())


def identity(root, host):
    value = dict(schema=1, workspace=str(root.resolve()), sources=source_inputs(root), host=host)
    key = hashlib.sha256(json.dumps(value, sort_keys=True).encode()).hexdigest()
    return 'Linux-crypto-v1-' + key, value


def check_products(root):
    """Reject an incomplete cache declaration before its successful-job save."""
    paths = cache_paths()
    manifests = {}
    for dependency, providers in (('musl', PROVIDERS[:2]), ('openssl', PROVIDERS)):
        for provider in providers:
            candidates = list((root / 'build' / dependency / provider).glob('*/manifest.json'))
            if len(candidates) != 1:
                raise RuntimeError(f'expected one completed {dependency}/{provider} manifest')
            manifest, = candidates
            saved = json.loads(manifest.read_text())
            if saved['identity'] != manifest.parent.name or saved['provider'] != provider:
                raise RuntimeError('crypto manifest identity differs: ' + str(manifest))
            for name, expected in saved['products'].items():
                product = manifest.parent / name
                relative = product.relative_to(root).as_posix()
                if '..' in PurePosixPath(name).parts or not covered(relative, paths):
                    raise RuntimeError('crypto product omitted from cache paths: ' + relative)
                if product.is_symlink() or digest(product) != expected:
                    raise RuntimeError('crypto cache product changed: ' + relative)
            for name, expected in saved.get('symlinks', {}).items():
                link = manifest.parent / name
                relative = link.relative_to(root).as_posix()
                if '..' in PurePosixPath(name).parts or not covered(relative, paths):
                    raise RuntimeError('crypto link omitted from cache paths: ' + relative)
                if not link.is_symlink() or os.readlink(link) != expected:
                    raise RuntimeError('crypto cache link changed: ' + relative)
            manifests[manifest.relative_to(root).as_posix()] = dict(
                sha256=digest(manifest), products=len(saved['products']),
                symlinks=len(saved.get('symlinks', {})))
    return manifests


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--check', action='store_true')
    parser.add_argument('--report', type=Path, required=True)
    args = parser.parse_args()
    started = time.monotonic()
    if args.check:
        result = dict(manifests=check_products(ROOT), elapsed_seconds=time.monotonic() - started)
    else:
        key, inputs = identity(ROOT, host_inputs())
        result = dict(key=key, inputs=inputs, paths=cache_paths(),
                      elapsed_seconds=time.monotonic() - started)
        print('key=' + key)
        print('paths<<AXIOM64_CRYPTO_PATHS')
        print('\n'.join(cache_paths()))
        print('AXIOM64_CRYPTO_PATHS')
    args.report.parent.mkdir(parents=True, exist_ok=True)
    args.report.write_text(json.dumps(result, indent=2) + '\n')


if __name__ == '__main__':
    main()
