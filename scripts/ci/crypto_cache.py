#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Key completed crypto products by their source and actual Linux build inputs."""
import argparse
from functools import lru_cache
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
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
        base = 'build/curl/' + provider + '/*/'
        paths.extend(base + name for name in (
            'manifest.json', 'COPYING', 'README', 'INSTALL.md', 'release-signature.log',
            'static-build.log', 'dynamic-build.log', 'source',
            'static/stage', 'dynamic/stage', 'static/metadata-original', 'dynamic/metadata-original',
            'static/build/lib/curl_config.h', 'dynamic/build/lib/curl_config.h',
            'static/build/config.log', 'dynamic/build/config.log'))
    return paths


@lru_cache(maxsize=8)
def coverage_pattern(paths):
    alternatives = []
    for pattern in paths:
        parts = PurePosixPath(pattern).parts
        if any(any(character in part for character in '*?[') and part != '*' for part in parts):
            raise RuntimeError('unsupported crypto cache path pattern: ' + pattern)
        alternatives.append('/'.join('[^/]+' if part == '*' else re.escape(part) for part in parts))
    return re.compile('(?:' + '|'.join(alternatives) + ')(?:/|$)')


def covered(relative, paths):
    return coverage_pattern(tuple(paths)).match(PurePosixPath(relative).as_posix()) is not None


def source_inputs(root):
    names = ['dependencies.json', 'ports.lock.json', 'sources.lock.json',
             'scripts/build_openssl.py', 'scripts/build_musl.py', 'scripts/build_curl.py',
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

    def check_tree(directory, files, links, label):
        if directory.is_symlink() or not directory.resolve().is_relative_to(root.resolve()):
            raise RuntimeError('crypto ' + label + ' directory escapes cache root')
        for values, symbolic in ((files, False), (links, True)):
            for name, expected in values.items():
                relative = PurePosixPath(name)
                path = directory / name
                if (relative.is_absolute() or '..' in relative.parts or '\\' in name or
                        not path.resolve().is_relative_to(directory.resolve()) or
                        not covered(path.relative_to(root).as_posix(), paths)):
                    raise RuntimeError('crypto ' + label + ' omitted from cache paths: ' + name)
                if symbolic:
                    if not path.is_symlink() or os.readlink(path) != expected:
                        raise RuntimeError('crypto cache ' + label + ' link changed: ' + name)
                elif path.is_symlink() or digest(path) != expected:
                    raise RuntimeError('crypto cache ' + label + ' changed: ' + name)

    for dependency, providers in (('musl', PROVIDERS[:2]), ('openssl', PROVIDERS), ('curl', PROVIDERS)):
        for provider in providers:
            candidates = list((root / 'build' / dependency / provider).glob('*/manifest.json'))
            if len(candidates) != 1:
                raise RuntimeError(f'expected one completed {dependency}/{provider} manifest')
            manifest, = candidates
            if not manifest.resolve().is_relative_to(root.resolve()):
                raise RuntimeError('crypto manifest escapes cache root: ' + str(manifest))
            saved = json.loads(manifest.read_text())
            if saved['identity'] != manifest.parent.name or saved['provider'] != provider:
                raise RuntimeError('crypto manifest identity differs: ' + str(manifest))
            check_tree(manifest.parent, saved['products'], saved.get('symlinks', {}), 'product')
            sources, source_links = {}, {}
            if dependency == 'curl':
                sources, source_links = saved.get('source_inputs', {}), saved.get('source_symlinks', {})
                if not sources:
                    raise RuntimeError('expected retained curl source inventory: ' + str(manifest))
                check_tree(manifest.parent / 'source', sources, source_links, 'source')
            manifests[manifest.relative_to(root).as_posix()] = dict(
                sha256=digest(manifest), products=len(saved['products']),
                symlinks=len(saved.get('symlinks', {})), sources=len(sources), source_symlinks=len(source_links))
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
