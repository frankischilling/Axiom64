#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Build pinned OpenSSL libraries and tools against an explicit libc provider."""
import argparse
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import shlex
import shutil
import subprocess
import tarfile
import tempfile

from build_musl import compiler_args, ensure as musl
from fetch import LOCK, ROOT, fetch
from ports import download

OUTPUT = ROOT / 'build/openssl'


def digest(path):
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def native_inputs():
    result = {}
    for name in ('libc.so.6', 'ld-linux-x86-64.so.2', 'libc.a', 'libc_nonshared.a',
                 'crt1.o', 'Scrt1.o', 'crti.o', 'crtn.o', 'libgcc.a', 'crtbegin.o', 'crtend.o'):
        path = Path(subprocess.check_output(['gcc', '-print-file-name=' + name],
                                           text=True).strip()).resolve()
        if not path.is_file():
            raise RuntimeError('missing native OpenSSL linker input: ' + name)
        result[name] = dict(path=str(path), sha256=digest(path))
    return result


def elf(path):
    headers = subprocess.check_output(['readelf', '-W', '-l', str(path)], text=True)
    dynamic = subprocess.check_output(['readelf', '-W', '-d', str(path)], text=True)
    return dict(program_headers=headers, dynamic=dynamic)


def uapi_headers():
    packages = json.loads((ROOT / 'ports.lock.json').read_text())['packages']
    package, = (item for item in packages if item['name'] == 'linux-headers')
    archive = download(package['url'], ROOT / 'downloads/ports' / package['archive'])
    if digest(archive) != package['sha256']:
        raise RuntimeError('OpenSSL Linux UAPI archive checksum differs')
    OUTPUT.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix='case-probe-', dir=OUTPUT) as temporary:
        probe = Path(temporary)
        (probe / 'a').write_bytes(b'lowercase')
        case_sensitive = not (probe / 'A').exists()
    if case_sensitive:
        destination = OUTPUT / 'uapi' / package['sha256']
    else:
        # Linux UAPI contains distinct filenames that differ only in case.
        # A Windows-mounted workspace cannot preserve those headers.
        cache = Path(os.environ.get('XDG_CACHE_HOME', str(Path.home() / '.cache')))
        if not cache.is_absolute():
            raise RuntimeError('the Linux UAPI cache must use an absolute path')
        destination = cache / 'axiom64-uapi' / package['sha256']
    expected = {}
    with tarfile.open(archive, 'r:gz', ignore_zeros=True) as stream:
        members = [member for member in stream if member.name.startswith('usr/include/')]
        for member in members:
            if member.isfile():
                expected[member.name] = hashlib.file_digest(stream.extractfile(member), 'sha256').hexdigest()
        if not destination.exists():
            destination.mkdir(parents=True)
            stream.extractall(destination, members=members, filter='data')
    if expected != {path.relative_to(destination).as_posix(): digest(path)
                    for path in destination.rglob('*') if path.is_file() and not path.is_symlink()}:
        raise RuntimeError('OpenSSL Linux UAPI headers differ from the pinned archive')
    return destination / 'usr/include', dict(package=package, products=expected)


def ensure(provider='build'):
    if provider not in ('build', 'runtime', 'native'):
        raise ValueError(provider)
    dependency = LOCK['openssl']
    compiler = ['gcc'] if provider == 'native' else compiler_args(provider)
    headers, uapi = uapi_headers()
    compiler += ['-isystem', str(headers)]
    libc = None if provider == 'native' else json.loads((musl(provider) / 'manifest.json').read_text())
    comparison_inputs = native_inputs() if provider == 'native' else {}
    version = subprocess.check_output(['gcc', '-dumpfullversion'], text=True).strip()
    target = subprocess.check_output(['gcc', '-dumpmachine'], text=True).strip()
    if target != 'x86_64-linux-gnu':
        raise RuntimeError('OpenSSL requires an x86-64 Linux build host')
    identity_data = dict(dependency=dependency, provider=provider, compiler=version, target=target,
                         libc_identity=libc['identity'] if libc else None,
                         native_inputs=comparison_inputs, uapi=uapi,
                         recipe_sha256=digest(Path(__file__)))
    identity = hashlib.sha256(json.dumps(identity_data, sort_keys=True).encode()).hexdigest()
    destination = OUTPUT / provider / identity
    manifest = destination / 'manifest.json'
    OUTPUT.mkdir(parents=True, exist_ok=True)
    with (OUTPUT / '.lock').open('a') as guard:
        fcntl.flock(guard, fcntl.LOCK_EX)
        if manifest.exists():
            saved = json.loads(manifest.read_text())
            if saved['identity'] != identity:
                raise RuntimeError('OpenSSL cache identity differs')
            for name, expected in saved['products'].items():
                if digest(destination / name) != expected:
                    raise RuntimeError('cached OpenSSL product changed: ' + name)
            for name, expected in saved['symlinks'].items():
                if os.readlink(destination / name) != expected:
                    raise RuntimeError('cached OpenSSL link changed: ' + name)
            return destination
        archive = fetch('openssl')
        source = OUTPUT / 'source' / dependency['sha256'] / ('openssl-' + dependency['version'])
        source_receipt = source.parent / 'archive.json'
        if source_receipt.exists():
            if json.loads(source_receipt.read_text()) != dict(sha256=digest(archive)):
                raise RuntimeError('OpenSSL source cache differs')
        else:
            source.parent.mkdir(parents=True, exist_ok=True)
            with tarfile.open(archive) as stream:
                stream.extractall(source.parent, filter='data')
            source_receipt.write_text(json.dumps(dict(sha256=digest(archive))) + '\n')
        source_inputs = {}
        source_date_epoch = None
        with tarfile.open(archive) as stream:
            prefix = 'openssl-' + dependency['version'] + '/'
            for member in stream:
                if member.isfile():
                    if not member.name.startswith(prefix):
                        raise RuntimeError('unexpected OpenSSL archive root')
                    name = member.name[len(prefix):]
                    source_inputs[name] = hashlib.file_digest(stream.extractfile(member), 'sha256').hexdigest()
                    if name == 'Configure':
                        source_date_epoch = member.mtime
                elif member.issym():
                    if os.readlink(source.parent / member.name) != member.linkname:
                        raise RuntimeError('cached OpenSSL source link differs')
        if source_inputs != {path.relative_to(source).as_posix(): digest(path)
                             for path in source.rglob('*') if path.is_file() and not path.is_symlink()}:
            raise RuntimeError('cached OpenSSL source differs from the pinned archive')
        if source_inputs['LICENSE.txt'] != dependency['license_sha256']:
            raise RuntimeError('OpenSSL license differs from its pinned source')
        destination.mkdir(parents=True, exist_ok=True)
        environment = os.environ.copy()
        for name in ('CC', 'CXX', 'CPP', 'CFLAGS', 'CPPFLAGS', 'LDFLAGS', 'CPATH',
                     'C_INCLUDE_PATH', 'CPLUS_INCLUDE_PATH', 'LIBRARY_PATH', 'GCC_EXEC_PREFIX',
                     'LD_LIBRARY_PATH', 'OPENSSL_CONF', 'OPENSSL_MODULES'):
            environment.pop(name, None)
        environment['CC'] = shlex.join(compiler)
        environment['AR'] = 'ar'
        environment['RANLIB'] = 'ranlib'
        environment['SOURCE_DATE_EPOCH'] = str(source_date_epoch)
        environment['CFLAGS'] = ('-O2 -g -ffile-prefix-map=' + str(OUTPUT) + '=/usr/src/openssl' +
                                 ' -ffile-prefix-map=' + str(headers) + '=/usr/src/linux-headers')
        commands = []
        products = {}
        links = {}
        binaries = {}
        for linkage in ('static', 'dynamic'):
            build = destination / linkage / 'build'
            build.mkdir(parents=True, exist_ok=True)
            stage = destination / linkage / 'stage'
            with (destination / (linkage + '-build.log')).open('w') as output:
                def run(command):
                    commands.append(dict(linkage=linkage, command=command))
                    subprocess.run(command, cwd=build, env=environment, stdin=subprocess.DEVNULL,
                                   stdout=output, stderr=subprocess.STDOUT, check=True)
                run(['perl', str(source / 'Configure'), 'linux-x86_64', '--prefix=/usr',
                     '--libdir=lib', '--openssldir=/etc/ssl', '--with-rand-seed=os',
                     'no-shared' if linkage == 'static' else 'shared'])
                run(['make', '-j4', 'build_sw'])
                if linkage == 'static':
                    # Only the executable link is static. Optional modules retain their
                    # normal build, and the shared profile can load them at runtime.
                    (build / 'apps/openssl').unlink()
                    run(['make', '-j4', 'apps/openssl', 'LDFLAGS=-static'])
                run(['make', 'DESTDIR=' + str(stage), 'install_sw', 'install_ssldirs'])
            configuration = build / 'include/openssl/configuration.h'
            configured = configuration.read_text()
            if not re.search(r'^\s*#\s*define\s+OPENSSL_RAND_SEED_OS\s*$', configured, re.MULTILINE):
                raise RuntimeError('OpenSSL did not select OS seed sources')
            binary = stage / 'usr/bin/openssl'
            binary_elf = elf(binary)
            if linkage == 'static':
                if 'INTERP' in binary_elf['program_headers'] or '(NEEDED)' in binary_elf['dynamic']:
                    raise RuntimeError('static OpenSSL has a dynamic dependency')
            elif provider != 'native':
                if '/lib/ld-musl-x86_64.so.1' not in binary_elf['program_headers']:
                    raise RuntimeError('target OpenSSL uses the wrong interpreter')
                if 'libc.so.6' in binary_elf['dynamic'] or 'RPATH' in binary_elf['dynamic']:
                    raise RuntimeError('target OpenSSL links host libc or a build path')
            binaries[linkage] = binary_elf
            for path in stage.rglob('*'):
                relative = path.relative_to(destination).as_posix()
                if path.is_symlink():
                    links[relative] = os.readlink(path)
                elif path.is_file():
                    products[relative] = digest(path)
            products[configuration.relative_to(destination).as_posix()] = digest(configuration)
        for name in ('LICENSE.txt', 'AUTHORS.md', 'INSTALL.md'):
            shutil.copyfile(source / name, destination / name)
            products[name] = digest(destination / name)
        if source_inputs != {path.relative_to(source).as_posix(): digest(path)
                             for path in source.rglob('*') if path.is_file() and not path.is_symlink()}:
            raise RuntimeError('OpenSSL changed its shared upstream source during the build')
        saved = dict(identity=identity, **identity_data, source=dict(archive=archive.name,
                     sha256=digest(archive)), source_inputs=source_inputs, commands=commands,
                     environment={name: environment[name] for name in
                                  ('CC', 'AR', 'RANLIB', 'SOURCE_DATE_EPOCH', 'CFLAGS')},
                     products=products, symlinks=links, binaries=binaries)
        manifest.write_text(json.dumps(saved, indent=2) + '\n')
        print('OPENSSL_BUILD_PASS provider=' + provider + ' identity=' + identity, flush=True)
    return destination


def runtime_files():
    destination = ensure('runtime')
    stage = destination / 'dynamic/stage'
    result = {}
    for path in stage.rglob('*'):
        name = path.relative_to(stage).as_posix()
        if path.is_symlink():
            result[name] = (0o120777, os.readlink(path).encode())
        elif path.is_file():
            result[name] = (0o100755 if os.access(path, os.X_OK) else 0o100644, path.read_bytes())
    for name in ('LICENSE.txt', 'AUTHORS.md', 'manifest.json'):
        result['usr/share/licenses/OpenSSL/' + name] = (0o100644, (destination / name).read_bytes())
    return result


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--provider', choices=('build', 'runtime', 'native', 'all'), default='build')
    args = parser.parse_args()
    for provider in ('build', 'runtime', 'native') if args.provider == 'all' else (args.provider,):
        ensure(provider)
