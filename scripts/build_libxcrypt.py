#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Build the signed password library with an explicit libc and retained provenance."""
import argparse
import fcntl
import hashlib
import json
import os
from pathlib import Path
import shlex
import subprocess
import tarfile
import tempfile

from build_musl import compiler_args, ensure as musl
from fetch import LOCK, ROOT, fetch
from linux_uapi import headers as uapi_headers
from ports import download

OUTPUT = ROOT / 'build/libxcrypt'


def digest(path):
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def native_inputs():
    result = {}
    for name in ('libc.so.6', 'ld-linux-x86-64.so.2', 'libc.a', 'libc_nonshared.a',
                 'crt1.o', 'Scrt1.o', 'crti.o', 'crtn.o', 'libgcc.a', 'crtbegin.o', 'crtend.o'):
        path = Path(subprocess.check_output(['gcc', '-print-file-name=' + name], text=True).strip()).resolve()
        if not path.is_file():
            raise RuntimeError('missing native password-library input: ' + name)
        result[name] = dict(path=str(path), sha256=digest(path))
    return result


def checked_download(url, name, expected):
    path = download(url, ROOT / 'downloads/sources/libxcrypt-upstream' / name)
    if digest(path) != expected:
        raise RuntimeError('password-library provenance checksum differs: ' + name)
    return path


def signature(archive, dependency, destination):
    signed = checked_download(dependency['signature_url'], archive.name + '.asc',
                              dependency['signature_sha256'])
    public = checked_download(dependency['public_key_url'], 'libxcrypt-gpgkey.asc',
                              dependency['public_key_sha256'])
    with tempfile.TemporaryDirectory(prefix='axiom64-password-signature-') as temporary:
        home = Path(temporary)
        keyring = home / 'release.gpg'
        imported = subprocess.run(['gpg', '--no-options', '--batch', '--homedir', str(home),
                                   '--dearmor', '--output', str(keyring), str(public)],
                                  capture_output=True, check=True)
        result = subprocess.run(['gpgv', '--homedir', str(home), '--keyring', str(keyring),
                                 '--status-fd', '1', str(signed), str(archive)], capture_output=True)
    (destination / 'release-signature.log').write_bytes(imported.stderr + result.stdout + result.stderr)
    statuses = [line.split() for line in result.stdout.splitlines() if line.startswith(b'[GNUPG:]')]
    valid = [row for row in statuses if row[1] == b'VALIDSIG']
    if (result.returncode or len(valid) != 1 or
        valid[0][-1].decode() != dependency['signing_primary_fingerprint'] or
        any(row[1] in (b'BADSIG', b'ERRSIG', b'REVKEYSIG', b'EXPSIG', b'EXPKEYSIG') for row in statuses)):
        raise RuntimeError('password-library detached signature is invalid')
    return dict(primary_fingerprint=valid[0][-1].decode(), signing_fingerprint=valid[0][2].decode(),
                archive_sha256=digest(archive), signature_sha256=digest(signed),
                public_key_sha256=digest(public), isolated_public_keyring=True)


def ensure(provider='build'):
    if provider not in ('build', 'runtime', 'native'):
        raise ValueError(provider)
    dependency = LOCK['libxcrypt']
    compiler = ['gcc'] if provider == 'native' else compiler_args(provider)
    headers, uapi = uapi_headers()
    compiler += ['-idirafter', str(headers)]
    libc = None if provider == 'native' else json.loads((musl(provider) / 'manifest.json').read_text())
    version = subprocess.check_output(['gcc', '-dumpfullversion'], text=True).strip()
    target = subprocess.check_output(['gcc', '-dumpmachine'], text=True).strip()
    if target != 'x86_64-linux-gnu':
        raise RuntimeError('password-library builds require the x86-64 Linux build host')
    identity_data = dict(dependency=dependency, provider=provider, compiler=version, target=target,
                         libc_identity=libc['identity'] if libc else None,
                         native_inputs=native_inputs() if provider == 'native' else {},
                         recipe_sha256=digest(Path(__file__)), uapi_recipe_sha256=digest(ROOT / 'scripts/linux_uapi.py'),
                         uapi=uapi, hashes='strong', obsolete_api=False)
    identity = hashlib.sha256(json.dumps(identity_data, sort_keys=True).encode()).hexdigest()
    destination = OUTPUT / provider / identity
    manifest = destination / 'manifest.json'
    OUTPUT.mkdir(parents=True, exist_ok=True)
    with (OUTPUT / '.lock').open('a') as guard:
        fcntl.flock(guard, fcntl.LOCK_EX)
        if manifest.exists():
            record = json.loads(manifest.read_text())
            if record['identity'] != identity or record['identity_inputs'] != identity_data:
                raise RuntimeError('password-library cache identity differs')
            for name, expected in record['products'].items():
                if digest(destination / name) != expected:
                    raise RuntimeError('password-library cached product changed: ' + name)
            for name, expected in record['symlinks'].items():
                if not (destination / name).is_symlink() or os.readlink(destination / name) != expected:
                    raise RuntimeError('password-library cached symlink changed: ' + name)
            for name, expected in record['source_inputs'].items():
                if digest(destination / 'source' / name) != expected:
                    raise RuntimeError('password-library cached source changed: ' + name)
            return destination
        if destination.exists():
            raise RuntimeError('incomplete password-library build retained for inspection: ' + str(destination))
        destination.mkdir(parents=True)
        # Libtool repeats options found in CC during shared linking. A wrapper
        # keeps musl's non-repeatable specs file out of its copied option list.
        wrapper = destination / 'compiler.sh'
        wrapper.write_text('#!/bin/sh\nexec ' + shlex.join(compiler) + ' "$@"\n')
        wrapper.chmod(0o755)
        archive = fetch('libxcrypt')
        release = signature(archive, dependency, destination)
        source_root = destination / 'source'
        source_root.mkdir()
        source_inputs = {}
        with tarfile.open(archive) as stream:
            for member in stream:
                if member.isfile():
                    source_inputs[member.name] = hashlib.file_digest(stream.extractfile(member), 'sha256').hexdigest()
            stream.extractall(source_root, filter='data')
        source = source_root / ('libxcrypt-' + dependency['version'])
        for name, expected in (('COPYING.LIB', dependency['license_sha256']),
                               ('LICENSING', dependency['licensing_sha256'])):
            if digest(source / name) != expected:
                raise RuntimeError('password-library license changed: ' + name)
        environment = os.environ.copy()
        for name in ('CC', 'CFLAGS', 'CPPFLAGS', 'LDFLAGS', 'CPATH', 'C_INCLUDE_PATH',
                     'CPLUS_INCLUDE_PATH', 'LIBRARY_PATH', 'GCC_EXEC_PREFIX', 'LD_LIBRARY_PATH',
                     'LD_PRELOAD', 'CONFIG_SITE'):
            environment.pop(name, None)
        environment['SOURCE_DATE_EPOCH'] = '1762796019'
        commands = []
        for linkage in ('static', 'dynamic'):
            build = destination / linkage / 'build'
            stage = destination / linkage / 'stage'
            build.mkdir(parents=True)
            flags = ('-O2 -g -ffile-prefix-map=' + str(source) + '=/usr/src/libxcrypt '
                     '-ffile-prefix-map=' + str(build) + '=/usr/src/libxcrypt-' + provider)
            configure = [str(source / 'configure'), '--prefix=/usr', '--enable-hashes=strong',
                         '--disable-obsolete-api', '--disable-dependency-tracking',
                         '--enable-static' if linkage == 'static' else '--disable-static',
                         '--disable-shared' if linkage == 'static' else '--enable-shared',
                         'CC=' + str(wrapper), 'CFLAGS=' + flags, 'AR=ar', 'RANLIB=ranlib']
            if provider != 'native':
                configure += ['--build=x86_64-linux-gnu', '--host=x86_64-linux-musl']
            with (destination / (linkage + '-build.log')).open('w') as log:
                for command in (configure, ['make', '-j2'], ['make', 'DESTDIR=' + str(stage), 'install']):
                    commands.append(dict(linkage=linkage, command=command))
                    subprocess.run(command, cwd=build, env=environment, stdin=subprocess.DEVNULL,
                                   stdout=log, stderr=subprocess.STDOUT, check=True)
                if provider == 'native':
                    command = ['make', '-j2', 'check']
                    commands.append(dict(linkage=linkage, command=command))
                    subprocess.run(command, cwd=build, env=environment, stdin=subprocess.DEVNULL,
                                   stdout=log, stderr=subprocess.STDOUT, check=True)
        staged = [path for linkage in ('static', 'dynamic')
                  for path in (destination / linkage / 'stage').rglob('*')]
        licenses = [source / 'COPYING.LIB', source / 'LICENSING', wrapper]
        products = {path.relative_to(destination).as_posix(): digest(path)
                    for path in staged + licenses if path.is_file() and not path.is_symlink()}
        symlinks = {path.relative_to(destination).as_posix(): os.readlink(path)
                    for path in staged if path.is_symlink()}
        record = dict(identity=identity, identity_inputs=identity_data, provider=provider,
                      version=dependency['version'], license=dependency['license'],
                      source_inputs=source_inputs, signature=release, commands=commands,
                      products=products, symlinks=symlinks)
        manifest.write_text(json.dumps(record, indent=2) + '\n')
    print('LIBXCRYPT_BUILD_PASS provider=' + provider + ' identity=' + identity, flush=True)
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
            result[name] = (0o100755 if '.so.' in path.name else 0o100644, path.read_bytes())
    result['usr/lib/libcrypt.a'] = (0o100644, (destination / 'static/stage/usr/lib/libcrypt.a').read_bytes())
    source = destination / 'source' / ('libxcrypt-' + LOCK['libxcrypt']['version'])
    for name in ('COPYING.LIB', 'LICENSING'):
        result['usr/share/licenses/libxcrypt/' + name] = (0o100644, (source / name).read_bytes())
    result['usr/share/licenses/libxcrypt/Axiom64-build.json'] = (0o100644, (destination / 'manifest.json').read_bytes())
    return result


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--provider', choices=('build', 'runtime', 'native', 'all'), default='build')
    args = parser.parse_args()
    for provider in ('build', 'runtime', 'native') if args.provider == 'all' else (args.provider,):
        ensure(provider)
