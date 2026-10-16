#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Build authenticated curl/libcurl with explicit libc and TLS providers."""
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
from build_openssl import elf, ensure as openssl, native_inputs
from fetch import LOCK, ROOT, fetch
from linux_uapi import headers as uapi_headers
from ports import download

OUTPUT = ROOT / 'build/curl'


def digest(path):
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def source_inputs():
    dependency = LOCK['curl']
    archive = fetch('curl')
    result = [archive]
    for field, name in (('signature', archive.name + '.asc'),
                        ('public_key', 'curl-release-key.asc')):
        path = download(dependency[field + '_url'], ROOT / 'downloads/sources/curl-upstream' / name)
        if digest(path) != dependency[field + '_sha256']:
            raise RuntimeError('curl release input checksum differs: ' + name)
        result.append(path)
    return 'curl-upstream', result


def release_signature(paths, destination):
    archive, signed, public = paths
    with tempfile.TemporaryDirectory(prefix='axiom64-curl-signature-') as temporary:
        keyring = Path(temporary) / 'release.gpg'
        imported = subprocess.run(['gpg', '--no-options', '--batch', '--homedir', temporary,
            '--dearmor', '--output', str(keyring), str(public)], capture_output=True, check=True)
        result = subprocess.run(['gpgv', '--homedir', temporary, '--keyring', str(keyring),
            '--status-fd', '1', str(signed), str(archive)], capture_output=True)
    (destination / 'release-signature.log').write_bytes(imported.stderr + result.stdout + result.stderr)
    statuses = [line.split() for line in result.stdout.splitlines() if line.startswith(b'[GNUPG:]')]
    valid = [row for row in statuses if row[1] == b'VALIDSIG']
    if (result.returncode or len(valid) != 1 or
        valid[0][-1].decode() != LOCK['curl']['signing_primary_fingerprint'] or
        any(row[1] in (b'BADSIG', b'ERRSIG', b'REVKEYSIG', b'EXPSIG', b'EXPKEYSIG') for row in statuses)):
        raise RuntimeError('curl detached release signature is invalid')
    return dict(primary_fingerprint=valid[0][-1].decode(), signing_fingerprint=valid[0][2].decode(),
                inputs={path.name: digest(path) for path in paths}, isolated_public_keyring=True)


def checked_tree(directory, files, links, label):
    for name, expected in files.items():
        path = directory / name
        if (not path.resolve().is_relative_to(directory.resolve()) or path.is_symlink() or
            not path.is_file() or digest(path) != expected):
            raise RuntimeError('curl ' + label + ' changed: ' + name)
    for name, expected in links.items():
        path = directory / name
        if not path.is_symlink() or os.readlink(path) != expected:
            raise RuntimeError('curl ' + label + ' link changed: ' + name)


def installed_metadata(stage, originals, replacements):
    """Keep original producer metadata and install usable target paths."""
    for name in ('usr/bin/curl-config', 'usr/lib/pkgconfig/libcurl.pc'):
        path = stage / name
        saved = originals / name
        saved.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(path, saved)
        text = path.read_text()
        for original, target in replacements.items():
            text = text.replace(str(original), target)
        if str(ROOT) in text:
            raise RuntimeError('installed curl metadata retains an unhandled producer path: ' + name)
        path.write_text(text)


def ensure(provider='build'):
    if provider not in ('build', 'runtime', 'native'):
        raise ValueError(provider)
    dependency = LOCK['curl']
    tls = openssl(provider)
    tls_manifest = json.loads((tls / 'manifest.json').read_text())
    libc = None if provider == 'native' else musl(provider)
    headers, uapi = uapi_headers()
    compiler = (['gcc'] if provider == 'native' else compiler_args(provider)) + ['-idirafter', str(headers)]
    identity_inputs = dict(dependency=dependency, provider=provider,
        compiler=subprocess.check_output(['gcc', '-dumpfullversion'], text=True).strip(),
        target=subprocess.check_output(['gcc', '-dumpmachine'], text=True).strip(),
        native_inputs=native_inputs() if provider == 'native' else {},
        libc_manifest_sha256=digest(libc / 'manifest.json') if libc else None,
        openssl_identity=tls_manifest['identity'], openssl_manifest_sha256=digest(tls / 'manifest.json'),
        uapi=uapi, uapi_recipe_sha256=digest(ROOT / 'scripts/linux_uapi.py'),
        recipe_sha256=digest(Path(__file__)))
    if identity_inputs['target'] != 'x86_64-linux-gnu':
        raise RuntimeError('curl builds require the x86-64 Linux build host')
    identity = hashlib.sha256(json.dumps(identity_inputs, sort_keys=True).encode()).hexdigest()
    destination = OUTPUT / provider / identity
    manifest = destination / 'manifest.json'
    OUTPUT.mkdir(parents=True, exist_ok=True)
    with (OUTPUT / '.lock').open('a') as guard:
        fcntl.flock(guard, fcntl.LOCK_EX)
        if manifest.exists():
            record = json.loads(manifest.read_text())
            if record['identity'] != identity or record['identity_inputs'] != identity_inputs:
                raise RuntimeError('curl cached build identity differs')
            checked_tree(destination, record['products'], record['symlinks'], 'cached product')
            checked_tree(destination / 'source', record['source_inputs'], record['source_symlinks'], 'cached source')
            return destination
        if destination.exists():
            raise RuntimeError('incomplete curl build retained for inspection: ' + str(destination))
        destination.mkdir(parents=True)
        _, inputs = source_inputs()
        release = release_signature(inputs, destination)
        source_root = destination / 'source'
        source_root.mkdir()
        source_files = {}
        source_links = {}
        epoch = None
        with tarfile.open(inputs[0]) as stream:
            for member in stream:
                if member.isfile():
                    source_files[member.name] = hashlib.file_digest(stream.extractfile(member), 'sha256').hexdigest()
                    if member.name == 'curl-' + dependency['version'] + '/configure':
                        epoch = member.mtime
                elif member.issym():
                    source_links[member.name] = member.linkname
            stream.extractall(source_root, filter='data')
        source = source_root / ('curl-' + dependency['version'])
        if epoch is None or digest(source / 'COPYING') != dependency['license_sha256']:
            raise RuntimeError('curl release layout or license differs')
        checked_tree(source_root, source_files, source_links, 'release source')
        # Libtool repeats options in CC; one wrapper keeps musl specs singular.
        wrapper = destination / 'compiler.sh'
        wrapper.write_text('#!/bin/sh\nexec ' + shlex.join(compiler) + ' "$@"\n')
        wrapper.chmod(0o755)
        environment = os.environ.copy()
        for name in ('CC', 'CXX', 'CPP', 'CFLAGS', 'CPPFLAGS', 'LDFLAGS', 'LIBS',
                     'CPATH', 'C_INCLUDE_PATH', 'CPLUS_INCLUDE_PATH', 'LIBRARY_PATH',
                     'GCC_EXEC_PREFIX', 'LD_LIBRARY_PATH', 'LD_PRELOAD', 'CONFIG_SITE',
                     'PKG_CONFIG_PATH', 'PKG_CONFIG_LIBDIR', 'PKG_CONFIG_SYSROOT_DIR',
                     'CURL_CA_BUNDLE', 'SSL_CERT_FILE', 'SSL_CERT_DIR'):
            environment.pop(name, None)
        environment.update(SOURCE_DATE_EPOCH=str(epoch), PKG_CONFIG='false')
        commands = []
        products = {}
        links = {}
        binaries = {}
        for linkage in ('static', 'dynamic'):
            build = destination / linkage / 'build'
            stage = destination / linkage / 'stage'
            build.mkdir(parents=True)
            tls_stage = tls / linkage / 'stage/usr'
            flags = ('-O2 -g -ffile-prefix-map=' + str(source_root) + '=/usr/src/curl '
                     '-ffile-prefix-map=' + str(build) + '=/usr/src/curl-build')
            configure = [str(source / 'configure'), '--prefix=/usr', '--libdir=/usr/lib',
                '--enable-static', '--disable-shared' if linkage == 'static' else '--enable-shared',
                '--disable-rpath', '--with-openssl=' + str(tls_stage),
                '--with-ca-bundle=/etc/ssl/cert.pem', '--without-ca-path',
                '--without-libpsl', '--without-libidn2', '--without-brotli', '--without-zstd',
                '--without-nghttp2', '--without-nghttp3', '--without-ngtcp2', '--without-quiche',
                '--without-libssh', '--without-libssh2', '--without-librtmp', '--without-libgsasl',
                '--disable-ldap', '--disable-ldaps', '--without-zlib',
                '--enable-threaded-resolver', '--enable-ipv6',
                'CC=' + str(wrapper), 'CFLAGS=' + flags, 'AR=ar', 'RANLIB=ranlib',
                'CPPFLAGS=-I' + str(tls_stage / 'include'),
                'LDFLAGS=' + ('-static ' if linkage == 'static' else '') + '-L' + str(tls_stage / 'lib')]
            if provider != 'native':
                configure += ['--build=x86_64-linux-gnu', '--host=x86_64-linux-musl']
            # Libtool's program flag includes the C runtime in the static executable.
            link_options = ['CURL_LDFLAGS_BIN=-all-static'] if linkage == 'static' else []
            with (destination / (linkage + '-build.log')).open('w') as log:
                for command in (configure, ['make', '-j4', *link_options],
                                ['make', *link_options, 'DESTDIR=' + str(stage), 'install']):
                    commands.append(dict(linkage=linkage, command=command))
                    subprocess.run(command, cwd=build, env=environment, stdin=subprocess.DEVNULL,
                                   stdout=log, stderr=subprocess.STDOUT, check=True)
            binary = stage / 'usr/bin/curl'
            binary_elf = elf(binary)
            if linkage == 'static':
                if 'INTERP' in binary_elf['program_headers'] or '(NEEDED)' in binary_elf['dynamic']:
                    raise RuntimeError('static curl has a dynamic dependency')
            elif provider != 'native':
                if '/lib/ld-musl-x86_64.so.1' not in binary_elf['program_headers']:
                    raise RuntimeError('target curl uses the wrong interpreter')
                if 'libc.so.6' in binary_elf['dynamic']:
                    raise RuntimeError('target curl links the host libc')
            originals = destination / linkage / 'metadata-original'
            installed_metadata(stage, originals, {wrapper: 'cc', tls_stage: '/usr',
                source_root: '/usr/src/curl', build: '/usr/src/curl-build'})
            for path in originals.rglob('*'):
                if path.is_file():
                    products[path.relative_to(destination).as_posix()] = digest(path)
            for path in stage.rglob('*'):
                relative = path.relative_to(destination).as_posix()
                if path.is_symlink():
                    links[relative] = os.readlink(path)
                elif path.is_file():
                    products[relative] = digest(path)
                    if path.name.startswith('libcurl.so.'):
                        library_elf = elf(path)
                        if re.search(r'\((?:RPATH|RUNPATH)\)', library_elf['dynamic']):
                            raise RuntimeError('target libcurl retains a build search path')
                        if provider != 'native' and 'libc.so.6' in library_elf['dynamic']:
                            raise RuntimeError('target libcurl links the host libc')
            if re.search(r'\((?:RPATH|RUNPATH)\)', binary_elf['dynamic']):
                raise RuntimeError('curl retains a build search path')
            for name in ('lib/curl_config.h', 'config.log'):
                path = build / name
                products[path.relative_to(destination).as_posix()] = digest(path)
            binaries[linkage] = binary_elf
        for name in ('COPYING', 'README', 'docs/INSTALL.md'):
            target = destination / Path(name).name
            shutil.copy2(source / name, target)
            products[target.relative_to(destination).as_posix()] = digest(target)
        products['release-signature.log'] = digest(destination / 'release-signature.log')
        checked_tree(source_root, source_files, source_links, 'post-build source')
        record = dict(identity=identity, provider=provider, identity_inputs=identity_inputs,
            signature=release, source_inputs=source_files, source_symlinks=source_links,
            commands=commands, environment={key: environment[key] for key in ('SOURCE_DATE_EPOCH', 'PKG_CONFIG')},
            products=products, symlinks=links, binaries=binaries,
            optional_dependencies_pending=['libpsl', 'libidn2', 'brotli', 'zstd', 'nghttp2',
                'nghttp3', 'ngtcp2', 'quiche', 'libssh', 'libssh2', 'librtmp', 'libgsasl', 'ldap', 'zlib'])
        manifest.write_text(json.dumps(record, indent=2) + '\n')
        print('CURL_BUILD_PASS provider=' + provider + ' identity=' + identity, flush=True)
    return destination


def runtime_files():
    destination = ensure('runtime')
    stage = destination / 'dynamic/stage'
    result = {}
    for path in stage.rglob('*'):
        name = path.relative_to(stage).as_posix()
        if path.suffix == '.la':
            continue
        if path.is_symlink():
            result[name] = (0o120777, os.readlink(path).encode())
        elif path.is_file():
            result[name] = (0o100755 if os.access(path, os.X_OK) else 0o100644, path.read_bytes())
    for name in ('COPYING', 'README', 'manifest.json'):
        result['usr/share/licenses/curl/' + name] = (0o100644, (destination / name).read_bytes())
    return result


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--provider', choices=('build', 'runtime', 'native', 'all'), default='build')
    args = parser.parse_args()
    for provider in ('build', 'runtime', 'native') if args.provider == 'all' else (args.provider,):
        ensure(provider)
