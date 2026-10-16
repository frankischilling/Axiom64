#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Build a static GNU utmp verification reader from explicit pinned package inputs."""
import argparse
import fcntl
import hashlib
import json
import os
from pathlib import Path
import shlex
import shutil
import subprocess

from fetch import ROOT
from linux_uapi import headers as linux_headers
from ports import download

PIN = ROOT / 'vendor/gnu-utmp-reader/inputs.json'
CACHE = ROOT / 'downloads/sources/gnu-utmp-reader'
OUTPUT = ROOT / 'build/gnu-utmp-reader'
CLIENT = ROOT / 'userspace/tests/security/account-login-libc.c'


def digest(path):
    with Path(path).open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def checked(row):
    if Path(row['name']).name != row['name'] or not row['url'].startswith('https://'):
        raise RuntimeError('invalid GNU reader package/source input')
    path = download(row['url'], CACHE / row['name'])
    if path.stat().st_size != row['bytes'] or digest(path) != row['sha256']:
        raise RuntimeError('GNU reader package/source checksum differs: ' + row['name'])
    return path


def pins():
    data = json.loads(PIN.read_text())
    if data['schema'] != 1 or data['target'] != 'x86_64-linux-gnu' or data['architecture'] != 'amd64':
        raise RuntimeError('GNU reader requires the pinned Linux x86-64 verification ABI')
    for name, expected in data['notices'].items():
        if Path(name).name != name or digest(PIN.parent / name) != expected:
            raise RuntimeError('GNU reader license notice differs: ' + name)
    return data


def source_inputs():
    """Return checked corresponding sources for the existing companion bundle."""
    data = pins()
    sources = [checked(row) for entry in data['sources'].values() for row in entry['files']]
    packages = [checked(row) for row in data['packages']]
    notices = [PIN.parent / name for name in data['notices']]
    return 'gnu-utmp-reader', [PIN, *sources, *packages, *notices]


def environment():
    data = os.environ.copy()
    for name in ('CC', 'CXX', 'CPP', 'CFLAGS', 'CPPFLAGS', 'LDFLAGS', 'CPATH', 'C_INCLUDE_PATH',
                 'CPLUS_INCLUDE_PATH', 'LIBRARY_PATH', 'GCC_EXEC_PREFIX', 'COMPILER_PATH',
                 'LD_LIBRARY_PATH', 'LD_PRELOAD'):
        data.pop(name, None)
    data['SOURCE_DATE_EPOCH'] = '0'
    return data


def link_arguments(base):
    libc = base / 'sysroot/usr/lib/x86_64-linux-gnu'
    gcc = base / 'sysroot/usr/lib/gcc/x86_64-linux-gnu/13'
    return ['-nostdlib', '-static', '-no-pie', '-Wl,--build-id=sha1', '-Wl,-t',
            str(libc / 'crt1.o'), str(libc / 'crti.o'), str(gcc / 'crtbeginT.o'),
            str(base / 'application.o'), '-Wl,--start-group', str(gcc / 'libgcc.a'),
            str(gcc / 'libgcc_eh.a'), str(libc / 'libc.a'), str(libc / 'libc_nonshared.a'),
            '-Wl,--end-group', str(gcc / 'crtend.o'), str(libc / 'crtn.o')]


def ensure():
    data = pins()
    origin, sources = source_inputs()
    compiler = Path(shutil.which('gcc')).resolve()
    version = subprocess.check_output([str(compiler), '-dumpfullversion'], text=True).strip()
    target = subprocess.check_output([str(compiler), '-dumpmachine'], text=True).strip()
    if target != data['target']:
        raise RuntimeError('GNU reader compiler is not Linux x86-64')
    tools = {}
    for name in ('gcc', 'as', 'ld'):
        tool = Path(shutil.which(name)).resolve()
        tools[name] = dict(path=str(tool), sha256=digest(tool))
    include, uapi = linux_headers()
    for name, row in data['linux_uapi_inputs'].items():
        if (include / name).stat().st_size != row['bytes'] or digest(include / name) != row['sha256']:
            raise RuntimeError('GNU reader Linux header differs from the original Ubuntu input: ' + name)
    identity_data = dict(pin_sha256=digest(PIN), recipe_sha256=digest(Path(__file__)),
                         source_sha256=digest(CLIENT), compiler_version=version, target=target,
                         tools=tools, uapi_package=uapi['package'],
                         uapi_recipe_sha256=digest(ROOT / 'scripts/linux_uapi.py'))
    identity = hashlib.sha256(json.dumps(identity_data, sort_keys=True).encode()).hexdigest()
    directory = OUTPUT / identity
    manifest = directory / 'manifest.json'
    OUTPUT.mkdir(parents=True, exist_ok=True)
    with (OUTPUT / '.lock').open('a') as guard:
        fcntl.flock(guard, fcntl.LOCK_EX)
        if manifest.exists():
            saved = json.loads(manifest.read_text())
            if saved['identity'] != identity:
                raise RuntimeError('GNU reader cached identity differs')
            for name, expected in saved['products'].items():
                if digest(directory / name) != expected:
                    raise RuntimeError('GNU reader cached product differs: ' + name)
            for name, expected in saved['symlinks'].items():
                if os.readlink(directory / name) != expected:
                    raise RuntimeError('GNU reader cached link differs: ' + name)
            return directory, saved
        directory.mkdir(parents=True, exist_ok=True)
        stage = directory / 'sysroot'
        stage.mkdir(exist_ok=True)
        for package in data['packages']:
            path = checked(package)
            fields = subprocess.check_output(['dpkg-deb', '-f', str(path), 'Package', 'Version',
                                              'Architecture', 'Source'], text=True)
            expected = ('Package: ' + package['package'] + '\nVersion: ' + package['version'] +
                        '\nArchitecture: ' + package['architecture'] + '\nSource: ' + package['source'] + '\n')
            if fields != expected:
                raise RuntimeError('GNU reader Debian package identity differs')
            subprocess.run(['dpkg-deb', '-x', str(path), str(stage)], check=True)
        for name, row in data['inputs'].items():
            path = stage / name
            if not path.resolve().is_relative_to(stage.resolve()):
                raise RuntimeError('GNU reader staged input escapes its sysroot: ' + name)
            if path.stat().st_size != row['bytes'] or digest(path) != row['sha256']:
                raise RuntimeError('GNU reader staged input differs from the saved Ubuntu bytes: ' + name)
        for name in data['linux_uapi_inputs']:
            path = stage / 'usr/include' / name
            path.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(include / name, path)
        shutil.copyfile(CLIENT, directory / 'application.c')
        notices = directory / 'licenses'
        notices.mkdir(exist_ok=True)
        for name in data['notices']:
            shutil.copyfile(PIN.parent / name, notices / name)
        flags = ['-std=c11', '-O2', '-g', '-Wall', '-Wextra', '-Werror', '-fno-pie',
                 '-nostdinc', '-isystem', str(stage / 'usr/include'),
                 '-isystem', str(stage / 'usr/include/x86_64-linux-gnu'),
                 '-isystem', str(stage / 'usr/lib/gcc/x86_64-linux-gnu/13/include'),
                 '-ffile-prefix-map=' + str(directory) + '=/usr/src/gnu-utmp-reader']
        command = [str(compiler), *flags, '-MMD', '-MF', str(directory / 'application.d'),
                   '-c', str(directory / 'application.c'), '-o', str(directory / 'application.o')]
        with (directory / 'compile.log').open('wb') as stream:
            subprocess.run(command, env=environment(), stdout=stream, stderr=subprocess.STDOUT, check=True)
        link = [str(compiler), *link_arguments(directory), '-o', str(directory / 'account-login-libc')]
        with (directory / 'linker-inputs.log').open('wb') as stream:
            subprocess.run(link, env=environment(), stdout=stream, stderr=subprocess.STDOUT, check=True)
        actual_links = (directory / 'linker-inputs.log').read_text().splitlines()
        expected_links = [argument for argument in link if argument.endswith(('.a', '.o'))]
        # GNU ld revisits archives while resolving a start-group. Every traced
        # input must still be one explicitly named staged archive/object.
        if set(actual_links) != set(expected_links):
            raise RuntimeError('GNU reader linker consumed unexpected inputs')
        headers = subprocess.check_output(['readelf', '-W', '-l', str(directory / 'account-login-libc')], text=True)
        dynamic = subprocess.check_output(['readelf', '-W', '-d', str(directory / 'account-login-libc')], text=True)
        if 'INTERP' in headers or '(NEEDED)' in dynamic or 'RPATH' in dynamic or 'RUNPATH' in dynamic:
            raise RuntimeError('GNU reader unexpectedly has runtime linkage')
        reloc = subprocess.check_output(['readelf', '-W', '-h', str(directory / 'application.o')], text=True)
        if 'REL (Relocatable file)' not in reloc:
            raise RuntimeError('GNU reader application object is not relinkable')
        script = ['#!/bin/sh', '# SPDX-License-Identifier: GPL-3.0-or-later', 'set -eu',
                  'base=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)', 'compiler=${CC:-gcc}',
                  '# Copy this kit before replacing its libraries with modified versions.']
        arguments = link_arguments(Path('GNU_RELINK_BASE'))
        portable = [arg.replace('GNU_RELINK_BASE/', '$base/') for arg in arguments]
        rendered = ['"' + arg + '"' if arg.startswith('$base/') else shlex.quote(arg) for arg in portable]
        script.append('exec "$compiler" ' + ' '.join(rendered) + ' -o "${1:-$base/relinked-reader}"')
        (directory / 'relink.sh').write_text('\n'.join(script) + '\n')
        (directory / 'relink.sh').chmod(0o755)
        products, links = {}, {}
        for path in directory.rglob('*'):
            if path.is_symlink():
                links[path.relative_to(directory).as_posix()] = os.readlink(path)
            elif path.is_file() and path != manifest:
                products[path.relative_to(directory).as_posix()] = digest(path)
        saved = dict(identity=identity, **identity_data, role=data['role'], origin=origin,
                     packages=data['packages'], sources=data['sources'], commands=[command, link],
                     source_inputs=data['inputs'], linux_uapi_inputs=data['linux_uapi_inputs'],
                     notices=data['notices'], headers=headers, dynamic=dynamic,
                     application_object_headers=reloc, products=products, symlinks=links)
        manifest.write_text(json.dumps(saved, indent=2) + '\n')
        print('GNU_UTMP_READER_BUILD_PASS identity=' + identity, flush=True)
        return directory, saved


def build(destination):
    """Export a reader and its self-contained object/library relinking kit."""
    directory, saved = ensure()
    destination = Path(destination)
    shutil.copytree(directory, destination, symlinks=True)
    binary = destination / 'account-login-libc'
    inputs = dict(command=saved['commands'][-1], commands=saved['commands'], sha256=digest(binary),
                  headers=saved['headers'], dynamic=saved['dynamic'], identity=saved['identity'],
                  manifest_sha256=digest(destination / 'manifest.json'),
                  application_object_sha256=digest(destination / 'application.o'),
                  relink_recipe_sha256=digest(destination / 'relink.sh'),
                  linker_trace_sha256=digest(destination / 'linker-inputs.log'),
                  pin_sha256=saved['pin_sha256'], packages=saved['packages'], sources=saved['sources'])
    return binary, inputs


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path)
    args = parser.parse_args()
    if args.output:
        binary, inputs = build(args.output)
        print('GNU_UTMP_READER_OUTPUT_PASS binary=' + str(binary) + ' identity=' + inputs['identity'], flush=True)
    else:
        directory, _ = ensure()
        print(directory, flush=True)


if __name__ == '__main__':
    main()
