#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
# @file    scripts/build_cross_toolchain.py
# @brief   Build the Linux-hosted GNU toolchain for Axiom64.
# @author  frankischilling
# @date    2026-11-20
#
# Installs verified releases against an explicit x86-64 musl sysroot.
#
# Copyright (C) 2026 frankischilling
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program. If not, see <https://gnu.org/licenses/>.

import argparse
import fcntl
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tarfile
import tempfile

from build_musl import ensure
from fetch import ROOT
from fixture_archive import fingerprint
from gnu_toolchain_sources import pins, source_inputs
from linux_uapi import case_sensitive, headers


TARGET = 'x86_64-alpine-linux-musl'
OUTPUT = ROOT / 'build/cross-toolchain'
BUILD_ENV = {'PATH': '/usr/bin:/bin', 'LC_ALL': 'C', 'CONFIG_SHELL': '/bin/bash',
             'CFLAGS': '-O2 -g0 -pipe', 'CXXFLAGS': '-O2 -g0 -pipe'}
RUNTIME_TARGETS = ('target-libgcc', 'target-libatomic', 'target-libstdc++-v3')


def output_directory():
    OUTPUT.mkdir(parents=True, exist_ok=True)
    if case_sensitive(OUTPUT):
        return OUTPUT
    cache = Path(os.environ.get('XDG_CACHE_HOME', str(Path.home() / '.cache')))
    if not cache.is_absolute():
        raise RuntimeError('GNU cross toolchain cache must use an absolute path')
    checkout = hashlib.sha256(os.fsencode(ROOT)).hexdigest()[:16]
    destination = (cache / 'axiom64-cross-toolchain' / checkout).resolve()
    destination.mkdir(parents=True, exist_ok=True)
    if not case_sensitive(destination):
        raise RuntimeError('GNU cross toolchain requires a case-sensitive Linux cache')
    return destination


def inventory(root):
    files = {}
    for path in sorted(root.rglob('*')):
        name = path.relative_to(root).as_posix()
        if path.is_symlink():
            files[name] = {'link': os.readlink(path)}
        elif path.is_file():
            files[name] = {**fingerprint(path), 'mode': path.stat().st_mode & 0o777}
    return files


def checked_sysroot(root):
    for name in ('lib/ld-musl-x86_64.so.1', 'usr/include/stdio.h', 'usr/include/linux/version.h',
                 'usr/lib/libc.a', 'usr/lib/libc.so', 'usr/lib/crt1.o', 'usr/lib/Scrt1.o'):
        path = (root / name).resolve(strict=True)
        if not path.is_relative_to(root) or not path.is_file():
            raise RuntimeError(f'invalid musl sysroot input: {name}')
    files = inventory(root)
    for name, item in files.items():
        if 'link' in item and (Path(item['link']).is_absolute() or
                               not (root / name).resolve().is_relative_to(root)):
            raise RuntimeError(f'sysroot link leaves its root: {name}')
    return files


def stage_sysroot(destination, explicit):
    if explicit:
        source = explicit.resolve(strict=True)
        checked_sysroot(source)
        shutil.copytree(source, destination, symlinks=True)
    else:
        musl = ensure('runtime')
        shutil.copytree(musl / 'sysroot', destination, symlinks=True)
        uapi, _ = headers()
        shutil.copytree(uapi, destination / 'usr/include', symlinks=True, dirs_exist_ok=True)
        (destination / 'lib/libc.musl-x86_64.so.1').symlink_to('ld-musl-x86_64.so.1')
        notice = destination / 'usr/share/licenses/musl'
        notice.mkdir(parents=True)
        shutil.copyfile(musl / 'COPYRIGHT', notice / 'COPYRIGHT')
    return checked_sysroot(destination)


def build(prefix, scratch, logfile, archives, jobs, lock):
    source = scratch / 'sources'
    source.mkdir()
    for archive in archives:
        if tarfile.is_tarfile(archive):
            with tarfile.open(archive) as stream:
                stream.extractall(source, filter='data')
    binutils = source / lock['releases']['binutils']['directory']
    gcc = source / lock['releases']['gcc']['directory']
    notices = {'binutils': binutils, 'gcc': gcc}
    for name, item in lock['gcc_prerequisites'].items():
        directory = source / item['directory']
        (gcc / name).symlink_to(directory, target_is_directory=True)
        notices[name] = directory

    sysroot = prefix / TARGET / 'sysroot'
    options = [f'--target={TARGET}', f'--prefix={prefix}', f'--with-sysroot={sysroot}', '--disable-nls']
    environment = BUILD_ENV.copy()
    commands = []
    with logfile.open('w') as output:
        def run(directory, *command):
            commands.append(dict(build=directory.name, command=list(command)))
            subprocess.run(command, cwd=directory, env=environment, stdin=subprocess.DEVNULL,
                           stdout=output, stderr=subprocess.STDOUT, check=True)

        binutils_build = scratch / 'binutils-build'
        binutils_build.mkdir()
        run(binutils_build, str(binutils / 'configure'), *options, '--disable-werror', '--enable-plugins',
            '--enable-deterministic-archives', '--enable-default-execstack=no',
            '--enable-default-hash-style=gnu', '--enable-new-dtags', '--enable-relro')
        run(binutils_build, 'make', f'-j{jobs}', 'all-binutils', 'all-gas', 'all-ld')
        run(binutils_build, 'make', 'install-binutils', 'install-gas', 'install-ld')

        environment['PATH'] = f'{prefix / "bin"}:{environment["PATH"]}'
        gcc_build = scratch / 'gcc-build'
        gcc_build.mkdir()
        run(gcc_build, str(gcc / 'configure'), *options, '--with-native-system-header-dir=/usr/include',
            f'--with-as={prefix / "bin" / (TARGET + "-as")}',
            f'--with-ld={prefix / "bin" / (TARGET + "-ld")}', '--with-gnu-as', '--with-gnu-ld',
            '--disable-multilib', '--enable-languages=c,c++', '--enable-threads=posix',
            '--enable-default-pie', '--enable-default-ssp', '--enable-shared', '--with-system-zlib')
        run(gcc_build, 'make', f'-j{jobs}', 'all-gcc', *(f'all-{target}' for target in RUNTIME_TARGETS))
        run(gcc_build, 'make', 'install-gcc', *(f'install-{target}' for target in RUNTIME_TARGETS))

    for name, directory in notices.items():
        destination = prefix / 'share/licenses' / name
        destination.mkdir(parents=True, exist_ok=True)
        for notice in directory.iterdir():
            if notice.name.startswith(('COPYING', 'LICENSE', 'COPYRIGHT')) and notice.is_file():
                shutil.copyfile(notice, destination / notice.name)
    return commands


def check_install(prefix):
    sysroot = prefix / TARGET / 'sysroot'
    cc = prefix / 'bin' / f'{TARGET}-gcc'
    cxx = prefix / 'bin' / f'{TARGET}-g++'

    def query(tool, argument):
        return subprocess.check_output([str(tool), argument], env=BUILD_ENV, text=True).strip()

    for driver in (cc, cxx):
        if query(driver, '-dumpmachine') != TARGET or Path(query(driver, '-print-sysroot')).resolve() != sysroot:
            raise RuntimeError(f'{driver.name} selected the wrong target or sysroot')
    for tool in ('as', 'ld'):
        selected = Path(query(cc, f'-print-prog-name={tool}')).resolve(strict=True)
        expected = prefix / 'bin' / f'{TARGET}-{tool}'
        if not selected.is_relative_to(prefix) or fingerprint(selected) != fingerprint(expected):
            raise RuntimeError(f'cross GCC selected a host {tool}')
    for driver, name, base in ((cc, 'libc.a', sysroot), (cxx, 'libstdc++.so', prefix),
                               (cc, 'libgcc.a', prefix), (cc, 'libatomic_asneeded.a', prefix)):
        selected = Path(query(driver, f'-print-file-name={name}')).resolve(strict=True)
        if not selected.is_relative_to(base):
            raise RuntimeError(f'{driver.name} selected a library from outside {base}: {name}')


def install(sysroot, offline, jobs):
    archives, signatures = source_inputs(offline)
    lock = pins()
    output = output_directory()
    with tempfile.TemporaryDirectory(prefix='workspace-', dir=output) as directory:
        scratch = Path(directory)
        files = stage_sysroot(scratch / 'sysroot', sysroot)
        host = {name: subprocess.check_output([name, '--version'], env=BUILD_ENV, text=True).splitlines()[0]
                for name in ('gcc', 'g++', 'as', 'ld', 'make')}
        inputs = dict(host=host, sources=lock, sysroot=files,
                      recipe={path.name: fingerprint(path) for path in (Path(__file__),
                              ROOT / 'scripts/gnu_toolchain_sources.py')})
        identity = hashlib.sha256(json.dumps(inputs, sort_keys=True).encode()).hexdigest()
        destination = output / identity
        destination.mkdir(exist_ok=True)
        prefix = destination / 'install'
        manifest = destination / 'manifest.json'
        with (destination / '.lock').open('a') as guard:
            fcntl.flock(guard, fcntl.LOCK_EX)
            if manifest.is_file():
                saved = json.loads(manifest.read_text())
                if saved['identity'] != identity or not prefix.is_dir() or saved['products'] != inventory(prefix):
                    raise RuntimeError(f'cached cross toolchain changed: {prefix}')
                check_install(prefix)
                return prefix

            if prefix.exists():
                shutil.rmtree(prefix)
            staged = prefix / TARGET / 'sysroot'
            staged.parent.mkdir(parents=True)
            (scratch / 'sysroot').rename(staged)
            logfile = destination / 'build.log'
            print(f'Building GNU cross toolchain. Log is at {logfile}', flush=True)
            commands = build(prefix, scratch, logfile, archives, jobs, lock)
            check_install(prefix)
            if inventory(staged) != files:
                raise RuntimeError('toolchain build changed the supplied sysroot')
            result = dict(identity=identity, inputs=inputs, signatures=signatures,
                          commands=commands, products=inventory(prefix))
            pending = manifest.with_suffix('.tmp')
            pending.write_text(json.dumps(result, indent=2) + '\n')
            pending.replace(manifest)
    return prefix


def main():
    parser = argparse.ArgumentParser(description='Build GNU binutils and GCC for x86-64 Axiom64 on Linux.')
    parser.add_argument('--sysroot', type=Path, help='use an existing musl and Linux UAPI sysroot')
    parser.add_argument('--sources-only', action='store_true', help='fetch and verify GNU toolchain sources')
    parser.add_argument('--offline', action='store_true', help='use only verified local source archives')
    parser.add_argument('--jobs', type=int, default=min(os.cpu_count() or 2, 6))
    args = parser.parse_args()
    if args.jobs < 1 or (args.offline and not (args.sysroot or args.sources_only)):
        parser.error('jobs must be positive and an offline build requires --sysroot')
    if args.sources_only:
        paths, _ = source_inputs(args.offline)
        print(f'Verified {len(paths)} GNU toolchain source inputs')
        return
    if not sys.platform.startswith('linux') or os.uname().machine != 'x86_64':
        parser.error('cross toolchain builds require an x86-64 Linux host')
    print(install(args.sysroot, args.offline, args.jobs))


if __name__ == '__main__':
    main()
