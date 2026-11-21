#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
# @file    scripts/guest_binutils_test.py
# @brief   Build, export and run GNU binutils inside Axiom64.
# @author  frankischilling
# @date    2026-11-20
#
# Verifies the prepared source disk and boots the exported tools on both
# firmware types.
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
import hashlib
import json
from pathlib import Path, PurePosixPath
import posixpath
import stat
import subprocess
import sys
import tarfile
import tempfile

from account_normal_test import write_cpio
from disk_root import archive_entries
from fetch import ROOT
from fixture_archive import fingerprint
from gnu_toolchain_sources import pins as gnu_pins, release_inputs
from guest_kernel_test import make_image, run_build_vm
from ports import LOCKFILE, locked_package, overlay_tar
from qemu_acceleration import Acceleration
from sources import SOURCE_LOCK, port_sources


TOOLCHAIN = ROOT / 'userspace/tests/toolchain'
PATCHED_RELEASE = 'binutils-with-gold-2.44'
LICENSES = ('COPYING', 'COPYING.LIB', 'COPYING3', 'COPYING3.LIB')
GENERATORS = {'bison', 'flex', 'm4'}


def source_checklist(tree):
    records = []
    for path in sorted(tree.rglob('*')):
        if path.is_file() and not path.is_symlink():
            name = path.relative_to(tree).as_posix()
            if '\n' in name or '\\' in name:
                raise ValueError(f'unsupported source filename: {name}')
            records.append(f"{fingerprint(path)['sha256']}  {name}")
    return ('\n'.join(records) + '\n').encode()


def make_disk(path, size, tree=None):
    with path.open('xb') as output:
        output.truncate(size * 1024 * 1024)
    command = ['mke2fs', '-q', '-F', '-t', 'ext2', '-b', '4096', '-I', '128',
               '-O', 'none,filetype,sparse_super']
    if tree is not None:
        command += ['-N', '40000', '-d', str(tree)]
    subprocess.run([*command, str(path)], check=True)


def prepare_source(directory, version):
    if version == '2.44':
        pin, = (row for row in json.loads(SOURCE_LOCK.read_text())['ports'] if row['origin'] == 'binutils')
        _, paths = port_sources(pin)
        release, size = PATCHED_RELEASE, 512
        patches = [path for path in paths if path.suffix == '.patch']
        archive, = (path for path in paths if path.name == f'{release}.tar.xz')
    else:
        lock = gnu_pins()
        pin = lock['releases']['binutils']
        paths, _ = release_inputs(lock, ('binutils',))
        release, size = pin['directory'], 640
        patches = []
        archive, = (path for path in paths if path.name == pin['archive'])
    disk = directory / 'source.raw'
    with tempfile.TemporaryDirectory(prefix='source-tree-', dir=directory) as temporary:
        tree = Path(temporary) / release
        with tarfile.open(archive) as stream:
            stream.extractall(temporary, filter='data')
        for patch in patches:
            subprocess.run(['patch', '--batch', '--fuzz=0', '--no-backup-if-mismatch',
                            '-p1', '-i', str(patch)], cwd=tree, check=True)
        # The patches change ldgram.y and ldlex.l. Leaving their release outputs
        # in the source tree makes the lexer wrapper include stale code and the
        # install rules try to update files on the read-only source disk.
        if patches:
            for generated in ('ldgram.c', 'ldgram.h', 'ldlex.c'):
                (tree / 'ld' / generated).unlink()
        checks = source_checklist(Path(temporary))
        (directory / 'source.sha256').write_bytes(checks)
        licenses = {name: (tree / name).read_bytes() for name in LICENSES}
        make_disk(disk, size, temporary)
    return disk, checks, licenses, pin, release


def verify_generator_inputs(files):
    pins = {row['name']: row for row in json.loads(LOCKFILE.read_text())['packages']
            if row['name'] in GENERATORS}
    if pins.keys() != GENERATORS:
        raise RuntimeError('the binutils generator packages must be pinned')
    for name, pin in pins.items():
        expected = {}
        with tarfile.open(locked_package(pin), 'r:gz', ignore_zeros=True) as archive:
            overlay_tar(expected, archive)
        for path, member in expected.items():
            if not stat.S_ISDIR(member[0]) and files.get(path) != member:
                raise RuntimeError(f'bootstrap {name} file differs from its package: {path}')
    return pins


def pack_compiler(rootfs, destination, checks, release):
    files = archive_entries(rootfs)
    pins = verify_generator_inputs(files)
    directory = 'root/binutils-inputs'
    if directory in files:
        raise RuntimeError('binutils build fixture requires a fresh input directory')
    files.setdefault('mnt', (0o40755, b''))
    files[directory] = (0o40755, b'')
    files[f'{directory}/source.sha256'] = (0o100644, checks)
    files[f'{directory}/check-binutils.sh'] = (0o100755, (TOOLCHAIN / 'check-binutils.sh').read_bytes())
    template = (TOOLCHAIN / 'build-binutils.sh').read_bytes()
    token = b'@BINUTILS_RELEASE@'
    if template.count(token) != 1:
        raise RuntimeError('binutils build script is missing its release input')
    files['etc/boot-test.sh'] = (0o100755, template.replace(token, release.encode()))
    write_cpio(destination, files)
    return pins


def build_tools(directory, source, image, acceleration, timeout):
    export = directory / 'export.raw'
    make_disk(export, 256)
    serial = directory / 'build-serial.log'
    command = ['qemu-system-x86_64', '-machine', acceleration.machine,
               '-cpu', 'host' if acceleration.requested == 'kvm' else 'max', '-smp', '2', '-m', '2G',
               '-nic', 'none', '-cdrom', str(image), '-display', 'none', '-serial', 'stdio',
               '-monitor', 'none', '-no-reboot', '-device', 'isa-debug-exit,iobase=0xf4,iosize=0x04',
               '-drive', f'if=none,id=source,format=raw,readonly=on,file={source}',
               '-device', 'virtio-blk-pci,drive=source,disable-legacy=on,addr=5',
               '-drive', f'if=none,id=export,format=raw,file={export}',
               '-device', 'virtio-blk-pci,drive=export,disable-legacy=on,addr=6']
    status, command = run_build_vm(command, serial, acceleration, timeout)
    markers = ('AXIOM64_BINUTILS_SOURCES_VERIFIED', 'AXIOM64_BINUTILS_TOP_CONFIGURED',
               'AXIOM64_BINUTILS_LINK_PASS', 'AXIOM64_BINUTILS_EXPORTED', 'AXIOM64_EXIT status=0')
    lines = serial.read_text(errors='replace').splitlines()
    if status != 1 or any(lines.count(marker) != 1 for marker in markers):
        raise RuntimeError(f'guest binutils build failed, see {serial}')
    package = verify_export(directory, export, lines)
    return package, command


def verify_export(directory, export, lines):
    with (directory / 'export-fsck.log').open('wb') as fsck:
        subprocess.run(['e2fsck', '-f', '-n', str(export)], stdout=fsck, stderr=subprocess.STDOUT, check=True)
    package = directory / 'binutils.tar'
    checks = directory / 'source-check.log'
    for path in (package, checks):
        subprocess.run(['debugfs', '-R', f'dump -p /{path.name} "{path}"', str(export)], check=True)
    expected = [row.split('  ', 1)[1] + ': OK'
                for row in (directory / 'source.sha256').read_text().splitlines()]
    if checks.read_text().splitlines() != expected:
        raise RuntimeError('guest did not check the complete prepared source tree')
    digest = fingerprint(package)['sha256']
    if lines.count(f'{digest}  /mnt/binutils-export/{package.name}') != 1:
        raise RuntimeError('recovered archive differs from the guest export')
    return package


def tool_bytes(entries, name):
    seen = set()
    while name not in seen:
        seen.add(name)
        mode, data = entries[name]
        if stat.S_ISREG(mode) and mode & 0o111:
            return data
        if not stat.S_ISLNK(mode):
            break
        name = posixpath.normpath(posixpath.join(posixpath.dirname(name), data.decode())).lstrip('/')
    raise RuntimeError(f'binutils tool is not executable: {name}')


def pack_boot(rootfs, package, destination, licenses):
    tools = {}
    with tarfile.open(package) as archive:
        overlay_tar(tools, archive)
    if not all(PurePosixPath(name).is_relative_to('usr') for name in tools):
        raise RuntimeError('binutils package exports paths outside /usr')
    for name, data in licenses.items():
        if tools[f'usr/share/licenses/binutils/{name}'][1] != data:
            raise RuntimeError(f'binutils license differs from the prepared source: {name}')
    products = {}
    for name in ('as', 'ld', 'ar', 'nm', 'ranlib', 'readelf', 'objcopy', 'objdump'):
        data = tool_bytes(tools, f'usr/bin/{name}')
        if not data.startswith(b'\x7fELF\x02\x01') or data[18:20] != b'\x3e\x00':
            raise RuntimeError(f'binutils export is missing an x86-64 ELF tool: {name}')
        products[name] = dict(bytes=len(data), sha256=hashlib.sha256(data).hexdigest())
    files = archive_entries(rootfs)
    files.update(tools)
    files['etc/boot-test.sh'] = (0o100755, b'#!/bin/sh\nset -eu\n'
        b'/bin/sh /root/check-binutils.sh /usr/bin\necho AXIOM64_TESTS_PASS\n')
    files['root/check-binutils.sh'] = (0o100755, (TOOLCHAIN / 'check-binutils.sh').read_bytes())
    write_cpio(destination, files)
    return products


def verify_boot(directory, kernel, rootfs, package, licenses):
    boot_root = directory / 'installed.cpio'
    tools = pack_boot(rootfs, package, boot_root, licenses)
    image = make_image(directory, 'binutils-boot.iso', kernel, boot_root)
    identity = fingerprint(image)
    result = subprocess.run([sys.executable, '-B', str(ROOT / 'scripts/boot_test.py'), '--prepared-image',
                             str(image), '--suite', 'guest-binutils', '--firmware', 'both', '--timeout', '900'],
                            cwd=ROOT)
    if fingerprint(image) != identity:
        raise RuntimeError('binutils boot image changed during verification')
    return result.returncode, dict(tools=tools, image=identity,
                                  boots=json.loads((directory / 'boot-results.json').read_text()))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--release', choices=('2.44', '2.46'), default='2.44')
    parser.add_argument('--accelerator', choices=('auto', 'kvm', 'tcg'), default='auto')
    parser.add_argument('--build-timeout', type=int, default=7200)
    args = parser.parse_args()
    if args.build_timeout <= 0:
        parser.error('--build-timeout must be positive')
    build = ROOT / 'build'
    directory = Path(tempfile.mkdtemp(prefix='guest-binutils-', dir=build))
    print(f'Guest binutils evidence: {directory}', flush=True)
    kernel, rootfs = build / 'axiom64.elf', build / 'rootfs.cpio'
    inputs = dict(kernel=fingerprint(kernel), bootstrap=fingerprint(rootfs))
    source, checks, licenses, pin, release = prepare_source(directory, args.release)
    source_identity = fingerprint(source)
    bootstrap = directory / 'compiler.cpio'
    generators = pack_compiler(rootfs, bootstrap, checks, release)
    image = make_image(directory, 'binutils-compiler.iso', kernel, bootstrap)
    acceleration = Acceleration(args.accelerator)
    package, command = build_tools(directory, source, image, acceleration, args.build_timeout)
    if fingerprint(source) != source_identity or fingerprint(kernel) != inputs['kernel'] or fingerprint(
            rootfs) != inputs['bootstrap']:
        raise RuntimeError('an input changed during the native binutils build')
    status, result = verify_boot(directory, kernel, rootfs, package, licenses)
    report = dict(passed=status == 0, release=args.release, inputs=inputs, source=source_identity, source_pin=pin,
                  prepared_source_list=fingerprint(directory / 'source.sha256'), generators=generators,
                  command=command, accelerator=acceleration.evidence, package=fingerprint(package), **result)
    (directory / 'result.json').write_text(json.dumps(report, indent=2) + '\n')
    sys.exit(status)


if __name__ == '__main__':
    main()
