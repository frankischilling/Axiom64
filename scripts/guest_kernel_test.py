#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
# @file    scripts/guest_kernel_test.py
# @brief   Build, export, and boot a kernel produced inside Axiom64.
# @author  frankischilling
# @date    2026-11-19
#
# Stages the kernel and optional tool sources, verifies the virtio disk export,
# and passes the recovered kernel or guest-authored image to the boot tests.
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
import os
from pathlib import Path
import stat
import subprocess
import sys
import tempfile
import time

from account_normal_test import write_cpio
from disk_root import archive_entries
from fetch import ROOT, fetch
from fixture_archive import fingerprint
from qemu_acceleration import Acceleration
from qmp import Qmp
from sources import SOURCE_LOCK, port_sources


def supply_tool_sources(files, source_root):
    records = {}
    checks = []
    directory = source_root / 'tool-sources'
    files[str(directory)] = (0o40755, b'')
    pins = json.loads(SOURCE_LOCK.read_text())['ports']
    for name in ('make', 'nasm'):
        pin = next(item for item in pins if item['origin'] == name)
        _, paths = port_sources(pin)
        if len(pin['files']) != 1 or len(paths) != 2 or paths[1].name != pin['files'][0]['name']:
            raise ValueError(f'unexpected source recipe shape for {name}')
        path = paths[1]
        payload = path.read_bytes()
        digest = pin['files'][0]['sha512']
        if hashlib.sha512(payload).hexdigest() != digest:
            raise ValueError(f'{path.name} changed during fixture creation')
        checks.append(f'{digest}  {path.name}\n')
        files[str(directory / path.name)] = (0o100644, payload)
        records[name] = dict(archive=path.name, sha512=digest, recipe_sha256=pin['recipe_sha256'])
    files[str(directory / 'sources.sha512')] = (0o100644, ''.join(checks).encode())
    return records


def pack_fixture(rootfs, destination, build_tools, system_image):
    files = archive_entries(rootfs)
    source_root = Path('root/kernel-build')
    if any(Path(name).is_relative_to(source_root) for name in files):
        raise ValueError('kernel build fixture requires a fresh guest source directory')
    files.update({name: (0o40755, b'') for name in ('mnt', str(source_root)) if name not in files})
    sources = [ROOT / 'Makefile', ROOT / 'vendor/limine.h']
    sources.extend(path for path in (ROOT / 'kernel').rglob('*')
                   if path.is_file() and path.suffix in {'.cpp', '.hpp', '.asm', '.ld'})
    if system_image:
        sources.extend(ROOT / name for name in ('boot/limine.conf', 'userspace/init/main.c',
            'userspace/init/console.c', 'userspace/init/console.h', 'userspace/init/seed_records.h',
            'userspace/tests/abi/abi.c'))
    inputs = {}
    for source in sorted(sources):
        name = source.relative_to(ROOT)
        member = source_root / name
        for parent in member.parents:
            if parent != Path('.'):
                files.setdefault(str(parent), (0o40755, b''))
        payload = source.read_bytes()
        files[str(member)] = (stat.S_IFREG | 0o644, payload)
        inputs[name.as_posix()] = hashlib.sha256(payload).hexdigest()
    if system_image:
        for name, path in (('build-system.sh', ROOT / 'userspace/tests/toolchain/build-system.sh'),
                           ('limine-binary.tar.gz', fetch('limine'))):
            payload = path.read_bytes()
            files[str(source_root / name)] = (0o100644, payload)
            inputs[name] = hashlib.sha256(payload).hexdigest()
    if build_tools:
        runner = ROOT / 'userspace/tests/toolchain/build-tools.sh'
        payload = runner.read_bytes()
        files[str(source_root / runner.name)] = (0o100755, payload)
        inputs[runner.name] = hashlib.sha256(payload).hexdigest()
    checks = ''.join(f'{digest}  {name}\n' for name, digest in inputs.items())
    files[str(source_root / 'inputs.sha256')] = (0o100644, checks.encode())
    runner = ROOT / 'userspace/tests/toolchain/kernel-build.sh'
    files['etc/boot-test.sh'] = (0o100755, runner.read_bytes())
    tools = supply_tool_sources(files, source_root) if build_tools else {}
    write_cpio(destination, files)
    return inputs, tools


def make_image(directory, name, kernel, rootfs):
    subprocess.run([sys.executable, '-B', str(ROOT / 'scripts/image.py'), '--test', '--suite', 'full',
                    '--kernel', str(kernel), '--initramfs', str(rootfs), '--output-name', name,
                    '--output-directory', str(directory)], cwd=ROOT, check=True)
    return directory / name


def run_build_vm(command, serial, acceleration, timeout):
    with tempfile.TemporaryDirectory(prefix='axiom64-build-qmp-') as temporary:
        control = Path(temporary) / 'qmp.sock'
        command = [*command, '-S', '-qmp', f'unix:{control},server=on,wait=off']
        with serial.open('wb') as log:
            deadline = time.monotonic() + timeout
            process = subprocess.Popen(command, stdout=log, stderr=subprocess.STDOUT,
                                       stdin=subprocess.DEVNULL)
            try:
                while not control.exists():
                    if process.poll() is not None or time.monotonic() >= deadline:
                        raise RuntimeError(f'guest build VM did not start, see {serial}')
                    time.sleep(.01)
                monitor = Qmp(control)
                try:
                    observed = acceleration.observe(monitor)
                    (serial.parent / 'build-accelerator.json').write_text(json.dumps(observed) + '\n')
                    print(f'Guest build accelerator: {observed["used"]} (requested {observed["requested"]})',
                          flush=True)
                    monitor.command('cont')
                finally:
                    monitor.close()
                status = process.wait(timeout=max(0, deadline - time.monotonic()))
            finally:
                if process.poll() is None:
                    process.kill()
                process.wait()
            return status, command


def export_kernel(directory, image, acceleration, timeout, system_image):
    disk = directory / 'kernel-export.raw'
    with disk.open('xb') as output:
        output.truncate(96 * 1024 * 1024)
    subprocess.run(['mke2fs', '-q', '-F', '-t', 'ext2', '-b', '4096', '-I', '128',
                    '-O', 'none,filetype,sparse_super', str(disk)], check=True)
    serial = directory / 'build-serial.log'
    command = ['qemu-system-x86_64', '-machine', acceleration.machine,
               '-cpu', 'host' if acceleration.requested == 'kvm' else 'max',
               '-smp', '2', '-m', '2G', '-nic', 'none',
               '-cdrom', str(image), '-display', 'none', '-serial', 'stdio', '-monitor', 'none', '-no-reboot',
               '-device', 'isa-debug-exit,iobase=0xf4,iosize=0x04',
               '-drive', f'if=none,id=export,format=raw,cache=writeback,file={disk}',
               '-device', 'virtio-blk-pci,drive=export,disable-legacy=on']
    status, command = run_build_vm(command, serial, acceleration, timeout)
    lines = serial.read_text(errors='replace').splitlines()
    if status != 1 or lines.count('AXIOM64_KERNEL_EXPORTED') != 1 or not any(
            'AXIOM64_EXIT status=0' in line for line in lines):
        raise RuntimeError(f'guest kernel build failed, see {serial}')
    with (directory / 'export-fsck.log').open('wb') as fsck:
        subprocess.run(['e2fsck', '-f', '-n', str(disk)], stdout=fsck, stderr=subprocess.STDOUT, check=True)
    kernel = directory / 'guest-built.elf'
    checks = directory / 'source-check.log'
    exports = [(kernel, 'axiom64.elf'), (checks, 'source-check.log')]
    if system_image:
        exports.extend((directory / name, name) for name in ('rootfs.cpio', 'guest-built.iso'))
    for artifact, guest in exports:
        subprocess.run(['debugfs', '-R', f'dump -p /{guest} "{artifact}"', str(disk)], check=True)
    expected = fingerprint(kernel)['sha256']
    for destination in ('build/axiom64.elf', '/mnt/kernel-export/axiom64.elf'):
        if lines.count(f'{expected}  {destination}') != 1:
            raise RuntimeError(f'guest and recovered kernel digests differ, see {serial}')
    return kernel, checks, serial, command


def verify_system_image(directory, kernel, serial):
    rootfs, image = (directory / name for name in ('rootfs.cpio', 'guest-built.iso'))
    lines = serial.read_text(errors='replace').splitlines()
    for marker in ('AXIOM64_GUEST_ROOTFS_BUILT', 'AXIOM64_GUEST_IMAGE_BUILT'):
        if lines.count(marker) != 1:
            raise RuntimeError(f'missing {marker}, see {serial}')
    for artifact in (rootfs, image):
        identity = fingerprint(artifact)
        if lines.count(f'{identity["sha256"]}  /mnt/kernel-export/{artifact.name}') != 1:
            raise RuntimeError(f'guest and recovered {artifact.name} digests differ, see {serial}')
    root_files = archive_entries(rootfs)
    for member in ('sbin/init', 'bin/abi-static', 'bin/abi-dynamic'):
        digest = hashlib.sha256(root_files[member][1]).hexdigest()
        if lines.count(f'{digest}  {member}') != 1:
            raise RuntimeError(f'guest and archived {member} digests differ, see {serial}')
    with tempfile.TemporaryDirectory(prefix='image-members-', dir=directory) as scratch:
        for member, original in (('axiom64.elf', kernel), ('rootfs.cpio', rootfs)):
            extracted = Path(scratch) / member
            subprocess.run(['xorriso', '-osirrox', 'on', '-indev', str(image), '-extract',
                            '/boot/' + member, str(extracted)], check=True)
            if fingerprint(extracted) != fingerprint(original):
                raise RuntimeError(f'guest ISO contains a different {member}')
    return image, fingerprint(rootfs)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--accelerator', choices=('auto', 'kvm', 'tcg'),
                        default=os.getenv('AXIOM64_KERNEL_BUILD_ACCEL', 'tcg'))
    parser.add_argument('--build-timeout', type=int, default=5400, help='seconds allowed for the in-guest build')
    parser.add_argument('--source-tools', action='store_true', help='build and use the pinned GNU Make and NASM sources')
    parser.add_argument('--system-image', action='store_true', help='build init, a small rootfs, and the ISO in the guest')
    args = parser.parse_args()
    if args.build_timeout <= 0:
        parser.error('--build-timeout must be positive')
    acceleration = Acceleration(args.accelerator)
    build = ROOT / 'build'
    directory = Path(tempfile.mkdtemp(prefix='guest-kernel-', dir=build))
    print(f'Guest kernel evidence: {directory}', flush=True)
    kernel, rootfs = build / 'axiom64.elf', build / 'rootfs.cpio'
    kernel_identity = fingerprint(kernel)
    rootfs_identity = fingerprint(rootfs)
    build_root = directory / 'compiler.cpio'
    sources, tools = pack_fixture(rootfs, build_root, args.source_tools, args.system_image)
    compile_image = make_image(directory, directory.name + '-compiler.iso', kernel, build_root)
    result, check, serial, command = export_kernel(directory, compile_image, acceleration, args.build_timeout,
                                                   args.system_image)
    if args.source_tools and serial.read_text(errors='replace').splitlines().count('AXIOM64_BUILD_TOOLS_BUILT') != 1:
        raise RuntimeError(f'no completed source tool build was observed, see {serial}')
    if check.read_text().splitlines() != [f'{name}: OK' for name in sources]:
        raise RuntimeError(f'guest source checks did not cover the supplied tree, see {check}')
    if fingerprint(rootfs) != rootfs_identity or fingerprint(kernel) != kernel_identity:
        raise RuntimeError('bootstrap kernel or installed rootfs changed during guest compilation')
    if args.system_image:
        boot_image, test_rootfs = verify_system_image(directory, result, serial)
    else:
        boot_image = make_image(directory, directory.name + '-boot.iso', result, rootfs)
        test_rootfs = rootfs_identity
    boot_image_identity = fingerprint(boot_image)
    boot = subprocess.run([sys.executable, '-B', str(ROOT / 'scripts/boot_test.py'), '--prepared-image',
                           str(boot_image), '--suite', 'guest-system' if args.system_image else 'full',
                           '--firmware', 'both', '--timeout', '900'], cwd=ROOT)
    if fingerprint(boot_image) != boot_image_identity:
        raise RuntimeError('guest-built boot image changed during validation')
    report = dict(passed=boot.returncode == 0, sources=sources, tool_sources=tools, build_command=command,
                  build_acceleration=acceleration.evidence, initial_kernel=kernel_identity,
                  build_serial=fingerprint(serial), source_check=fingerprint(check), guest_kernel=fingerprint(result),
                  bootstrap_rootfs=rootfs_identity, boot_rootfs=test_rootfs, guest_authored_image=args.system_image,
                  boot_image=boot_image_identity,
                  boot_results=json.loads((directory / 'boot-results.json').read_text()))
    (directory / 'result.json').write_text(json.dumps(report, indent=2) + '\n')
    boot.check_returncode()


if __name__ == '__main__':
    main()
