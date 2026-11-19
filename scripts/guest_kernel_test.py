#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
# @file scripts/guest_kernel_test.py
# @brief Build a kernel in Axiom64, export it through ext2, and boot it again.
# @author frankischilling
# @date 2026-11-19

import argparse
import hashlib
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
import tempfile

from account_normal_test import write_cpio
from disk_root import archive_entries
from fetch import ROOT
from fixture_archive import fingerprint
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
    runner = ROOT / 'userspace/tests/toolchain/build-tools.sh'
    files[str(source_root / runner.name)] = (0o100755, runner.read_bytes())
    return records


def pack_fixture(rootfs, destination, build_tools):
    files = archive_entries(rootfs)
    source_root = Path('root/kernel-build')
    if any(Path(name).is_relative_to(source_root) for name in files):
        raise ValueError('kernel build fixture requires a fresh guest source directory')
    files.update({name: (0o40755, b'') for name in ('mnt', str(source_root)) if name not in files})
    sources = [ROOT / 'Makefile', ROOT / 'vendor/limine.h']
    sources.extend(path for path in (ROOT / 'kernel').rglob('*')
                   if path.is_file() and path.suffix in {'.cpp', '.hpp', '.asm', '.ld'})
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


def export_kernel(directory, image, accelerator, timeout):
    disk = directory / 'kernel-export.raw'
    with disk.open('xb') as output:
        output.truncate(96 * 1024 * 1024)
    subprocess.run(['mke2fs', '-q', '-F', '-t', 'ext2', '-b', '4096', '-I', '128',
                    '-O', 'none,filetype,sparse_super', str(disk)], check=True)
    serial = directory / 'build-serial.log'
    command = ['qemu-system-x86_64', '-machine', 'pc', '-accel', accelerator,
               '-cpu', 'host' if accelerator == 'kvm' else 'max', '-smp', '2', '-m', '2G', '-nic', 'none',
               '-cdrom', str(image), '-display', 'none', '-serial', 'stdio', '-monitor', 'none', '-no-reboot',
               '-device', 'isa-debug-exit,iobase=0xf4,iosize=0x04',
               '-drive', f'if=none,id=export,format=raw,cache=writeback,file={disk}',
               '-device', 'virtio-blk-pci,drive=export,disable-legacy=on']
    with serial.open('wb') as log:
        build = subprocess.run(command, stdout=log, stderr=subprocess.STDOUT, stdin=subprocess.DEVNULL,
                               timeout=timeout)
    lines = serial.read_text(errors='replace').splitlines()
    if build.returncode != 1 or lines.count('AXIOM64_KERNEL_EXPORTED') != 1 or not any(
            'AXIOM64_EXIT status=0' in line for line in lines):
        raise RuntimeError(f'guest kernel build failed, see {serial}')
    with (directory / 'export-fsck.log').open('wb') as fsck:
        subprocess.run(['e2fsck', '-f', '-n', str(disk)], stdout=fsck, stderr=subprocess.STDOUT, check=True)
    kernel = directory / 'guest-built.elf'
    checks = directory / 'source-check.log'
    for artifact, guest in ((kernel, 'axiom64.elf'), (checks, 'source-check.log')):
        subprocess.run(['debugfs', '-R', f'dump -p /{guest} "{artifact}"', str(disk)], check=True)
    expected = fingerprint(kernel)['sha256']
    for destination in ('build/axiom64.elf', '/mnt/kernel-export/axiom64.elf'):
        if lines.count(f'{expected}  {destination}') != 1:
            raise RuntimeError(f'guest and recovered kernel digests differ, see {serial}')
    return kernel, checks, serial, command


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--accelerator', choices=('kvm', 'tcg'), default=os.getenv('AXIOM64_KERNEL_BUILD_ACCEL', 'tcg'))
    parser.add_argument('--build-timeout', type=int, default=5400, help='seconds allowed for the in-guest build')
    parser.add_argument('--source-tools', action='store_true', help='build and use the pinned GNU Make and NASM sources')
    args = parser.parse_args()
    if args.build_timeout <= 0:
        parser.error('--build-timeout must be positive')
    build = ROOT / 'build'
    directory = Path(tempfile.mkdtemp(prefix='guest-kernel-', dir=build))
    print(f'Guest kernel evidence: {directory}', flush=True)
    kernel, rootfs = build / 'axiom64.elf', build / 'rootfs.cpio'
    kernel_identity = fingerprint(kernel)
    rootfs_identity = fingerprint(rootfs)
    build_root = directory / 'compiler.cpio'
    sources, tools = pack_fixture(rootfs, build_root, args.source_tools)
    compile_image = make_image(directory, directory.name + '-compiler.iso', kernel, build_root)
    result, check, serial, command = export_kernel(directory, compile_image, args.accelerator, args.build_timeout)
    if args.source_tools and serial.read_text(errors='replace').splitlines().count('AXIOM64_BUILD_TOOLS_BUILT') != 1:
        raise RuntimeError(f'no completed source tool build was observed, see {serial}')
    if check.read_text().splitlines() != [f'{name}: OK' for name in sources]:
        raise RuntimeError(f'guest source checks did not cover the supplied tree, see {check}')
    if fingerprint(rootfs) != rootfs_identity or fingerprint(kernel) != kernel_identity:
        raise RuntimeError('bootstrap kernel or installed rootfs changed during guest compilation')
    boot_image = make_image(directory, directory.name + '-boot.iso', result, rootfs)
    boot_image_identity = fingerprint(boot_image)
    boot = subprocess.run([sys.executable, '-B', str(ROOT / 'scripts/boot_test.py'), '--prepared-image',
                           str(boot_image), '--firmware', 'both', '--timeout', '900'], cwd=ROOT)
    if fingerprint(boot_image) != boot_image_identity:
        raise RuntimeError('guest-built boot image changed during validation')
    report = dict(passed=boot.returncode == 0, sources=sources, tool_sources=tools, build_command=command,
                  initial_kernel=kernel_identity,
                  build_serial=fingerprint(serial), source_check=fingerprint(check), guest_kernel=fingerprint(result),
                  reused_rootfs=rootfs_identity, boot_image=boot_image_identity,
                  boot_results=json.loads((directory / 'boot-results.json').read_text()))
    (directory / 'result.json').write_text(json.dumps(report, indent=2) + '\n')
    boot.check_returncode()


if __name__ == '__main__':
    main()
