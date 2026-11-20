#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
# @file    scripts/sysinfo_test.py
# @brief   Verify Linux sysinfo with native and guest libc clients.
# @author  frankischilling
# @date    2026-11-19
#
# Compiles the test clients, boots isolated BIOS and UEFI guests, and checks
# memory accounting, process load, and clean ext2 cache teardown.
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
"""Exercise sysinfo with native libc clients and real Axiom64 allocations and tasks."""
import argparse
from concurrent.futures import ThreadPoolExecutor
import json
from pathlib import Path
import shutil
import subprocess

from account_store_guest import fixture
from account_store_test import digest, environment
from build_musl import compiler_args, loader
from fetch import ROOT

SOURCE = ROOT / 'userspace/tests/process/sysinfo.c'
FIRMWARE = Path('/usr/share/OVMF')
GUEST_MARKERS = ('SYSINFO_GUEST_MEMORY_PASS', 'SYSINFO_GUEST_SHARED_PASS', 'SYSINFO_GUEST_MEMFD_PASS',
                 'SYSINFO_GUEST_BUFFERS_PASS',
                 'SYSINFO_GUEST_LOAD_PASS ', 'AXIOM64_TESTS_PASS', 'AXIOM64_EXIT status=0')


def compile_client(provider, linkage, directory):
    program = directory / 'sysinfo-test'
    compiler = ['gcc'] if provider == 'native' else compiler_args(provider)
    command = [*compiler, '-std=c11', '-O2', '-g', '-Wall', '-Wextra', '-Werror',
               str(SOURCE), '-o', str(program)]
    if linkage == 'static':
        command.append('-static')
    subprocess.run(command, cwd=ROOT, env=environment(), check=True)
    headers = subprocess.check_output(['readelf', '-Wl', str(program)], text=True)
    assert ('INTERP' in headers) == (linkage == 'dynamic')
    return program, dict(command=command, sha256=digest(program), source_sha256=digest(SOURCE))


def execute(directory, command, firmware=None):
    log = directory / 'serial.log'
    with log.open('wb') as stream:
        run = subprocess.run(command, cwd=ROOT, stdout=stream, stderr=subprocess.STDOUT,
                             stdin=subprocess.DEVNULL, timeout=90, check=False)
    text = log.read_text()
    markers = ['SYSINFO_ABI_PASS ', 'SYSINFO_PASS']
    if firmware:
        markers.extend((*GUEST_MARKERS, 'Firmware: ' + firmware.upper()))
    passed = (run.returncode == (1 if firmware else 0)
              and all(text.count(marker) == 1 for marker in markers)
              and not any(marker in text for marker in ('SYSINFO_FAIL', 'PANIC:', 'FAULT pid=')))
    return dict(command=command, returncode=run.returncode, serial_sha256=digest(log), passed=passed)


def boot(directory, image, firmware):
    directory.mkdir(exist_ok=True)
    disk = directory / 'buffers.ext2'
    with disk.open('wb') as stream:
        stream.truncate(8 * 1024 * 1024)
    subprocess.run(['mke2fs', '-q', '-F', '-t', 'ext2', '-b', '1024', '-I', '128',
                    '-O', 'none,filetype,sparse_super', str(disk)], check=True)
    command = ['qemu-system-x86_64', '-machine', 'pc', '-cpu', 'max', '-m', '256M', '-nic', 'none',
               '-cdrom', str(image), '-display', 'none', '-serial', 'stdio', '-monitor', 'none',
               '-no-reboot', '-device', 'isa-debug-exit,iobase=0xf4,iosize=0x04',
               '-drive', f'if=none,id=stats,format=raw,file={disk}',
               '-device', 'virtio-blk-pci,drive=stats,disable-legacy=on']
    if firmware == 'uefi':
        variables = directory / 'OVMF_VARS.fd'
        code = FIRMWARE / 'OVMF_CODE_4M.fd'
        shutil.copyfile(FIRMWARE / 'OVMF_VARS_4M.fd', variables)
        command += ['-drive', f'if=pflash,format=raw,readonly=on,file={code}',
                    '-drive', f'if=pflash,format=raw,file={variables}']
    result = execute(directory, command, firmware)
    with (directory / 'fsck.log').open('wb') as stream:
        fsck = subprocess.run(['e2fsck', '-f', '-n', str(disk)],
                              stdout=stream, stderr=subprocess.STDOUT, check=False)
    return dict(result, firmware=firmware, image_sha256=digest(image), disk_sha256=digest(disk),
                fsck_returncode=fsck.returncode, passed=result['passed'] and fsck.returncode == 0)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--native', action='store_true')
    parser.add_argument('--directory', type=Path)
    args = parser.parse_args()
    directory = (args.directory or ROOT / ('build/sysinfo-native' if args.native else 'build/sysinfo')).resolve()
    directory.mkdir(parents=True, exist_ok=True)
    rows = []
    if args.native:
        for provider, linkage in (('native', 'dynamic'), ('build', 'static'), ('build', 'dynamic')):
            case = directory / (provider + '-' + linkage)
            case.mkdir(exist_ok=True)
            program, provenance = compile_client(provider, linkage, case)
            command = [str(program)]
            if provider == 'build' and linkage == 'dynamic':
                command.insert(0, str(loader('build')))
            rows.append(dict(execute(case, command), provider=provider, linkage=linkage,
                             inputs=provenance))
    else:
        subprocess.run(['make', '-s', '-j2', 'build/axiom64.elf', 'build/init', 'busybox'],
                       cwd=ROOT, check=True)
        inputs = {str(path.relative_to(ROOT)): digest(path) for path in
                  (SOURCE, Path(__file__).resolve(), ROOT / 'scripts/account_store_guest.py',
                   ROOT / 'scripts/build_musl.py', ROOT / 'scripts/image.py',
                   ROOT / 'sources.lock.json', ROOT / 'dependencies.json', ROOT / 'Makefile',
                   *sorted(path for path in (ROOT / 'kernel').rglob('*') if path.is_file()))}
        (directory / 'source-inputs.json').write_text(json.dumps(inputs, indent=2) + '\n')
        cases = {}
        for linkage in ('static', 'dynamic'):
            case = directory / linkage
            case.mkdir(exist_ok=True)
            cases[linkage] = fixture(case, 'build', linkage, program_builder=compile_client,
                                     filename='sysinfo-test', command='/bin/sysinfo-test --guest')
        with ThreadPoolExecutor(max_workers=2) as pool:
            runs = [(linkage, pool.submit(boot, directory / linkage / firmware, image, firmware))
                    for linkage, image in cases.items() for firmware in ('bios', 'uefi')]
            rows = [dict(run.result(), linkage=linkage) for linkage, run in runs]
        if any(digest(ROOT / name) != value for name, value in inputs.items()):
            raise RuntimeError('sysinfo sources changed during verification')
    (directory / 'results.json').write_text(json.dumps(rows, indent=2) + '\n')
    if not all(row['passed'] for row in rows):
        raise SystemExit(f'sysinfo profile failed, see {directory}')
    print(f'SYSINFO_MATRIX_PASS profiles={len(rows)}')


if __name__ == '__main__':
    main()
