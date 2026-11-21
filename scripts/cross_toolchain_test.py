#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
# @file    scripts/cross_toolchain_test.py
# @brief   Run cross-built GNU C and C++ programs inside Axiom64.
# @author  frankischilling
# @date    2026-11-20
#
# Checks target input paths, then boots the produced ELF files on both firmwares.
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
import json
from pathlib import Path
import shlex
import subprocess
import sys
import tempfile

from account_normal_test import write_cpio
from build_cross_toolchain import BUILD_ENV, TARGET, check_install
from disk_root import archive_entries
from fetch import ROOT
from fixture_archive import fingerprint
from guest_kernel_test import make_image


TESTS = ROOT / 'userspace/tests/toolchain'
LOADER = 'lib/ld-musl-x86_64.so.1'
GUEST = 'root/cross-toolchain'


def check_inputs(output, prefix, working):
    for path in output.glob('*.d'):
        dependencies = shlex.split(path.read_text().replace('\\\n', '').split(':', 1)[1])
        for name in dependencies:
            source = (working / name).resolve()
            if not any(source.is_relative_to(parent) for parent in (prefix, TESTS, working)):
                raise RuntimeError(f'cross compile read a host header: {source}')
    for path in output.glob('*.map'):
        loads = [line[5:] for line in path.read_text().splitlines() if line.startswith('LOAD ')]
        if not loads:
            raise RuntimeError(f'missing linker inputs: {path}')
        for name in loads:
            source = (working / name).resolve()
            if not source.is_relative_to(prefix) and not source.is_relative_to(working):
                raise RuntimeError(f'cross link read a host library: {source}')


def compile_clients(prefix, output):
    check_install(prefix)
    environment = {**BUILD_ENV, 'TMPDIR': str(output)}
    cc, cxx, assembler, readelf = (prefix / 'bin' / f'{TARGET}-{name}'
                                  for name in ('gcc', 'g++', 'as', 'readelf'))

    def run(*command):
        return subprocess.check_output(command, cwd=output, env=environment, text=True)

    assembly = '.text\n.globl native_asm_add\n.type native_asm_add,@function\nnative_asm_add:\n' \
               '    lea (%rdi,%rsi), %eax\n    ret\n.section .note.GNU-stack,"",@progbits\n'
    (output / 'arithmetic.s').write_text(assembly)
    run(assembler, '--64', 'arithmetic.s', '-o', 'arithmetic.o')
    common = ('-O2', '-Wall', '-Wextra', '-Werror')
    run(cc, *common, '-MD', '-c', TESTS / 'hello.c', '-o', 'hello.o')
    run(cc, '-static', 'hello.o', 'arithmetic.o', '-Wl,-Map,c-static.map', '-o', 'c-static')
    run(cc, 'hello.o', 'arithmetic.o', '-Wl,-Map,c-dynamic.map', '-o', 'c-dynamic')
    run(cxx, *common, '-std=c++20', '-MD', '-fPIC', '-c', TESTS / 'library.cpp', '-o', 'library.o')
    run(cxx, '-shared', '-Wl,-z,defs', 'library.o', '-Wl,-Map,library.map', '-o', 'library.so')
    run(cxx, *common, '-std=c++20', '-pthread', '-MD', '-c', TESTS / 'shared.cpp', '-o', 'shared.o')
    run(cxx, '-pthread', 'shared.o', '-ldl', '-Wl,-Map,cxx.map', '-o', 'cxx')
    check_inputs(output, prefix, output)

    empty = output / 'empty-sysroot'
    empty.mkdir()
    result = subprocess.run([cc, f'--sysroot={empty}', '-static', 'hello.o', 'arithmetic.o', '-o', 'negative'],
                            cwd=output, env=environment, text=True, capture_output=True)
    (output / 'empty-sysroot.log').write_text(result.stderr)
    if result.returncode == 0 or (output / 'negative').exists() or 'cannot find' not in result.stderr:
        raise RuntimeError('empty sysroot did not fail to link with missing target libraries')

    for name in ('c-static', 'c-dynamic', 'cxx'):
        elf = run(readelf, '-Whl', name)
        (output / f'{name}.elf.txt').write_text(elf)
        expected = 'INTERP' not in elf if name == 'c-static' else f'program interpreter: /{LOADER}]' in elf
        if not expected or 'Advanced Micro Devices X86-64' not in elf:
            raise RuntimeError(f'invalid cross-linked executable: {name}')
    runtimes = {}
    for name in ('libstdc++.so.6', 'libgcc_s.so.1', 'libatomic.so.1'):
        path = Path(run(cxx, f'-print-file-name={name}').strip()).resolve(strict=True)
        if not path.is_relative_to(prefix):
            raise RuntimeError(f'cross C++ selected a host runtime: {name}')
        runtimes[name] = path
    return runtimes


def make_root(prefix, output, rootfs, runtimes):
    entries = archive_entries(rootfs)
    entries[GUEST] = (0o40755, b'')
    loader = prefix / TARGET / 'sysroot' / LOADER
    entries[LOADER] = (0o100755, loader.read_bytes())
    entries['lib/libc.musl-x86_64.so.1'] = (0o120777, b'ld-musl-x86_64.so.1')
    clients = {name: output / name for name in ('c-static', 'c-dynamic', 'library.so', 'cxx')}
    for name, path in {**clients, **runtimes}.items():
        entries[f'{GUEST}/{name}'] = (0o100755, path.read_bytes())
    entries['etc/boot-test.sh'] = (0o100755, b'''#!/bin/sh
set -eu
cd /root/cross-toolchain
./c-static
echo AXIOM64_CROSS_C_STATIC_PASS
./c-dynamic
echo AXIOM64_CROSS_C_DYNAMIC_PASS
LD_LIBRARY_PATH=$PWD ./cxx "$PWD/library.so"
echo AXIOM64_TESTS_PASS
''')
    image_root = output / 'root.cpio'
    write_cpio(image_root, entries)
    return image_root, {name: fingerprint(path) for name, path in {**clients, **runtimes, LOADER: loader}.items()}


def main():
    parser = argparse.ArgumentParser(description='Boot the GNU cross-toolchain smoke test on BIOS and UEFI.')
    parser.add_argument('--prefix', type=Path, required=True, help='installation printed by make cross-toolchain')
    prefix = parser.parse_args().prefix.resolve(strict=True)
    build = ROOT / 'build'
    output = Path(tempfile.mkdtemp(prefix='cross-toolchain-test-', dir=build))
    print(f'Cross-toolchain evidence: {output}', flush=True)
    kernel, rootfs = build / 'axiom64.elf', build / 'rootfs.cpio'
    inputs = {path.name: fingerprint(path) for path in (kernel, rootfs)}
    runtimes = compile_clients(prefix, output)
    installed, products = make_root(prefix, output, rootfs, runtimes)
    image = make_image(output, 'cross-boot.iso', kernel, installed)
    report = dict(inputs=inputs, products=products, image=fingerprint(image))
    result = subprocess.run([sys.executable, '-B', str(ROOT / 'scripts/boot_test.py'), '--prepared-image', str(image),
                             '--suite', 'cross-toolchain', '--firmware', 'both', '--timeout', '900'], cwd=ROOT)
    if fingerprint(image) != report['image'] or inputs != {path.name: fingerprint(path) for path in (kernel, rootfs)}:
        raise RuntimeError('cross-toolchain test inputs changed during validation')
    report['boots'] = json.loads((output / 'boot-results.json').read_text())
    (output / 'result.json').write_text(json.dumps(report, indent=2) + '\n')
    sys.exit(result.returncode)


if __name__ == '__main__':
    main()
