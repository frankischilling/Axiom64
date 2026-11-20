#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
# @file    scripts/membarrier_test.py
# @brief   Run the Linux membarrier contract on native and guest kernels.
# @author  frankischilling
# @date    2026-11-19
#
# Compiles native and musl clients and records BIOS and UEFI boot results.
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
"""Compare Linux membarrier semantics on native Linux and fresh Axiom64 boots."""
import argparse
import json
from pathlib import Path
import shutil
import subprocess

from account_store_guest import fixture
from account_store_test import digest, environment
from build_musl import compiler_args, loader
from fetch import ROOT

SOURCE = ROOT / 'userspace/tests/process/membarrier.c'
FIRMWARE = Path('/usr/share/OVMF')


def compile_client(provider, linkage, directory):
    program = directory / 'membarrier-test'
    compiler = ['gcc'] if provider == 'native' else compiler_args(provider)
    command = [*compiler, '-std=c11', '-O2', '-g', '-Wall', '-Wextra', '-Werror', '-pthread',
               str(SOURCE), '-o', str(program)]
    if linkage == 'static':
        command.append('-static')
    subprocess.run(command, cwd=ROOT, env=environment(), check=True)
    headers = subprocess.check_output(['readelf', '-Wl', str(program)], text=True)
    if ('INTERP' in headers) != (linkage == 'dynamic'):
        raise RuntimeError(f'incorrect ELF linkage for {program}')
    return program, dict(command=command, sha256=digest(program), source_sha256=digest(SOURCE))


def execute(log, command, firmware=None):
    with log.open('wb') as stream:
        run = subprocess.run(command, cwd=ROOT, stdout=stream, stderr=subprocess.STDOUT,
                             stdin=subprocess.DEVNULL, timeout=90, check=False)
    text = log.read_text(errors='replace')
    markers = ['MEMBARRIER_EXEC_PASS', 'MEMBARRIER_PASS']
    if firmware:
        markers.extend(('AXIOM64_TESTS_PASS', 'AXIOM64_EXIT status=0', 'Firmware: ' + firmware.upper()))
    lines = text.splitlines()
    passed = (run.returncode == (1 if firmware else 0)
              and all(lines.count(marker) == 1 for marker in markers)
              and not any(marker in text for marker in ('MEMBARRIER_FAIL', 'PANIC:', 'FAULT pid=')))
    return dict(command=command, returncode=run.returncode, log_sha256=digest(log), passed=passed)


def boot(directory, image, firmware):
    command = ['qemu-system-x86_64', '-machine', 'pc', '-cpu', 'max', '-m', '256M', '-nic', 'none',
               '-cdrom', str(image), '-display', 'none', '-serial', 'stdio', '-monitor', 'none',
               '-no-reboot', '-device', 'isa-debug-exit,iobase=0xf4,iosize=0x04']
    if firmware == 'uefi':
        variables = directory / 'OVMF_VARS.fd'
        shutil.copyfile(FIRMWARE / 'OVMF_VARS_4M.fd', variables)
        command += ['-drive', f'if=pflash,format=raw,readonly=on,file={FIRMWARE / "OVMF_CODE_4M.fd"}',
                    '-drive', f'if=pflash,format=raw,file={variables}']
    return dict(execute(directory / (firmware + '.log'), command, firmware),
                firmware=firmware, image_sha256=digest(image))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--native', action='store_true')
    parser.add_argument('--directory', type=Path)
    args = parser.parse_args()
    directory = (args.directory or ROOT / ('build/membarrier-native' if args.native else 'build/membarrier')).resolve()
    directory.mkdir(parents=True, exist_ok=True)
    rows = []
    if args.native:
        for provider, linkage in (('native', 'dynamic'), ('build', 'static'), ('build', 'dynamic')):
            case = directory / (provider + '-' + linkage)
            case.mkdir(exist_ok=True)
            program, inputs = compile_client(provider, linkage, case)
            command = [str(program)]
            if provider == 'build' and linkage == 'dynamic':
                interpreter = str(loader(provider))
                command = [interpreter, str(program), '--native', interpreter]
            rows.append(dict(execute(case / 'native.log', command), provider=provider, linkage=linkage,
                             inputs=inputs))
    else:
        subprocess.run(['make', '-s', '-j2', 'build/axiom64.elf', 'build/init', 'busybox'],
                       cwd=ROOT, check=True)
        for linkage in ('static', 'dynamic'):
            case = directory / linkage
            case.mkdir(exist_ok=True)
            image = fixture(case, 'build', linkage, program_builder=compile_client,
                            filename='membarrier-test', command='/bin/membarrier-test --guest')
            rows.extend(dict(boot(case, image, firmware), linkage=linkage)
                        for firmware in ('bios', 'uefi'))

    (directory / 'results.json').write_text(json.dumps(rows, indent=2) + '\n')
    if not all(row['passed'] for row in rows):
        raise SystemExit(f'membarrier profile failed, see {directory}')
    print(f'MEMBARRIER_MATRIX_PASS profiles={len(rows)}')


if __name__ == '__main__':
    main()
