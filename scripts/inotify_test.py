#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Compare Linux inotify and run the same client on guest RAM and ext2 mounts."""
import argparse
from concurrent.futures import ThreadPoolExecutor
from itertools import product
import json
import os
from pathlib import Path
import shlex
import shutil
import subprocess
import sys
import tempfile

from account_store_guest import fixture
from build_musl import compiler_args
from compile_uapi_client import audit_compile
from ext2_test import create_volume
from fetch import ROOT
from fixture_archive import archive_fixture
from random_seed_crash_test import qemu_command
from tcp_fixture_inputs import audit_fixture, digest
from unix_datagram_proof import binary_linkage


CLIENT = 'userspace/tests/fs/inotify.c'
CASES = ('descriptor', 'namespace', 'readiness', 'detachment', 'attributes', 'lifetime')
GUEST_USES = (0, 65534, 0, 65534)
BOOT_BODY = '\n'.join((
    '/bin/busybox chmod 1777 /tmp',
    '/bin/inotify-test /tmp/notify-root',
    '/bin/inotify-test /tmp/notify-user --ordinary',
    '/bin/busybox mkdir -p /mnt/notify',
    '/bin/busybox mount -t ext2 /dev/vda /mnt/notify',
    '/bin/busybox chmod 1777 /mnt/notify',
    '/bin/inotify-test /mnt/notify/root',
    '/bin/inotify-test /mnt/notify/user --ordinary',
    '/bin/inotify-test /mnt/notify --unmount',
))


def compile_client(directory, compiler, flags):
    program = directory / 'inotify-test'
    with (directory / 'compile.log').open('xb') as output:
        subprocess.run([sys.executable, '-B', 'scripts/compile_uapi_client.py', '--compiler',
                        shlex.join(compiler), '--output', str(program), '--', '-std=c11',
                        '-O2', '-g', '-Wall', '-Wextra', '-Werror', *flags, CLIENT],
                       cwd=ROOT, stdout=output, stderr=subprocess.STDOUT, check=True)
    return program, audit_compile(program, ROOT)


def execute(command, log, returncode, identities, **kwargs):
    with log.open('xb') as output:
        done = subprocess.run(command, cwd=ROOT, stdin=subprocess.DEVNULL, stdout=output,
                              stderr=subprocess.STDOUT, timeout=80, **kwargs)
    lines = log.read_text().splitlines()
    cases = [line for line in lines if line.startswith('INOTIFY_CASE ')]
    expected_cases = [f'INOTIFY_CASE {case}' for case in CASES] * len(identities)
    passes = [line for line in lines if line.startswith('INOTIFY_PASS ')]
    expected_passes = [f'INOTIFY_PASS uid={uid} cases={len(CASES)}' for uid in identities]
    if (done.returncode != returncode or cases != expected_cases or passes != expected_passes or
            any(mark in line for line in lines for mark in ('INOTIFY_FAIL', 'PANIC:', 'FAULT pid='))):
        raise RuntimeError(f'inotify comparison failed in {log}')
    return lines, dict(returncode=done.returncode, uids=identities, cases=list(CASES),
                       log_sha256=digest(log))


def native(directory):
    program, compiled = compile_client(directory, ['gcc'], [])
    # The older WSL 5.15 kernel predates seek support on this anonymous inode.
    legacy = ['--legacy-seek'] if os.uname().release.split('.')[0] == '5' else []
    rows = []
    with tempfile.TemporaryDirectory(prefix='axiom-inotify-native-', dir='/var/tmp') as scratch:
        root = Path(scratch)
        root.chmod(0o755)
        data = root / 'data'
        data.mkdir()
        data.chmod(0o1777)
        actual = root / program.name
        shutil.copy2(program, actual)
        if digest(actual) != compiled['product']['sha256']:
            raise RuntimeError('native inotify copy differs from the compiled program')
        for profile, caller, expected, options in (
                ('root', 0, 0, []), ('drop', 0, 65534, ['--ordinary']),
                ('ordinary', 65534, 65534, [])):
            _, row = execute([str(actual), str(data / profile), *legacy, *options],
                             directory / f'{profile}.log', 0, [expected], user=caller,
                             group=caller, extra_groups=[])
            rows.append(dict(profile=profile, kernel=os.uname().release,
                             program_sha256=digest(actual), **row))
    return rows


def guest_profile(case, image, ids, kernel, program):
    firmware, transport = ids
    cell = case / f'{firmware}-{transport}'
    cell.mkdir()
    disk = cell / 'disk.raw'
    create_volume(disk)
    before = digest(disk)
    command = qemu_command(cell, image, disk, firmware, transport)
    lines, row = execute(command, cell / 'guest.log', 1, GUEST_USES)
    for marker in ('Firmware: ' + firmware.upper(), 'INOTIFY_UNMOUNT_PASS', 'AXIOM64_TESTS_PASS',
                   'AXIOM64_EXIT status=0'):
        if lines.count(marker) != 1:
            raise RuntimeError(f'inotify guest is missing {marker} in {cell}')
    fsck = cell / 'fsck.log'
    with fsck.open('xb') as output:
        subprocess.run(['e2fsck', '-f', '-n', str(disk)], stdout=output,
                       stderr=subprocess.STDOUT, timeout=30, check=True)
    saved = archive_fixture(disk, remove=True)
    print(f'INOTIFY_GUEST_PASS {case.name}/{cell.name}', flush=True)
    return dict(provider_linkage=case.name, firmware=firmware, transport=transport,
                command=command, kernel_sha256=kernel, program_sha256=program,
                image_sha256=digest(image), base_disk_sha256=before,
                final_disk=saved, fsck_sha256=digest(fsck), **row)


def guest(directory):
    subprocess.run(['make', '-j2', 'build/axiom64.elf', 'build/init', 'busybox'],
                   cwd=ROOT, check=True)
    kernel = digest(ROOT / 'build/axiom64.elf')
    script = ('#!/bin/sh\nset -e\n' + BOOT_BODY + '\necho AXIOM64_TESTS_PASS\n').encode()
    rows = []
    with ThreadPoolExecutor(max_workers=2) as workers:
        for provider, linkage in product(('build', 'runtime'), ('static', 'dynamic')):
            case = directory / f'{provider}-{linkage}'
            case.mkdir()
            program, inputs = compile_client(case, compiler_args(provider),
                                             ['-static'] if linkage == 'static' else [])
            if binary_linkage(program) != linkage:
                raise RuntimeError('inotify client has the wrong ELF linkage')
            image = fixture(case, provider, linkage, program_builder=lambda *args: (program, inputs),
                            filename=program.name, command=BOOT_BODY)
            records = json.loads((case / 'products.json').read_text())
            audit_fixture(image, kernel, {name: record['sha256'] for name, record in records.items()
                          if name not in ('kernel.elf', 'image.iso', 'root.cpio')}, script,
                          initramfs_sha256=records['root.cpio']['sha256'])
            program_hash = inputs['product']['sha256']
            if records['bin/inotify-test']['sha256'] != program_hash:
                raise RuntimeError('boot fixture differs from the compiled inotify client')
            futures = [workers.submit(guest_profile, case, image, ids, kernel, program_hash)
                       for ids in product(('bios', 'uefi'), ('modern', 'legacy'))]
            for future in futures:
                rows.append(future.result())
                (directory / 'partial-results.json').write_text(json.dumps(rows, indent=2) + '\n')
    return rows


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--directory', type=Path, required=True)
    parser.add_argument('--native', action='store_true')
    args = parser.parse_args()
    if args.native and os.geteuid():
        parser.error('native comparison needs root to run all three caller profiles')
    directory = args.directory.resolve()
    directory.mkdir(parents=True)
    source = ROOT / CLIENT
    shutil.copyfile(source, directory / source.name)
    inputs = [source, Path(__file__).resolve(), ROOT / 'Makefile']
    if not args.native:
        inputs.extend(path for path in (ROOT / 'kernel').rglob('*')
                      if path.is_file() and path.suffix in ('.cpp', '.hpp', '.asm'))
    sources = {path.relative_to(ROOT).as_posix(): digest(path) for path in inputs}
    (directory / 'source-inputs.json').write_text(json.dumps(sources, indent=2) + '\n')
    rows = (native if args.native else guest)(directory)
    if sources != {name: digest(ROOT / name) for name in sources}:
        raise RuntimeError('inotify inputs changed during validation')
    (directory / 'results.json').write_text(json.dumps(dict(passed=True, native=args.native, rows=rows),
                                                        indent=2) + '\n')
    print(f'INOTIFY_MATRIX_PASS native={int(args.native)} profiles={len(rows)}', flush=True)


if __name__ == '__main__':
    main()
