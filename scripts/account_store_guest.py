#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Run account generation, concurrency and permission controls on fresh guest RAM roots."""
import argparse
import json
from pathlib import Path
import shutil
import subprocess
import time

from account_store_test import SOURCES, MARKER, build, digest
from build_musl import loader
from fetch import LOCK, ROOT


def fixture(directory, provider, linkage, *, program_builder=build, filename='account-store',
            command='/bin/account-store /run/account-store', extra_products=None):
    program, provenance = program_builder(provider, linkage, directory)
    files = {name: (0o40755, b'') for name in ('bin', 'sbin', 'lib', 'etc', 'dev', 'proc', 'sys', 'tmp', 'run')}
    products = {'sbin/init': ROOT / 'build/init', 'bin/' + filename: program,
                'bin/busybox': ROOT / ('build/busybox-' + LOCK['busybox']['version']) / 'busybox',
                'lib/ld-musl-x86_64.so.1': loader(provider)}
    products.update(extra_products or {})
    for name in products:
        for parent in Path(name).parents:
            if str(parent) != '.':
                files.setdefault(parent.as_posix(), (0o40755, b''))
    records = {}
    for name, path in products.items():
        files[name] = (0o100755, path.read_bytes())
        records[name] = dict(bytes=path.stat().st_size, sha256=digest(path))
    files['etc/net-test.sh'] = (0o100755, ('#!/bin/sh\nset -e\n' + command + '\necho AXIOM64_TESTS_PASS\n').encode())
    cpio = directory / 'root.cpio'
    with cpio.open('wb') as stream:
        for inode, (name, (mode, data)) in enumerate([*sorted(files.items()), ('TRAILER!!!', (0, b''))], 1):
            encoded = name.encode() + b'\0'
            fields = [inode, mode, 0, 0, 1, 0, len(data), 0, 0, 0, 0, len(encoded), 0]
            stream.write(b'070701' + b''.join(f'{field:08x}'.encode() for field in fields) + encoded)
            stream.write(bytes(-stream.tell() % 4))
            stream.write(data)
            stream.write(bytes(-stream.tell() % 4))
    name = filename + '-' + provider + '-' + linkage + '.iso'
    subprocess.run(['python3', 'scripts/image.py', '--test', '--suite', 'network',
                    '--initramfs', str(cpio), '--output-name', name], cwd=ROOT,
                   stdout=subprocess.DEVNULL, check=True)
    image = directory / 'image.iso'
    shutil.copy2(ROOT / 'build' / name, image)
    shutil.copy2(ROOT / 'build/axiom64.elf', directory / 'kernel.elf')
    for name in ('image.iso', 'root.cpio', 'kernel.elf'):
        records[name] = dict(bytes=(directory / name).stat().st_size, sha256=digest(directory / name))
    (directory / 'products.json').write_text(json.dumps(records, indent=2) + '\n')
    (directory / 'compiler-inputs.json').write_text(json.dumps(provenance, indent=2) + '\n')
    return image


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--directory', type=Path, default=ROOT / 'build/account-store-guest')
    args = parser.parse_args()
    args.directory.mkdir(parents=True, exist_ok=False)
    names = [*SOURCES, 'scripts/account_store_guest.py', 'Makefile', 'dependencies.json', 'ports.lock.json',
             'userspace/init/main.c', 'userspace/init/console.c', 'userspace/init/console.h',
             'userspace/init/seed_records.h', 'scripts/image.py', 'boot/limine.conf']
    names += [path.relative_to(ROOT).as_posix() for path in (ROOT / 'kernel').rglob('*')
              if path.is_file() and path.suffix in ('.cpp', '.hpp', '.asm')]
    source = {name: digest(ROOT / name) for name in names}
    (args.directory / 'source-inputs.json').write_text(json.dumps(source, indent=2) + '\n')
    subprocess.run(['make', '-s', '-j2', 'build/axiom64.elf', 'build/init', 'busybox'], cwd=ROOT, check=True)
    rows = []
    for provider in ('build', 'runtime'):
        for linkage in ('static', 'dynamic'):
            case = args.directory / (provider + '-' + linkage)
            case.mkdir()
            image = fixture(case, provider, linkage)
            for firmware in ('bios', 'uefi'):
                command = ['qemu-system-x86_64', '-machine', 'pc', '-cpu', 'max', '-m', '256M',
                           '-nic', 'none', '-cdrom', str(image), '-display', 'none', '-serial', 'stdio',
                           '-monitor', 'none', '-no-reboot', '-device', 'isa-debug-exit,iobase=0xf4,iosize=0x04']
                if firmware == 'uefi':
                    variables = case / 'OVMF_VARS.fd'
                    shutil.copy2('/usr/share/OVMF/OVMF_VARS_4M.fd', variables)
                    command += ['-drive', 'if=pflash,format=raw,readonly=on,file=/usr/share/OVMF/OVMF_CODE_4M.fd',
                                '-drive', 'if=pflash,format=raw,file=' + str(variables)]
                start = time.monotonic_ns()
                path = case / (firmware + '.log')
                timed_out = False
                with path.open('wb') as log:
                    process = subprocess.Popen(command, cwd=ROOT, stdin=subprocess.DEVNULL,
                                               stdout=log, stderr=subprocess.STDOUT)
                    try:
                        process.wait(timeout=90)
                    except subprocess.TimeoutExpired:
                        timed_out = True
                        process.kill()
                        process.wait()
                text = path.read_text().replace('\r\n', '\n')
                passed = (not timed_out and process.returncode == 1 and
                          text.splitlines().count(MARKER + '/run/account-store') == 1 and
                          text.splitlines().count('AXIOM64_TESTS_PASS') == 1 and
                          'AXIOM64_EXIT status=0' in text and 'Firmware: ' + firmware.upper() in text and
                          not any(marker in text for marker in ('PANIC:', 'FAULT pid=', 'ACCOUNT_STORE_FAIL')))
                rows.append(dict(provider=provider, linkage=linkage, firmware=firmware, case=case.name,
                                 root='ram', command=command, returncode=process.returncode,
                                 timed_out=timed_out, elapsed_ns=time.monotonic_ns() - start,
                                 log=path.relative_to(args.directory).as_posix(), log_sha256=digest(path), passed=passed))
                (args.directory / 'results.json').write_text(json.dumps(rows, indent=2) + '\n')
                if not passed:
                    raise RuntimeError('account store guest profile failed: ' + case.name + '/' + firmware)
                print('ACCOUNT_STORE_GUEST_PASS ' + case.name + '/' + firmware, flush=True)
    if source != {name: digest(ROOT / name) for name in source}:
        raise RuntimeError('account store guest inputs changed during validation')
    print('ACCOUNT_STORE_GUEST_MATRIX_PASS profiles=8 concurrent_updates=96 root=ram', flush=True)


if __name__ == '__main__':
    main()
