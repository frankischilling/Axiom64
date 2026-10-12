#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Run real password hashing and denial controls in both target libc providers."""
import argparse
import json
from pathlib import Path
import shutil
import subprocess
import time

from build_libxcrypt import digest
from build_musl import loader
from fetch import LOCK, ROOT
from password_library_test import build


def fixture(directory, provider, linkage):
    program, library, provenance = build(provider, linkage, directory)
    files = {name: (0o40755, b'') for name in ('bin', 'sbin', 'lib', 'usr', 'usr/lib', 'etc',
             'dev', 'proc', 'sys', 'tmp', 'run', 'root')}
    products = {'sbin/init': ROOT / 'build/init', 'bin/password-library': program,
                'bin/busybox': ROOT / ('build/busybox-' + LOCK['busybox']['version']) / 'busybox',
                'lib/ld-musl-x86_64.so.1': loader(provider)}
    if linkage == 'dynamic':
        products['usr/lib/libcrypt.so.2'] = library / 'dynamic/stage/usr/lib/libcrypt.so.2.0.0'
    records = {}
    for name, path in products.items():
        files[name] = (0o100755, path.read_bytes())
        target = directory / name
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(path, target)
        records[name] = dict(bytes=target.stat().st_size, sha256=digest(target))
    files['etc/net-test.sh'] = (0o100755, b'#!/bin/sh\nset -e\n/bin/password-library\necho AXIOM64_TESTS_PASS\n')
    cpio = directory / 'root.cpio'
    with cpio.open('wb') as stream:
        for inode, (name, (mode, data)) in enumerate([*sorted(files.items()), ('TRAILER!!!', (0, b''))], 1):
            encoded = name.encode() + b'\0'
            fields = [inode, mode, 0, 0, 1, 0, len(data), 0, 0, 0, 0, len(encoded), 0]
            stream.write(b'070701' + b''.join(f'{field:08x}'.encode() for field in fields) + encoded)
            stream.write(bytes(-stream.tell() % 4))
            stream.write(data)
            stream.write(bytes(-stream.tell() % 4))
    image_name = 'password-library-' + provider + '-' + linkage + '.iso'
    subprocess.run(['python3', 'scripts/image.py', '--test', '--suite', 'network',
                    '--initramfs', str(cpio), '--output-name', image_name], cwd=ROOT,
                   stdout=subprocess.DEVNULL, check=True)
    image = directory / 'image.iso'
    shutil.copy2(ROOT / 'build' / image_name, image)
    shutil.copy2(ROOT / 'build/axiom64.elf', directory / 'kernel.elf')
    for name in ('image.iso', 'root.cpio', 'kernel.elf'):
        records[name] = dict(bytes=(directory / name).stat().st_size, sha256=digest(directory / name))
    (directory / 'products.json').write_text(json.dumps(records, indent=2) + '\n')
    (directory / 'compiler-inputs.json').write_text(json.dumps(provenance, indent=2) + '\n')
    return image


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--directory', type=Path, default=ROOT / 'build/password-library-guest')
    parser.add_argument('--firmware', choices=('bios', 'uefi', 'both'), default='both')
    parser.add_argument('--provider', choices=('build', 'runtime', 'both'), default='both')
    parser.add_argument('--linkage', choices=('static', 'dynamic', 'both'), default='both')
    args = parser.parse_args()
    args.directory.mkdir(parents=True, exist_ok=False)
    names = ['Makefile', 'dependencies.json', 'ports.lock.json', 'sources.lock.json',
             'scripts/build_libxcrypt.py', 'scripts/build_musl.py', 'scripts/linux_uapi.py',
             'scripts/password_library_guest.py', 'scripts/password_library_test.py',
             'userspace/accounts/password.c', 'userspace/accounts/password.h',
             'userspace/tests/security/password.c', 'userspace/init/main.c',
             'userspace/init/seed_records.h', 'scripts/image.py', 'boot/limine.conf']
    names += [path.relative_to(ROOT).as_posix() for path in (ROOT / 'kernel').rglob('*')
              if path.is_file() and path.suffix in ('.cpp', '.hpp', '.asm')]
    source = {name: digest(ROOT / name) for name in names}
    (args.directory / 'source-inputs.json').write_text(json.dumps(source, indent=2) + '\n')
    subprocess.run(['make', '-s', '-j2', 'build/axiom64.elf', 'build/init', 'busybox'], cwd=ROOT, check=True)
    rows = []
    for provider in ('build', 'runtime') if args.provider == 'both' else (args.provider,):
        for linkage in ('static', 'dynamic') if args.linkage == 'both' else (args.linkage,):
            case = args.directory / (provider + '-' + linkage)
            case.mkdir()
            image = fixture(case, provider, linkage)
            for firmware in ('bios', 'uefi') if args.firmware == 'both' else (args.firmware,):
                command = ['qemu-system-x86_64', '-machine', 'pc', '-cpu', 'max', '-m', '256M',
                           '-nic', 'none', '-cdrom', str(image), '-display', 'none', '-serial', 'stdio',
                           '-monitor', 'none', '-no-reboot', '-device', 'isa-debug-exit,iobase=0xf4,iosize=0x04']
                if firmware == 'uefi':
                    variables = case / 'OVMF_VARS.fd'
                    shutil.copy2('/usr/share/OVMF/OVMF_VARS_4M.fd', variables)
                    command += ['-drive', 'if=pflash,format=raw,readonly=on,file=/usr/share/OVMF/OVMF_CODE_4M.fd',
                                '-drive', 'if=pflash,format=raw,file=' + str(variables)]
                start = time.monotonic_ns()
                timed_out = False
                with (case / (firmware + '.log')).open('wb') as log:
                    process = subprocess.Popen(command, cwd=ROOT, stdin=subprocess.DEVNULL,
                                               stdout=log, stderr=subprocess.STDOUT)
                    try:
                        process.wait(timeout=90)
                    except subprocess.TimeoutExpired:
                        timed_out = True
                        process.kill()
                        process.wait()
                path = case / (firmware + '.log')
                text = path.read_text().replace('\r\n', '\n')
                observations = len([line for line in text.splitlines() if line.startswith('PASSWORD_LIBRARY_OBSERVATION ')])
                passed = (not timed_out and process.returncode == 1 and observations == 22 and
                          text.splitlines().count('PASSWORD_LIBRARY_PASS observations=22') == 1 and
                          text.splitlines().count('AXIOM64_TESTS_PASS') == 1 and
                          'AXIOM64_EXIT status=0' in text and 'Firmware: ' + firmware.upper() in text and
                          not any(marker in text for marker in ('PANIC:', 'FAULT pid=', 'PASSWORD_LIBRARY_FAIL')))
                row = dict(provider=provider, linkage=linkage, firmware=firmware, case=case.name,
                           command=command, returncode=process.returncode, timed_out=timed_out,
                           elapsed_ns=time.monotonic_ns()-start, observations=observations,
                           log=path.relative_to(args.directory).as_posix(), log_sha256=digest(path), passed=passed)
                rows.append(row)
                (args.directory / 'results.json').write_text(json.dumps(rows, indent=2) + '\n')
                if not passed:
                    raise RuntimeError('guest password-library profile failed: ' + case.name + '/' + firmware)
                print('PASSWORD_LIBRARY_GUEST_PASS provider=' + provider + ' linkage=' + linkage +
                      ' firmware=' + firmware, flush=True)
    if source != {name: digest(ROOT / name) for name in source}:
        raise RuntimeError('password guest inputs changed during validation')
    print('PASSWORD_LIBRARY_GUEST_MATRIX_PASS profiles=' + str(len(rows)) +
          ' observations=' + str(sum(row['observations'] for row in rows)), flush=True)


if __name__ == '__main__':
    main()
