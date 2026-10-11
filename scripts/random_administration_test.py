#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Compare Linux random administration and observe fresh guest initialization."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import time

from build_musl import ensure, loader
from fetch import LOCK, ROOT


def fingerprint(path):
    return dict(bytes=path.stat().st_size, sha256=hashlib.sha256(path.read_bytes()).hexdigest())


def snapshot(directory):
    inputs = ['Makefile', 'userspace/tests/random/administration.c',
              'kernel/include/core/random.hpp', 'kernel/include/core/random/engine.hpp',
              'kernel/core/random/engine.cpp', 'kernel/arch/x86_64/random.cpp',
              'kernel/drivers/platform/devices.cpp', 'scripts/random_administration_test.py',
              'scripts/build_musl.py', 'sources.lock.json']
    inputs += sorted(str(path.relative_to(ROOT)) for path in (ROOT / 'kernel').rglob('*')
                     if path.is_file() and path.suffix in ('.cpp', '.hpp') and
                     'tests' not in path.relative_to(ROOT / 'kernel').parts)
    inputs = sorted(set(inputs))
    for provider in ('build', 'runtime'):
        path = ensure(provider)
        shutil.copyfile(path / 'manifest.json', directory / f'musl-{provider}-manifest.json')
    record = {name: fingerprint(ROOT / name) for name in inputs}
    (directory / 'source-inputs.json').write_text(json.dumps(record, indent=2) + '\n')
    return record


def checked_run(command, logfile, timeout):
    started = time.monotonic_ns()
    with logfile.open('wb') as output:
        process = subprocess.Popen(command, cwd=ROOT, stdin=subprocess.DEVNULL,
                                   stdout=output, stderr=subprocess.STDOUT)
        timed_out = False
        try:
            process.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            timed_out = True
            process.kill()
            process.wait()
    text = logfile.read_text()
    observations = re.findall(r'RANDOM_ADMIN_OBSERVATION case=(\S+) request=([0-9a-f]{8}) '
                              r'result=(-?\d+) error=(\d+)\n', text)
    return dict(command=command, returncode=process.returncode, timed_out=timed_out,
                elapsed_ns=time.monotonic_ns() - started, observations=len(observations),
                log=logfile.name, log_input=fingerprint(logfile)), text


def fixture(directory, linkage, mode, *, program='random-admin', options=(), before=''):
    files = {name: (0o40755, b'') for name in
             ('bin', 'sbin', 'lib', 'etc', 'dev', 'proc', 'sys', 'tmp', 'run', 'root')}
    products = [('sbin/init', ROOT / 'build/init'),
                (f'bin/{program}', ROOT / f'build/{program}-{linkage}'),
                ('bin/busybox', ROOT / f"build/busybox-{LOCK['busybox']['version']}/busybox"),
                ('lib/ld-musl-x86_64.so.1', loader())]
    products_record = {}
    for name, source in products:
        files[name] = (0o100755, source.read_bytes())
        products_record[name] = fingerprint(source)
        target = directory / name
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(source, target)
    files['etc/net-test.sh'] = (0o100755, (
        f'#!/bin/sh\nset -e\n{before}\n/bin/{program} {mode}\necho AXIOM64_TESTS_PASS\n').encode())
    cpio = ROOT / 'build/rootfs-network.cpio'
    with cpio.open('wb') as output:
        entries = [*sorted(files.items()), ('TRAILER!!!', (0, b''))]
        for inode, (name, (permissions, data)) in enumerate(entries, 1):
            encoded = name.encode() + b'\0'
            fields = [inode, permissions, 0, 0, 1, 0, len(data), 0, 0, 0, 0, len(encoded), 0]
            output.write(b'070701' + b''.join(f'{value:08x}'.encode() for value in fields) + encoded)
            output.write(bytes(-output.tell() % 4))
            output.write(data)
            output.write(bytes(-output.tell() % 4))
    image_name = f'axiom64-{program}-{linkage}-{mode}.iso'
    command = ['python3', 'scripts/image.py', '--test', '--suite', 'network',
               '--output-name', image_name]
    if mode != 'ready':
        command += ['--kernel-option', 'random.trust_cpu=off']
    for option in options:
        command += ['--kernel-option', option]
    subprocess.run(command, cwd=ROOT, check=True, stdout=subprocess.DEVNULL)
    for name, source in [('image.iso', ROOT / 'build' / image_name),
                         ('kernel.elf', ROOT / 'build/axiom64.elf'), ('root.cpio', cpio)]:
        shutil.copyfile(source, directory / name)
        products_record[name] = fingerprint(directory / name)
    (directory / 'products.json').write_text(json.dumps(products_record, indent=2) + '\n')
    return directory / 'image.iso'


def native(directory, linkages, timeout):
    if os.geteuid() != 0:
        raise RuntimeError('native administrative comparisons require CAP_SYS_ADMIN')
    rows = []
    for linkage in linkages:
        client = ROOT / f'build/random-admin-{linkage}'
        shutil.copyfile(client, directory / client.name)
        command = [str(client), 'ready']
        if linkage == 'dynamic':
            command.insert(0, str(loader()))
        row, text = checked_run(command, directory / f'native-{linkage}.log', timeout)
        row.update(linkage=linkage, mode='ready', client=fingerprint(client))
        row['passed'] = (not row['timed_out'] and row['returncode'] == 0 and
                         f'RANDOM_ADMIN_PASS linkage={linkage} mode=ready ' in text and
                         'RANDOM_ADMIN_CAPABILITY_PASS uid=0 administrative_capability=absent' in text and
                         'RANDOM_ADMIN_FAIL ' not in text)
        rows.append(row)
        print(json.dumps(row), flush=True)
        (directory / 'results.json').write_text(json.dumps(rows, indent=2) + '\n')
        if not row['passed']:
            raise RuntimeError(f'native random administration failed: {linkage}')
    return rows


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--native', action='store_true')
    p.add_argument('--linkage', choices=('native', 'static', 'dynamic', 'both'), default='both')
    p.add_argument('--firmware', choices=('bios', 'uefi', 'both'), default='both')
    p.add_argument('--mode', choices=('ready', 'bootstrap', 'count-bootstrap'), nargs='+',
                   default=['ready', 'bootstrap', 'count-bootstrap'])
    p.add_argument('--output', type=Path)
    p.add_argument('--timeout', type=float, default=90)
    args = p.parse_args()
    if args.timeout <= 0 or (args.linkage == 'native' and not args.native):
        p.error('positive timeout and a guest musl linkage are required')
    linkages = ('native', 'static', 'dynamic') if args.native and args.linkage == 'both' else (
        ('static', 'dynamic') if args.linkage == 'both' else (args.linkage,))
    directory = args.output or ROOT / ('build/random-admin-native-results' if args.native
                                       else 'build/random-admin-guest-results')
    if directory.exists():
        raise RuntimeError('use a new output directory to retain previous comparisons')
    directory.mkdir(parents=True)
    targets = [f'build/random-admin-{linkage}' for linkage in linkages]
    if not args.native:
        targets += ['build/axiom64.elf', 'build/init', 'busybox']
    subprocess.run(['make', '-s', '-j2', *targets], cwd=ROOT, check=True)
    inputs = snapshot(directory)
    if args.native:
        native(directory, linkages, args.timeout)
    else:
        results = []
        for linkage in linkages:
            for mode in args.mode:
                case = directory / f'{linkage}-{mode}'
                case.mkdir()
                image = fixture(case, linkage, mode)
                for firmware in ('bios', 'uefi') if args.firmware == 'both' else (args.firmware,):
                    command = ['qemu-system-x86_64', '-machine', 'pc', '-cpu', 'max', '-m', '256M',
                               '-nic', 'none', '-cdrom', str(image), '-display', 'none',
                               '-serial', 'stdio', '-monitor', 'none', '-no-reboot',
                               '-device', 'isa-debug-exit,iobase=0xf4,iosize=0x04']
                    if firmware == 'uefi':
                        variables = case / f'{firmware}-OVMF_VARS.fd'
                        shutil.copyfile('/usr/share/OVMF/OVMF_VARS_4M.fd', variables)
                        command += ['-drive', 'if=pflash,format=raw,readonly=on,file=/usr/share/OVMF/OVMF_CODE_4M.fd',
                                    '-drive', f'if=pflash,format=raw,file={variables}']
                    row, text = checked_run(command, case / f'{firmware}.log', args.timeout)
                    markers = [f'RANDOM_ADMIN_PASS linkage={linkage} mode={mode} ',
                               'RANDOM_ADMIN_CAPABILITY_PASS uid=0 administrative_capability=absent',
                               'AXIOM64_TESTS_PASS', 'AXIOM64_EXIT status=0',
                               f'Firmware: {firmware.upper()}']
                    if mode != 'ready':
                        markers += [f'RANDOM_ADMIN_BOOTSTRAP_PASS count_only={int(mode == "count-bootstrap")}',
                                    'RANDOM_READY source=administrator bits=256',
                                    'RANDOM_SOURCE rdseed=1 trust_cpu=0']
                    else:
                        markers += ['RANDOM_READY source=rdseed bits=256']
                    row.update(linkage=linkage, mode=mode, firmware=firmware,
                               image=fingerprint(image), case=case.name)
                    row['missing'] = [marker for marker in markers if marker not in text]
                    row['passed'] = (not row['timed_out'] and row['returncode'] == 1 and
                                     not row['missing'] and not any(marker in text for marker in
                                     ('RANDOM_ADMIN_FAIL ', 'PANIC:', 'FAULT pid=')))
                    results.append(row)
                    print(json.dumps(row), flush=True)
                    (directory / 'results.json').write_text(json.dumps(results, indent=2) + '\n')
                    if not row['passed']:
                        raise RuntimeError(f'guest random administration failed: {case.name}/{firmware}')
    assert inputs == {name: fingerprint(ROOT / name) for name in inputs}, 'source changed during validation'


if __name__ == '__main__':
    main()
