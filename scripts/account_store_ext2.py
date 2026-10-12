#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Verify account generations on actual ext2 disks across independent kernel boots."""
import argparse
import json
import re
import shutil
import subprocess
from pathlib import Path

from account_store_guest import SOURCES
from account_store_test import build, digest, environment
from build_musl import compiler_args, loader
from fetch import LOCK, ROOT
from random_administration_test import checked_run, fingerprint
from random_seed_test import blank_disk


def image(directory, provider, linkage, verify):
    if verify:
        program = directory / ('account-reboot-' + provider + '-' + linkage)
        command = [*compiler_args(provider), '-std=c11', '-O2', '-g', '-Wall', '-Wextra', '-Werror',
                   str(ROOT / 'userspace/accounts/store.c'),
                   str(ROOT / 'userspace/tests/security/account-store-reboot.c'), '-o', str(program)]
        if linkage == 'static':
            command += ['-static']
        subprocess.run(command, env=environment(), check=True)
        provenance = dict(command=command, binary_sha256=digest(program))
    else:
        program, provenance = build(provider, linkage, directory)
    files = {name: (0o40755, b'') for name in
             ('bin', 'sbin', 'lib', 'etc', 'dev', 'proc', 'sys', 'tmp', 'run', 'mnt', 'mnt/accounts')}
    products = {'sbin/init': ROOT / 'build/init', 'bin/account-store': program,
                'bin/busybox': ROOT / ('build/busybox-' + LOCK['busybox']['version']) / 'busybox',
                'lib/ld-musl-x86_64.so.1': loader(provider)}
    records = {}
    for name, path in products.items():
        files[name] = (0o100755, path.read_bytes())
        records[name] = fingerprint(path)
    script = ('#!/bin/sh\nset -e\n/bin/busybox mount -t ext2 /dev/vda /mnt/accounts\n'
              '/bin/account-store /mnt/accounts/accounts\n/bin/busybox sync\n'
              '/bin/busybox umount /mnt/accounts\necho AXIOM64_TESTS_PASS\n')
    files['etc/net-test.sh'] = (0o100755, script.encode())
    cpio = directory / 'root.cpio'
    with cpio.open('wb') as stream:
        for inode, (name, (mode, data)) in enumerate([*sorted(files.items()), ('TRAILER!!!', (0, b''))], 1):
            encoded = name.encode() + b'\0'
            fields = [inode, mode, 0, 0, 1, 0, len(data), 0, 0, 0, 0, len(encoded), 0]
            stream.write(b'070701' + b''.join(f'{field:08x}'.encode() for field in fields) + encoded)
            stream.write(bytes(-stream.tell() % 4))
            stream.write(data)
            stream.write(bytes(-stream.tell() % 4))
    image_name = 'account-ext2-' + provider + '-' + linkage + ('-verify' if verify else '-write') + '.iso'
    command = ['python3', 'scripts/image.py', '--test', '--suite', 'network', '--initramfs', str(cpio),
               '--output-name', image_name]
    with (directory / 'image.log').open('wb') as output:
        subprocess.run(command, cwd=ROOT, check=True, stdout=output, stderr=subprocess.STDOUT)
    image = directory / 'image.iso'
    shutil.copyfile(ROOT / 'build' / image_name, image)
    shutil.copyfile(ROOT / 'build/axiom64.elf', directory / 'kernel.elf')
    for name in ('root.cpio', 'image.iso', 'kernel.elf'):
        records[name] = fingerprint(directory / name)
    (directory / 'products.json').write_text(json.dumps(records, indent=2) + '\n')
    (directory / 'compiler-inputs.json').write_text(json.dumps(provenance, indent=2) + '\n')
    return image


def inspect(disk, directory, label):
    def stat(name, mode, kind):
        result = subprocess.run(['debugfs', '-R', 'stat ' + name, str(disk)], capture_output=True, text=True, check=True)
        text = result.stdout + result.stderr
        (directory / (label + '-' + Path(name).name + '-stat.log')).write_text(text)
        inode, actual_kind, actual_mode = re.search(r'Inode:\s+(\d+)\s+Type:\s+(\S+)\s+Mode:\s+([0-7]+)', result.stdout).groups()
        uid, gid, size = re.search(r'User:\s+(\d+)\s+Group:\s+(\d+).*?Size:\s+(\d+)', result.stdout).groups()
        links = int(re.search(r'Links:\s+(\d+)', result.stdout)[1])
        assert int(actual_mode, 8) == mode and actual_kind == kind and int(uid) == int(gid) == 0
        if kind != 'directory':
            assert links == 1
        return dict(inode=int(inode), kind=kind, mode=mode, uid=0, gid=0, bytes=int(size), links=links), text
    records = {}
    for name in ('/accounts', '/accounts/db'):
        records[name], _ = stat(name, 0o755, 'directory')
    records['current'], text = stat('/accounts/db/current', 0o777, 'symlink')
    target = re.search(r'Fast link dest:\s+"(g-[0-9a-f]{32})"', text)[1]
    expected = {'passwd': b'root:x:0:0:root:/root:/bin/sh\nalice:x:1000:1000:epoch13:/home/alice:/bin/sh\n',
                'group': b'root:x:0:\nusers:x:1000:alice\nepoch13:x:1001:\n',
                'shadow': b'root:!:1:0:99999:7:::\nalice:!:13:0:99999:7:::\n'}
    for name, data in expected.items():
        path = '/accounts/db/' + target + '/' + name
        records[name], _ = stat(path, 0o600 if name == 'shadow' else 0o644, 'regular')
        payload = directory / (label + '-' + name + '.bin')
        subprocess.run(['debugfs', '-R', 'dump ' + path + ' ' + str(payload), str(disk)],
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=True)
        assert payload.read_bytes() == data
        records[name]['payload'] = fingerprint(payload)
    records['lock'], _ = stat('/accounts/db/lock', 0o600, 'regular')
    with (directory / (label + '-fsck.log')).open('wb') as log:
        result = subprocess.run(['e2fsck', '-f', '-n', str(disk)], stdout=log, stderr=subprocess.STDOUT)
    assert result.returncode == 0
    return dict(disk=fingerprint(disk), files=records, current=target, fsck_returncode=result.returncode,
                fsck_log_input=fingerprint(directory / (label + '-fsck.log')))


def boot(directory, label, iso, disk, firmware, transport, verify):
    command = ['qemu-system-x86_64', '-machine', 'pc', '-cpu', 'max', '-m', '256M', '-nic', 'none',
               '-cdrom', str(iso), '-display', 'none', '-serial', 'stdio', '-monitor', 'none', '-no-reboot',
               '-device', 'isa-debug-exit,iobase=0xf4,iosize=0x04',
               '-drive', 'if=none,format=raw,cache=writeback,file=' + str(disk) + ',id=accounts',
               '-device', 'virtio-blk-pci,drive=accounts,' +
               ('disable-legacy=on' if transport == 'modern' else 'disable-modern=on')]
    if firmware == 'uefi':
        variables = directory / (label + '-VARS.fd')
        shutil.copyfile('/usr/share/OVMF/OVMF_VARS_4M.fd', variables)
        command += ['-drive', 'if=pflash,format=raw,readonly=on,file=/usr/share/OVMF/OVMF_CODE_4M.fd',
                    '-drive', 'if=pflash,format=raw,file=' + str(variables)]
    row, text = checked_run(command, directory / (label + '.log'), 90)
    expected = ('ACCOUNT_STORE_REBOOT_PASS epoch=13 files=3 ordinary_denials=2' if verify else
                'ACCOUNT_STORE_PASS generations=2 concurrent_updates=12 epoch=13 ordinary_denials=3 protected_rejections=5 fixture=/mnt/accounts/accounts')
    row['passed'] = (row['returncode'] == 1 and not row['timed_out'] and text.splitlines().count(expected) == 1
                     and 'Firmware: ' + firmware.upper() in text and 'AXIOM64_EXIT status=0' in text
                     and text.splitlines().count('AXIOM64_TESTS_PASS') == 1
                     and not any(marker in text for marker in ('PANIC:', 'FAULT pid=', 'ACCOUNT_STORE_FAIL', 'ACCOUNT_STORE_REBOOT_FAIL')))
    return row


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--directory', type=Path, default=ROOT / 'build/account-store-ext2')
    args = parser.parse_args()
    assert args.directory.resolve().is_relative_to((ROOT / 'build').resolve())
    args.directory.mkdir(parents=True, exist_ok=False)
    names = [*SOURCES, 'scripts/account_store_guest.py', 'scripts/account_store_ext2.py',
             'userspace/tests/security/account-store-reboot.c', 'scripts/random_seed_test.py',
             'scripts/random_administration_test.py', 'scripts/image.py', 'Makefile',
             'userspace/init/main.c', 'userspace/init/console.c', 'userspace/init/console.h',
             'userspace/init/seed_records.h', 'boot/limine.conf']
    names += [path.relative_to(ROOT).as_posix() for path in (ROOT / 'kernel').rglob('*')
              if path.is_file() and path.suffix in ('.cpp', '.hpp', '.asm')]
    source = {name: digest(ROOT / name) for name in names}
    (args.directory / 'source-inputs.json').write_text(json.dumps(source, indent=2) + '\n')
    subprocess.run(['make', '-s', '-j2', 'build/axiom64.elf', 'build/init', 'busybox'], cwd=ROOT, check=True)
    rows = []
    for provider in ('build', 'runtime'):
        for linkage in ('static', 'dynamic'):
            images = {}
            for verify in (False, True):
                directory = args.directory / (provider + '-' + linkage + ('-verify' if verify else '-write'))
                directory.mkdir()
                images[verify] = image(directory, provider, linkage, verify)
            for firmware in ('bios', 'uefi'):
                for transport in ('modern', 'legacy'):
                    name = '-'.join((provider, linkage, firmware, transport))
                    case = args.directory / name
                    case.mkdir()
                    disk = case / 'accounts.ext2'
                    assert not disk.exists()
                    blank_disk(disk)
                    before = fingerprint(disk)
                    write = boot(case, 'write', images[False], disk, firmware, transport, False)
                    row = dict(provider=provider, linkage=linkage, firmware=firmware, transport=transport,
                               before=before, write=write, passed=False)
                    rows.append(row)
                    (args.directory / 'results.json').write_text(json.dumps(rows, indent=2) + '\n')
                    if not write['passed']:
                        raise RuntimeError('account store ext2 write failed: ' + name)
                    row['written_state'] = inspect(disk, case, 'write')
                    verify = boot(case, 'verify', images[True], disk, firmware, transport, True)
                    row['verify'] = verify
                    if not verify['passed']:
                        raise RuntimeError('account store ext2 reboot failed: ' + name)
                    row['rebooted_state'] = inspect(disk, case, 'verify')
                    assert row['written_state']['current'] == row['rebooted_state']['current']
                    assert row['written_state']['files'] == row['rebooted_state']['files']
                    row['passed'] = True
                    (args.directory / 'results.json').write_text(json.dumps(rows, indent=2) + '\n')
                    print('ACCOUNT_STORE_EXT2_REBOOT_PASS ' + name, flush=True)
    assert source == {name: digest(ROOT / name) for name in source}
    print('ACCOUNT_STORE_EXT2_MATRIX_PASS cells=16 fresh_kernel_boots=32 independent_fsck=32', flush=True)


if __name__ == '__main__':
    main()
