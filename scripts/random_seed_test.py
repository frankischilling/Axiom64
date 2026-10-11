#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Check persisted seeds using fresh guest kernels and independently read ext2 disks."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile

from build_musl import loader
from fetch import LOCK, ROOT
from random_administration_test import checked_run, fingerprint, snapshot


def image(directory, linkage, mode, *, probe='random-seed-probe', command=None,
          extra_products=None, kernel_options=(), trace=False):
    files = {name: (0o40755, b'') for name in
             ('bin', 'sbin', 'lib', 'etc', 'dev', 'proc', 'sys', 'tmp', 'run', 'mnt', 'mnt/seed')}
    products = {'sbin/init': ROOT / 'build/init',
                'sbin/random-seed': ROOT / f'build/random-seed-{linkage}',
                'bin/seed-probe': ROOT / f'build/{probe}-{linkage}',
                'bin/random': ROOT / f'build/random-{linkage}',
                'bin/busybox': ROOT / f"build/busybox-{LOCK['busybox']['version']}/busybox",
                'lib/ld-musl-x86_64.so.1': loader()}
    products.update(extra_products or {})
    record = {}
    for name, source in products.items():
        for parent in reversed(Path(name).parents):
            if str(parent) != '.':
                files.setdefault(str(parent), (0o40755, b''))
        files[name] = (0o100755, source.read_bytes())
        record[name] = fingerprint(source)
        target = directory / name
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(source, target)
    command = command or '/bin/seed-probe ' + mode + ' /mnt/seed'
    script = '#!/bin/sh\nset -e\n' + command + '\n'
    if mode == 'unready':
        script += '/bin/random unready\n'
    files['etc/net-test.sh'] = (0o100755, (script + 'echo AXIOM64_TESTS_PASS\n').encode())
    archive = directory / 'root.cpio'
    with archive.open('wb') as stream:
        for inode, (name, (mode_bits, data)) in enumerate(
                [*sorted(files.items()), ('TRAILER!!!', (0, b''))], 1):
            encoded = name.encode() + b'\0'
            fields = [inode, mode_bits, 0, 0, 1, 0, len(data), 0, 0, 0, 0, len(encoded), 0]
            stream.write(b'070701' + b''.join(f'{value:08x}'.encode() for value in fields) + encoded)
            stream.write(bytes(-stream.tell() % 4))
            stream.write(data)
            stream.write(bytes(-stream.tell() % 4))
    identifier = hashlib.sha256(str(directory.relative_to(ROOT)).encode()).hexdigest()[:12]
    name = f'axiom64-seed-{linkage}-{mode}-{identifier}.iso'
    command = ['python3', 'scripts/image.py', '--test', '--suite', 'network', '--output-name', name,
               '--initramfs', str(archive)]
    if trace:
        command.append('--trace')
    if mode == 'unready':
        command += ['--kernel-option', 'random.trust_cpu=off']
    for option in kernel_options:
        command += ['--kernel-option', option]
    with (directory / 'image.log').open('wb') as stream:
        subprocess.run(command, cwd=ROOT, check=True, stdout=stream, stderr=subprocess.STDOUT)
    shutil.copyfile(ROOT / 'build' / name, directory / 'image.iso')
    shutil.copyfile(ROOT / 'build/axiom64.elf', directory / 'kernel.elf')
    for name in ('root.cpio', 'image.iso', 'kernel.elf'):
        record[name] = fingerprint(directory / name)
    (directory / 'products.json').write_text(json.dumps(record, indent=2) + '\n')
    return directory / 'image.iso'


def blank_disk(path):
    with path.open('wb') as stream:
        stream.truncate(32 * 1024 * 1024)
    command = ['mke2fs', '-q', '-F', '-t', 'ext2', '-b', '4096', '-I', '128',
               '-O', 'none,filetype,sparse_super,large_file', '-N', '512',
               '-U', 'e9d75d4d-9512-4f0c-b6d0-ead057575315',
               '-E', 'lazy_itable_init=0,root_owner=0:0', str(path)]
    subprocess.run(command, check=True, env=dict(os.environ, E2FSPROGS_FAKE_TIME='1700000000'),
                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


def disk_state(path, directory, label):
    state = dict(disk=fingerprint(path))
    checks = []
    for name, expected_mode, expected_size in (('random', 0o700, None),
                                              ('random/seed', 0o600, 32),
                                              ('random/lock', 0o600, 0)):
        result = subprocess.run(['debugfs', '-R', 'stat /' + name, str(path)],
                                capture_output=True, text=True, check=True)
        (directory / f'{label}-{name.replace("/", "-")}-stat.log').write_text(result.stdout + result.stderr)
        if 'Inode:' not in result.stdout:
            if 'File not found' not in result.stderr:
                raise RuntimeError('debugfs failed without a missing inode: ' + name)
            state[name] = None
            continue
        inode, kind, mode = re.search(r'Inode:\s+(\d+)\s+Type:\s+(\S+)\s+Mode:\s+([0-7]+)', result.stdout).groups()
        uid, gid, size = re.search(r'User:\s+(\d+)\s+Group:\s+(\d+).*?Size:\s+(\d+)', result.stdout).groups()
        links = int(re.search(r'Links:\s+(\d+)', result.stdout)[1])
        record = dict(inode=int(inode), kind=kind, mode=int(mode, 8), uid=int(uid), gid=int(gid),
                      size=int(size), links=links)
        if record['mode'] != expected_mode or record['uid'] or record['gid']:
            raise RuntimeError('unsafe persisted seed metadata: ' + name)
        if expected_size is not None:
            if record['size'] != expected_size or record['links'] != 1 or kind != 'regular':
                raise RuntimeError('wrong persisted seed file type, length or links: ' + name)
        elif kind != 'directory':
            raise RuntimeError('seed directory has the wrong type')
        if name == 'random/seed':
            payload = directory / f'{label}-seed.bin'
            subprocess.run(['debugfs', '-R', 'dump /random/seed ' + json.dumps(str(payload)), str(path)],
                           check=True, capture_output=True)
            if payload.stat().st_size != 32:
                raise RuntimeError('independent persisted seed export is incomplete')
            record['payload'] = fingerprint(payload)
        state[name] = record
    with (directory / f'{label}-fsck.log').open('wb') as stream:
        result = subprocess.run(['e2fsck', '-f', '-n', str(path)], stdout=stream, stderr=subprocess.STDOUT)
    if result.returncode != 0:
        raise RuntimeError('persisted seed filesystem is not clean: ' + label)
    state['fsck'] = dict(returncode=result.returncode, log=f'{label}-fsck.log',
                         input=fingerprint(directory / f'{label}-fsck.log'))
    return state


def boot(directory, label, iso, disk, linkage, firmware, transport, mode):
    before = disk_state(disk, directory, label + '-before')
    command = ['qemu-system-x86_64', '-machine', 'pc', '-cpu', 'max', '-m', '256M',
               '-nic', 'none', '-cdrom', str(iso), '-display', 'none', '-serial', 'stdio',
               '-monitor', 'none', '-no-reboot', '-device', 'isa-debug-exit,iobase=0xf4,iosize=0x04',
               '-drive', f'if=none,format=raw,cache=writeback,file={disk},id=seed' +
               (',readonly=on' if mode == 'readonly' else ''),
               '-device', 'virtio-blk-pci,drive=seed,' +
               ('disable-legacy=on' if transport == 'modern' else 'disable-modern=on')]
    if firmware == 'uefi':
        variables = directory / (label + '-VARS.fd')
        shutil.copyfile('/usr/share/OVMF/OVMF_VARS_4M.fd', variables)
        command += ['-drive', 'if=pflash,format=raw,readonly=on,file=/usr/share/OVMF/OVMF_CODE_4M.fd',
                    '-drive', 'if=pflash,format=raw,file=' + str(variables)]
    row, text = checked_run(command, directory / (label + '.log'), 90)
    markers = [f'RANDOM_SEED_PROBE_PASS linkage={linkage} mode={mode} ',
               'RANDOM_SEED_LOADED ', f'Firmware: {firmware.upper()}',
               'AXIOM64_TESTS_PASS', 'AXIOM64_EXIT status=0']
    if mode == 'rotate':
        markers += ['RANDOM_SEED_ROTATED bytes=32 ',
                    'RANDOM_SEED_FAILED stage=singleton-ownership error=11']
    elif mode == 'unready':
        markers += ['RANDOM_SEED_FAILED stage=initialized-output error=11', 'RANDOM_UNREADY_PASS']
        if 'RANDOM_READY ' in text:
            markers.append('uninitialized source must remain unready')
    else:
        markers += ['RANDOM_SEED_FAILED stage=private-temporary error=30']
    row['missing'] = [marker for marker in markers if marker not in text]
    row.update(label=label, linkage=linkage, firmware=firmware, transport=transport, mode=mode,
               image=fingerprint(iso), before=before)
    row['passed'] = (not row['timed_out'] and row['returncode'] == 1 and not row['missing'] and
                     not any(marker in text for marker in ('RANDOM_SEED_PROBE_FAIL ', 'PANIC:', 'FAULT pid=')))
    if not row['passed']:
        (directory / (label + '-failed.json')).write_text(json.dumps(row, indent=2) + '\n')
        raise RuntimeError('persisted seed guest failed: ' + label)
    row['after'] = disk_state(disk, directory, label + '-after')
    if mode in ('unready', 'readonly'):
        if before['random/seed'] != row['after']['random/seed']:
            raise RuntimeError('failed seed rotation changed the preserved seed')
        if mode == 'readonly' and before['disk'] != row['after']['disk']:
            raise RuntimeError('read-only seed volume changed')
    elif before['random/seed'] and before['random/seed']['payload'] == row['after']['random/seed']['payload']:
        raise RuntimeError('initialized seed rotation repeated its stored bytes')
    print(json.dumps(dict(label=label, passed=True, mode=mode, elapsed_ns=row['elapsed_ns'])), flush=True)
    return row


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--linkage', choices=('static', 'dynamic', 'both'), default='both')
    parser.add_argument('--firmware', choices=('bios', 'uefi', 'both'), default='both')
    parser.add_argument('--transport', choices=('modern', 'legacy', 'both'), default='both')
    parser.add_argument('--output', type=Path, default=ROOT / 'build/random-seed-results')
    args = parser.parse_args()
    directory = args.output.resolve()
    directory.mkdir(parents=True, exist_ok=False)
    linkages = ('static', 'dynamic') if args.linkage == 'both' else (args.linkage,)
    subprocess.run(['make', '-s', '-j2', 'build/axiom64.elf', 'build/init', 'busybox',
                    *(f'build/{program}-{linkage}' for linkage in linkages
                      for program in ('random', 'random-seed', 'random-seed-probe'))], cwd=ROOT, check=True)
    inputs = snapshot(directory)
    for name in ('scripts/random_seed_test.py', 'userspace/services/random_seed.c',
                 'userspace/tests/random/seed_lifecycle.c', 'userspace/tests/random/random.c',
                 'scripts/image.py', 'scripts/disk_root.py', 'userspace/init/main.c'):
        inputs[name] = fingerprint(ROOT / name)
    (directory / 'source-inputs.json').write_text(json.dumps(inputs, indent=2) + '\n')
    results = []
    for linkage in linkages:
        images = {}
        for mode in ('rotate', 'unready', 'readonly'):
            case = directory / (linkage + '-' + mode)
            case.mkdir()
            images[mode] = image(case, linkage, mode)
        for firmware in ('bios', 'uefi') if args.firmware == 'both' else (args.firmware,):
            for transport in ('modern', 'legacy') if args.transport == 'both' else (args.transport,):
                label = linkage + '-' + firmware + '-' + transport
                disk = directory / (label + '.raw')
                blank_disk(disk)
                results.append(boot(directory, label + '-first', images['rotate'], disk,
                                    linkage, firmware, transport, 'rotate'))
                replay = directory / (label + '-replay.raw')
                shutil.copyfile(disk, replay)
                results.append(boot(directory, label + '-second', images['rotate'], disk,
                                    linkage, firmware, transport, 'rotate'))
                clone = directory / (label + '-clone.raw')
                shutil.copyfile(disk, clone)
                for suffix, current in (('replay', replay), ('clone', clone)):
                    results.append(boot(directory, label + '-' + suffix, images['unready'], current,
                                        linkage, firmware, transport, 'unready'))
                results.append(boot(directory, label + '-readonly', images['readonly'], disk,
                                    linkage, firmware, transport, 'readonly'))
                (directory / 'results.json').write_text(json.dumps(results, indent=2) + '\n')
    if inputs != {name: fingerprint(ROOT / name) for name in inputs}:
        raise RuntimeError('source changed during persisted seed validation')


if __name__ == '__main__':
    main()
