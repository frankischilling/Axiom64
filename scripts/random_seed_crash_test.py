#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Kill real seed-service processes or VMs at file-operation boundaries."""
import argparse
import json
import os
from pathlib import Path
import re
import shutil
import signal
import stat
import subprocess
import tempfile
import time

from build_musl import loader
from fetch import ROOT
from random_administration_test import checked_run, fingerprint, snapshot
from random_seed_fault_test import debugfs
from random_seed_native import compile_client
from random_seed_test import blank_disk, disk_state, image

POINTS = ('temporary-created', 'temporary-written', 'temporary-synced', 'checkpoint-synced',
          'before-publication', 'published', 'committed', 'cleanup-unlinked')
WRAPS = ('openat', 'write', 'fsync', 'linkat', 'renameat', 'unlinkat')
OLD = bytes(range(32))


def points(initial):
    return POINTS if initial == 'present' else tuple(
        point for point in POINTS if point not in ('checkpoint-synced', 'cleanup-unlinked'))


def fixture_disk(directory, initial):
    disk = directory / ('base-' + initial + '.raw')
    blank_disk(disk)
    (directory / 'old.bin').write_bytes(OLD)
    (directory / 'empty.bin').write_bytes(b'')
    (directory / 'unrelated.bin').write_bytes(b'keep')
    commands = ['mkdir /random', 'sif /random mode 040700',
                'write ' + json.dumps(str(directory / 'empty.bin')) + ' /random/lock',
                'sif /random/lock mode 0100600',
                'write ' + json.dumps(str(directory / 'unrelated.bin')) + ' /random/unrelated',
                'sif /random/unrelated mode 0100600']
    if initial == 'present':
        commands += ['write ' + json.dumps(str(directory / 'old.bin')) + ' /random/seed',
                     'sif /random/seed mode 0100600']
    for number, command in enumerate(commands):
        result = debugfs(disk, command, directory, f'{initial}-create-{number}', write=True)
        if any(text in result.stderr for text in ('not found', 'Could not allocate', 'File exists')):
            raise RuntimeError('crash fixture creation failed')
    disk_state(disk, directory, 'base-' + initial)
    return disk


def inspect_disk(disk, directory, label):
    listing = debugfs(disk, 'ls -p /random', directory, label + '-directory').stdout
    result = dict(disk=fingerprint(disk), entries={})
    for line in listing.splitlines():
        if not line.startswith('/'):
            continue
        fields = line.split('/')
        name = fields[5]
        if name in ('.', '..'):
            continue
        inode = int(fields[1])
        text = debugfs(disk, 'stat /random/' + name, directory, label + '-' + name).stdout
        kind, mode = re.search(r'Type:\s+(\S+)\s+Mode:\s+([0-7]+)', text).groups()
        uid, gid, size = re.search(r'User:\s+(\d+)\s+Group:\s+(\d+).*?Size:\s+(\d+)', text).groups()
        links = int(re.search(r'Links:\s+(\d+)', text)[1])
        if kind != 'regular' or int(mode, 8) != 0o600 or int(uid) or int(gid):
            raise RuntimeError('unsafe metadata at an actual crash boundary: ' + name)
        output = directory / (label + '-' + name + '.bin')
        debugfs(disk, 'dump /random/' + name + ' ' + json.dumps(str(output)), directory,
                label + '-' + name + '-dump')
        if output.stat().st_size != int(size):
            raise RuntimeError('crash payload export is incomplete')
        result['entries'][name] = dict(inode=inode, links=links, size=int(size),
                                       mode=int(mode, 8), uid=int(uid), gid=int(gid),
                                       payload=fingerprint(output), value=output.read_bytes().hex())
    if result['entries']['unrelated']['value'] != b'keep'.hex():
        raise RuntimeError('the crash changed unrelated file contents')
    return result


def validate_boundary(state, point, initial):
    entries = state['entries']
    replaced = point in ('published', 'committed', 'cleanup-unlinked')
    current = entries.get('seed')
    if initial == 'present' or replaced:
        if current is None or current['size'] != 32:
            raise RuntimeError('the interrupted seed is not a complete file')
        if (bytes.fromhex(current['value']) == OLD) == replaced:
            raise RuntimeError('the crash boundary has the wrong seed generation')
    elif current is not None:
        raise RuntimeError('a pre-publication crash unexpectedly published a seed')
    previous = entries.get('seed.previous')
    checkpoint = initial == 'present' and point in (
        'checkpoint-synced', 'before-publication', 'published', 'committed')
    if bool(previous) != checkpoint:
        raise RuntimeError('the previous-seed checkpoint does not match the actual boundary')
    if previous and (bytes.fromhex(previous['value']) != OLD or previous['size'] != 32):
        raise RuntimeError('the previous generation is incomplete')
    if previous and not replaced and (previous['inode'] != current['inode'] or
                                      previous['links'] != 2 or current['links'] != 2):
        raise RuntimeError('the retained hardlink checkpoint is invalid')
    temporaries = [name for name in entries if name.startswith('seed.tmp.')]
    if len(temporaries) != int(not replaced):
        raise RuntimeError('the temporary does not match the interrupted operation')
    if temporaries:
        temporary = entries[temporaries[0]]
        if temporary['size'] != (0 if point == 'temporary-created' else 32) or temporary['links'] != 1:
            raise RuntimeError('the interrupted temporary has an unexpected size or lifetime')
    expected = {'lock', 'unrelated', *temporaries}
    if current:
        expected.add('seed')
    if previous:
        expected.add('seed.previous')
    if set(entries) != expected:
        raise RuntimeError('unexpected files at the crash boundary')


def validate_recovery(before, after, point, initial):
    present = initial == 'present' or point in ('published', 'committed', 'cleanup-unlinked')
    expected = {'lock', 'unrelated'} | ({'seed'} if present else set())
    if set(after['entries']) != expected:
        raise RuntimeError('seed recovery did not clean exactly its own incomplete state')
    for name in expected:
        if before['entries'][name]['payload'] != after['entries'][name]['payload'] or \
                before['entries'][name]['inode'] != after['entries'][name]['inode']:
            raise RuntimeError('recovery replaced an already complete file: ' + name)
        if after['entries'][name]['links'] != 1:
            raise RuntimeError('recovery retained an unexpected hardlink')


def qemu_command(case, iso, disk, firmware, transport):
    command = ['qemu-system-x86_64', '-machine', 'pc', '-cpu', 'max', '-m', '256M',
               '-nic', 'none', '-cdrom', str(iso), '-display', 'none', '-serial', 'stdio',
               '-monitor', 'none', '-no-reboot', '-device', 'isa-debug-exit,iobase=0xf4,iosize=0x04',
               '-drive', f'if=none,format=raw,cache=writeback,file={disk},id=seed',
               '-device', 'virtio-blk-pci,drive=seed,' +
               ('disable-legacy=on' if transport == 'modern' else 'disable-modern=on')]
    if firmware == 'uefi':
        variables = case / 'VARS.fd'
        shutil.copyfile('/usr/share/OVMF/OVMF_VARS_4M.fd', variables)
        command += ['-drive', 'if=pflash,format=raw,readonly=on,file=/usr/share/OVMF/OVMF_CODE_4M.fd',
                    '-drive', 'if=pflash,format=raw,file=' + str(variables)]
    return command


def guest_case(case, images, base, linkage, firmware, transport, point, initial):
    case.mkdir()
    disk = case / 'disk.raw'
    shutil.copyfile(base, disk)
    if fingerprint(disk) != fingerprint(base):
        raise RuntimeError('the crash disk differs from its verified base')
    row = dict(linkage=linkage, firmware=firmware, transport=transport, point=point, initial=initial,
               base=fingerprint(base), images={name: fingerprint(path) for name, path in images.items()})
    log = case / 'stopped.log'
    command = qemu_command(case, images['stop'], disk, firmware, transport)
    started = time.monotonic_ns()
    with log.open('wb') as output:
        process = subprocess.Popen(command, stdin=subprocess.DEVNULL, stdout=output,
                                   stderr=subprocess.STDOUT, cwd=ROOT)
        try:
            deadline = time.monotonic() + 90
            while True:
                text = log.read_text(errors='strict')
                marker = re.search(r'^RANDOM_SEED_CRASH_BOUNDARY point=' + re.escape(point) +
                                   r' child=(\d+) status=(\d+)\n', text, re.MULTILINE)
                if marker:
                    if process.poll() is not None or f'Firmware: {firmware.upper()}' not in text:
                        raise RuntimeError('the VM did not remain live at the selected boundary')
                    row['boundary'] = dict(child=int(marker[1]), stopped_status=int(marker[2]))
                    break
                if process.poll() is not None or time.monotonic() >= deadline:
                    raise RuntimeError('the actual guest seed service did not reach its stop point')
                time.sleep(0.02)
            process.kill()  # SIGKILL: neither the guest nor QEMU performs graceful shutdown.
            process.wait(timeout=10)
            if process.returncode != -signal.SIGKILL:
                raise RuntimeError('the crash VM was not terminated by SIGKILL')
            row['crash'] = dict(command=command, returncode=process.returncode,
                                elapsed_ns=time.monotonic_ns() - started, log=fingerprint(log))
        finally:
            if process.poll() is None:
                process.kill()
                process.wait(timeout=10)
    row['interrupted'] = inspect_disk(disk, case, 'interrupted')
    validate_boundary(row['interrupted'], point, initial)
    command = qemu_command(case, images['recover'], disk, firmware, transport)
    recovery, text = checked_run(command, case / 'recovered.log', 90)
    marker = f'RANDOM_SEED_CRASH_PASS linkage={linkage} point={point} initial={initial} '
    required = [marker, 'credit=0\n', 'AXIOM64_TESTS_PASS', 'AXIOM64_EXIT status=0',
                f'Firmware: {firmware.upper()}']
    if recovery['timed_out'] or recovery['returncode'] != 1 or any(item not in text for item in required):
        raise RuntimeError('the new kernel did not recover the interrupted service')
    if any(item in text for item in ('RANDOM_READY ', 'RANDOM_SEED_CRASH_FAIL ', 'PANIC:', 'FAULT pid=')):
        raise RuntimeError('recovery credited untrusted input or reported a guest failure')
    row['recovery'] = recovery
    row['recovered'] = inspect_disk(disk, case, 'recovered')
    validate_recovery(row['interrupted'], row['recovered'], point, initial)
    row['filesystem'] = disk_state(disk, case, 'final')
    row['passed'] = True
    return row


def native_case(case, wrapped, service, base, linkage, point, initial):
    case.mkdir()
    disk = case / 'disk.raw'
    shutil.copyfile(base, disk)
    row = dict(linkage=linkage, point=point, initial=initial, base=fingerprint(base),
               client=fingerprint(wrapped), service=fingerprint(service))
    with tempfile.TemporaryDirectory(prefix='axiom64-seed-crash-native-') as name:
        jail = Path(name)
        for folder in ('bin', 'lib', 'dev', 'var', 'var/lib', 'var/lib/axiom64'):
            (jail / folder).mkdir(mode=0o755)
        for source, target in ((wrapped, 'bin/random-seed-stop'), (service, 'bin/random-seed')):
            shutil.copyfile(source, jail / target)
            (jail / target).chmod(0o755)
        if linkage == 'dynamic':
            shutil.copyfile(loader(), jail / 'lib/ld-musl-x86_64.so.1')
            (jail / 'lib/ld-musl-x86_64.so.1').chmod(0o755)
        os.mknod(jail / 'dev/urandom', stat.S_IFCHR | 0o666, os.makedev(1, 9))
        mountpoint = jail / 'var/lib/axiom64'
        subprocess.run(['mount', '-t', 'ext2', '-o', 'loop', str(disk), str(mountpoint)], check=True)
        mounted = True
        try:
            log = case / 'stopped.log'
            command = ['chroot', str(jail), '/bin/random-seed-stop', 'rotate', '--nonblock']
            with log.open('wb') as output:
                process = subprocess.Popen(command, stdout=output, stderr=subprocess.STDOUT,
                                           stdin=subprocess.DEVNULL,
                                           env=dict(os.environ, AXIOM64_SEED_CRASH_POINT=point))
                try:
                    deadline = time.monotonic() + 15
                    while True:
                        waited, status = os.waitpid(process.pid, os.WNOHANG | os.WUNTRACED)
                        if waited:
                            if not os.WIFSTOPPED(status) or os.WSTOPSIG(status) != signal.SIGSTOP:
                                process.returncode = os.waitstatus_to_exitcode(status)
                                raise RuntimeError('the native service exited before the actual boundary')
                            break
                        if time.monotonic() >= deadline:
                            raise RuntimeError('the native service did not stop within its deadline')
                        time.sleep(0.01)
                    if f'RANDOM_SEED_CRASH_STOP point={point}\n' not in log.read_text():
                        raise RuntimeError('the native service stopped at an unexpected point')
                    row['boundary'] = dict(pid=process.pid, stopped_status=status)
                    process.kill()
                    process.wait(timeout=10)
                    if process.returncode != -signal.SIGKILL:
                        raise RuntimeError('the native child did not exit by SIGKILL')
                    row['crash'] = dict(command=command, returncode=process.returncode,
                                        log=fingerprint(log))
                finally:
                    if process.returncode is None:
                        process.kill()
                        process.wait(timeout=10)
            subprocess.run(['umount', str(mountpoint)], check=True)
            mounted = False
            row['interrupted'] = inspect_disk(disk, case, 'interrupted')
            validate_boundary(row['interrupted'], point, initial)
            subprocess.run(['mount', '-t', 'ext2', '-o', 'loop', str(disk), str(mountpoint)], check=True)
            mounted = True
            command = ['chroot', str(jail), '/bin/random-seed', 'load']
            recovery, text = checked_run(command, case / 'recovered.log', 15)
            if recovery['returncode'] or recovery['timed_out'] or 'RANDOM_SEED_PASS mode=load ' not in text:
                raise RuntimeError('the native service failed to recover')
            row['recovery'] = recovery
            subprocess.run(['umount', str(mountpoint)], check=True)
            mounted = False
        finally:
            if mounted:
                subprocess.run(['umount', str(mountpoint)], check=True)
    row['recovered'] = inspect_disk(disk, case, 'recovered')
    validate_recovery(row['interrupted'], row['recovered'], point, initial)
    row['filesystem'] = disk_state(disk, case, 'final')
    row['passed'] = True
    return row


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--native', action='store_true')
    parser.add_argument('--linkage', choices=('native', 'static', 'dynamic', 'both'), default='both')
    parser.add_argument('--firmware', choices=('bios', 'uefi', 'both'), default='both')
    parser.add_argument('--transport', choices=('modern', 'legacy', 'both'), default='both')
    parser.add_argument('--point', choices=POINTS, nargs='+', default=list(POINTS))
    parser.add_argument('--initial', choices=('present', 'absent', 'both'), default='both')
    parser.add_argument('--output', type=Path, default=ROOT / 'build/random-seed-crash-results')
    args = parser.parse_args()
    if args.linkage == 'native' and not args.native:
        parser.error('native libc requires --native')
    if args.native and os.geteuid() != 0:
        parser.error('native actual-ext2 comparisons require an isolated root mount namespace')
    directory = args.output.resolve()
    directory.mkdir(parents=True, exist_ok=False)
    linkages = ('native', 'static', 'dynamic') if args.native and args.linkage == 'both' else (
        ('static', 'dynamic') if args.linkage == 'both' else (args.linkage,))
    if not args.native:
        subprocess.run(['make', '-s', '-j2', 'build/axiom64.elf', 'build/init', 'busybox',
                        *(f'build/{program}-{linkage}' for linkage in linkages for program in
                          ('random', 'random-seed', 'random-seed-stop', 'random-seed-crash'))],
                       cwd=ROOT, check=True)
    inputs = snapshot(directory)
    for name in ('userspace/services/random_seed.c', 'userspace/tests/random/seed_crash.c',
                 'userspace/tests/random/seed_crash_stop.c', 'scripts/random_seed_crash_test.py',
                 'scripts/random_seed_test.py', 'scripts/random_seed_native.py',
                 'scripts/random_seed_fault_test.py', 'scripts/image.py', 'scripts/build_openssl.py'):
        inputs[name] = fingerprint(ROOT / name)
    (directory / 'source-inputs.json').write_text(json.dumps(inputs, indent=2) + '\n')
    initials = ('present', 'absent') if args.initial == 'both' else (args.initial,)
    bases = {initial: fixture_disk(directory, initial) for initial in initials}
    results = []
    for linkage in linkages:
        if args.native:
            sources = [ROOT / 'userspace/services/random_seed.c']
            service, _ = compile_client(directory / (linkage + '-service'), linkage, sources)
            wrapped, _ = compile_client(directory / (linkage + '-stops'), linkage,
                                         [*sources, ROOT / 'userspace/tests/random/seed_crash_stop.c'],
                                         wraps=WRAPS)
        for initial in initials:
            for point in (point for point in args.point if point in points(initial)):
                label = f'{linkage}-{initial}-{point}'
                if args.native:
                    row = native_case(directory / label, wrapped, service, bases[initial],
                                      linkage, point, initial)
                    results.append(row)
                else:
                    images = {}
                    for mode in ('stop', 'recover'):
                        folder = directory / (label + '-' + mode + '-image')
                        folder.mkdir()
                        images[mode] = image(folder, linkage, 'crash-' + mode + '-' + point + '-' + initial,
                            probe='random-seed-crash', command=f'/bin/seed-probe {mode} {point} {initial}',
                            extra_products={'sbin/random-seed-stop': ROOT / f'build/random-seed-stop-{linkage}'},
                            kernel_options=('random.trust_cpu=off',) if mode == 'recover' else ())
                    for firmware in ('bios', 'uefi') if args.firmware == 'both' else (args.firmware,):
                        for transport in ('modern', 'legacy') if args.transport == 'both' else (args.transport,):
                            case = directory / (label + '-' + firmware + '-' + transport)
                            row = guest_case(case, images, bases[initial], linkage, firmware, transport,
                                             point, initial)
                            results.append(row)
                            (case / 'result.json').write_text(json.dumps(row, indent=2) + '\n')
                (directory / 'results.json').write_text(json.dumps(results, indent=2) + '\n')
                print(json.dumps(dict(case=label, native=args.native, passed=True)), flush=True)
    if not results or inputs != {name: fingerprint(ROOT / name) for name in inputs}:
        raise RuntimeError('seed crash sources changed or no selected case ran')


if __name__ == '__main__':
    main()
