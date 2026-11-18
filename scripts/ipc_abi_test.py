#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Compare Linux and Axiom64 IPC workloads."""
import argparse
import hashlib
from itertools import product
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile

from account_store_guest import fixture
from build_musl import compiler_args
from disk_root import build as build_disk_root
from fetch import ROOT
from tcp_fixture_inputs import audit_fixture, digest
from timerfd_test import compile_client
from unix_datagram_proof import binary_linkage


WORKLOADS = {
    'sysv-semaphores': ('SYSV_SEM', ()),
    'sysv-message-queues': ('SYSV_MSG', ('identity', 'selection', 'capacity-faults',
                                  'direct-delivery', 'blocked-senders',
                                  'interruption-removal', 'permissions', 'exec')),
    'sysv-shared-memory': ('SYSV_SHM', ('metadata', 'fragments', 'remapping',
                                 'process-lifecycle', 'locking', 'permissions')),
    'posix-semaphores': ('POSIX_SEM', ('unnamed', 'named-lifetime', 'concurrent-create',
                                      'permissions')),
}


def execute(command, log, expected_exit, uids, workload, firmware=None, root='ramfs'):
    with log.open('xb') as output:
        child = subprocess.run(command, stdin=subprocess.DEVNULL, stdout=output,
                               stderr=subprocess.STDOUT, timeout=90)
    lines = log.read_text().splitlines()
    prefix, cases = WORKLOADS[workload]
    receipts = [line for line in lines if line.startswith((f'{prefix}_CASE ', f'{prefix}_PASS '))]
    expected = []
    for uid in uids:
        expected.extend(f'{prefix}_CASE {case}' for case in cases)
        expected.append(f'{prefix}_PASS uid={uid}')
    markers = [] if firmware is None else [
        f'Firmware: {firmware.upper()}', 'AXIOM64_TESTS_PASS', 'AXIOM64_EXIT status=0']
    if root == 'ext2':
        markers.append('VFS_ROOT_PASS filesystem=ext2 device=/dev/vda readonly=1')
    if (child.returncode != expected_exit or receipts != expected or
            any(lines.count(marker) != 1 for marker in markers) or
            any(marker in line for marker in (f'{prefix}_FAIL', 'PANIC:', 'FAULT pid=')
                for line in lines)):
        raise RuntimeError(f'{workload} workload failed in {log}')
    return dict(returncode=child.returncode, uids=uids, log_sha256=digest(log))


def native(directory, workload):
    rows = []
    prefix, _ = WORKLOADS[workload]
    for linkage in ('static', 'dynamic'):
        case = directory / linkage
        case.mkdir()
        program, inputs = compile_client(case, ['gcc'], ['-static'] if linkage == 'static' else [],
                                         workload)
        headers = subprocess.check_output(['readelf', '-lW', str(program)], text=True)
        if ('INTERP' in headers) != (linkage == 'dynamic'):
            raise RuntimeError('native IPC executable linkage differs')
        # The ordinary caller reexecutes the test. Its executable must remain
        # reachable even when the build lives under a root-only directory.
        with tempfile.TemporaryDirectory(prefix=f'axiom-{workload}-native-', dir='/var/tmp') as scratch:
            public = Path(scratch)
            public.chmod(0o755)
            executable = public / program.name
            shutil.copy2(program, executable)
            program_hash = inputs['product']['sha256']
            if digest(executable) != program_hash:
                raise RuntimeError('native executable copy differs from the compiled client')
            namespace = ['unshare', '--ipc', '--']
            if workload == 'posix-semaphores':
                namespace = ['unshare', '--ipc', '--mount', '--', '/bin/sh', '-ec',
                             'mount -t tmpfs -o mode=1777,nosuid,nodev tmpfs /dev/shm; exec "$@"',
                             'axiom-posix-semaphores']
            for uid, flags in ((0, []), (65534, ['--ordinary'])):
                row = execute([*namespace, str(executable), *flags],
                              case / f'{uid}.log', 0, [uid], workload)
                rows.append(dict(linkage=linkage, kernel=os.uname().release,
                                 program_sha256=program_hash, **row))
                print(f'{prefix}_NATIVE_PASS {linkage} uid={uid}', flush=True)
    return rows


def disk_digest(path):
    with path.open('rb') as source:
        return hashlib.file_digest(source, 'sha256').hexdigest()


def ext2_fixture(case, kernel, products, script):
    disk = build_disk_root(source=case / 'root.cpio', destination=case / 'ext2.raw')
    name = 'posix-semaphores-ext2.iso'
    subprocess.run(['python3', '-B', 'scripts/image.py', '--test', '--suite', 'network',
                    '--root-device', '/dev/vda', '--root-readonly', '--output-name', name,
                    '--output-directory', str(case)], cwd=ROOT, stdout=subprocess.DEVNULL,
                   check=True)
    image = case / name
    with tempfile.TemporaryDirectory(prefix='axiom-ipc-disk-readback-') as temporary:
        directory = Path(temporary)
        subprocess.run(['xorriso', '-osirrox', 'on', '-indev', str(image),
                        '-extract', '/boot/axiom64.elf', str(directory / 'kernel'),
                        '-extract', '/boot/rootfs.cpio', str(directory / 'bootstrap')],
                       capture_output=True, check=True)
        if (digest(directory / 'kernel') != kernel or
                digest(directory / 'bootstrap') != digest(ROOT / 'build/rootfs-bootstrap.cpio')):
            raise RuntimeError('ext2 boot image uses different kernel or bootstrap inputs')
        expected = {path: entry['sha256'] for path, entry in products.items()}
        expected['etc/net-test.sh'] = hashlib.sha256(script).hexdigest()
        for index, (path, fingerprint) in enumerate(expected.items()):
            target = directory / str(index)
            subprocess.run(['debugfs', '-R', f'dump /{path} {target}', str(disk)],
                           capture_output=True, check=True)
            if not target.is_file() or digest(target) != fingerprint:
                raise RuntimeError(f'ext2 root does not contain the recorded {path}')
    return image, disk


def boot_guest(case, workload, image, firmware, disk=None):
    root = 'ext2' if disk else 'ramfs'
    command = ['qemu-system-x86_64', '-machine', 'pc', '-cpu', 'max', '-m', '256M',
               '-nic', 'none', '-cdrom', str(image), '-display', 'none', '-serial',
               'stdio', '-monitor', 'none', '-no-reboot', '-device',
               'isa-debug-exit,iobase=0xf4,iosize=0x04']
    if disk:
        command += ['-drive', f'if=none,id=root,file={disk},format=raw,snapshot=on',
                    '-device', 'virtio-blk-pci,drive=root']
    if firmware == 'uefi':
        store = case / ('ext2-OVMF_VARS.fd' if disk else 'OVMF_VARS.fd')
        shutil.copyfile('/usr/share/OVMF/OVMF_VARS_4M.fd', store)
        command += ['-drive', 'if=pflash,format=raw,readonly=on,file=/usr/share/OVMF/OVMF_CODE_4M.fd',
                    '-drive', f'if=pflash,format=raw,file={store}']
    log = case / (f'ext2-{firmware}.log' if disk else f'{firmware}.log')
    return execute(command, log, 1, [0, 65534], workload, firmware, root)


def guest(directory, workload, client):
    with (directory / 'kernel-build.log').open('xb') as output:
        subprocess.run(['make', '-j2', 'build/axiom64.elf', 'build/init', 'busybox'],
                       cwd=ROOT, stdout=output, stderr=subprocess.STDOUT, check=True)
    kernel = digest(ROOT / 'build/axiom64.elf')
    rows = []
    prefix, _ = WORKLOADS[workload]
    for provider, linkage in product(('build', 'runtime'), ('static', 'dynamic')):
        case = directory / f'{provider}-{linkage}'
        case.mkdir()
        program, inputs = compile_client(case, compiler_args(provider),
                                         ['-static'] if linkage == 'static' else [],
                                         workload)
        if binary_linkage(program) != linkage:
            raise RuntimeError('guest IPC executable linkage differs')
        boot = f'/bin/{program.name}\n/bin/{program.name} --ordinary'
        if workload == 'sysv-shared-memory':
            boot = '/bin/busybox chmod 1777 /tmp\n' + boot
        image = fixture(case, provider, linkage, program_builder=lambda *args: (program, inputs),
                        filename=program.name, command=boot,
                        extra_products={f'source/{client.name}': client,
                                        'source/compiler-inputs.json': program.with_suffix('.inputs.json')})
        products = json.loads((case / 'products.json').read_text())
        script = f'#!/bin/sh\nset -e\n{boot}\necho AXIOM64_TESTS_PASS\n'.encode()
        payload = {name: entry for name, entry in products.items()
                   if name not in ('image.iso', 'root.cpio', 'kernel.elf')}
        audit_fixture(image, kernel, {name: entry['sha256'] for name, entry in payload.items()}, script,
                      initramfs_sha256=products['root.cpio']['sha256'])
        for firmware in ('bios', 'uefi'):
            row = boot_guest(case, workload, image, firmware)
            rows.append(dict(provider=provider, linkage=linkage, firmware=firmware,
                             root='ramfs', kernel_sha256=kernel, program_sha256=digest(program),
                             image_sha256=digest(image), **row))
            print(f'{prefix}_GUEST_PASS {provider}/{linkage}/{firmware}', flush=True)
        if (workload, provider, linkage) == ('posix-semaphores', 'build', 'static'):
            image, disk = ext2_fixture(case, kernel, payload, script)
            fingerprint = disk_digest(disk)
            for firmware in ('bios', 'uefi'):
                row = boot_guest(case, workload, image, firmware, disk)
                rows.append(dict(provider=provider, linkage=linkage, firmware=firmware,
                                 root='ext2', kernel_sha256=kernel, program_sha256=digest(program),
                                 image_sha256=digest(image), disk_sha256=fingerprint, **row))
                print(f'{prefix}_GUEST_PASS ext2/{firmware}', flush=True)
            if disk_digest(disk) != fingerprint:
                raise RuntimeError('read-only ext2 fixture changed during boot')
    return rows


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('workload', choices=WORKLOADS)
    parser.add_argument('--directory', type=Path, required=True)
    parser.add_argument('--native', action='store_true')
    args = parser.parse_args()
    if args.native and os.geteuid():
        parser.error('native matrix uses root and ordinary credentials')
    directory = args.directory.resolve()
    directory.mkdir(parents=True, exist_ok=False)
    client = ROOT / f'userspace/tests/ipc/{args.workload}.c'
    source = digest(client)
    rows = native(directory, args.workload) if args.native else guest(directory, args.workload, client)
    if digest(client) != source:
        raise RuntimeError('client source changed during the workload')
    (directory / 'results.json').write_text(json.dumps(
        dict(passed=True, source_sha256=source, profiles=rows), indent=2)+'\n')


if __name__ == '__main__':
    main()
