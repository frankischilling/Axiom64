#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Compare Linux and Axiom64 IPC workloads."""
import argparse
import hashlib
from itertools import product
import json
import os
import re
from pathlib import Path
import shutil
import subprocess
import tempfile

from account_normal_test import write_cpio
from account_store_guest import fixture
from build_musl import compiler_args
from disk_root import archive_entries, build as build_disk_root
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
    'posix-message-queues': ('POSIX_MQ', ('priority-names', 'blocking', 'notifications',
                                           'permissions-limits')),
    'poll-waits': ('POLL_WAITS', ('arguments-and-masks', 'revents-copy', 'raw-and-libc-deadlines',
                                 'temporary-signal-mask', 'retained-poll', 'retained-ppoll',
                                 'stopped-poll', 'stopped-ppoll')),
    'select-waits': ('SELECT_WAITS', ('argument-order', 'bitmap-capacity', 'readiness-masks',
                                     'deadlines', 'temporary-signal-mask', 'retained-select',
                                     'retained-pselect', 'stopped-select', 'stopped-pselect')),
    'epoll-nested': ('EPOLL_NESTED', ('readiness-and-aliases', 'depth-and-cycles',
                                     'shared-descendant', 'timer-and-signal', 'round-robin')),
    'epoll-lifetime': ('EPOLL_LIFETIME', ('descriptor-admission', 'pollable-controls-and-devices',
                                         'epoll-creation-and-resource-limit', 'epoll-anonymous-descriptor',
                                         'retained-alias', 'same-number-different-descriptions',
                                         'fork-and-final-close', 'exec-cloexec-alias',
                                         'rights-in-flight', 'blocked-instance-reuse',
                                         'pwait2-arguments-and-copy',
                                         'pwait2-infinite-wait', 'pwait2-saturating-timeout',
                                         'pwait2-signal-mask', 'signal-mask-and-stop',
                                         'pwait2-read-only-deadline',
                                         'exclusive-registration', 'exclusive-pipe-readers',
                                         'exclusive-eventfd-writers', 'exclusive-signalfd',
                                         'exclusive-listener-backlog',
                                         'reuse-and-copy-fault')),
    'named-pipes': ('NAMED_PIPE', ('create', 'readiness', 'rendezvous', 'transient-peer',
                                       'interruption-cancellation', 'inode-aliases', 'unlink-recreate')),
    'posix-aio': ('POSIX_AIO', ('positioned-sync-errors', 'signal', 'lists-thread',
                                'timeout-interrupt-cancel', 'descriptor-reuse')),
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
    observed = {}
    if workload == 'poll-waits':
        deadlines = [re.fullmatch(r'POLL_WAITS_DEADLINE request_ns=(\d+) elapsed_ns=(\d+)', line)
                     for line in lines if line.startswith('POLL_WAITS_DEADLINE ')]
        if len(deadlines) != len(uids) or any(match is None for match in deadlines):
            raise RuntimeError(f'missing or invalid poll deadline observations in {log}')
        observations = []
        for uid, match in zip(uids, deadlines):
            requested, elapsed = map(int, match.groups())
            if requested != 31000001 or not requested <= elapsed < 2000000000:
                raise RuntimeError(f'incorrect poll deadline in {log}')
            observations.append(dict(uid=uid, request_ns=requested, elapsed_ns=elapsed))
        observed['deadline_observations'] = observations
    if workload == 'select-waits':
        deadlines = [re.fullmatch(r'SELECT_WAITS_DEADLINE (select|pselect) request_ns=(\d+) elapsed_ns=(\d+)',
                                  line) for line in lines if line.startswith('SELECT_WAITS_DEADLINE ')]
        observations = []
        expected_deadlines = [(uid, call, requested) for uid in uids
                              for call, requested in (('select', 31001000), ('pselect', 31000001))]
        if len(deadlines) != len(expected_deadlines) or any(match is None for match in deadlines):
            raise RuntimeError(f'missing or invalid select deadline observations in {log}')
        for (uid, call, requested), match in zip(expected_deadlines, deadlines):
            observed_call, request_ns, elapsed_ns = match.groups()
            elapsed = int(elapsed_ns)
            if observed_call != call or int(request_ns) != requested or not requested <= elapsed < 2000000000:
                raise RuntimeError(f'incorrect select deadline in {log}')
            observations.append(dict(uid=uid, call=call, request_ns=requested, elapsed_ns=elapsed))
        observed['deadline_observations'] = observations
    if workload == 'epoll-lifetime':
        seek = 'espipe' if '--legacy-seek' in command else 'noop'
        if [line for line in lines if line.startswith('EPOLL_LIFETIME_SEEK ')] != [
                f'EPOLL_LIFETIME_SEEK {seek}'] * len(uids):
            raise RuntimeError(f'wrong epoll seek behavior in {log}')
        observed['seek_contract'] = seek
    if workload == 'posix-aio':
        outcomes = [line.removeprefix('POSIX_AIO_OUTCOME ') for line in lines
                    if line.startswith('POSIX_AIO_OUTCOME ')]
        kinds = ('cancel', 'close') * len(uids)
        if len(outcomes) != len(kinds) or any(
                outcome not in (f'{kind}=cancelled', f'{kind}=completed')
                for outcome, kind in zip(outcomes, kinds)):
            raise RuntimeError(f'missing or invalid POSIX AIO cancellation observations in {log}')
        if firmware is not None and outcomes != ['cancel=cancelled', 'close=cancelled'] * len(uids):
            raise RuntimeError(f'guest musl did not cancel the blocked requests in {log}')
        observed['cancellation_outcomes'] = [dict(uid=uid, cancel=outcomes[2 * index].split('=')[1],
                                                 close=outcomes[2 * index + 1].split('=')[1])
                                             for index, uid in enumerate(uids)]
    if (child.returncode != expected_exit or receipts != expected or
            any(lines.count(marker) != 1 for marker in markers) or
            any(marker in line for marker in (f'{prefix}_FAIL', 'PANIC:', 'FAULT pid=')
                for line in lines)):
        raise RuntimeError(f'{workload} workload failed in {log}')
    return dict(returncode=child.returncode, uids=uids, log_sha256=digest(log), **observed)


def compile_workload(case, compiler, linkage, workload):
    flags = ['-static'] if linkage == 'static' else []
    libraries = ('-lrt',) if workload == 'posix-aio' else ()
    return compile_client(case, compiler, flags, workload, libraries=libraries)


def native(directory, workload):
    rows = []
    prefix, _ = WORKLOADS[workload]
    for linkage in ('static', 'dynamic'):
        case = directory / linkage
        case.mkdir()
        program, inputs = compile_workload(case, ['gcc'], linkage, workload)
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
            elif workload == 'posix-message-queues':
                namespace = ['unshare', '--ipc', '--mount', '--', '/bin/sh', '-ec',
                             'mount -t mqueue mqueue /dev/mqueue; exec "$@"',
                             'axiom-posix-message-queues']
            legacy_depth = (workload == 'epoll-nested' and
                            os.uname().release == '5.15.153.1-microsoft-standard-WSL2')
            legacy_seek = False
            if workload == 'epoll-lifetime':
                version = re.match(r'(\d+)\.(\d+)', os.uname().release)
                if not version:
                    raise RuntimeError('cannot determine native Linux epoll seek ABI')
                legacy_seek = tuple(map(int, version.groups())) < (6, 0)
            for uid, flags in ((0, []), (65534, ['--ordinary'])):
                if legacy_depth:
                    flags = ['--legacy-depth', *flags]
                if legacy_seek:
                    flags = ['--legacy-seek', *flags]
                row = execute([*namespace, str(executable), *flags],
                              case / f'{uid}.log', 0, [uid], workload)
                if workload == 'epoll-nested':
                    row['depth_policy'] = 'legacy-empty-chain' if legacy_depth else 'four-links'
                rows.append(dict(linkage=linkage, kernel=os.uname().release,
                                 program_sha256=program_hash, **row))
                print(f'{prefix}_NATIVE_PASS {linkage} uid={uid}', flush=True)
    return rows


def disk_digest(path):
    with path.open('rb') as source:
        return hashlib.file_digest(source, 'sha256').hexdigest()


def ext2_fixture(case, kernel, products, script, workload, *, readonly=True):
    disk = build_disk_root(source=case / 'root.cpio', destination=case / 'ext2.raw')
    name = f'{workload}-ext2.iso'
    flags = ['--root-readonly'] if readonly else []
    subprocess.run(['python3', '-B', 'scripts/image.py', '--test', '--suite', 'network',
                    '--root-device', '/dev/vda', *flags, '--output-name', name,
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


def guest_command(case, image, firmware, disk=None, *, writable=False):
    command = ['qemu-system-x86_64', '-machine', 'pc', '-cpu', 'max', '-m', '256M',
               '-nic', 'none', '-cdrom', str(image), '-display', 'none', '-serial',
               'stdio', '-monitor', 'none', '-no-reboot', '-device',
               'isa-debug-exit,iobase=0xf4,iosize=0x04']
    if disk:
        options = 'cache=writethrough' if writable else 'snapshot=on'
        command += ['-drive', f'if=none,id=root,file={disk},format=raw,{options}',
                    '-device', 'virtio-blk-pci,drive=root']
    if firmware == 'uefi':
        store = case / ('ext2-OVMF_VARS.fd' if disk else 'OVMF_VARS.fd')
        shutil.copyfile('/usr/share/OVMF/OVMF_VARS_4M.fd', store)
        command += ['-drive', 'if=pflash,format=raw,readonly=on,file=/usr/share/OVMF/OVMF_CODE_4M.fd',
                    '-drive', f'if=pflash,format=raw,file={store}']
    return command


def boot_guest(case, workload, image, firmware, disk=None):
    root = 'ext2' if disk else 'ramfs'
    command = guest_command(case, image, firmware, disk)
    log = case / (f'ext2-{firmware}.log' if disk else f'{firmware}.log')
    return execute(command, log, 1, [0, 65534], workload, firmware, root)


def named_pipe_storage(base, case, kernel, program, payload):
    base.mkdir()
    script = f'''#!/bin/sh
set -e
if test -p /source/axiom-fifo-retained; then
    /bin/{program.name} --storage-reopen
else
    /bin/{program.name} --storage-create
fi
echo AXIOM64_TESTS_PASS
'''.encode()
    entries = archive_entries(case / 'root.cpio')
    entries['etc/net-test.sh'] = (0o100755, script)
    write_cpio(base / 'root.cpio', entries)
    image, disk = ext2_fixture(base, kernel, payload, script, 'named-pipes-storage', readonly=False)
    original_digest = disk_digest(disk)
    rows = []
    inode = None
    for firmware, phase in (('bios', 'create'), ('uefi', 'reopen')):
        command = guest_command(base, image, firmware, disk, writable=True)
        log = base / f'{firmware}.log'
        with log.open('xb') as output:
            child = subprocess.run(command, stdin=subprocess.DEVNULL, stdout=output,
                                   stderr=subprocess.STDOUT, timeout=90)
        text = log.read_text()
        observed = re.findall(r'^NAMED_PIPE_STORAGE_PASS phase=(create|reopen) inode=([0-9]+)$',
                              text, re.MULTILINE)
        markers = [f'Firmware: {firmware.upper()}', 'VFS_ROOT_PASS filesystem=ext2 device=/dev/vda readonly=0',
                   'AXIOM64_TESTS_PASS', 'AXIOM64_EXIT status=0']
        if (child.returncode != 1 or len(observed) != 1 or observed[0][0] != phase or
                any(text.splitlines().count(marker) != 1 for marker in markers) or
                any(failure in text for failure in ('NAMED_PIPE_FAIL', 'PANIC:', 'FAULT pid='))):
            raise RuntimeError(f'ext2 FIFO {phase} failed in {log}')
        observed_inode = int(observed[0][1])
        if inode is not None and inode != observed_inode:
            raise RuntimeError('reboot changed the persisted FIFO inode')
        inode = observed_inode
        for name in ('axiom-fifo-retained', 'axiom-fifo-alias'):
            record = subprocess.check_output(['debugfs', '-R', f'stat /source/{name}', str(disk)],
                                             text=True, stderr=subprocess.DEVNULL)
            (base / f'{firmware}-{name}.txt').write_text(record)
            if (not re.search(rf'Inode:\s+{inode}\s+Type:\s+FIFO\b.*Mode:\s+0640', record, re.IGNORECASE) or
                    not re.search(r'^Links:\s+2\s+Blockcount:\s+0\b', record, re.MULTILINE)):
                raise RuntimeError(f'{name} does not reference the persisted FIFO')
        file_check = base / f'{firmware}-e2fsck.log'
        with file_check.open('xb') as output:
            subprocess.run(['e2fsck', '-fn', str(disk)], stdout=output,
                           stderr=subprocess.STDOUT, check=True)
        rows.append(dict(firmware=firmware, phase=phase, inode=inode, log_sha256=digest(log),
                         disk_sha256=disk_digest(disk), command=command))
        print(f'NAMED_PIPE_STORAGE_PASS {firmware}/{phase}', flush=True)
    if rows[0]['disk_sha256'] == original_digest:
        raise RuntimeError('guest FIFO creation left no persistent change')
    (base / 'results.json').write_text(json.dumps(dict(kernel_sha256=kernel,
        image_sha256=digest(image), client_sha256=digest(program), initial_disk_sha256=original_digest,
        boots=rows), indent=2) + '\n')


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
        program, inputs = compile_workload(case, compiler_args(provider), linkage, workload)
        if binary_linkage(program) != linkage:
            raise RuntimeError('guest IPC executable linkage differs')
        boot = f'/bin/{program.name}\n/bin/{program.name} --ordinary'
        if workload == 'sysv-shared-memory':
            boot = '/bin/busybox chmod 1777 /tmp\n' + boot
        elif workload == 'named-pipes':
            applet = '/dev/shm/axiom-fifo-applet'
            boot = (f'/bin/busybox mkfifo -m 0640 {applet}\n'
                    f'test -p {applet}\n'
                    f'/bin/busybox rm {applet}\n' + boot)
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
        if (provider, linkage) == ('build', 'static') and (
                workload.startswith('posix-') or workload in ('named-pipes', 'poll-waits', 'select-waits',
                                                          'epoll-lifetime', 'epoll-nested')):
            image, disk = ext2_fixture(case, kernel, payload, script, workload)
            fingerprint = disk_digest(disk)
            for firmware in ('bios', 'uefi'):
                row = boot_guest(case, workload, image, firmware, disk)
                rows.append(dict(provider=provider, linkage=linkage, firmware=firmware,
                                 root='ext2', kernel_sha256=kernel, program_sha256=digest(program),
                                 image_sha256=digest(image), disk_sha256=fingerprint, **row))
                print(f'{prefix}_GUEST_PASS ext2/{firmware}', flush=True)
            if disk_digest(disk) != fingerprint:
                raise RuntimeError('read-only ext2 fixture changed during boot')
            if workload == 'named-pipes':
                named_pipe_storage(directory / 'storage', case, kernel, program, payload)
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
