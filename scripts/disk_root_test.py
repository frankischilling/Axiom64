#!/usr/bin/env python3
"""Verify ext2 root and data files across clean shutdown and fresh VM boots."""
import argparse
import hashlib
import json
from pathlib import Path
import shutil
import stat
import struct
import subprocess
import sys
import time
from fetch import ROOT
from disk_root import archive_entries, build
from ext2_test import create_volume, check_fs, dump, debugfs

PAYLOAD = bytes((i * 31 + 17) & 255 for i in range(8193))


def digest(path):
    with path.open('rb') as source:
        return hashlib.file_digest(source, 'sha256').hexdigest()


def boot(firmware, transport, phase, root, data, image, timeout, hardware_readonly=False):
    suffix = '-hardware' if hardware_readonly else ''
    label = f'disk-root-{firmware}-{transport}-{phase}{suffix}'
    logfile = ROOT / 'build' / (label + '.log')
    readonly = phase == 'readonly'
    mode = 'disable-legacy=on' if transport == 'modern' else 'disable-modern=on'
    command = ['qemu-system-x86_64', '-machine', 'pc', '-cpu', 'max', '-m', '512M',
               '-cdrom', str(image), '-display', 'none', '-serial', 'stdio', '-monitor', 'none',
               '-no-reboot', '-device', 'isa-debug-exit,iobase=0xf4,iosize=0x04']
    for index, disk in enumerate([root, data]):
        command += ['-drive', f'if=none,id=disk{index},format=raw,cache=writeback,file={disk},readonly={"on" if hardware_readonly else "off"}',
                    '-device', f'virtio-blk-pci,drive=disk{index},{mode},rerror=report,werror=report,addr={5 + index}']
    if firmware == 'uefi':
        variables = ROOT / 'build' / (label + '-VARS.fd')
        shutil.copy2('/usr/share/OVMF/OVMF_VARS_4M.fd', variables)
        command += ['-drive', 'if=pflash,format=raw,readonly=on,file=/usr/share/OVMF/OVMF_CODE_4M.fd',
                    '-drive', f'if=pflash,format=raw,file={variables}']
    markers = [f'Firmware: {firmware.upper()}', 'AXIOM64_EXIT status=0',
               f'VFS_ROOT_PASS filesystem=ext2 device=/dev/vda readonly={int(readonly)}',
               f'DISK_ROOT_PHASE_PASS phase={phase}',
               {'write': 'DISK_ROOT_WRITE_PASS', 'verify': 'DISK_ROOT_REBOOT_PASS',
                'readonly': 'DISK_ROOT_READONLY_PASS'}[phase]]
    if phase == 'write':
        markers += ['DISK_ROOT_COHERENCE_PASS', 'DISK_ROOT_OPEN_UNLINK_SHUTDOWN_READY']
    started = time.monotonic()
    timed_out = False
    with logfile.open('w') as output:
        try:
            result = subprocess.run(command, stdin=subprocess.DEVNULL, stdout=output,
                                    stderr=subprocess.STDOUT, timeout=timeout)
            returncode = result.returncode
        except subprocess.TimeoutExpired:
            timed_out, returncode = True, None
    text = logfile.read_text(errors='replace')
    lines = {line.strip() for line in text.splitlines()}
    missing = [marker for marker in markers if marker not in lines]
    passed = not timed_out and returncode == 1 and not missing and not any(
        marker in text for marker in ['DISK_ROOT_FAIL', 'BOOT_ROOT_FAIL', 'FILESYSTEM_SHUTDOWN_FAIL', 'PANIC:', 'FAULT '])
    report = {'firmware': firmware, 'transport': transport, 'phase': phase, 'passed': passed,
              'hardware_readonly': hardware_readonly,
              'returncode': returncode, 'timed_out': timed_out, 'missing': missing,
              'seconds': round(time.monotonic() - started, 2), 'log': logfile.name}
    print(json.dumps(report), flush=True)
    if not passed:
        print('\n'.join(text.splitlines()[-40:]), flush=True)
    return report


def host_verify(root, data, label):
    for disk, name, suffix in [(root, '/root/root-persistence/payload', '-root'), (data, '/payload', '-data')]:
        if dump(disk, name, label + suffix) != PAYLOAD:
            raise RuntimeError('host file bytes differ: ' + name)
        metadata = debugfs(disk, 'stat ' + name)
        if ('Mode:  0640' not in metadata or 'Links: 1' not in metadata or
                'Size: 8193' not in metadata or '0x0dfb38d2' not in metadata):
            raise RuntimeError('host file metadata differs: ' + name)
        check_fs(disk, label + suffix)
        with disk.open('rb') as source:
            source.seek(1024 + 58)
            if not struct.unpack('<H', source.read(2))[0] & 1:
                raise RuntimeError('disk was not marked clean: ' + disk.name)
    if 'Fast link dest: "payload"' not in debugfs(root, 'stat /root/root-persistence/alias'):
        raise RuntimeError('host root symlink differs')


def negative_boot(firmware, transport, name, disk, image, timeout, stage, error,
                  readonly=False, rules=None):
    label = f'disk-root-{firmware}-{transport}-reject-{name}'
    mode = 'disable-legacy=on' if transport == 'modern' else 'disable-modern=on'
    command = ['qemu-system-x86_64', '-machine', 'pc', '-cpu', 'max', '-m', '512M',
               '-cdrom', str(image), '-display', 'none', '-serial', 'stdio', '-monitor', 'none',
               '-no-reboot', '-device', 'isa-debug-exit,iobase=0xf4,iosize=0x04']
    if disk:
        backend = f'blkdebug:{rules}:{disk}' if rules else str(disk)
        command += ['-drive', f'if=none,id=root,format=raw,cache=writeback,file={backend},readonly={"on" if readonly else "off"}',
                    '-device', f'virtio-blk-pci,drive=root,{mode},rerror=report,werror=report,addr=5']
    if firmware == 'uefi':
        variables = ROOT / 'build' / (label + '-VARS.fd')
        shutil.copy2('/usr/share/OVMF/OVMF_VARS_4M.fd', variables)
        command += ['-drive', 'if=pflash,format=raw,readonly=on,file=/usr/share/OVMF/OVMF_CODE_4M.fd',
                    '-drive', f'if=pflash,format=raw,file={variables}']
    logfile = ROOT / 'build' / (label + '.log')
    started = time.monotonic()
    timed_out = False
    with logfile.open('w') as output:
        try:
            returncode = subprocess.run(command, stdin=subprocess.DEVNULL, stdout=output,
                                        stderr=subprocess.STDOUT, timeout=timeout).returncode
        except subprocess.TimeoutExpired:
            timed_out, returncode = True, None
    text = logfile.read_text(errors='replace')
    lines = {line.strip() for line in text.splitlines()}
    markers = [f'Firmware: {firmware.upper()}', 'AXIOM64_EXIT status=1',
               f'BOOT_ROOT_FAIL stage={stage} errno={error}']
    missing = [marker for marker in markers if marker not in lines]
    passed = not timed_out and returncode == 3 and not missing and not any(
        marker in text for marker in ['VFS_ROOT_PASS', 'Entering userspace', 'PANIC:', 'FAULT '])
    report = {'firmware': firmware, 'transport': transport, 'phase': 'reject', 'case': name,
              'passed': passed, 'returncode': returncode, 'timed_out': timed_out,
              'missing': missing, 'seconds': round(time.monotonic() - started, 2), 'log': logfile.name}
    print(json.dumps(report), flush=True)
    if not passed:
        print('\n'.join(text.splitlines()[-35:]), flush=True)
    return report


def negative_cases():
    # A root-device option selects the tiny bootstrap, never a fallback userspace.
    normal = ['--root-device', '/dev/vda']
    return [
        ('empty', ['--kernel-option', 'root='], 'configuration', 22, None),
        ('duplicate', normal + ['--kernel-option', 'root=/dev/vda'], 'configuration', 22, None),
        ('long', ['--kernel-option', 'root=' + 'x' * 32], 'configuration', 22, None),
        ('bad-device', ['--kernel-option', 'root=/dev/sda'], 'root-device', 19, None),
        ('missing-device', normal, '/dev/vda', 19, 'absent'),
        ('wrong-device', ['--root-device', '/dev/vdb'], '/dev/vdb', 19, None),
        ('type-alone', ['--kernel-option', 'rootfstype=ext2'], 'configuration', 22, None),
        ('flags-alone', ['--kernel-option', 'rootflags=ro'], 'configuration', 22, None),
        ('unsupported-type', ['--kernel-option', 'root=/dev/vda', '--kernel-option', 'rootfstype=ext4'], 'rootfstype', 19, None),
        ('bad-flags', ['--kernel-option', 'root=/dev/vda', '--kernel-option', 'rootflags=invalid'], 'rootflags', 22, None),
        ('readonly-device', normal, '/dev/vda', 30, 'readonly'),
        ('bad-superblock', normal, '/dev/vda', 22, 'magic'),
        ('missing-init', normal, '/sbin/init', 2, 'rm /sbin/init'),
        ('init-mode', normal, '/sbin/init', 13, 'set_inode_field /sbin/init mode 0100644'),
        ('missing-busybox', normal, '/bin/busybox', 2, 'rm /bin/busybox'),
        ('missing-loader', normal, '/lib/ld-musl-x86_64.so.1', 2, 'rm /lib/ld-musl-x86_64.so.1'),
        ('missing-dev', normal, '/dev', 2, 'rmdir /dev'),
        ('missing-proc', normal, '/proc', 2, 'rmdir /proc'),
        ('missing-tmp', normal, '/tmp', 2, 'rmdir /tmp'),
        ('read-error', normal, '/dev/vda', 5, 'read'),
        ('write-error', normal, '/dev/vda', 5, 'write'),
        ('flush-error', normal, '/dev/vda', 5, 'flush'),
    ]


def remove_fixture_directory(disk, target):
    entries = archive_entries(ROOT / 'build/rootfs-desktop.cpio')
    relative = target.lstrip('/')
    descendants = [name for name in entries if name == relative or name.startswith(relative + '/')]
    for name in sorted(descendants, key=lambda name: (len(Path(name).parts), name), reverse=True):
        operation = 'rmdir' if stat.S_ISDIR(entries[name][0]) else 'rm'
        debugfs(disk, operation + ' ' + json.dumps('/' + name), write=True)
    if 'Inode:' in debugfs(disk, 'stat ' + target):
        raise RuntimeError('required directory still exists in rejection fixture: ' + target)


def rejection_matrix(seed, firmwares, transports, timeout, reports, selected=None):
    images = {}
    cases = [case for case in negative_cases() if selected is None or case[0] == selected]
    for name, options, _, _, _ in cases:
        image = ROOT / 'build' / f'disk-root-reject-{name}.iso'
        with image.with_suffix('.image.log').open('w') as output:
            subprocess.run([sys.executable, str(ROOT / 'scripts/image.py'), '--test',
                            '--suite', 'root', '--output-name', image.name, *options],
                           check=True, stdout=output, stderr=subprocess.STDOUT)
        images[name] = image
    seed_hash = digest(seed)
    for firmware in firmwares:
        for transport in transports:
            disk = ROOT / 'build' / f'disk-root-{firmware}-{transport}-negative.raw'
            for name, _, stage, error, change in cases:
                shutil.copyfile(seed, disk)
                if change and (' ' in change):
                    if change.startswith('rmdir '):
                        remove_fixture_directory(disk, change.split(' ', 1)[1])
                    else:
                        debugfs(disk, change, write=True)
                    if change.startswith('rm ') and 'Inode:' in debugfs(disk, 'stat ' + change[3:]):
                        raise RuntimeError('required file still exists in rejection fixture: ' + change[3:])
                    check_fs(disk, f'disk-root-fixture-{firmware}-{transport}-{name}')
                if change == 'magic':
                    with disk.open('r+b') as output:
                        output.seek(1024 + 56)
                        output.write(b'\0\0')
                rules = None
                if change in ['read', 'write', 'flush']:
                    rules = disk.with_suffix('.blkdebug')
                    if change == 'read':
                        with disk.open('rb') as source:
                            source.seek(4096)
                            bitmap = struct.unpack('<I', source.read(4))[0]
                        text = f'[inject-error]\nevent = "read_aio"\niotype = "read"\nsector = "{bitmap * 8}"\n'
                    elif change == 'write':
                        text = '[inject-error]\nevent = "write_aio"\niotype = "write"\nsector = "2"\n'
                    else:
                        text = '[inject-error]\nevent = "flush_to_disk"\niotype = "flush"\n'
                    rules.write_text(text + 'errno = "5"\nonce = "on"\n' if change != 'read' else
                                     text + 'errno = "5"\nonce = "off"\n')
                unchanged = change not in ['flush']
                before = digest(disk) if unchanged else None
                report = negative_boot(firmware, transport, name,
                                       None if change == 'absent' else disk, images[name],
                                       timeout, stage, error, change == 'readonly', rules)
                reports.append(report)
                if not report['passed']:
                    raise RuntimeError('root rejection failed: ' + name)
                try:
                    # Required-file rejection mounts and cleanly closes the disk, so its
                    # superblock mount counter may change, but every inode remains valid.
                    if (change and ' ' in change) or change == 'flush':
                        check_fs(disk, f'disk-root-{firmware}-{transport}-reject-{name}')
                    elif before != digest(disk):
                        raise RuntimeError('rejected root disk changed: ' + name)
                    if digest(seed) != seed_hash:
                        raise RuntimeError('root seed fixture changed')
                except Exception as error:
                    report.update(passed=False, host_verified=False, host_error=str(error))
                    raise
                report['host_verified'] = True
                print(f'HOST_DISK_ROOT_REJECT_PASS {firmware}/{transport}/{name}', flush=True)
            disk.unlink()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--firmware', choices=['bios', 'uefi', 'both'], default='both')
    parser.add_argument('--transport', choices=['modern', 'legacy', 'both'], default='both')
    parser.add_argument('--timeout', type=int, default=120)
    parser.add_argument('--checks', choices=['all', 'files', 'errors'], default='all')
    parser.add_argument('--case', choices=[case[0] for case in negative_cases()],
                        help='isolate one rejection case with --checks errors')
    args = parser.parse_args()
    if args.case and args.checks != 'errors':
        parser.error('--case requires --checks errors')
    subprocess.run(['make', '-j2', 'build/axiom64.elf', 'build/rootfs-desktop.cpio'], cwd=ROOT, check=True)
    seed = build('desktop', verify_reproducible=True)
    images = {}
    for phase in ['write', 'verify', 'readonly'] if args.checks != 'errors' else []:
        name = f'disk-root-{phase}.iso'
        with (ROOT / 'build' / f'disk-root-image-{phase}.log').open('w') as output:
            subprocess.run([sys.executable, str(ROOT / 'scripts/image.py'), '--test', '--suite', 'root',
                            '--phase', phase, '--root-device', '/dev/vda', '--output-name', name,
                            *(['--root-readonly'] if phase == 'readonly' else [])],
                           check=True, stdout=output, stderr=subprocess.STDOUT)
        images[phase] = ROOT / 'build' / name
    reports = []
    firmwares = ['bios', 'uefi'] if args.firmware == 'both' else [args.firmware]
    transports = ['modern', 'legacy'] if args.transport == 'both' else [args.transport]
    try:
        for firmware in firmwares if args.checks != 'errors' else []:
            for transport in transports:
                label = f'disk-root-{firmware}-{transport}'
                root = ROOT / 'build' / (label + '-root.raw')
                data = ROOT / 'build' / (label + '-data.raw')
                shutil.copyfile(seed, root)
                create_volume(data, block_size=4096, inode_size=128)
                for phase, hardware_readonly in [('write', False), ('verify', False),
                                                  ('readonly', False), ('readonly', True)]:
                    before = [digest(root), digest(data)] if phase == 'readonly' else None
                    report = boot(firmware, transport, phase, root, data, images[phase],
                                  args.timeout, hardware_readonly)
                    reports.append(report)
                    if not report['passed']:
                        raise RuntimeError('disk-root boot failed: ' + label + '/' + phase)
                    try:
                        host_verify(root, data, label + '-' + phase +
                                    ('-hardware' if hardware_readonly else ''))
                        if before and before != [digest(root), digest(data)]:
                            raise RuntimeError('read-only disk bytes changed')
                    except Exception as error:
                        report.update(passed=False, host_verified=False, host_error=str(error))
                        raise
                    report['host_verified'] = True
                    print('HOST_DISK_ROOT_PASS ' + label + '/' + phase, flush=True)
        if args.checks != 'files':
            rejection_matrix(seed, firmwares, transports, args.timeout, reports, args.case)
    finally:
        (ROOT / 'build/disk-root-results.json').write_text(json.dumps(reports, indent=2) + '\n')
    print(f'DISK_ROOT_MATRIX_PASS boots={len(reports)}', flush=True)


if __name__ == '__main__':
    main()
