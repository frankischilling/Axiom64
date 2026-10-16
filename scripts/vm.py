#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Start a normal VM with a persistent disk that is created once and then preserved."""
import argparse
import fcntl
import json
import os
from pathlib import Path
import shutil
import stat
import subprocess
import tempfile

from build_accounts import digest
from disk_root import archive_entries, bootstrap, populate
from fetch import ROOT


def regular(path):
    value = path.lstat()
    if not stat.S_ISREG(value.st_mode) or value.st_nlink != 1:
        raise RuntimeError('VM state must be a regular file with one link: ' + str(path))
    return value


def create_disk(destination, entries):
    size = sum(len(payload) for mode, payload in entries.values() if stat.S_ISREG(mode))
    unit = 64 * 1024 * 1024
    capacity = max(256 * 1024 * 1024, ((size * 2 + unit + unit - 1) // unit) * unit)
    with tempfile.TemporaryDirectory(prefix='axiom64-vm-root-') as temporary:
        stage = Path(temporary)
        populate(stage, entries)
        with destination.open('wb') as output:
            output.truncate(capacity)
        subprocess.run(['mke2fs', '-q', '-F', '-t', 'ext2', '-b', '4096', '-I', '128',
                        '-O', 'none,filetype,sparse_super,large_file', '-N', str(len(entries) + 4096),
                        '-E', 'lazy_itable_init=0,root_owner=0:0', '-d', str(stage), str(destination)],
                       check=True, capture_output=True)
    commands = [f'set_inode_field {json.dumps(name)} {field} 0'
                for name in ['/', '/lost+found', *('/' + name for name in sorted(entries))]
                for field in ('uid', 'gid')]
    subprocess.run(['debugfs', '-w', '-f', '-', str(destination)], input='\n'.join(commands) + '\n',
                   check=True, capture_output=True, text=True)
    with destination.with_suffix('.fsck.log').open('wb') as log:
        subprocess.run(['e2fsck', '-f', '-n', str(destination)], check=True,
                       stdout=log, stderr=subprocess.STDOUT)


def prepare(state, source):
    state = state.resolve()
    state.mkdir(parents=True, exist_ok=True, mode=0o700)
    disk, manifest = state / 'root.ext2', state / 'created.json'
    present = disk.exists() or disk.is_symlink() or manifest.exists() or manifest.is_symlink()
    if present:
        regular(disk)
        regular(manifest)
        record = json.loads(manifest.read_text())
        if record.get('version') != 1 or record.get('disk') != 'root.ext2':
            raise RuntimeError('unsupported VM state manifest')
        if disk.stat().st_size != record['disk_bytes']:
            raise RuntimeError('persistent VM disk size changed')
        # Its contents change inside the guest. Never regenerate it from a new
        # build or compare mutable user data with the original image digest.
        return disk, False
    if any(path.name != 'lock' for path in state.iterdir()):
        raise RuntimeError('unfinished VM state retained for inspection: ' + str(state))
    entries = archive_entries(source)
    for name in ('dev', 'proc', 'run', 'sys', 'tmp'):
        entries.setdefault(name, (0o40755, b''))
    descriptor, temporary = tempfile.mkstemp(prefix='pending-', suffix='.ext2', dir=state)
    os.close(descriptor)
    temporary = Path(temporary)
    create_disk(temporary, entries)
    with temporary.open('r+b') as output:
        os.fsync(output.fileno())
    record = dict(version=1, disk='root.ext2', disk_bytes=temporary.stat().st_size,
                  initial_disk_sha256=digest(temporary), initial_rootfs_sha256=digest(source))
    # Exclusive links publish fresh names; a pre-existing disk or manifest is
    # never replaced, even if an external writer ignores the advisory lock.
    os.link(temporary, disk)
    temporary.unlink()
    with manifest.open('x') as output:
        json.dump(record, output, indent=2)
        output.write('\n')
        output.flush()
        os.fsync(output.fileno())
    directory = os.open(state, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(directory)
    finally:
        os.close(directory)
    return disk, True


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--state-directory', type=Path, default=ROOT / '.local/vm')
    parser.add_argument('--serial', action='store_true', help='hide the graphical QEMU window')
    parser.add_argument('--firmware', choices=('bios', 'uefi'), default='bios')
    parser.add_argument('--prepare-only', action='store_true')
    args = parser.parse_args()
    state = args.state_directory.resolve()
    state.mkdir(parents=True, exist_ok=True, mode=0o700)
    descriptor = os.open(state / 'lock', os.O_RDWR | os.O_CREAT | os.O_CLOEXEC | os.O_NOFOLLOW, 0o600)
    with os.fdopen(descriptor, 'r+b') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        regular(state / 'lock')
        disk, created = prepare(state, ROOT / 'build/rootfs.cpio')
        if args.prepare_only:
            print(json.dumps(dict(disk=str(disk), created=created)))
            return
        bootstrap(ROOT / 'build/rootfs-bootstrap.cpio')
        subprocess.run(['python3', 'scripts/image.py', '--root-device', '/dev/vda',
                        '--output-name', 'axiom64-vm.iso'], cwd=ROOT, check=True)
        command = ['qemu-system-x86_64', '-machine', 'pc', '-cpu', 'max', '-m', '2G',
                   '-cdrom', str(ROOT / 'build/axiom64-vm.iso'), '-serial', 'stdio', '-no-reboot',
                   '-drive', 'if=none,id=root,format=raw,cache=writeback,file=' + str(disk),
                   '-device', 'virtio-blk-pci,drive=root,disable-legacy=on,rerror=report,werror=report']
        if args.serial:
            command += ['-display', 'none']
        if args.firmware == 'uefi':
            variables = state / 'OVMF_VARS_4M.fd'
            if not variables.exists():
                with variables.open('xb') as output, Path('/usr/share/OVMF/OVMF_VARS_4M.fd').open('rb') as source:
                    shutil.copyfileobj(source, output)
            regular(variables)
            command += ['-drive', 'if=pflash,format=raw,readonly=on,file=/usr/share/OVMF/OVMF_CODE_4M.fd',
                        '-drive', 'if=pflash,format=raw,file=' + str(variables)]
        print('Using persistent VM disk: ' + str(disk), flush=True)
        # Keep the host lock for the entire VM lifetime, including failed boots.
        process = subprocess.Popen(command, cwd=ROOT)
        try:
            status = process.wait()
        finally:
            if process.poll() is None:
                process.terminate()
                try:
                    process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait()
        raise SystemExit(status)


if __name__ == '__main__':
    main()
