#!/usr/bin/env python3
"""Populate an ext2 root from the same pinned files as the initramfs image."""
import argparse
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import stat
import subprocess
import tempfile
from fetch import ROOT


def archive_entries(source):
    data = source.read_bytes()
    at = 0
    entries = {}
    while at + 110 <= len(data):
        header = data[at:at + 110]
        if header[:6] != b'070701':
            raise RuntimeError('invalid newc header')
        values = [int(header[6 + i * 8:14 + i * 8], 16) for i in range(13)]
        mode, length, name_length = values[1], values[6], values[11]
        if not name_length or at + 110 + name_length > len(data):
            raise RuntimeError('invalid newc name length')
        name = data[at + 110:at + 110 + name_length]
        if name[-1:] != b'\0':
            raise RuntimeError('unterminated newc name')
        name = name[:-1].decode()
        content = (at + 110 + name_length + 3) & ~3
        if length > len(data) - content:
            raise RuntimeError('truncated newc content')
        if name == 'TRAILER!!!':
            if mode or length or any(data[(content + 3) & ~3:]):
                raise RuntimeError('invalid newc trailer or trailing data')
            return entries
        path = PurePosixPath(name)
        if (path.is_absolute() or '..' in path.parts or path.as_posix() != name or
                any(ord(character) < 32 for character in name) or
                '\\' in name or name in entries or not path.parts):
            raise RuntimeError('unsafe or duplicate newc path: ' + name)
        if stat.S_IFMT(mode) not in (stat.S_IFDIR, stat.S_IFREG, stat.S_IFLNK):
            raise RuntimeError('unsupported root fixture type: ' + name)
        if stat.S_ISDIR(mode) and length:
            raise RuntimeError('root fixture directory has content: ' + name)
        entries[name] = (mode, data[content:content + length])
        at = (content + length + 3) & ~3
    raise RuntimeError('newc trailer missing')


def populate(stage, entries):
    for name, (mode, _) in entries.items():
        for parent in PurePosixPath(name).parents:
            if str(parent) != '.' and (str(parent) not in entries or
                                        not stat.S_ISDIR(entries[str(parent)][0])):
                raise RuntimeError('non-directory root fixture parent: ' + name)
    ordered = sorted(entries, key=lambda name: (len(PurePosixPath(name).parts), name))
    for name in ordered:
        mode, _ = entries[name]
        if stat.S_ISDIR(mode):
            (stage / name).mkdir()
    for name in ordered:
        mode, data = entries[name]
        destination = stage / name
        if stat.S_ISREG(mode):
            destination.write_bytes(data)
        elif stat.S_ISLNK(mode):
            destination.symlink_to(data.decode())
        if not stat.S_ISLNK(mode):
            destination.chmod(stat.S_IMODE(mode))
    # Apply timestamps after creating children, which change directory timestamps.
    for name in ordered:
        os.utime(stage / name, (1700000000, 1700000000), follow_symlinks=False)
    os.utime(stage, (1700000000, 1700000000))


def bootstrap(destination):
    names = ['dev', 'proc', 'run', 'sys', 'tmp']
    with destination.open('wb') as output:
        for inode, name in enumerate(names + ['TRAILER!!!'], 1):
            encoded = name.encode() + b'\0'
            values = [inode, 0 if name == 'TRAILER!!!' else 0o40755,
                      0, 0, 1, 0, 0, 0, 0, 0, 0, len(encoded), 0]
            output.write(b'070701' + b''.join(f'{value:08x}'.encode() for value in values) + encoded)
            output.write(bytes(-output.tell() % 4))


def build(profile='full', verify_reproducible=False):
    source = ROOT / 'build' / ('rootfs.cpio' if profile == 'full' else 'rootfs-desktop.cpio')
    entries = archive_entries(source)
    for name in ['dev', 'proc', 'run', 'sys', 'tmp']:
        entries.setdefault(name, (0o40755, b''))
    for name in ['mnt', 'mnt/data']:
        entries.setdefault(name, (0o40755, b''))
    length = sum(len(data) for mode, data in entries.values() if stat.S_ISREG(mode))
    unit = 64 * 1024 * 1024
    capacity = max(256 * 1024 * 1024, ((length * 2 + unit + unit - 1) // unit) * unit)
    destination = ROOT / 'build' / ('root-disk.raw' if profile == 'full' else 'root-disk-desktop.raw')
    environment = dict(os.environ, E2FSPROGS_FAKE_TIME='1700000000')
    def populate_image(destination):
        with tempfile.TemporaryDirectory(prefix='axiom64-disk-root-') as temporary:
            stage = Path(temporary)
            populate(stage, entries)
            command = ['mke2fs', '-q', '-F', '-t', 'ext2', '-b', '4096', '-I', '128',
                        '-O', 'none,filetype,sparse_super,large_file',
                        '-N', str(len(entries) + 4096), '-U', 'ba24cd46-6712-49c5-8615-82ea1e0c7546',
                        '-E', 'hash_seed=ba24cd46-6712-49c5-8615-82ea1e0c7546,lazy_itable_init=0,root_owner=0:0',
                        '-d', str(stage)]
            with destination.open('wb') as output:
                output.truncate(capacity)
            subprocess.run(command + [str(destination)], env=environment, check=True)
        # mke2fs imports host uid/gid and ctime. Normalize those independently
        # of the staging user and the time this fixture is rebuilt.
        commands = []
        for name in ['/', '/lost+found', *('/' + name for name in sorted(entries))]:
            for field, value in [('uid', 0), ('gid', 0), ('ctime', 1700000000)]:
                commands.append(f'set_inode_field {json.dumps(name)} {field} {value}')
        subprocess.run(['debugfs', '-w', '-f', '-', str(destination)],
                       input='\n'.join(commands) + '\n', text=True,
                       env=environment, check=True, capture_output=True)
    populate_image(destination)
    if verify_reproducible:
        duplicate = destination.with_suffix('.reproducible.raw')
        populate_image(duplicate)
        def digest(path):
            with path.open('rb') as source:
                return hashlib.file_digest(source, 'sha256').hexdigest()
        if digest(destination) != digest(duplicate):
            raise RuntimeError('ext2 root fixture is not reproducible')
        duplicate.unlink()
        print('DISK_ROOT_FIXTURE_REPRODUCIBLE_PASS', flush=True)
    bootstrap(ROOT / 'build/rootfs-bootstrap.cpio')
    subprocess.run(['e2fsck', '-f', '-n', str(destination)], check=True)
    print(f'Disk root: {len(entries)} entries, {capacity} bytes, {destination}', flush=True)
    return destination


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--profile', choices=['full', 'desktop'], default='full')
    parser.add_argument('--verify-reproducible', action='store_true')
    args = parser.parse_args()
    build(args.profile, args.verify_reproducible)
