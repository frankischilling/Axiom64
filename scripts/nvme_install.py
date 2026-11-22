#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
# @file    scripts/nvme_install.py
# @brief   Package and install an Axiom64 NVMe disk image.
# @author  frankischilling
# @date    2026-11-22
#
# Keeps the boot partitions and both GPT copies at their original offsets.
#
# Copyright (C) 2026 frankischilling
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program. If not, see <https://gnu.org/licenses/>.

"""Transfer an installed image without sending its unused disk space."""
import argparse
from contextlib import contextmanager
import errno
import fcntl
import gzip
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import struct
import subprocess
import tempfile


SECTOR = 512
GPT_TAIL = 33 * SECTOR
GPT_HEAD = 34 * SECTOR
CHUNK = 256 * 1024
MAGIC = b'AXNVME01'
HEADER = struct.Struct('<8sQQ')
PARTITIONS = ('BIOS', 'AXIOM64', 'AXIOM64_ROOT')
BLKGETSIZE64 = 0x80081272
BLKSSZGET = 0x1268
BLKROGET = 0x125e


@contextmanager
def regular_file(path):
    with os.fdopen(os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK), 'rb') as stream:
        if not stat.S_ISREG(os.fstat(stream.fileno()).st_mode):
            raise ValueError('the image must be a regular file')
        yield stream


def chunks(read, size):
    while size:
        data = read(min(size, CHUNK))
        if not data:
            raise ValueError('unexpected end of image')
        size -= len(data)
        yield data


def geometry(capacity, prefix):
    if (capacity >= 1 << 63 or capacity % SECTOR or prefix % SECTOR or
            not GPT_HEAD < prefix <= capacity - GPT_TAIL):
        raise ValueError('invalid disk image geometry')


def pack(image, output):
    with regular_file(image) as source:
        fd = source.fileno()
        descriptor = f'/proc/self/fd/{fd}'
        subprocess.run(['sfdisk', '--verify', descriptor], pass_fds=(fd,), check=True)
        table = json.loads(subprocess.check_output(['sfdisk', '--json', descriptor],
                                                  pass_fds=(fd,)))['partitiontable']
        parts = table['partitions']
        if (table['label'] != 'gpt' or table['sectorsize'] != SECTOR or
                tuple(part.get('name') for part in parts) != PARTITIONS):
            raise ValueError('expected an installed Axiom64 GPT image')
        capacity = os.fstat(fd).st_size
        prefix = max(part['start'] + part['size'] for part in parts) * SECTOR
        geometry(capacity, prefix)
        if table['lastlba'] + 1 != (capacity - GPT_TAIL) // SECTOR:
            raise ValueError('the backup GPT must use the last 33 sectors')
        with tempfile.NamedTemporaryFile(dir=output.parent, prefix='.nvme-install-') as temporary:
            with gzip.GzipFile(fileobj=temporary, filename='', mode='wb', mtime=0) as compressed:
                compressed.write(HEADER.pack(MAGIC, capacity, prefix))
                for offset, size in ((0, prefix), (capacity - GPT_TAIL, GPT_TAIL)):
                    source.seek(offset)
                    for data in chunks(source.read, size):
                        compressed.write(data)
            temporary.flush()
            temporary.seek(0)
            digest = hashlib.file_digest(temporary, 'sha256').hexdigest()
            os.fsync(temporary.fileno())
            os.link(temporary.name, output)
    print(f'{digest}  {output}')


@contextmanager
def target_device(path, write=False):
    match = re.fullmatch(r'/dev/(nvme[0-9]+)n[1-9][0-9]*', path)
    if not match:
        raise ValueError('choose a whole NVMe device such as /dev/nvme0n1')
    flags = os.O_RDWR if write else os.O_RDONLY
    fd = os.open(path, flags | os.O_EXCL | os.O_NOFOLLOW)
    try:
        status = os.fstat(fd)
        if not stat.S_ISBLK(status.st_mode) or os.major(status.st_rdev) != 259:
            raise ValueError('the target must be an NVMe block device')
        number = str(os.major(status.st_rdev)), str(os.minor(status.st_rdev))
        with open('/proc/partitions', encoding='ascii') as partitions:
            if not any(len(fields) == 4 and tuple(fields[:2]) == number and
                       fields[3] == os.path.basename(path)
                       for fields in map(str.split, partitions)):
                raise ValueError('the device node does not match the kernel partition list')
        try:
            duplicate = os.open(path, os.O_RDONLY | os.O_EXCL | os.O_NOFOLLOW)
        except OSError as error:
            if error.errno != errno.EBUSY:
                raise
        else:
            os.close(duplicate)
            raise ValueError('the kernel did not reserve the target for exclusive access')
        controller = Path('/sys/class/nvme', match[1])
        serial = (controller / 'serial').read_text(encoding='ascii').strip()
        model = (controller / 'model').read_text(encoding='ascii').strip()
        if not serial or not model:
            raise ValueError('the NVMe controller reported an empty identity')
        yield fd, dict(serial=serial, model=model,
                       disk_bytes=struct.unpack('=Q', fcntl.ioctl(fd, BLKGETSIZE64, bytes(8)))[0],
                       sector_bytes=struct.unpack('=I', fcntl.ioctl(fd, BLKSSZGET, bytes(4)))[0],
                       read_only=bool(struct.unpack('=I', fcntl.ioctl(fd, BLKROGET, bytes(4)))[0]))
    finally:
        os.close(fd)


def checked_bundle(source, sha256):
    if hashlib.file_digest(source, 'sha256').hexdigest() != sha256:
        raise ValueError('install bundle SHA-256 does not match')
    source.seek(0)
    with gzip.GzipFile(fileobj=source) as stream:
        magic, capacity, prefix = HEADER.unpack(stream.read(HEADER.size))
        if magic != MAGIC:
            raise ValueError('unrecognized Axiom64 install bundle')
        geometry(capacity, prefix)
        sizes = GPT_HEAD, prefix - GPT_HEAD, GPT_TAIL
        offsets = 0, GPT_HEAD, capacity - GPT_TAIL
        ranges = []
        for offset, size in zip(offsets, sizes):
            digest = hashlib.sha256()
            for data in chunks(stream.read, size):
                digest.update(data)
            ranges.append((offset, size, digest.digest()))
        if stream.read(1):
            raise ValueError('unexpected data after backup GPT')
    return capacity, ranges


def pwrite_all(fd, data, offset):
    remaining = memoryview(data)
    while remaining:
        done = os.pwrite(fd, remaining, offset)
        if done <= 0:
            raise OSError('disk write made no progress')
        offset += done
        remaining = remaining[done:]


def range_digest(fd, offset, size):
    def read(length):
        nonlocal offset
        data = os.pread(fd, length, offset)
        offset += len(data)
        return data

    digest = hashlib.sha256()
    for data in chunks(read, size):
        digest.update(data)
    return digest.digest()


def apply(args):
    with regular_file(args.bundle) as source:
        capacity, ranges = checked_bundle(source, args.sha256.lower())
        with target_device(args.target, args.write) as (fd, identity):
            print(json.dumps(dict(device=args.target, **identity)), flush=True)
            if (identity['model'] != args.model or identity['serial'] != args.serial or
                    identity['disk_bytes'] != capacity or identity['sector_bytes'] != SECTOR or
                    identity['read_only']):
                raise ValueError('NVMe identity or geometry does not match this install')
            print('The install replaces the partition table and overwrites the boot and root areas.', flush=True)
            if not args.write:
                print('Preview passed. The disk was opened read-only.')
                return
            source.seek(0)
            with gzip.GzipFile(fileobj=source) as stream:
                stream.seek(HEADER.size)
                primary = stream.read(GPT_HEAD)
                if hashlib.sha256(primary).digest() != ranges[0][2]:
                    raise ValueError('the install bundle changed during verification')
                for offset, size, expected in ranges[1:]:
                    digest = hashlib.sha256()
                    position = offset
                    for data in chunks(stream.read, size):
                        digest.update(data)
                        pwrite_all(fd, data, position)
                        position += len(data)
                    if digest.digest() != expected:
                        raise ValueError('the install bundle changed during the write')
                os.fsync(fd)
                pwrite_all(fd, primary, 0)
            os.fsync(fd)
            for offset, size, expected in ranges:
                if range_digest(fd, offset, size) != expected:
                    raise ValueError(f'NVMe read-back mismatch at byte {offset}')
    print('Axiom64 install written, flushed, and verified.')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest='command', required=True)
    create = commands.add_parser('pack', help='compress an installed raw disk for transfer')
    create.add_argument('image', type=Path)
    create.add_argument('output', type=Path)
    inspect = commands.add_parser('inspect', help='read identity and geometry from an unused NVMe disk')
    inspect.add_argument('target')
    install = commands.add_parser('apply', help='verify a bundle and target, then write if requested')
    install.add_argument('bundle', type=Path)
    install.add_argument('target')
    install.add_argument('--model', required=True)
    install.add_argument('--serial', required=True)
    install.add_argument('--sha256', required=True, metavar='DIGEST')
    install.add_argument('--write', action='store_true', help='overwrite the verified target')
    args = parser.parse_args()
    try:
        if args.command == 'pack':
            pack(args.image, args.output)
        elif args.command == 'inspect':
            with target_device(args.target) as (_, disk):
                print(json.dumps(dict(device=args.target, **disk)))
        else:
            apply(args)
    except (EOFError, OSError, ValueError, struct.error, subprocess.CalledProcessError) as error:
        parser.exit(1, f'{error}\n')


if __name__ == '__main__':
    main()
