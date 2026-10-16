# SPDX-License-Identifier: GPL-3.0-or-later
"""Retain an owned disk fixture with independently verified decompressed bytes."""
import gzip
import hashlib
from pathlib import Path
import stat

from fetch import ROOT


def fingerprint(path):
    with path.open('rb') as stream:
        return dict(bytes=path.stat().st_size, sha256=hashlib.file_digest(stream, 'sha256').hexdigest())


def archive_fixture(path, remove=False, owned_root=None):
    path = Path(path)
    root = Path(owned_root or ROOT / 'build').resolve()
    if path.is_symlink() or not path.resolve().is_relative_to(root):
        raise RuntimeError('fixture archive source must be inside the owned build directory')
    original = path.stat()
    if not stat.S_ISREG(original.st_mode) or original.st_nlink != 1:
        raise RuntimeError('fixture archive source must be a single-link regular file')
    expected = fingerprint(path)
    destination = path.with_name(path.name + '.gz')
    if destination.resolve().parent != path.resolve().parent:
        raise RuntimeError('fixture archive destination must remain beside its source')
    with path.open('rb') as source, destination.open('xb') as output:
        with gzip.GzipFile(filename='', mode='wb', compresslevel=1, fileobj=output, mtime=0) as packed:
            while chunk := source.read(1024 * 1024):
                packed.write(chunk)
    with gzip.open(destination, 'rb') as stream:
        actual = hashlib.sha256()
        size = 0
        while chunk := stream.read(1024 * 1024):
            actual.update(chunk)
            size += len(chunk)
    if dict(bytes=size, sha256=actual.hexdigest()) != expected:
        raise RuntimeError('fixture archive does not reproduce the original bytes')
    current = path.stat()
    if (current.st_dev, current.st_ino, current.st_size, current.st_mtime_ns) != (
            original.st_dev, original.st_ino, original.st_size, original.st_mtime_ns):
        raise RuntimeError('fixture archive source changed during retention')
    record = dict(path=str(destination), original=expected, compressed=fingerprint(destination))
    if remove:
        if path.is_symlink() or not path.resolve().is_relative_to(root):
            raise RuntimeError('fixture archive cleanup target changed')
        path.unlink()
    return record
