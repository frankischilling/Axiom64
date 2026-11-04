# SPDX-License-Identifier: GPL-3.0-or-later
"""Retain an owned disk fixture with independently verified decompressed bytes."""
import gzip
import hashlib
import subprocess
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


def owned_fixture(path, root):
    path = Path(path)
    if path.is_symlink() or not path.resolve().is_relative_to(root):
        raise RuntimeError('fixture must remain inside its owned build directory')
    info = path.stat()
    if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
        raise RuntimeError('fixture must be a single-link regular file')
    return info


def unchanged_fixture(path, original, root):
    current = owned_fixture(path, root)
    fields = ('st_dev', 'st_ino', 'st_size', 'st_mtime_ns', 'st_ctime_ns', 'st_mode', 'st_uid', 'st_gid')
    if any(getattr(current, field) != getattr(original, field) for field in fields):
        raise RuntimeError('fixture changed during storage verification')


def sparse_copy_fixture(source, destination, owned_root=None):
    """Copy all disk bytes while retaining holes and independent write ownership."""
    root = Path(owned_root or ROOT / 'build').resolve()
    source, destination = Path(source), Path(destination)
    original = owned_fixture(source, root)
    if destination.is_symlink() or destination.exists() or not destination.resolve().is_relative_to(root):
        raise RuntimeError('fixture copy requires a fresh owned destination')
    expected = fingerprint(source)
    subprocess.run(['cp', '--sparse=always', '--reflink=auto', '--no-clobber', '--',
                    str(source), str(destination)], check=True)
    copied = owned_fixture(destination, root)
    if fingerprint(destination) != expected:
        raise RuntimeError('fixture copy changed the original bytes')
    unchanged_fixture(source, original, root)
    unchanged_fixture(destination, copied, root)
    return dict(source=str(source), path=str(destination), original=expected,
                allocated_bytes=copied.st_blocks * 512)


def retire_duplicate_fixture(alias, retained, owned_root=None):
    """Unlink one owned alias only after verifying a separate retained copy."""
    root = Path(owned_root or ROOT / 'build').resolve()
    alias, retained = Path(alias), Path(retained)
    original, canonical = owned_fixture(alias, root), owned_fixture(retained, root)
    if (original.st_dev, original.st_ino) == (canonical.st_dev, canonical.st_ino):
        raise RuntimeError('fixture retirement requires a separate retained copy')
    expected = fingerprint(retained)
    if fingerprint(alias) != expected:
        raise RuntimeError('fixture alias differs from its retained copy')
    unchanged_fixture(alias, original, root)
    unchanged_fixture(retained, canonical, root)
    alias.unlink()
    return dict(original=str(alias), retained=str(retained), fingerprint=expected,
                retired_allocated_bytes=original.st_blocks * 512)
