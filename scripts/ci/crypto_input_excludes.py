#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""List generated crypto paths outside the completed-provider cache contract."""
from pathlib import Path, PurePosixPath

from crypto_cache import cache_paths


def excluded(parent, selectors):
    for entry in sorted(parent.iterdir()):
        matching = [parts[1:] for parts in selectors if parts[0] in ('*', entry.name)]
        if not matching:
            name = entry.as_posix()
            if '\n' in name or '\r' in name:
                raise ValueError(f'line break in generated crypto path: {name!r}')
            yield './' + name
        elif all(matching):
            if entry.is_symlink() or not entry.is_dir():
                raise ValueError(f'crypto cache ancestor is not a directory: {entry}')
            yield from excluded(entry, matching)


if __name__ == '__main__':
    patterns = [PurePosixPath(name).parts for name in cache_paths()]
    for dependency in ('openssl', 'curl'):
        root = Path('build') / dependency
        if root.is_symlink():
            raise ValueError(f'crypto cache root is a symbolic link: {root}')
        if root.exists():
            selectors = [parts[2:] for parts in patterns if parts[:2] == root.parts]
            for name in excluded(root, selectors):
                print(name)
