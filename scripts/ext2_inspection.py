# SPDX-License-Identifier: GPL-3.0-or-later
"""Read-only named-file exports independent of guest filesystem readers."""
import os
from pathlib import Path
import re
import stat
import tempfile

from ext2_test import debugfs


def disk_files(disk, *, root='/', metadata=False):
    with tempfile.TemporaryDirectory(prefix='axiom64-ext2-export-') as temporary:
        destination = Path(temporary)
        debugfs(disk, 'rdump ' + root + ' ' + str(destination))
        exported = destination / Path(root).name
        if not exported.exists():
            return {}, {}, []
        files, directories = {}, ['.']
        for path in exported.rglob('*'):
            name = path.relative_to(exported).as_posix()
            mode = path.lstat().st_mode
            if stat.S_ISREG(mode):
                files[name] = path.read_bytes()
            elif stat.S_ISLNK(mode):
                files[name] = os.fsencode(os.readlink(path))
            elif stat.S_ISDIR(mode):
                directories.append(name)
            else:
                raise ValueError('unsupported exported fixture type: ' + name)
        records = {}
        if metadata:
            for name in [*directories, *files]:
                text = debugfs(disk, 'stat ' + str(Path(root) / name))
                identity = re.search(r'Inode:\s+(\d+)', text)
                kind = re.search(r'Type:\s+(\S+)\s+Mode:\s+([0-7]+)', text)
                owners = re.search(r'User:\s+(\d+)\s+Group:\s+(\d+).*?Size:\s+(\d+)', text)
                links = re.search(r'Links:\s+(\d+)', text)
                if not all((identity, kind, owners, links)):
                    raise ValueError('incomplete offline fixture metadata: ' + name)
                records[name] = dict(inode=int(identity[1]), kind=kind[1], mode=int(kind[2], 8),
                                     uid=int(owners[1]), gid=int(owners[2]), bytes=int(owners[3]), links=int(links[1]))
        return files, records, directories
