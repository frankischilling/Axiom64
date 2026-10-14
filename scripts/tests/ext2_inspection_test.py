# SPDX-License-Identifier: GPL-3.0-or-later
"""Observe the whole volume and link targets without following exported host links."""
import os
from pathlib import Path
import sys
import tempfile

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from ext2_inspection import disk_files
from ext2_test import create_volume, debugfs
from fetch import ROOT


def main():
    (ROOT / 'build').mkdir(exist_ok=True)
    with tempfile.TemporaryDirectory(prefix='ext2-observation-', dir=ROOT / 'build') as temporary:
        directory = Path(temporary)
        disk = directory / 'disk.raw'
        create_volume(disk)
        trap = directory / 'host-only-data'
        trap.write_bytes(b'this data belongs only to the host fixture\n')
        debugfs(disk, 'mkdir /nested', True)
        payload = directory / 'payload'
        payload.write_bytes(b'guest named data\n')
        debugfs(disk, 'write ' + str(payload) + ' /nested/data', True)
        debugfs(disk, 'symlink /foreign ' + str(trap), True)
        debugfs(disk, 'symlink /dangling /axiom64-missing-observation-target', True)
        before = disk.read_bytes()
        files, metadata, directories = disk_files(disk, metadata=True)
        assert files == {'seed.txt': b'host-created seed\n', 'nested/data': payload.read_bytes(),
                         'foreign': os.fsencode(trap), 'dangling': b'/axiom64-missing-observation-target'}
        assert set(directories) == {'.', 'nested', 'lost+found'}
        assert set(metadata) == set(directories) | set(files)
        assert metadata['foreign']['kind'] == metadata['dangling']['kind'] == 'symlink'
        assert metadata['nested/data']['kind'] == 'regular'
        assert all(record['inode'] > 0 for record in metadata.values())
        selected, selected_metadata, selected_directories = disk_files(disk, root='/nested', metadata=True)
        assert selected == {'data': payload.read_bytes()} and selected_directories == ['.']
        assert selected_metadata['data'] == metadata['nested/data']
        assert disk.read_bytes() == before, 'offline observation modified the volume'
    print('EXT2_INSPECTION_PASS whole_volume=1 isolated_tree=1 link_targets=2 disk_unchanged=1')


if __name__ == '__main__':
    main()
