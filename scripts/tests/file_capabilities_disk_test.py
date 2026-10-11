# SPDX-License-Identifier: GPL-3.0-or-later
"""Compare the native mixed-layout EA reader with actual e2fsprogs exports."""
from pathlib import Path
import re
import struct
import sys
import tempfile
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from fetch import ROOT
from file_capabilities.common import debugfs, fsck, volume
from file_capabilities.disk import attributes, inode_offset


with tempfile.TemporaryDirectory(prefix='filecap-native-layout-', dir=ROOT / 'build') as temporary:
    output = Path(temporary)
    disk = output / 'mixed.img'
    volume(disk, block=2048, inode=256, capacity=8 * 1024 * 1024)
    source = output / 'payload'
    source.write_bytes(b'ordinary file payload\n')
    debugfs(disk, f'write "{source}" /file', write=True)
    expected = {'user.shared': b'original', 'user.é': b'utf8',
                'security.capability': struct.pack('<5I', 0x02000001, 2, 0, 0, 0),
                'security.opaque-extra': b'invisible'}
    for name, value in expected.items():
        source.write_bytes(value)
        debugfs(disk, f'ea_set -f "{source}" /file {name}', write=True)
    fsck(disk, output, 'mixed')
    raw = disk.read_bytes()
    number = int(re.search(r'Inode:\s+(\d+)', debugfs(disk, 'stat /file'))[1])
    values, header = attributes(raw, inode_offset(raw, number), allow_inline=True)
    assert header['layout'] == 'mixed' and header['references'] == 1
    keys = {(1 if name.startswith('user.') else 6, name.split('.', 1)[1].encode()): value
            for name, value in expected.items()}
    assert values == keys
    for name, value in expected.items():
        export = output / name
        debugfs(disk, f'ea_get -f "{export}" /file {name}')
        assert export.read_bytes() == value
    assert disk.read_bytes() == raw
print('FILECAP_NATIVE_DISK_READER_PASS actual_mixed_layout independently_exported=4 source_unchanged')
