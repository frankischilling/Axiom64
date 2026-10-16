# SPDX-License-Identifier: GPL-3.0-or-later
"""Classify real refused directory checks without modifying or repairing their disks."""
import gzip
from pathlib import Path
import struct
import subprocess
import sys
import tempfile

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from ext2_deleted_inode_test import directory_entries
from ext2_named_retirement_inspection import directory_retirement_findings, named_retirement_findings
from ext2_test import inode_offset


def checked(data):
    with tempfile.TemporaryDirectory(prefix='axiom64-directory-finding-') as name:
        disk = Path(name) / 'disk.raw'
        disk.write_bytes(data)
        process = subprocess.run(['e2fsck', '-f', '-n', str(disk)], capture_output=True, text=True, timeout=60)
        assert process.returncode == 4 and disk.read_bytes() == data
        return process.stdout+process.stderr


def rejected(data, text):
    try:
        named_retirement_findings(data, text)
    except (ValueError, struct.error, IndexError):
        return
    raise AssertionError('unproven directory retirement finding accepted')


def main():
    fixtures = Path(__file__).parent / 'fixtures'
    data = gzip.decompress((fixtures / 'ext2-named-directory-retirement.raw.gz').read_bytes())
    text = checked(data)
    result = named_retirement_findings(data, text)
    assert result['inodes'] == [20, 41] and result['blocks'] == [420]
    assert result['restored_names'] == [dict(name='g-ddf7c441df09912037b60d0ac8f2d736',
        directory='/build-static/db', parent=15, inode=20)]
    assert result['restored_parent_links'] == [dict(inode=15, before=4, after=5)]
    assert not result['repair_performed']
    before_decrement = bytearray(data)
    struct.pack_into('<H', before_decrement, inode_offset(data, 15)+26, 5)
    identified = named_retirement_findings(before_decrement, checked(before_decrement))
    assert identified['restored_parent_links'] == [dict(inode=15, before=5, after=5)]
    detached = bytearray(data)
    position, = [position for position, number, name in directory_entries(data, 15) if number == 20]
    struct.pack_into('<I', detached, position, 0)
    detached_text = checked(detached)
    identified = directory_retirement_findings(detached, detached_text)
    assert identified['restored_names'] == identified['restored_parent_links'] == []
    rejected(detached, detached_text)
    negatives = [(data, text.replace('g-ddf7c441df09912037b60d0ac8f2d736', 'other')),
                 (data, text.replace('/build-static/db (15)', '/wrong (15)')),
                 (data, text.replace('(15, counted=14)', '(15, counted=13)')),
                 (data, text.replace('group #0', 'group #1')),
                 (data, text + 'Unattached inode 24\n'),
                 (data, text + 'Free blocks count wrong.\nFix? no\n')]
    for number, field, width, value in ((20,20,4,0), (20,20,4,17), (20,26,2,1),
                                       (15,26,2,6), (20,32,4,0x10)):
        changed = bytearray(data)
        struct.pack_into('<I' if width == 4 else '<H', changed, inode_offset(data, number)+field, value)
        negatives.append((changed, text))
    changed = bytearray(data)
    up, = [position for position, number, name in directory_entries(data, 20) if name == b'..']
    struct.pack_into('<I', changed, up, 20)
    negatives.append((changed, text))
    for volume, findings in negatives:
        rejected(volume, findings)
    cleared = gzip.decompress((fixtures / 'ext2-cleared-named-directory.raw.gz').read_bytes())
    rejected(cleared, checked(cleared))
    print('EXT2_DIRECTORY_RETIREMENT_INSPECTION_PASS readonly_actual_checkers=4 negative_cases=' + str(len(negatives)+2))


if __name__ == '__main__':
    main()
