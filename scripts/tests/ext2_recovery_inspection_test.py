# SPDX-License-Identifier: GPL-3.0-or-later
"""Keep dirty-volume admission tied to an actual retired-inode allocation finding."""
import gzip
from pathlib import Path
import struct
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from ext2_recovery_inspection import deleted_allocation_findings
from ext2_test import inode_offset


def main():
    data = gzip.decompress((Path(__file__).parent / 'fixtures/ext2-deleted-open-inode.raw.gz').read_bytes())
    text = ('e2fsck 1.47.0 (5-Feb-2023)\nPass 1: Checking inodes, blocks, and sizes\n'
            'Pass 2: Checking directory structure\nPass 3: Checking directory connectivity\n'
            'Pass 4: Checking reference counts\nPass 5: Checking group summary information\n'
            'Block bitmap differences:  -(342--343) -(345--346)\nFix? no\n\n'
            'Inode bitmap differences:  -17\nFix? no\n\n'
            'fixture: ********** WARNING: Filesystem still has errors **********\n\n'
            'fixture: 31/4096 files (3.2% non-contiguous), 686/16384 blocks\n')
    result = deleted_allocation_findings(data, text)
    assert result['inodes'] == [17] and result['blocks'] == [342, 343, 345, 346]
    negatives = [(data, text.replace('-17', '+17')),
                 (data, text.replace('-(345--346)', '-345')),
                 (data, text + 'Free blocks count wrong.\nFix? no\n'),
                 (data, text + 'Unattached inode 24\n'),
                 (data, text.replace('-17', '-2'))]
    inode = inode_offset(data, 17)
    changed = bytearray(data)
    struct.pack_into('<I', changed, inode + 20, 0)
    negatives.append((changed, text))
    changed = bytearray(data)
    struct.pack_into('<H', changed, inode + 26, 1)
    negatives.append((changed, text))
    for offset, value in ((1048, 3), (1024, len(data)), (1056, 0), (1064, 0)):
        changed = bytearray(data)
        struct.pack_into('<I', changed, offset, value)
        negatives.append((changed, text))
    for volume, findings in negatives:
        try:
            deleted_allocation_findings(volume, findings)
        except (ValueError, struct.error, IndexError):
            continue
        raise AssertionError('unproven pre-recovery finding accepted')
    print('EXT2_RECOVERY_INSPECTION_PASS actual_volume=1 negative_cases=' + str(len(negatives)))


if __name__ == '__main__':
    main()
