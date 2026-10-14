# SPDX-License-Identifier: GPL-3.0-or-later
"""Use the actual refused native checker result; keep mismatched evidence red."""
import gzip
import hashlib
from pathlib import Path
import struct
import subprocess
import sys
import tempfile

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from ext2_named_retirement_inspection import named_retirement_findings
from ext2_recovery_inspection import deleted_allocation_findings
from ext2_test import inode_offset


def main():
    data = gzip.decompress((Path(__file__).parent / 'fixtures/ext2-named-retirement.raw.gz').read_bytes())
    assert hashlib.sha256(data).hexdigest() == '9561c8cd01f27dd7e606aa3b25c78678b550cfb1abf2296c09fde89027e92866'
    with tempfile.TemporaryDirectory(prefix='axiom64-named-retirement-') as temporary:
        disk = Path(temporary) / 'disk.raw'
        disk.write_bytes(data)
        process = subprocess.run(['e2fsck', '-f', '-n', str(disk)], capture_output=True, text=True, timeout=60)
        assert process.returncode == 4 and disk.read_bytes() == data
        text = process.stdout + process.stderr
    try:
        deleted_allocation_findings(data, text)
    except ValueError:
        pass
    else:
        raise AssertionError('the old detached-inode contract admitted a named inode')
    result = named_retirement_findings(data, text)
    assert result['inodes'] == [17] and result['blocks'] == [342, 343, 345, 346]
    assert result['restored_names'] == [dict(name='journal', directory='/rotation/records', parent=15, inode=17)]
    assert not result['repair_performed']
    negatives = [(data, text.replace("Entry 'journal'", "Entry 'other'")),
                 (data, text.replace('/rotation/records (15)', '/wrong (15)')),
                 (data, text.replace('/rotation/records (15)', '/rotation/records (14)')),
                 (data, text.replace('unused inode 17', 'unused inode 18')),
                 (data, text.replace('Clear? no', 'Clear? yes')),
                 (data, text.replace('-17', '+17')),
                 (data, text.replace('-(345--346)', '-345')),
                 (data, text + 'Unattached inode 31\n'),
                 (data, text + 'Free blocks count wrong.\nFix? no\n')]
    inode = inode_offset(data, 17)
    for field, value, width in ((20, 0, 4), (20, 14, 4), (26, 1, 2), (0, 0o120600, 2), (32, 0x10, 4)):
        changed = bytearray(data)
        struct.pack_into('<I' if width == 4 else '<H', changed, inode + field, value)
        negatives.append((changed, text))
    changed = bytearray(data)
    struct.pack_into('<H', changed, inode_offset(data, 2), 0)
    negatives.append((changed, text))
    for volume, findings in negatives:
        try:
            named_retirement_findings(volume, findings)
        except (ValueError, struct.error, IndexError):
            continue
        raise AssertionError('unproven named-retirement finding accepted')
    print('EXT2_NAMED_RETIREMENT_INSPECTION_PASS readonly_actual_checker=1 negative_cases=' + str(len(negatives)))


if __name__ == '__main__':
    main()
