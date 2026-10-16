# SPDX-License-Identifier: GPL-3.0-or-later
"""Admit only checker counter drift that exactly matches the retained allocation maps."""
import gzip
from pathlib import Path
import struct
import subprocess
import sys
import tempfile

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from ext2_counter_inspection import counter_findings
from account_logbook_rotation_ext2 import fsck
from fetch import ROOT


def main():
    raw = gzip.decompress((Path(__file__).parent / 'fixtures/ext2-counter-drift.raw.gz').read_bytes())
    (ROOT / 'build').mkdir(exist_ok=True)
    with tempfile.TemporaryDirectory(prefix='counter-inspection-', dir=ROOT / 'build') as temporary:
        disk = Path(temporary) / 'disk.raw'
        disk.write_bytes(raw)
        check = subprocess.run(['e2fsck', '-f', '-n', str(disk)], capture_output=True, text=True, timeout=60)
        # Some checker versions return zero despite these refused corrections.
        assert check.returncode in (0, 4) and disk.read_bytes() == raw
        text = check.stdout + check.stderr
        result = counter_findings(raw, text)
        assert result['groups'] == 2 and result['counters'] == [
            dict(kind='blocks', group=None, stored=15710, counted=15709),
            dict(kind='inodes', group=None, stored=4073, counted=4072)]
        admitted = fsck(disk, Path(temporary), 'pending', pending_recovery=True)
        assert not admitted['passed'] and admitted['expected_checked_recovery'] == result
        try:
            fsck(disk, Path(temporary), 'strict')
        except RuntimeError:
            pass
        else:
            raise AssertionError('incorrect counters passed the strict checker')
        assert disk.read_bytes() == raw
        negatives = [(raw, text.replace('counted=15709', 'counted=15708')),
                     (raw, text.replace('Free inodes count wrong (4073, counted=4072).\n', '')),
                     (raw, text + 'Inode bitmap differences: -17\nFix? no\n'),
                     (raw, text + 'Unattached inode 17\n'),
                     (raw, text + 'Free blocks count wrong (15710, counted=15709).\n')]
        for offset, value, code in ((1082, 1, '<H'), (1036, 16385, '<I'),
                                    (1048, 3, '<I'), (1064, 0, '<I')):
            changed = bytearray(raw)
            struct.pack_into(code, changed, offset, value)
            negatives.append((changed, text))
        for data, report in negatives:
            try:
                counter_findings(data, report)
            except (ValueError, struct.error, IndexError):
                continue
            raise AssertionError('unproven counter recovery admitted')
    print('EXT2_COUNTER_INSPECTION_PASS actual_readonly_checker=1 negative_cases=' + str(len(negatives)))


if __name__ == '__main__':
    main()
