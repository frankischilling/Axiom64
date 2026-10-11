# SPDX-License-Identifier: GPL-3.0-or-later
"""Test real file-capability exec on RAM and ext2, then boot the stored files again."""
import argparse
from pathlib import Path
import shutil
import sys
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from fetch import ROOT
from file_capabilities.common import boot, image, prepare, save, snapshot, volume
from file_capabilities.disk import verify_persist

FORMATS = ((1024, 128, 'default'), (2048, 256, 'default'),
           (4096, 256, 'default'), (1024, 128, 'original'))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, default=ROOT / 'build/file-capabilities/guest')
    parser.add_argument('--firmware', choices=('bios', 'uefi', 'both'), default='both')
    parser.add_argument('--transport', choices=('modern', 'legacy', 'both'), default='both')
    parser.add_argument('--linkage', choices=('static', 'dynamic', 'both'), default='both')
    parser.add_argument('--format', choices=('all', 'default', 'original'), default='all')
    parser.add_argument('--filesystem', choices=('ram', 'ext2', 'both'), default='both')
    args = parser.parse_args()
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=False)
    prepare()
    snapshot(output)
    rows = []
    for linkage in ('static', 'dynamic') if args.linkage == 'both' else (args.linkage,):
        for filesystem in ('ram', 'ext2') if args.filesystem == 'both' else (args.filesystem,):
            formats = [None] if filesystem == 'ram' else [entry for entry in FORMATS
                        if args.format == 'all' or entry[2] == args.format]
            for form in formats:
                suffix = '-'.join(map(str, form)) if form else 'memory'
                base = f'{linkage}-{filesystem}-{suffix}'
                if form:
                    script = ('/bin/busybox mount -t ext2 /dev/vda /tmp\n'
                              'export FILECAP_MOUNT_TARGET=/tmp\nexport FILECAP_PERSIST_DIR=/tmp/filecap-persisted\n'
                              f'export FILECAP_EXT2_BLOCK_SIZE={form[0]}\n')
                else:
                    script = 'export FILECAP_SHARED_MAPPING=1\nexport FILECAP_MOUNT_TARGET=/\n'
                script += '/bin/file-capabilities-tests\n/bin/busybox sync\n'
                if form:
                    script += '/bin/busybox umount /tmp\n'
                iso = image(output, base + '-write', linkage, script)
                reboot_iso = image(output, base + '-reboot', linkage,
                    '/bin/busybox mount -t ext2 /dev/vda /tmp\n'
                    '/bin/file-capabilities-tests --verify-persist /tmp/filecap-persisted\n'
                    '/bin/busybox sync\n/bin/busybox umount /tmp\n') if form else None
                for firmware in ('bios', 'uefi') if args.firmware == 'both' else (args.firmware,):
                    for transport in ('modern', 'legacy') if args.transport == 'both' else (args.transport,):
                        label = f'{base}-{firmware}-{transport}'
                        disk = output / (label + '.img') if form else None
                        if disk:
                            volume(disk, form[0], form[1], form[2] == 'original')
                        record = dict(linkage=linkage, filesystem=filesystem, format=form,
                                      write=boot(output, label + '-write', iso, disk, firmware, transport))
                        rows.append(record)
                        save(output / 'results.json', rows)
                        if disk:
                            record['host_write'] = verify_persist(disk, output, label + '-write', linkage)
                            shutil.copy2(disk, output / (label + '-after-write.img'))
                            record['reboot'] = boot(output, label + '-reboot', reboot_iso, disk, firmware, transport)
                            record['host_reboot'] = verify_persist(disk, output, label + '-reboot', linkage)
                            save(output / 'results.json', rows)
                        print('FILECAP_GUEST_PASS label=' + label, flush=True)


if __name__ == '__main__':
    main()
