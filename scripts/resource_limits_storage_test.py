#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Exercise file limits on real ext2 and inspect the guest's durable result."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import shutil
import subprocess

from account_store_guest import fixture
from ext2_test import create_volume, SEED
from fetch import ROOT
from fixture_archive import archive_fixture
from resource_limits_test import build, digest, execute, INPUTS


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--directory', type=Path, default=ROOT / 'build/resource-limits-storage')
    args = parser.parse_args()
    args.directory.mkdir(parents=True, exist_ok=False)
    names = [*INPUTS, 'scripts/resource_limits_storage_test.py', 'scripts/ext2_test.py',
             'scripts/fixture_archive.py',
             *(path.relative_to(ROOT).as_posix() for path in (ROOT / 'kernel').rglob('*')
               if path.is_file() and path.suffix in ('.cpp', '.hpp', '.asm'))]
    sources = {name: digest(ROOT / name) for name in names}
    (args.directory / 'source-inputs.json').write_text(json.dumps(sources, indent=2) + '\n')
    subprocess.run(['make', '-s', '-j2', 'build/axiom64.elf', 'build/init', 'busybox'], cwd=ROOT, check=True)
    rows = []
    for provider in ('build', 'runtime'):
        for linkage in ('static', 'dynamic'):
            case = args.directory / (provider + '-' + linkage)
            case.mkdir()
            program, inputs = build(provider, linkage, case)
            iso = fixture(case, provider, linkage, program_builder=lambda *unused: (program, inputs),
                          filename='resource-limits-test', command=(
                              '/bin/busybox mkdir -p /mnt/resource && '
                              '/bin/busybox mount -t ext2 /dev/vda /mnt/resource && '
                              'AXIOM64_RESOURCE_DIRECTORY=/mnt/resource /bin/resource-limits-test && '
                              '/bin/busybox umount /mnt/resource'))
            for firmware in ('bios', 'uefi'):
                for transport in ('modern', 'legacy'):
                    phase = case / (firmware + '-' + transport)
                    phase.mkdir()
                    disk = phase / 'disk.raw'
                    create_volume(disk)
                    command = ['qemu-system-x86_64', '-machine', 'pc', '-cpu', 'max', '-m', '256M',
                               '-nic', 'none', '-cdrom', str(iso), '-display', 'none', '-serial', 'stdio',
                               '-monitor', 'none', '-no-reboot',
                               '-device', 'isa-debug-exit,iobase=0xf4,iosize=0x04',
                               '-drive', 'if=none,id=data,format=raw,file=' + str(disk), '-device',
                               'virtio-blk-pci,drive=data,' + (
                                   'disable-legacy=on' if transport == 'modern' else 'disable-modern=on')]
                    if firmware == 'uefi':
                        variables = phase / 'VARS.fd'
                        shutil.copyfile('/usr/share/OVMF/OVMF_VARS_4M.fd', variables)
                        command += ['-drive', 'if=pflash,format=raw,readonly=on,file=/usr/share/OVMF/OVMF_CODE_4M.fd',
                                    '-drive', 'if=pflash,format=raw,file=' + str(variables)]
                    row = execute(command, phase / 'execution.log', firmware)
                    row.update(provider=provider, linkage=linkage, firmware=firmware, transport=transport,
                               inputs=inputs, products_sha256=digest(case / 'products.json'))
                    check = subprocess.run(['e2fsck', '-f', '-n', str(disk)], capture_output=True, timeout=60)
                    log = check.stdout + check.stderr
                    (phase / 'fsck.log').write_bytes(log)
                    row['fsck_returncode'] = check.returncode
                    row['passed'] &= check.returncode == 0 and not re.search(
                        rb'count wrong|Fix\?|Clear\?|still has errors|corrupt', log, re.IGNORECASE)
                    exports = {}
                    for filename, expected in (('resource-file-result', bytes(6) + b'01'), ('seed.txt', SEED)):
                        exported = subprocess.run(['debugfs', '-R', 'cat /' + filename, str(disk)],
                                                  capture_output=True, check=True)
                        (phase / (filename + '.export')).write_bytes(exported.stdout)
                        exports[filename] = dict(bytes=len(exported.stdout),
                            sha256=hashlib.sha256(exported.stdout).hexdigest(), matches=exported.stdout == expected)
                        row['passed'] &= exported.stdout == expected
                    metadata = subprocess.check_output(['debugfs', '-R', 'stat /resource-file-result', str(disk)])
                    (phase / 'result-inode.txt').write_bytes(metadata)
                    row['passed'] &= bool(re.search(rb'Mode:\s+0600', metadata) and
                                          re.search(rb'Size:\s+8\b', metadata) and re.search(rb'Links:\s+1\b', metadata))
                    row['native_exports'] = exports
                    row['retained_disk'] = archive_fixture(disk, remove=True)
                    rows.append(row)
                    (args.directory / 'results.json').write_text(json.dumps(rows, indent=2) + '\n')
                    if not row['passed']:
                        raise RuntimeError('resource-limit storage comparison failed: ' + str(phase))
                    print('RESOURCE_LIMIT_STORAGE_PASS ' + '/'.join(phase.relative_to(args.directory).parts), flush=True)
    assert sources == {name: digest(ROOT / name) for name in sources}, 'sources changed during validation'
    print('RESOURCE_LIMIT_STORAGE_MATRIX_PASS profiles=' + str(len(rows)), flush=True)


if __name__ == '__main__':
    main()
