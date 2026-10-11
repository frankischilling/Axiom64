# SPDX-License-Identifier: GPL-3.0-or-later
"""Exercise the upstream capability tools from both ordinary rootfs profiles."""
import argparse
from pathlib import Path
import shutil
import subprocess
import sys
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from fetch import ROOT
from file_capabilities.common import boot, prepare, save, snapshot
from file_capabilities.check import cpio


def fixture(output, profile):
    original = (ROOT / 'build' / ('rootfs.cpio' if profile == 'full' else 'rootfs-desktop.cpio')).read_bytes()
    files = cpio(original)
    if 'bin/file-capabilities-tests' in files:
        raise ValueError('ordinary image already contains a test override')
    shutil.copy2(ROOT / 'build' / ('rootfs.cpio' if profile == 'full' else 'rootfs-desktop.cpio'),
                 output / (profile + '-original.cpio'))
    at, parts = 0, []
    while original[at:at + 6] == b'070701':
        size = int(original[at + 54:at + 62], 16)
        length = int(original[at + 94:at + 102], 16)
        start = at + 110
        name = original[start:start + length - 1]
        if name == b'TRAILER!!!':
            break
        end = ((((start + length + 3) & ~3) + size) + 3) & ~3
        if name != b'etc/net-test.sh':
            parts.append(original[at:end])
        at = end
    else:
        raise ValueError('ordinary rootfs archive has no trailer')
    archive = ROOT / 'build/rootfs-network.cpio'
    previous = archive.read_bytes() if archive.exists() else None
    try:
        with archive.open('wb') as stream:
            stream.write(b''.join(parts))
            additions = [('bin/file-capabilities-tests', (ROOT / 'build/file-capabilities-dynamic').read_bytes()),
                         ('etc/net-test.sh', b'#!/bin/sh\nset -e\n/bin/file-capabilities-tests --installed-tools\necho AXIOM64_TESTS_PASS\n'),
                         ('TRAILER!!!', b'')]
            for inode, (name, data) in enumerate(additions, len(files) + 1):
                encoded = name.encode() + b'\0'
                fields = [inode, 0o100755, 0, 0, 1, 0, len(data), 0, 0, 0, 0, len(encoded), 0]
                stream.write(b'070701' + b''.join(f'{value:08x}'.encode() for value in fields) + encoded)
                stream.write(bytes(-stream.tell() % 4))
                stream.write(data)
                stream.write(bytes(-stream.tell() % 4))
        name = f'axiom64-filecap-installed-dynamic-{profile}.iso'
        shutil.copy2(archive, output / (profile + '.cpio'))
        with (output / (profile + '-image.log')).open('wb') as stream:
            subprocess.run(['python3', 'scripts/image.py', '--test', '--suite', 'network', '--output-name', name],
                           cwd=ROOT, check=True, stdout=stream, stderr=subprocess.STDOUT)
        shutil.copy2(ROOT / 'build' / name, output / name)
        return output / name
    finally:
        if previous is None:
            archive.unlink(missing_ok=True)
        else:
            archive.write_bytes(previous)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, default=ROOT / 'build/file-capabilities/installed')
    args = parser.parse_args()
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=False)
    prepare()
    subprocess.run(['make', '-s', 'build/rootfs.cpio', 'build/rootfs-desktop.cpio'], cwd=ROOT, check=True)
    snapshot(output)
    results = []
    for profile in ('full', 'desktop'):
        iso = fixture(output, profile)
        for firmware in ('bios', 'uefi'):
            results.append(dict(kind='installed', profile=profile,
                                boot=boot(output, f'installed-{profile}-{firmware}', iso, firmware=firmware, memory='2G')))
            save(output / 'results.json', results)


if __name__ == '__main__':
    main()
