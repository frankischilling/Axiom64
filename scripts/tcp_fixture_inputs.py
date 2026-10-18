# SPDX-License-Identifier: GPL-3.0-or-later
"""Open actual controlled TCP boot fixtures and verify their executable inputs."""
from pathlib import Path
import hashlib
import subprocess
import tempfile
from fetch import LOCK
from disk_root import archive_entries


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def require(value, message):
    if not value:
        raise ValueError(message)


def audit_image(inputs, input_root, program, profile):
    linkage = inputs['linkage']
    image = input_root / f'build/axiom64-{profile}-{linkage}.iso'
    require(f'build/{image.name}' in inputs['products'], 'actual controlled TCP boot image is fingerprinted')
    with tempfile.TemporaryDirectory(prefix='axiom64-malformed-image-audit-') as temporary:
        directory = Path(temporary)
        subprocess.run(['xorriso', '-osirrox', 'on', '-indev', str(image),
                        '-extract', '/boot/axiom64.elf', str(directory / 'kernel'),
                        '-extract', '/boot/rootfs.cpio', str(directory / 'root.cpio')],
                       check=True, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
        require(digest(directory / 'kernel') == inputs['products']['build/axiom64.elf'],
                'actual ISO contains the fingerprinted running kernel')
        entries = archive_entries(directory / 'root.cpio')
    products = {'sbin/init': 'build/init', f'bin/{program}': f'build/{program}-{linkage}',
                'bin/busybox': f'build/busybox-{LOCK["busybox"]["version"]}/busybox'}
    for name, product in products.items():
        require(name in entries and entries[name][0] == 0o100755 and
                hashlib.sha256(entries[name][1]).hexdigest() == inputs['products'][product],
                f'actual ISO contains the exact executable: {name}')
    # The shared fixture selects build_musl.loader() with its build-provider default.
    loaders = [fingerprint for name, fingerprint in inputs['products'].items()
               if '/build/' in name and name.endswith('/ld-musl-x86_64.so.1')]
    require(len(loaders) == 1 and entries['lib/ld-musl-x86_64.so.1'][0] == 0o100755 and
            hashlib.sha256(entries['lib/ld-musl-x86_64.so.1'][1]).hexdigest() == loaders[0],
            'actual ISO contains the recorded build-provider musl loader')
    require(entries['etc/net-test.sh'] == (0o100755,
            f'#!/bin/sh\nset -e\n/bin/{program}\necho AXIOM64_TESTS_PASS\n'.encode()),
            'actual boot script executes the exact controlled TCP socket client')
    return dict(image=image.name, sha256=digest(image), actual_image_opened=True)
