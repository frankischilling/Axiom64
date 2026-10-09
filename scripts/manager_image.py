# SPDX-License-Identifier: GPL-3.0-or-later
"""Build isolated observer images with the production foreground managers."""
import json
from pathlib import Path
import subprocess
from fetch import ROOT, LOCK
from dhcp_peer import check


def fixture(linkage, scenario, affected, observer='manager-protocol'):
    check(observer in ('manager-protocol', 'manager-link'), 'known isolated manager observer')
    subprocess.run(['make', '-j2', 'build/axiom64.elf', 'build/init', 'busybox',
                    f'build/{observer}', 'build/network-manager',
                    'build/network-manager-dynamic'], cwd=ROOT, check=True)
    expected = json.loads((ROOT / 'sources.lock.json').read_text())['build_musl']['version']
    check(subprocess.check_output(['dpkg-query', '-W', '-f=${Version}', 'musl-dev'], text=True) == expected,
          'fixture uses the pinned musl build version')
    files = {name: (0o40755, b'') for name in
             ['bin', 'sbin', 'etc', 'dev', 'proc', 'sys', 'tmp', 'run', 'root', 'lib']}
    sources = [('sbin/init', ROOT / 'build/init'),
               ('bin/busybox', ROOT / 'build' / f"busybox-{LOCK['busybox']['version']}" / 'busybox'),
               (f'bin/{observer}', ROOT / 'build' / observer),
               ('sbin/network-manager', ROOT / 'build/network-manager'),
               ('sbin/network-manager-dynamic', ROOT / 'build/network-manager-dynamic'),
               ('lib/ld-musl-x86_64.so.1', Path('/lib/ld-musl-x86_64.so.1').resolve())]
    files.update({name: (0o100755, source.read_bytes()) for name, source in sources})
    binary = 'network-manager-dynamic' if linkage == 'dynamic' else 'network-manager'
    script = (f'#!/bin/sh\nset -e\n/bin/{observer} /sbin/{binary} {scenario} /tmp {affected}\n'
              'echo AXIOM64_TESTS_PASS\n')
    files['etc/net-test.sh'] = (0o100755, script.encode())
    temporary = ROOT / 'build/rootfs-manager-observer.cpio'
    with temporary.open('wb') as output:
        for inode, (name, (mode, data)) in enumerate([*sorted(files.items()), ('TRAILER!!!', (0, b''))], 1):
            encoded = name.encode() + b'\0'
            fields = [inode, mode, 0, 0, 1, 0, len(data), 0, 0, 0, 0, len(encoded), 0]
            output.write(b'070701' + b''.join(f'{value:08x}'.encode() for value in fields) + encoded)
            output.write(bytes(-output.tell() % 4))
            output.write(data)
            output.write(bytes(-output.tell() % 4))
    temporary.replace(ROOT / 'build/rootfs-network.cpio')
    image = f'axiom64-{observer}-{scenario}-{linkage}-lane{affected}.iso'
    subprocess.run(['python3', 'scripts/image.py', '--test', '--suite', 'network',
                    '--output-name', image], cwd=ROOT, check=True)
    return ROOT / 'build' / image
