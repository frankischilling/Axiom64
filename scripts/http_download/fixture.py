# SPDX-License-Identifier: GPL-3.0-or-later
"""Construct an owned guest image containing the actual selected curl products."""
from pathlib import Path
import json
import shutil
import subprocess

from account_normal_test import write_cpio
from build_musl import loader
from build_openssl import ensure as openssl
from fetch import LOCK, ROOT
from http_download.client import commands
from random_administration_test import fingerprint


def image(directory, provider, linkage, curl_directory, certificates, peers):
    files = {name: (0o40755, b'') for name in
        ('bin', 'sbin', 'lib', 'usr', 'usr/bin', 'usr/lib', 'etc', 'etc/ssl', 'dev', 'proc', 'sys', 'tmp', 'run')}
    stage = curl_directory / linkage / 'stage'
    products = {
        'sbin/init': ROOT / 'build/init',
        'bin/busybox': ROOT / ('build/busybox-' + LOCK['busybox']['version'] + '/busybox'),
        'usr/bin/curl': stage / 'usr/bin/curl',
        'lib/ld-musl-x86_64.so.1': loader(provider),
        'etc/ssl/test-ca.pem': certificates / 'ca.pem',
        'etc/ssl/untrusted-ca.pem': certificates / 'untrusted.pem',
    }
    if linkage == 'dynamic':
        products['usr/lib/libcurl.so.4'] = stage / 'usr/lib/libcurl.so.4'
        tls = openssl(provider) / 'dynamic/stage/usr/lib'
        products.update({f'usr/lib/{name}': tls / name for name in ('libssl.so.3', 'libcrypto.so.3')})
    record = {}
    for name, path in products.items():
        files[name] = (0o100755 if not name.endswith('.pem') else 0o100644, path.read_bytes())
        record[name] = fingerprint(path)
        saved = directory / 'products' / name
        saved.parent.mkdir(parents=True, exist_ok=True)
        saved.write_bytes(path.read_bytes())
    for name in ('libc.so', 'libc.musl-x86_64.so.1'):
        files['lib/' + name] = (0o120777, b'/lib/ld-musl-x86_64.so.1')
    setup = ['#!/bin/sh', 'set -eu', 'export PATH=/bin:/usr/bin:/sbin',
             'export LD_LIBRARY_PATH=/usr/lib:/lib']
    expected = {}
    for lane in (0, 1):
        host = f'10.23.{lane+1}.1'
        address = f'10.23.{lane+1}.2/24'
        root = '/tmp/download-' + str(lane)
        setup += [f'/bin/busybox ip link set eth{lane} up',
            f'/bin/busybox ip addr add {address} dev eth{lane}',
            f'/bin/busybox mkdir -p {root}/deny',
            f'/bin/busybox chmod 0700 {root}',
            f'/bin/busybox chmod 0500 {root}/deny',
            f'/bin/busybox chown 60011:60011 {root}']
        script, expected[lane] = commands(['/usr/bin/curl'], '/bin/busybox',
            '/etc/ssl/test-ca.pem', '/etc/ssl/untrusted-ca.pem', peers[lane], host, root)
        files[f'etc/download-{lane}.sh'] = (0o100755, script.encode())
        setup += [f'echo DOWNLOAD_LANE_BEGIN {lane}',
            f'/bin/busybox chpst -u 60011:60011 /bin/busybox sh /etc/download-{lane}.sh',
            f'echo DOWNLOAD_LANE_END {lane}']
    setup.append('echo AXIOM64_TESTS_PASS')
    files['etc/net-test.sh'] = (0o100755, ('\n'.join(setup)+'\n').encode())
    archive = directory / 'root.cpio'
    write_cpio(archive, files)
    iso_name = 'axiom64-download-' + directory.name + '.iso'
    command = ['python3', 'scripts/image.py', '--test', '--suite', 'network',
               '--output-name', iso_name, '--initramfs', str(archive)]
    with (directory / 'image-build.log').open('wb') as output:
        subprocess.run(command, cwd=ROOT, stdout=output, stderr=subprocess.STDOUT, check=True)
    iso = directory / 'image.iso'
    shutil.copy2(ROOT / 'build' / iso_name, iso)
    shutil.copy2(ROOT / 'build/axiom64.elf', directory / 'kernel.elf')
    record.update({name: fingerprint(directory / name) for name in ('root.cpio', 'image.iso', 'kernel.elf')})
    (directory / 'products.json').write_text(json.dumps(record, indent=2)+'\n')
    return iso, expected
