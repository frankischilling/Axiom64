# SPDX-License-Identifier: GPL-3.0-or-later
"""Add explicit clients to the unmodified normal image and inspect owned ext2 files."""
import hashlib
import json
from pathlib import Path
import posixpath
import re
import shutil
import stat
import subprocess

from disk_root import archive_entries, bootstrap
from fetch import LOCK, ROOT
from http_download.audit import fingerprint
from http_download.normal_client import files as download_files, script
from http_download.normal_client import PROFILES
from http_download.peer import PAYLOAD_SHA256
from tcp_fault_capture import require


def contents(files, name):
    seen = set()
    while name in files and name not in seen and len(seen) < 40:
        seen.add(name)
        mode, data = files[name]
        if stat.S_ISREG(mode):
            return data
        require(stat.S_ISLNK(mode), 'installed dependency is a file or symlink: '+name)
        target = data.decode()
        require(target and '\\' not in target, 'installed dependency has a bounded POSIX link')
        name = posixpath.normpath(posixpath.join('/', posixpath.dirname(name), target)).lstrip('/')
    raise ValueError('installed dependency link is missing or cyclic: '+name)


def entries(original, providers, runtimes, network, certificates, directory, profiles=PROFILES):
    result = archive_entries(original)
    public = result['etc/ssl/cert.pem'][1]
    require(hashlib.sha256(public).hexdigest() == LOCK['ca_bundle']['sha256'],
            'normal installed image contains the authenticated public trust bundle')
    installed = providers['runtime'] / 'dynamic/stage/usr/bin/curl'
    require(result['usr/bin/curl'][1] == installed.read_bytes(), 'actual installed runtime curl product')
    products = {}
    for provider in ('build', 'runtime'):
        for linkage in ('static', 'dynamic'):
            profile = provider+'-'+linkage
            if profile not in profiles:
                continue
            base = 'usr/share/download-fixture/'+profile
            selected = {base+'/curl': providers[provider] / linkage / 'stage/usr/bin/curl'}
            if linkage == 'dynamic':
                selected[base+'/loader'] = runtimes[provider]['loader']
                selected[base+'/lib/libc.musl-x86_64.so.1'] = runtimes[provider]['loader']
                selected[base+'/lib/libc.so'] = runtimes[provider]['loader']
                selected[base+'/lib/libcurl.so.4'] = providers[provider] / 'dynamic/stage/usr/lib/libcurl.so.4'
                for name in ('libssl.so.3', 'libcrypto.so.3'):
                    selected[base+'/lib/'+name] = runtimes[provider]['tls'] / 'dynamic/stage/usr/lib' / name
            for name, path in selected.items():
                for parent in Path(name).parents:
                    if parent.as_posix() != '.':
                        result.setdefault(parent.as_posix(), (0o40755, b''))
                data = path.read_bytes()
                result[name] = (0o100755, data)
                products[name] = fingerprint(path)
                saved = directory / 'products' / name
                saved.parent.mkdir(parents=True, exist_ok=True)
                saved.write_bytes(data)
    # The installed dynamic command uses its installed loader and libraries.
    for name, path in (
            ('usr/bin/curl', installed),
            ('usr/bin/openssl', runtimes['runtime']['tls'] / 'dynamic/stage/usr/bin/openssl'),
            ('lib/ld-musl-x86_64.so.1', runtimes['runtime']['loader']),
            ('usr/lib/libcurl.so.4', providers['runtime'] / 'dynamic/stage/usr/lib/libcurl.so.4'),
            *((f'usr/lib/{name}', runtimes['runtime']['tls'] / 'dynamic/stage/usr/lib' / name)
              for name in ('libssl.so.3', 'libcrypto.so.3'))):
        data = path.read_bytes()
        require(contents(result, name) == data, 'normal installed dynamic dependency: '+name)
        regular = (Path(name).parent / path.resolve().name).as_posix() if stat.S_ISLNK(result[name][0]) else name
        require(contents(result, regular) == data and stat.S_ISREG(result[regular][0]),
                'normal installed dependency retains its regular product')
        products[regular] = fingerprint(path)
        saved = directory / 'products' / regular
        saved.parent.mkdir(parents=True, exist_ok=True)
        saved.write_bytes(data)
    authority = (certificates / 'ca.pem').read_bytes()
    trust_hash = hashlib.sha256(public+authority).hexdigest()
    result['usr/share/download-fixture/ca.pem'] = (0o100644, authority)
    result['usr/bin/normal-download-test'] = (0o100755, script(network, trust_hash, profiles).encode())
    (directory / 'client-products.json').write_text(json.dumps(products, indent=2)+'\n')
    return result, trust_hash


def image(directory, archive, disk_root=False):
    directory.mkdir()
    name = 'axiom64-download-'+directory.parent.name+'-'+directory.name+'.iso'
    command = ['python3', 'scripts/image.py', '--output-name', name]
    if disk_root:
        bootstrap(ROOT / 'build/rootfs-bootstrap.cpio')
        command += ['--root-device', '/dev/vda']
    else:
        command += ['--initramfs', str(archive)]
    with (directory / 'build.log').open('wb') as log:
        subprocess.run(command, cwd=ROOT, check=True, stdout=log, stderr=subprocess.STDOUT)
    iso = directory / 'image.iso'
    shutil.copyfile(ROOT / 'build' / name, iso)
    shutil.copyfile(ROOT / 'build/axiom64.elf', directory / 'kernel.elf')
    (directory / 'inputs.json').write_text(json.dumps(dict(command=command,
        image=fingerprint(iso), kernel=fingerprint(directory / 'kernel.elf'),
        initramfs=fingerprint(ROOT / 'build/rootfs-bootstrap.cpio' if disk_root else archive)), indent=2)+'\n')
    return iso


def exports(disk, directory, trust_hash, profiles=PROFILES, products=None):
    directory.mkdir()
    records = {}
    selected = [(name, 0o600, 1000, 1000, PAYLOAD_SHA256) for name in download_files(profiles)]
    selected.append(('/etc/ssl/cert.pem', 0o644, 0, 0, trust_hash))
    for name, value in (products or {}).items():
        selected.append(('/'+name, 0o755, 0, 0, value['sha256']))
    for name, mode, uid, gid, expected in selected:
        observed = subprocess.run(['debugfs', '-R', 'stat '+name, str(disk)],
                                  capture_output=True, text=True, check=True)
        stem = name.strip('/').replace('/', '-')
        (directory / (stem+'-stat.log')).write_text(observed.stdout+observed.stderr)
        metadata = re.search(r'Inode:\s+(\d+)\s+Type:\s+(\S+)\s+Mode:\s+([0-7]+)', observed.stdout)
        owner = re.search(r'User:\s+(\d+)\s+Group:\s+(\d+).*?Size:\s+(\d+)', observed.stdout)
        require(metadata and owner and
                (metadata[2], int(metadata[3], 8), int(owner[1]), int(owner[2])) == ('regular', mode, uid, gid) and
                re.search(r'Links:\s+1\b', observed.stdout), 'actual ext2 file ownership, mode, type and links: '+name)
        target = directory / (stem+'.bin')
        dumped = subprocess.run(['debugfs', '-R', 'dump '+name+' '+str(target), str(disk)],
                                capture_output=True, check=True)
        (directory / (stem+'-dump.log')).write_bytes(dumped.stdout+dumped.stderr)
        require(target.is_file() and fingerprint(target)['sha256'] == expected and
                target.stat().st_size == int(owner[3]), 'actual ext2 file bytes: '+name)
        records[name] = dict(**fingerprint(target), mode=mode, uid=uid, gid=gid)
    with (directory / 'fsck.log').open('wb') as log:
        check = subprocess.run(['e2fsck', '-f', '-n', str(disk)], stdout=log, stderr=subprocess.STDOUT)
    require(check.returncode == 0, 'strict ext2 filesystem check after authenticated downloads')
    report = dict(passed=True, files=records, strict_fsck_returncode=check.returncode, disk=fingerprint(disk))
    (directory / 'receipt.json').write_text(json.dumps(report, indent=2)+'\n')
    return report
