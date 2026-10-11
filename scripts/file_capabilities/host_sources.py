# SPDX-License-Identifier: GPL-3.0-or-later
"""Retain the signed corresponding Ubuntu glibc source for native test binaries."""
import hashlib
import lzma
from pathlib import Path
import re
import shutil
import subprocess
import urllib.error
import urllib.request
from fetch import ROOT


def capture(output):
    version = subprocess.check_output(['dpkg-query', '-W', '-f=${source:Version}', 'libc6'], text=True).strip()
    if not re.fullmatch(r'[0-9][a-zA-Z0-9.+~:-]*', version):
        raise ValueError('unexpected installed glibc source version')
    name = 'glibc_' + version.split(':')[-1] + '.dsc'
    cache = ROOT / 'downloads/host-glibc' / version.replace(':', '_')
    cache.mkdir(parents=True, exist_ok=True)
    mirrors = ('https://archive.ubuntu.com/ubuntu/pool/main/g/glibc/',
               'https://security.ubuntu.com/ubuntu/pool/main/g/glibc/')
    def fetch(filename):
        path = cache / filename
        if not path.exists():
            for mirror in mirrors:
                try:
                    with urllib.request.urlopen(mirror + filename, timeout=60) as response:
                        data = response.read()
                    path.write_bytes(data)
                    break
                except urllib.error.HTTPError as error:
                    if error.code != 404:
                        raise
            else:
                raise RuntimeError('installed glibc corresponding source is unavailable: ' + filename)
        return path
    keyring = Path('/usr/share/keyrings/ubuntu-archive-keyring.gpg')
    # Source descriptors are signed by uploaders, whose keys need not occur in
    # the archive keyring. Authenticate the descriptor through the archive's
    # signed Release and SHA256-verified Sources index instead.
    release = dict(line.split('=', 1) for line in Path('/etc/os-release').read_text().splitlines() if '=' in line)
    codename = release['UBUNTU_CODENAME'].strip('"')
    if not re.fullmatch('[a-z]+', codename):
        raise ValueError('unexpected Ubuntu source suite')
    archive_files, paragraph = [], None
    for suite, mirror in ((codename + '-updates', 'https://archive.ubuntu.com/ubuntu/'),
                          (codename + '-security', 'https://security.ubuntu.com/ubuntu/'),
                          (codename, 'https://archive.ubuntu.com/ubuntu/')):
        signed = cache / (suite + '-InRelease')
        index = cache / (suite + '-Sources.xz')
        if not signed.exists():
            with urllib.request.urlopen(mirror + 'dists/' + suite + '/InRelease', timeout=60) as response:
                signed.write_bytes(response.read())
        verified = subprocess.run(['gpgv', '--keyring', str(keyring), str(signed)], capture_output=True, check=True)
        (output / (suite + '-signature.log')).write_bytes(verified.stdout + verified.stderr)
        match = re.search(r'^ ([a-f0-9]{64})\s+(\d+) main/source/Sources.xz$', signed.read_text(), re.M)
        if not match:
            raise ValueError('signed Ubuntu Release lacks the Sources index')
        if not index.exists():
            with urllib.request.urlopen(mirror + 'dists/' + suite + '/main/source/Sources.xz', timeout=60) as response:
                index.write_bytes(response.read())
        data = index.read_bytes()
        if len(data) != int(match[2]) or hashlib.sha256(data).hexdigest() != match[1]:
            raise ValueError('signed Ubuntu Sources index checksum differs')
        for item in lzma.decompress(data).decode().split('\n\n'):
            if re.search(r'^Package: glibc$', item, re.M) and re.search(r'^Version: ' + re.escape(version) + '$', item, re.M):
                paragraph = item + '\n'
                break
        if paragraph:
            archive_files = [signed, index]
            break
    if paragraph is None:
        raise RuntimeError('installed glibc source version is absent from authenticated Ubuntu indices')
    descriptor = fetch(name)
    checksums = re.search(r'^Checksums-Sha256:\n((?: [^\n]+\n)+)', paragraph, re.M)
    if not checksums:
        raise ValueError('authenticated glibc source lacks descriptor checksums')
    expected = {filename: (checksum, int(size)) for checksum, size, filename in
                (line.split() for line in checksums[1].splitlines())}
    if name not in expected or (hashlib.sha256(descriptor.read_bytes()).hexdigest(), descriptor.stat().st_size) != expected[name]:
        raise ValueError('authenticated glibc source descriptor checksum differs')
    text = descriptor.read_text()
    if not re.search(r'^Version: ' + re.escape(version) + r'$', text, re.M):
        raise ValueError('signed glibc descriptor differs from installed source version')
    match = re.search(r'^Checksums-Sha256:\n((?: [^\n]+\n)+)', text, re.M)
    if not match:
        raise ValueError('signed glibc source lacks SHA256 checksums')
    files = [descriptor]
    for line in match[1].splitlines():
        expected, size, filename = line.split()
        if Path(filename).name != filename:
            raise ValueError('unsafe glibc source filename')
        path = fetch(filename)
        data = path.read_bytes()
        if len(data) != int(size) or hashlib.sha256(data).hexdigest() != expected:
            raise ValueError('signed glibc source checksum differs: ' + filename)
        files.append(path)
    destination = output / 'glibc-source'
    destination.mkdir()
    for path in [*files, keyring, *archive_files]:
        shutil.copy2(path, destination / path.name)
    return dict(version=version, descriptor=name, files={path.name: hashlib.sha256(path.read_bytes()).hexdigest()
                                                       for path in [*files, keyring, *archive_files]})
