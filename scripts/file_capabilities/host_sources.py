# SPDX-License-Identifier: GPL-3.0-or-later
"""Retain the signed corresponding Ubuntu glibc source for native test binaries."""
from datetime import timezone
from email.utils import parsedate_to_datetime
import hashlib
import http.client
import json
import lzma
import os
from pathlib import Path
import re
import shutil
import socket
import subprocess
import tempfile
import time
import urllib.error
import urllib.request
from fetch import ROOT


SNAPSHOT = 'https://snapshot.ubuntu.com/ubuntu/'


def open_archive_url(url, attempts=None):
    for attempt in range(3):
        try:
            return urllib.request.urlopen(url, timeout=60)
        except urllib.error.HTTPError as error:
            if error.code not in (429, 500, 502, 503, 504) or attempt == 2:
                raise
            detail = dict(status=error.code)
            error.close()
        except (ConnectionError, TimeoutError, urllib.error.URLError) as error:
            reason = getattr(error, 'reason', error)
            temporary_dns = isinstance(reason, socket.gaierror) and reason.errno == socket.EAI_AGAIN
            if attempt == 2 or not (isinstance(reason, (ConnectionError, TimeoutError)) or temporary_dns):
                raise
            detail = dict(error=type(reason).__name__, message=str(reason))
        if attempts is not None:
            attempts.append(dict(url=url, retry=True, **detail))
        time.sleep(attempt + 1)


def snapshot_archive(release):
    """Locate the signed publication in Canonical's dated archive."""
    match = re.search(r'^Date: (.+)$', release, re.M)
    if not match:
        return None
    try:
        published = parsedate_to_datetime(match[1])
    except (ValueError, OverflowError):
        return None
    if published.tzinfo is None:
        return None
    day = published.astimezone(timezone.utc).strftime('%Y%m%dT%H%M%SZ')
    return f'{SNAPSHOT}{day}/'


def publish_cache(path, data):
    # Native capture runs as root. Ordinary CI readers need these public bytes.
    temporary = None
    try:
        with tempfile.NamedTemporaryFile(dir=path.parent, prefix=path.name + '.',
                                         suffix='.part', delete=False) as stream:
            temporary = Path(stream.name)
            stream.write(data)
            os.fchmod(stream.fileno(), 0o644)
        os.replace(temporary, path)
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)


def authenticated_index(signed, cache, output, suite, mirror):
    """Fetch the exact index named by an already signature-verified Release."""
    diagnostic = output / 'archive-authentication' / suite
    diagnostic.mkdir(parents=True, exist_ok=True)
    shutil.copy2(signed, diagnostic / 'InRelease')
    release = signed.read_text()
    match = re.search(r'^ ([a-f0-9]{64})\s+(\d+) main/source/Sources.xz$', release, re.M)
    if not match:
        raise ValueError('signed Ubuntu Release lacks the Sources index')
    expected, size = match[1], int(match[2])
    index = cache / (suite + '-Sources.xz')
    url = mirror + 'dists/' + suite + '/main/source/by-hash/SHA256/' + expected
    cached = index.exists()
    interrupted = None
    attempts = []
    if cached:
        data = index.read_bytes()
    else:
        canonical = mirror + 'dists/' + suite + '/main/source/Sources.xz'
        snapshot = snapshot_archive(release)
        frozen = snapshot + 'dists/' + suite + '/main/source/Sources.xz' if snapshot else None
        candidates = (url, canonical, frozen) if frozen else (url, canonical)
        for position, candidate in enumerate(candidates):
            url = candidate
            interrupted = None
            try:
                with open_archive_url(url, attempts) as response:
                    attempts.append(dict(url=url, status=response.status))
                    declared = response.headers.get('Content-Length')
                    try:
                        data = response.read(size + 1)
                    except http.client.IncompleteRead as error:
                        data = error.partial
                        interrupted = 'incomplete HTTP response'
                    if declared and declared.isdecimal() and len(data) < int(declared):
                        interrupted = 'incomplete HTTP response'
                # A mutable path may be out of sync with the signed Release.
                # Keep those bytes and check the dated copy against the same pin.
                if candidate == canonical and frozen and (interrupted or len(data) != size or
                                                          hashlib.sha256(data).hexdigest() != expected):
                    (diagnostic / 'Sources.canonical.xz').write_bytes(data)
                    attempts[-1].update(actual_sha256=hashlib.sha256(data).hexdigest(), actual_bytes=len(data),
                                        interrupted=interrupted)
                    continue
                break
            except urllib.error.HTTPError as error:
                status = error.code
                attempts.append(dict(url=url, status=status))
                (diagnostic / 'fetch.json').write_text(json.dumps(dict(
                    url=url, status=status, attempts=attempts, passed=False,
                    expected_sha256=expected, expected_bytes=size), indent=2) + '\n')
                error.close()
                # A publishing mirror can expose the signed Release before its
                # hash path. The canonical bytes must match that same signature.
                if position == len(candidates) - 1 or status != 404:
                    raise
            except (ConnectionError, TimeoutError, urllib.error.URLError) as error:
                reason = getattr(error, 'reason', error)
                attempts.append(dict(url=url, error=type(reason).__name__, message=str(reason)))
                (diagnostic / 'fetch.json').write_text(json.dumps(dict(
                    url=url, attempts=attempts, passed=False, expected_sha256=expected,
                    expected_bytes=size), indent=2) + '\n')
                raise
    actual = hashlib.sha256(data).hexdigest()
    passed = interrupted is None and len(data) == size and actual == expected
    (diagnostic / 'Sources.xz').write_bytes(data)
    (diagnostic / 'fetch.json').write_text(json.dumps(dict(
        url=url, cached=cached, attempts=attempts, expected_sha256=expected, expected_bytes=size,
        actual_sha256=actual, actual_bytes=len(data), interrupted=interrupted, passed=passed), indent=2) + '\n')
    if not passed:
        raise ValueError('signed Ubuntu Sources index checksum differs')
    if not cached:
        publish_cache(index, data)
    else:
        index.chmod(0o644)
    return index


def authenticated_payload(filename, cache, output, mirrors, checksum, size):
    """Fetch a public pool file only after learning its authenticated digest."""
    if not re.fullmatch(r'[a-zA-Z0-9][a-zA-Z0-9.+_~-]*', filename):
        raise ValueError('unsafe glibc source filename')
    if size <= 0 or not re.fullmatch(r'[a-f0-9]{64}', checksum):
        raise ValueError('invalid glibc source checksum record')
    path = cache / filename
    diagnostic = output / 'archive-authentication' / 'glibc-payloads'
    diagnostic.mkdir(parents=True, exist_ok=True)
    report = diagnostic / (filename + '.json')
    cached = path.exists()
    attempts = []
    receipt = dict(filename=filename, cached=cached, attempts=attempts, expected_sha256=checksum,
                   expected_bytes=size, passed=False)

    def report_status():
        report.write_text(json.dumps(receipt, indent=2) + '\n')

    if cached:
        with path.open('rb') as stream:
            data = stream.read(size + 1)
    else:
        for position, mirror in enumerate(mirrors):
            url = mirror + filename
            try:
                with open_archive_url(url, attempts) as response:
                    attempts.append(dict(url=url, status=response.status))
                    data = response.read(size + 1)
                break
            except urllib.error.HTTPError as error:
                status = error.code
                attempts.append(dict(url=url, status=status))
                error.close()
                if status not in (403, 404) or position == len(mirrors) - 1:
                    report_status()
                    raise
            except (ConnectionError, TimeoutError, urllib.error.URLError, http.client.IncompleteRead) as error:
                reason = getattr(error, 'reason', error)
                attempts.append(dict(url=url, error=type(reason).__name__, message=str(reason)))
                report_status()
                raise
        else:
            report_status()
            raise RuntimeError('no archive mirror for authenticated glibc source')

    actual = hashlib.sha256(data).hexdigest()
    receipt.update(actual_sha256=actual, actual_bytes=len(data),
                   passed=actual == checksum and len(data) == size)
    report_status()
    if not receipt['passed']:
        raise ValueError('authenticated glibc source checksum differs: ' + filename)
    if not cached:
        publish_cache(path, data)
    else:
        path.chmod(0o644)
    return path


def indexed_glibc(version, keyring, cache, output, candidates):
    for suite, mirror in candidates:
        signed = cache / (suite + '-InRelease')
        if not signed.exists():
            with open_archive_url(mirror + 'dists/' + suite + '/InRelease') as response:
                publish_cache(signed, response.read())
        verified = subprocess.run(['gpgv', '--keyring', str(keyring), str(signed)], capture_output=True, check=True)
        (output / (suite + '-signature.log')).write_bytes(verified.stdout + verified.stderr)
        index = authenticated_index(signed, cache, output, suite, mirror)
        for item in lzma.decompress(index.read_bytes()).decode().split('\n\n'):
            if re.search(r'^Package: glibc$', item, re.M) and re.search(r'^Version: ' + re.escape(version) + '$', item, re.M):
                return item + '\n', (signed, index)
    return None, ()


def pinned_glibc_snapshot(version, descriptor):
    manifest = ROOT / 'vendor/gnu-utmp-reader/inputs.json'
    source = json.loads(manifest.read_text())['sources']['glibc']
    if source['version'] == version:
        for item in source['files']:
            if item['name'] == descriptor:
                match = re.fullmatch(re.escape(SNAPSHOT) + r'(\d{8}T\d{6}Z)/pool/main/g/glibc/' +
                                     re.escape(descriptor), item['url'])
                if match:
                    return match[1]
    return None


def capture(output):
    version = subprocess.check_output(['dpkg-query', '-W', '-f=${source:Version}', 'libc6'], text=True).strip()
    if not re.fullmatch(r'[0-9][a-zA-Z0-9.+~:-]*', version):
        raise ValueError('unexpected installed glibc source version')
    name = 'glibc_' + version.split(':')[-1] + '.dsc'
    cache = ROOT / 'downloads/host-glibc' / version.replace(':', '_')
    cache.mkdir(parents=True, exist_ok=True)
    keyring = Path('/usr/share/keyrings/ubuntu-archive-keyring.gpg')
    # Source descriptors are signed by uploaders, whose keys need not occur in
    # the archive keyring. Authenticate the descriptor through the archive's
    # signed Release and SHA256-verified Sources index instead.
    release = dict(line.split('=', 1) for line in Path('/etc/os-release').read_text().splitlines() if '=' in line)
    codename = release['UBUNTU_CODENAME'].strip('"')
    if not re.fullmatch('[a-z]+', codename):
        raise ValueError('unexpected Ubuntu source suite')
    candidates = ((codename + '-updates', 'https://archive.ubuntu.com/ubuntu/'),
                  (codename + '-security', 'https://security.ubuntu.com/ubuntu/'),
                  (codename, 'https://archive.ubuntu.com/ubuntu/'))
    paragraph, archive_files = indexed_glibc(version, keyring, cache, output, candidates)
    historical_mirror = None
    if paragraph is None and (timestamp := pinned_glibc_snapshot(version, name)):
        historical_mirror = SNAPSHOT + timestamp + '/'
        historical_cache = cache / timestamp
        historical_output = output / 'historical-archive' / timestamp
        for directory in (historical_cache, historical_output):
            directory.mkdir(parents=True, exist_ok=True)
        paragraph, archive_files = indexed_glibc(version, keyring, historical_cache, historical_output,
                                                [(suite, historical_mirror) for suite, _ in candidates])
    if paragraph is None:
        raise RuntimeError(f'installed glibc source {version} is absent from authenticated Ubuntu indices')
    checksums = re.search(r'^Checksums-Sha256:\n((?: [^\n]+\n)+)', paragraph, re.M)
    if not checksums:
        raise ValueError('authenticated glibc source lacks descriptor checksums')
    expected = {filename: (checksum, int(size)) for checksum, size, filename in
                (line.split() for line in checksums[1].splitlines())}
    if name not in expected:
        raise ValueError('authenticated glibc source lacks the installed version descriptor')
    mirrors = ['https://archive.ubuntu.com/ubuntu/', 'https://security.ubuntu.com/ubuntu/']
    snapshot = snapshot_archive(archive_files[0].read_text())
    if historical_mirror:
        mirrors.insert(0, historical_mirror)
    if snapshot and snapshot != historical_mirror:
        mirrors.append(snapshot)
    archives = tuple(mirror + 'pool/main/g/glibc/' for mirror in mirrors)
    descriptor = authenticated_payload(name, cache, output, archives, *expected[name])
    text = descriptor.read_text()
    if not re.search(r'^Version: ' + re.escape(version) + r'$', text, re.M):
        raise ValueError('signed glibc descriptor differs from installed source version')
    match = re.search(r'^Checksums-Sha256:\n((?: [^\n]+\n)+)', text, re.M)
    if not match:
        raise ValueError('signed glibc source lacks SHA256 checksums')
    files = [descriptor]
    for line in match[1].splitlines():
        expected, size, filename = line.split()
        files.append(authenticated_payload(filename, cache, output, archives, expected, int(size)))
    destination = output / 'glibc-source'
    destination.mkdir()
    for path in [*files, keyring, *archive_files]:
        shutil.copy2(path, destination / path.name)
    return dict(version=version, descriptor=name, files={path.name: hashlib.sha256(path.read_bytes()).hexdigest()
                                                       for path in [*files, keyring, *archive_files]})
