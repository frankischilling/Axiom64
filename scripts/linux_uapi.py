# SPDX-License-Identifier: GPL-3.0-or-later
"""Provide the complete checksum-pinned Linux headers on a case-sensitive filesystem."""
import fcntl
import hashlib
import json
import os
from pathlib import Path
import tarfile
import tempfile

from fetch import ROOT
from ports import download


def digest(path):
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def headers():
    packages = json.loads((ROOT / 'ports.lock.json').read_text())['packages']
    package, = (item for item in packages if item['name'] == 'linux-headers')
    archive = download(package['url'], ROOT / 'downloads/ports' / package['archive'])
    if digest(archive) != package['sha256']:
        raise RuntimeError('Linux UAPI archive checksum differs')
    output = ROOT / 'build/linux-uapi'
    output.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix='case-probe-', dir=output) as temporary:
        probe = Path(temporary)
        (probe / 'a').write_bytes(b'lowercase')
        case_sensitive = not (probe / 'A').exists()
    if case_sensitive:
        destination = output / package['sha256']
    else:
        cache = Path(os.environ.get('XDG_CACHE_HOME', str(Path.home() / '.cache')))
        if not cache.is_absolute():
            raise RuntimeError('Linux UAPI cache must use an absolute path')
        destination = cache / 'axiom64-uapi' / package['sha256']
    expected = {}
    destination.parent.mkdir(parents=True, exist_ok=True)
    with (destination.parent / (package['sha256'] + '.lock')).open('a') as guard:
        fcntl.flock(guard, fcntl.LOCK_EX)
        with tarfile.open(archive, 'r:gz', ignore_zeros=True) as stream:
            members = [member for member in stream if member.name.startswith('usr/include/')]
            for member in members:
                if member.isfile():
                    if member.name in expected:
                        raise RuntimeError('duplicate Linux UAPI member: ' + member.name)
                    expected[member.name] = hashlib.file_digest(stream.extractfile(member), 'sha256').hexdigest()
            if not destination.exists():
                destination.mkdir(parents=True)
                stream.extractall(destination, members=members, filter='data')
        actual = {path.relative_to(destination).as_posix(): digest(path)
                  for path in destination.rglob('*') if path.is_file() and not path.is_symlink()}
        if actual != expected:
            raise RuntimeError('Linux UAPI headers differ from the pinned archive')
    return destination / 'usr/include', dict(package=package, products=expected)
