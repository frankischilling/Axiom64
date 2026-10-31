# SPDX-License-Identifier: GPL-3.0-or-later
"""Retain the actual mapped native loader and library bytes before releasing a client."""
from pathlib import Path
import shutil
import time
from tcp6.inputs import digest, write
from ipv4_source_route.controls import require


def capture(process, program, executable, directory, profile, parent_namespace):
    deadline = time.monotonic() + 10
    while process.poll() is None and time.monotonic() < deadline:
        try:
            actual = Path('/proc') / str(process.pid)
            image = (actual / 'exe').resolve(strict=True)
            maps = (actual / 'maps').read_text()
        except (FileNotFoundError, ProcessLookupError):
            continue
        if image == executable and str(program) in maps:
            break
        time.sleep(.002)
    else:
        raise ValueError('native client did not reach its mapped-runtime barrier')
    namespace = (actual / 'ns/net').stat().st_ino
    require(namespace != parent_namespace, 'private native network namespace')
    (directory / 'runtime-maps.txt').write_text(maps)
    providers = {}
    for line in maps.splitlines():
        fields = line.split(None, 5)
        if len(fields) == 6 and fields[5].startswith('/'):
            path = Path(fields[5])
            if path not in (program, executable) and ('.so' in path.name or 'ld-linux' in path.name):
                providers[path] = int(fields[4])
    require(bool(providers) == (profile == 'native'), 'actual GNU or standalone musl linkage')
    (directory / 'runtime').mkdir()
    retained = {}
    for number, (path, inode) in enumerate(providers.items()):
        require(path.stat().st_ino == inode, 'actual mapped provider inode')
        target = directory / 'runtime' / (str(number) + '-' + path.name)
        shutil.copy2(path, target)
        require(path.stat().st_ino == inode and digest(path) == digest(target), 'unchanged mapped provider bytes')
        retained[target.relative_to(directory).as_posix()] = dict(source=str(path), inode=inode, sha256=digest(target))
    if profile == 'dynamic':
        target = directory / 'runtime/ld-musl-x86_64.so.1'
        shutil.copy2(executable, target)
        require(digest(executable) == digest(target), 'actual dynamic musl loader')
        retained[target.relative_to(directory).as_posix()] = dict(source=str(executable), sha256=digest(target))
    record = dict(namespace=namespace, parent_namespace=parent_namespace, providers=retained,
                  maps_sha256=digest(directory / 'runtime-maps.txt'), executable=str(image))
    write(directory / 'runtime.json', record)
    return record
