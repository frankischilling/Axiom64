# SPDX-License-Identifier: GPL-3.0-or-later
"""Shared source compilation, ELF linkage and actual runtime-provider checks."""
from pathlib import Path
import struct

from ipv4_source_route.controls import decode, require
from tcp6.inputs import digest


def compilation(case, inputs, profile, client):
    program = case / 'program'
    saved = decode((case / 'program.inputs.json').read_text())
    require(saved['product'] == dict(bytes=program.stat().st_size, sha256=digest(program)) and
            saved['sources'].get(client) == inputs[client] and
            all(inputs.get(name) == value for name, value in saved['sources'].items()) and
            [name for name in saved['command'] if name.endswith('.c')] == [client] and
            ('-static' in saved['command']) == (profile == 'static'), 'exact client compilation and linkage')
    elf = program.read_bytes()
    require(elf[:7] == b'\x7fELF\2\1\1' and struct.unpack_from('<H', elf, 18)[0] == 62,
            'actual x86-64 executable')
    begin = struct.unpack_from('<Q', elf, 32)[0]
    size, count = struct.unpack_from('<HH', elf, 54)
    require(size == 56 and begin + count * size <= len(elf), 'bounded executable headers')
    interpreters = []
    for at in range(begin, begin + count * size, size):
        if struct.unpack_from('<I', elf, at)[0] == 3:
            start, length = struct.unpack_from('<Q', elf, at + 8)[0], struct.unpack_from('<Q', elf, at + 32)[0]
            require(0 < length < 256 and start + length <= len(elf), 'bounded executable interpreter')
            interpreters.append(elf[start:start + length])
    require((not interpreters if profile == 'static' else len(interpreters) == 1), 'actual static/dynamic linkage')
    if profile == 'dynamic':
        require(interpreters == [b'/lib/ld-musl-x86_64.so.1\0'], 'target musl interpreter')



def providers(case, runtime, maps, profile, executables, loader):
    providers = runtime['providers']
    require(bool(providers) == (profile != 'static') and
            {path.relative_to(case).as_posix() for path in (case / 'runtime').iterdir()} == set(providers),
            'all retained actual runtime providers')
    mapped = {}
    for line in maps.splitlines():
        fields = line.split(None, 5)
        if len(fields) == 6 and fields[5].startswith('/') and fields[5] not in executables:
            path = Path(fields[5])
            if '.so' in path.name or 'ld-linux' in path.name:
                mapped[str(path)] = int(fields[4])
    if profile == 'native':
        require(set(mapped) == {value['source'] for value in providers.values()} and
                all(type(value['inode']) is int and mapped[value['source']] == value['inode']
                    for value in providers.values()), 'complete actual GNU provider paths and inodes')
    else:
        require(not mapped, 'standalone musl has no other mapped providers')
    for name, value in providers.items():
        require(Path(name).parts[0] == 'runtime' and len(Path(name).parts) == 2 and
                '\\' not in name and digest(case / name) == value['sha256'] and value['source'] in maps,
                'actual mapped loader/library bytes')
    if profile == 'dynamic':
        require(set(providers) == {'runtime/ld-musl-x86_64.so.1'} and
                providers['runtime/ld-musl-x86_64.so.1']['source'] == loader, 'owned native musl loader')
