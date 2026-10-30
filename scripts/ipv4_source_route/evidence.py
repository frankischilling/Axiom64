# SPDX-License-Identifier: GPL-3.0-or-later
"""Reopen routing-control source, executables, native providers and actual boot images."""
import argparse
import json
from pathlib import Path
import struct
import zipfile

from ipv4_source_route.controls import CLIENT, SCRIPT, client_binding, decode, fingerprint, observations, require
from tcp6.inputs import digest
from tcp_fixture_inputs import audit_fixture


def source(directory):
    receipt = decode((directory / 'receipt.json').read_text())
    binding = receipt['source']
    require(digest(directory / 'source.zip') == binding['source_zip_sha256'] and
            digest(directory / 'source-inputs.json') == binding['source_inputs_sha256'],
            'exact complete public source snapshot')
    inputs = decode((directory / 'source-inputs.json').read_text())
    require(inputs and len(inputs) == binding['files'], 'complete public source inventory')
    with zipfile.ZipFile(directory / 'source.zip') as archive:
        require(len(archive.namelist()) == len(inputs) and set(archive.namelist()) == set(inputs),
                'source archive matches its complete inventory')
        for name, value in inputs.items():
            path = Path(name)
            require(bool(path.parts) and not path.is_absolute() and '..' not in path.parts and '\\' not in name and
                    ':' not in path.parts[0] and path.as_posix() == name and
                    path.parts[0] not in ('.git', '.local', 'build', 'downloads') and
                    fingerprint(archive.read(name)) == value, 'bounded public source name and actual bytes')
    return inputs


def compilation(case, inputs, profile):
    program = case / 'program'
    saved = decode((case / 'program.inputs.json').read_text())
    require(saved['product'] == dict(bytes=program.stat().st_size, sha256=digest(program)) and
            saved['sources'].get(CLIENT) == inputs[CLIENT] and
            all(inputs.get(name) == value for name, value in saved['sources'].items()) and
            [name for name in saved['command'] if name.endswith('.c')] == [CLIENT] and
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


def verify(directory):
    directory = Path(directory)
    inputs = source(directory)
    client_binding(inputs)
    receipt = decode((directory / 'receipt.json').read_text())
    rows = receipt['profiles']
    expected = {(True, profile, None) for profile in ('native', 'static', 'dynamic')}
    expected |= {(False, profile, firmware) for profile in ('static', 'dynamic') for firmware in ('bios', 'uefi')}
    require(len(rows) == 7 and {(row['native'], row['profile'], row.get('firmware')) for row in rows} == expected,
            'exact three-native/four-guest control matrix')
    require(receipt['parent_namespace_controls_unchanged'] is True and
            receipt['full_source_routing_acceptance'] is False, 'control-only acceptance boundary')
    audited = set()
    total = 0
    for row in rows:
        native, profile = row['native'], row['profile']
        require(type(native) is bool and row['observations'] == 157 and type(row['observations']) is int,
                'fixed profile identity and observation count')
        require(row['case'] == ('native-' + profile if native else profile), 'bounded exact profile directory')
        case = directory / row['case']
        compilation(case, inputs, profile)
        name = 'client' if native else row['firmware']
        text = (case / (name + '.log')).read_text()
        process = decode((case / (name + '-process.json')).read_text())
        require(process['status'] == 'completed' and process['returncode'] == (0 if native else 1) and
                process['log_sha256'] == digest(case / (name + '.log')) and
                type(process['elapsed_ns']) is int and process['elapsed_ns'] > 0,
                'completed actual process and exact full log')
        total += observations(text, native)
        command = decode((case / (name + '-command.json')).read_text())
        if native:
            require(command[:2] == ['unshare', '--net'] and
                    len(command) == (4 if profile == 'dynamic' else 3) and
                    Path(command[-1]).name == 'ipv4-source-controls-' + profile, 'private native namespace command')
            runtime = decode((case / 'runtime.json').read_text())
            require(type(runtime['namespace']) is int and type(runtime['parent_namespace']) is int and
                    runtime['namespace'] != runtime['parent_namespace'] and
                    runtime['maps_sha256'] == digest(case / 'runtime-maps.txt'), 'actual private mapped runtime')
            maps = (case / 'runtime-maps.txt').read_text()
            require(command[-1] in maps and runtime['executable'] == command[2], 'actual mapped program and executable')
            providers = runtime['providers']
            require(bool(providers) == (profile != 'static') and
                    {path.relative_to(case).as_posix() for path in (case / 'runtime').iterdir()} == set(providers),
                    'all retained actual runtime providers')
            mapped = {}
            for line in maps.splitlines():
                fields = line.split(None, 5)
                if len(fields) == 6 and fields[5].startswith('/') and fields[5] not in command[2:]:
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
                        providers['runtime/ld-musl-x86_64.so.1']['source'] == command[2], 'owned native musl loader')
        else:
            require(command[0] == 'qemu-system-x86_64' and '-cdrom' in command and '-nic' in command and
                    command[command.index('-nic') + 1] == 'none' and
                    Path(command[command.index('-cdrom') + 1]).name == 'image.iso' and
                    ('/usr/share/OVMF/OVMF_CODE_4M.fd' in ' '.join(command)) == (row['firmware'] == 'uefi') and
                    ('Firmware: ' + row['firmware'].upper()) in text, 'actual BIOS/UEFI control guest command')
            if profile not in audited:
                products = decode((case / 'products.json').read_text())
                require(all(digest(case / name) == products[name]['sha256'] for name in ('image.iso', 'root.cpio', 'kernel.elf')),
                        'exact retained guest products')
                require(products['bin/ipv4-source-controls']['sha256'] == digest(case / 'program'), 'same guest client')
                executables = {name: value['sha256'] for name, value in products.items()
                               if name not in ('image.iso', 'root.cpio', 'kernel.elf')}
                audit_fixture(case / 'image.iso', products['kernel.elf']['sha256'], executables, SCRIPT,
                              products['root.cpio']['sha256'])
                require(products['lib/ld-musl-x86_64.so.1']['sha256'] ==
                        digest(directory / 'native-dynamic/runtime/ld-musl-x86_64.so.1'), 'same native and guest musl loader')
                require((case / 'program').read_bytes() == (directory / ('native-' + profile) / 'program').read_bytes(),
                        'same actual native and guest client bytes')
                audited.add(profile)
    return dict(passed=True, native_profiles=3, guest_profiles=4, observations_each=157,
                total_observations=total, actual_images=len(audited), full_source_routing_acceptance=False)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('directory', type=Path)
    args = parser.parse_args()
    print(json.dumps(verify(args.directory)), flush=True)


if __name__ == '__main__':
    main()
