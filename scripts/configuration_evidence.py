# SPDX-License-Identifier: GPL-3.0-or-later
"""Reopen original configuration source, journals, programs and guest images."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import struct
import zipfile

from configuration_inputs import COMMON, PROGRAMS
from tcp_fixture_inputs import audit_fixture


def require(value, message):
    if not value:
        raise ValueError(message)


def digest(path):
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def load(path):
    require(path.is_file() and not path.is_symlink() and path.stat().st_size <= 16 * 1024 * 1024,
            'bounded original regular JSON record')
    return json.loads(path.read_text())


def journal(data, index):
    require(144 < len(data) < 4096 and data[:8] == b'AXNWOWN1' and
            struct.unpack_from('<I', data, 8)[0] == len(data), 'original owned intent framing')
    checksum = 2166136261
    for byte in data[16:]:
        checksum = ((checksum ^ byte) * 16777619) & 0xffffffff
    require(checksum == struct.unpack_from('<I', data, 12)[0], 'original journal checksum')
    require(struct.unpack_from('<I', data, 16)[0] == index and any(data[20:26]) and not any(data[26:28]),
            'journal interface identity and padding')
    require(struct.unpack_from('<4I', data, 28) == (0x0a170228, 0xffffff00, 0x0a1702ff, 1) and
            struct.unpack_from('<4I', data, 44) == (0x0a170229, 0xffffff80, 0x0a17027f, 2),
            'complete old and desired owned tuples')
    routes = [struct.unpack_from('<5I2B2x', data, at) for at in (60, 84, 108)]
    default = (0, 0, 0x0a170201, 2002, index, 16, 0)
    direct = (0xc6336400, 0xffffff00, 0, 2002, index, 16, 253)
    require(routes[0] == default and set(routes[1:]) == {default, direct} and
            all(data[at + 22:at + 24] == bytes(2) for at in (60, 84, 108)),
            'owned routes retain exact protocol, scope, priority and padding')
    require(data[132:140] == b'AXNPRSV1' and struct.unpack_from('<I', data, 140)[0] == len(data) - 144,
            'preserved route extension framing')
    raw = data[144:]
    length, kind, flags, sequence, port = struct.unpack_from('<IHHII', raw)
    require(length == len(raw) and kind == 24 and flags & 2 and not flags & ~(2 | 32) and
            sequence and port, 'original complete multipart route record')
    require(struct.unpack_from('<8BI', raw, 16) == (2, 24, 0, 0, 254, 3, 253, 1, 0),
            'preserved IPv4 main-table route identity')
    attributes = {}
    at = 28
    while at < len(raw):
        require(len(raw) - at >= 4, 'complete preserved attribute header')
        size, field = struct.unpack_from('<HH', raw, at)
        require(size == 8 and size <= len(raw) - at and field not in attributes,
                'bounded unique preserved scalar attribute')
        attributes[field] = raw[at + 4:at + size]
        at += (size + 3) & ~3
    require(set(attributes) in ({1, 4, 6}, {1, 4, 6, 15}) and
            attributes[1] == bytes.fromhex('cb007100') and
            attributes[4] == struct.pack('<I', index) and attributes[6] == struct.pack('<I', 3002) and
            attributes.get(15, struct.pack('<I', 254)) == struct.pack('<I', 254),
            'saved manual route keeps its exact independent tuple')


def observations(text, native):
    names = COMMON + (['PRESERVATION_BOUND', 'TOS_OWNERSHIP'] if native else ['ADDRESS_PRESSURE', 'ROLLBACK'])
    require(all('CONFIGURATION_' + name + '_PASS' in text for name in names), 'all actual configuration checks completed')
    interfaces = re.findall(r'^CONFIGURATION_INTERFACE lane=(\d+) index=(\d+) name=(eth[01])$', text, re.M)
    require(len(interfaces) == 2 and [int(row[0]) for row in interfaces] == [0, 1] and
            [row[2] for row in interfaces] == ['eth0', 'eth1'] and interfaces[0][1] != interfaces[1][1],
            'two actual selected interface identities')
    indexes = [int(row[1]) for row in interfaces]
    require(all(0 < value <= 8 for value in indexes), 'bounded physical interface identities')
    rows = re.findall(r'^CONFIGURATION_INTENT_RECORD phase=(\d+) address=([0-9a-f]{8}) owned=(\d+) foreign=([01]) length=(\d+) data=([0-9a-f]+)$', text, re.M)
    require(len(rows) == 8 and [int(row[0]) for row in rows] == list(range(8)), 'all eight original interrupted observations')
    for phase, address, owned, foreign, length, encoded in rows:
        phase = int(phase)
        stage = phase if phase < 6 else 2
        expected_address = 0x0a170228 if stage < 2 else 0 if stage == 2 else 0x0a170229
        expected_owned = 1 if stage == 0 else 0 if stage < 4 else stage - 3
        require(int(address, 16) == expected_address and int(owned) == expected_owned and
                int(foreign) == int(stage < 2 or stage >= 4), 'actual interrupted kernel state')
        data = bytes.fromhex(encoded)
        require(len(data) == int(length), 'complete original journal bytes')
        journal(data, indexes[1])
    restored = re.findall(r'^CONFIGURATION_INTENT_RESTORED phase=(\d+) address=([0-9a-f]{8}) owned=(\d+) foreign=([01]) protocol=(\d+) index=(\d+)$', text, re.M)
    require(len(restored) == 8 and [int(row[0]) for row in restored] == list(range(8)), 'all eight restored observations')
    for phase, address, owned, foreign, protocol, index in restored:
        phase = int(phase)
        require(address == '00000000' and int(owned) == 0 and int(foreign) == 1 and
                int(protocol) == (4 if phase == 6 else 3) and
                int(index) == indexes[0 if phase == 7 else 1], 'manual replacement and restoration precedence')
    if not native:
        require('AXIOM64_TESTS_PASS' in text and 'AXIOM64_EXIT status=0' in text and
                'PANIC:' not in text and 'Page fault' not in text, 'actual successful guest completion')


def program(directory, profile, metadata, inputs):
    products = metadata['products']
    expected = {'program.elf', 'program.inputs.json'} | ({'loader.elf'} if profile == 'dynamic' else set())
    require(set(products) == expected and all(digest(directory / name) == value for name, value in products.items()),
            'complete original executable products')
    compiled = load(directory / 'program.inputs.json')
    require(compiled['product'] == dict(bytes=(directory / 'program.elf').stat().st_size,
            sha256=products['program.elf']) and ('-static' in compiled['command']) == (profile == 'static'),
            'actual compilation and selected linkage')
    required = {'userspace/tests/net/configuration.cpp', 'userspace/net/config/configuration.cpp',
                'userspace/net/config/routing.cpp', 'userspace/net/config/route_snapshot.cpp',
                'userspace/net/config/profile.cpp', 'userspace/net/config/saved.cpp',
                'userspace/net/dhcp/transport.cpp', 'userspace/net/dhcp/wire.cpp'}
    recorded = compiled['sources']
    require({name for name in compiled['command'] if name.endswith(('.c', '.cpp'))} == required and
            {name for name in recorded if name.endswith(('.c', '.cpp'))} == required and
            {'userspace/net/config/configuration.hpp', 'userspace/net/config/routing.hpp',
             'userspace/net/config/route_snapshot.hpp'} <= recorded.keys() and
            metadata['compile_sources'] == recorded and all(inputs.get(name) == value for name, value in recorded.items()),
            'all C++ translation units and shared headers bind to complete source')
    require(compiled['command'][-2] == '-o' and Path(compiled['command'][-1]).name == PROGRAMS[profile],
            'actual selected compiler output')


def verify(directory, complete=False):
    receipt = load(directory / 'acceptance.json')
    require(receipt['passed'] is True and receipt['source_unchanged'] is True and
            receipt['kind'] in ('native', 'guest') and receipt['original_timeout_seconds'] == 60,
            'successful source-stable cohort with original execution deadline')
    inputs = load(directory / 'source-inputs.json')
    source = receipt['source']
    require(source['files'] == len(inputs) and 1600 <= len(inputs) < 10000 and
            digest(directory / 'source.zip') == source['source_zip_sha256'] and
            digest(directory / 'source-inputs.json') == source['source_inputs_sha256'], 'complete original source fingerprints')
    require(all(not Path(name).is_absolute() and '..' not in Path(name).parts and
                not set(Path(name).parts) & {'.git', '.local', 'build', 'downloads'} for name in inputs),
            'public source boundary excludes private records')
    with zipfile.ZipFile(directory / 'source.zip') as archive:
        require(len(archive.namelist()) == len(inputs) and set(archive.namelist()) == set(inputs) and
                sum(item.file_size for item in archive.infolist()) <= 128 * 1024 * 1024 and
                all(hashlib.sha256(archive.read(name)).hexdigest() == value for name, value in inputs.items()),
                'every complete archived source member')
        script_source = archive.read('userspace/tests/net/configuration.sh')
    native = receipt['kind'] == 'native'
    if native:
        requested = receipt['requested']
        require(len(requested) == len(set(requested)) and set(requested) <= {'native', 'static', 'dynamic'} and
                [row['profile'] for row in receipt['results']] == requested,
                'complete requested native profile identities')
        if complete:
            require(requested == ['native', 'static', 'dynamic'], 'all three native linkages')
        for row in receipt['results']:
            profile = row['profile']
            selected = directory / profile
            require(load(selected / 'results.json') == row and row['passed'] is True and row['returncode'] == 0 and
                    not row['missing'] and row['runtime_unchanged'] is True and row['kernel']['release'] and
                    row['namespace_inode'] > 0 and row['pid'] > 0, 'actual private Linux execution')
            require(digest(selected / 'client.log') == row['log_sha256'] and
                    digest(selected / 'maps.txt') == row['maps_sha256'], 'original native log and process maps')
            maps = (selected / 'maps.txt').read_text()
            require('program.elf' in maps and all(Path(name).parts[0] == 'runtime' and
                    '..' not in Path(name).parts and digest(selected / name) == value['sha256'] and
                    value['source'] in maps and str(value['inode']) in maps for name, value in row['runtime'].items()),
                    'original mapped runtime provider bytes')
            if profile == 'native':
                require(any('libc.so' in value['source'] for value in row['runtime'].values()), 'actual mapped GNU libc')
            require(row['command'][-1] == '--native' and Path(row['command'][-2]).name == 'program.elf' and
                    len(row['command']) == (3 if profile == 'dynamic' else 2), 'exact retained native program command')
            program(selected, profile, row['products'], inputs)
            observations((selected / 'client.log').read_text(), True)
    else:
        requested = receipt['requested']
        profiles = ['static', 'dynamic'] if requested['linkage'] == 'both' else [requested['linkage']]
        firmwares = ['bios', 'uefi'] if requested['firmware'] == 'both' else [requested['firmware']]
        transports = ['modern', 'legacy'] if requested['transport'] == 'both' else [requested['transport']]
        expected = {(profile, firmware, transport) for profile in profiles for firmware in firmwares for transport in transports}
        actual = [(row['linkage'], row['firmware'], row['transport']) for row in receipt['results']]
        require(set(receipt['profiles']) == set(profiles) and len(actual) == len(set(actual)) and set(actual) == expected,
                'complete requested guest matrix')
        if complete:
            require(len(actual) == 8, 'all eight firmware, transport and linkage boots')
        require(digest(directory / 'kernel.elf') == receipt['kernel_sha256'], 'actual retained kernel')
        for profile, metadata in receipt['profiles'].items():
            selected = directory / profile
            program(selected, profile, metadata, inputs)
            require(digest(selected / 'image.iso') == metadata['image_sha256'] and
                    digest(selected / 'root.cpio') == metadata['root_sha256'], 'original guest image and initramfs')
            script = ('export AXIOM64_CONFIGURATION_PROGRAM=' + PROGRAMS[profile] + '\n').encode() + script_source
            expected_bindings = {'sbin/init', 'bin/busybox', 'bin/' + PROGRAMS[profile]}
            if profile == 'dynamic':
                expected_bindings.add('lib/ld-musl-x86_64.so.1')
            require(set(metadata['bindings']) == expected_bindings and
                    metadata['bindings']['bin/' + PROGRAMS[profile]] == metadata['products']['program.elf'] and
                    (profile != 'dynamic' or metadata['bindings']['lib/ld-musl-x86_64.so.1'] == metadata['products']['loader.elf']),
                    'boot products are the same compiler-bound executable and loader')
            audit = audit_fixture(selected / 'image.iso', receipt['kernel_sha256'], metadata['bindings'], script, metadata['root_sha256'])
            require(audit == metadata['image_audit'], 'independently reopened executable image')
        for row in receipt['results']:
            selected = directory / row['linkage']
            log = selected / row['log']
            require(load(log.with_suffix('.json')) == row and row['passed'] is True and row['returncode'] == 1 and
                    row['timed_out'] is False and not row['missing'] and row['actual_firmware_and_adapters'] is True and
                    digest(log) == row['log_sha256'], 'actual successful guest process')
            text = log.read_text()
            require(all(marker in text for marker in ('Firmware: ' + row['firmware'].upper(),
                    'virtio-net: index=1 transport=' + row['transport'], 'e1000: index=2 model=82540EM')),
                    'observed firmware and physical adapter identities')
            observations(text, False)
    return dict(passed=True, kind=receipt['kind'], profiles=len(receipt['results']),
                source_files=len(inputs), original_journals=8 * len(receipt['results']))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('directory', type=Path)
    parser.add_argument('--complete', action='store_true')
    args = parser.parse_args()
    print(json.dumps(verify(args.directory.resolve(), args.complete)), flush=True)


if __name__ == '__main__':
    main()
