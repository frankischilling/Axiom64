# SPDX-License-Identifier: GPL-3.0-or-later
"""Reopen IPv4 option source, programs, images and original TCP observations."""
import argparse
import hashlib
import json
from pathlib import Path, PurePosixPath
import re
import struct
import zipfile

from disk_root import archive_entries
from tcp_fixture_inputs import audit_fixture
from ipv4_options.fixtures import LEGACY_SOCKET, SOCKET, socket_table_bytes
from ipv4_options.native_policy import verify_policy


def require(value, message):
    if not value:
        raise ValueError(message)


def digest(path):
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def load(path):
    require(path.is_file() and not path.is_symlink() and path.stat().st_size < 16 * 1024 * 1024,
            'bounded original JSON record')
    return json.loads(path.read_text())


def checksum(data):
    data += b'\0' if len(data) % 2 else b''
    value = sum(struct.unpack('!' + str(len(data) // 2) + 'H', data))
    while value >> 16:
        value = (value & 65535) + (value >> 16)
    return (~value) & 65535


def option(kind, visits=0):
    if kind < 3:
        return (b'', b'\1' * 4, bytes.fromhex('94040000'))[kind]
    size = 36 if kind == 5 else 32
    result = bytearray(size)
    result[:4] = bytes((7 if kind == 3 else 68, 31 if kind == 3 else size,
                        (4 if kind == 3 else 5) + visits * (8 if kind == 5 else 4), int(kind == 5)))
    for at in range(visits):
        if kind in (3, 5):
            offset = (3 if kind == 3 else 4) + at * (8 if kind == 5 else 4)
            result[offset:offset + 4] = bytes((127, 0, 0, 1))
    return bytes(result)


def expected_options(actual, kind, visits):
    expected = option(kind, visits)
    require(len(actual) == len(expected), 'exact response option length')
    normalized = bytearray(actual)
    if kind in (4, 5):
        for at in range(visits):
            offset = 4 + at * (8 if kind == 5 else 4) + (4 if kind == 5 else 0)
            require(int.from_bytes(actual[offset:offset + 4], 'big') < 86400000,
                    'bounded UTC milliseconds in every recorded timestamp slot')
            normalized[offset:offset + 4] = bytes(4)
    require(bytes(normalized) == expected, 'complete processed option bytes and pointer')


def packet(data):
    require(40 <= len(data) <= 2048 and data[0] >> 4 == 4 and data[9] == 6 and
            int.from_bytes(data[2:4], 'big') == len(data) and
            data[12:20] == bytes((127, 0, 0, 1)) * 2 and not int.from_bytes(data[6:8], 'big') & 0xbfff,
            'complete loopback TCP packet framing and addressing')
    header = (data[0] & 15) * 4
    require(20 <= header <= 60 and header + 20 <= len(data), 'bounded actual IPv4 header')
    original = bytearray(data[:header])
    at = 20
    while at < header:
        kind = original[at]
        if kind == 0:
            break
        if kind == 1:
            at += 1
            continue
        require(at + 2 <= header and 2 <= original[at + 1] <= header - at, 'bounded captured IP option')
        size = original[at + 1]
        if kind in (7, 68):
            require(size >= (3 if kind == 7 else 4), 'complete route or timestamp option')
            stride = 8 if kind == 68 and original[at + 3] & 15 == 1 else 4
            pointer = original[at + 2]
            require(pointer > stride and pointer - 1 <= size, 'actual received option pointer')
            original[at + 2] -= stride
            start = at + original[at + 2] - 1
            original[start:start + stride] = bytes(stride)
        at += size
    require(checksum(bytes(original)) == 0, 'original input IP checksum before local option mutation')
    tcp = data[header:]
    require(20 <= (tcp[12] >> 4) * 4 <= len(tcp) and all(int.from_bytes(tcp[at:at + 2], 'big')
            for at in (0, 2)), 'complete captured TCP header and ports')
    return dict(data=data, options=data[20:header], tcp=tcp, flags=tcp[13] & 63,
                ports=struct.unpack_from('!HH', tcp), sequence=int.from_bytes(tcp[4:8], 'big'),
                acknowledgement=int.from_bytes(tcp[8:12], 'big'))


def transport(item):
    pseudo = bytes((127, 0, 0, 1)) * 2 + bytes((0, 6)) + len(item['tcp']).to_bytes(2, 'big')
    require(checksum(pseudo + item['tcp']) == 0, 'actual reset or TIME-WAIT TCP checksum')


def tcp_observations(text):
    require('IPV4_TCP_OPTIONS_FAIL' not in text and
            text.count('IPV4_TCP_OPTIONS_PASS scopes=2 cases=36') == 1, 'actual complete TCP option execution')
    groups = {}
    pattern = (r'^IPV4_TCP_OPTIONS_BYTES uid=(\d+) phase=([a-z-]+) case=(\d+) '
               r'label=([a-z-]+) length=(\d+) bytes=([0-9a-f]*)$')
    matches = list(re.finditer(pattern, text, re.M))
    require(len(matches) == text.count('IPV4_TCP_OPTIONS_BYTES '), 'every TCP observation is serialized completely')
    for match in matches:
        uid, phase, sample, label, length, encoded = match.groups()
        require(int(uid) in (0, 65534) and 0 <= int(sample) < 6 and label in ('packet', 'query', 'replayed-fin'),
                'known TCP observation identity')
        data = bytes.fromhex(encoded)
        require(len(data) == int(length), 'complete serialized TCP observation bytes')
        groups.setdefault((int(uid), phase, int(sample)), []).append((label, data))
    expected_groups = set()
    packets = 0
    for uid in (0, 65534):
        marker = (f'IPV4_TCP_OPTIONS_SCOPE_PASS uid={uid} reset_cases=6 listener_cases=6 time_wait_cases=6 '
                  'time_wait_retained=3 time_wait_compacted=3 raw_protocols=261')
        require(text.count(marker) == 1 and text.count('IPV4_TCP_OPTIONS_SCOPE_PASS ') == 2,
                'both complete credential scopes and both TIME-WAIT forms')
        for sample in range(6):
            time_wait = 'time-wait-compacted' if sample % 2 else 'time-wait-retained'
            phases = {}
            for phase in ('reset', 'listener', 'close', time_wait):
                key = uid, phase, sample
                expected_groups.add(key)
                require(key in groups, 'all actual reset, accepted and TIME-WAIT cases')
                rows = groups[key]
                phases[phase] = ([packet(data) for label, data in rows if label == 'packet'],
                                 [data for label, data in rows if label == 'query'],
                                 [data for label, data in rows if label == 'replayed-fin'])
                packets += len(phases[phase][0])
            reset, queries, replay = phases['reset']
            require(len(reset) == 2 and len(queries) == 1 and queries[0] == option(sample) and not replay,
                    'reset preserves the initiating description value')
            syn, response = reset
            require(syn['flags'] == 2 and response['flags'] == 20 and response['ports'] == syn['ports'][::-1] and
                    response['sequence'] == 0 and response['acknowledgement'] == (syn['sequence'] + 1) % 2**32,
                    'reset replies to its actual triggering SYN')
            expected_options(response['options'], sample if sample >= 3 else 0, 4)
            transport(response)
            accepted, queries, replay = phases['listener']
            require(len(accepted) == 2 and len(queries) == 5 and not replay, 'complete original accepted snapshots')
            syn, response = accepted
            require(syn['flags'] == 2 and response['flags'] == 18 and response['ports'] == syn['ports'][::-1] and
                    response['acknowledgement'] == (syn['sequence'] + 1) % 2**32,
                    'accepted reply belongs to the observed original SYN')
            expected_options(response['options'], sample if sample >= 3 else 0, 4)
            owned = syn['options'] if sample >= 3 else b''
            require(queries == [owned, owned, option(1), option(1), option(2)],
                    'accepted value owns its original SYN independently of listener and child setters')
            closing, queries, replay = phases['close']
            require(closing and not queries and not replay, 'actual close packets precede the TIME-WAIT replay')
            replies, queries, replay = phases[time_wait]
            require(len(replies) == 2 and not queries and len(replay) == 1, 'one actual FIN replay and its response')
            trigger, response = replies
            require(trigger['flags'] == 17 and response['flags'] == 16 and
                    trigger['ports'] == syn['ports'] and response['ports'] == trigger['ports'][::-1] and
                    response['acknowledgement'] == (trigger['sequence'] + 1) % 2**32 and
                    response['sequence'] == trigger['acknowledgement'] and replay[0] == trigger['tcp'],
                    'TIME-WAIT acknowledgment answers the actual replayed FIN and sequence range')
            require(any(item['ports'] == trigger['ports'] and item['tcp'][:16] == trigger['tcp'][:16] and
                        item['tcp'][18:] == trigger['tcp'][18:] for item in closing),
                    'replayed FIN bytes originate in the observed close')
            expected_options(response['options'], 4 if sample == 3 else 3, 4)
            transport(trigger)
            transport(response)
    require(set(groups) == expected_groups, 'exact complete TCP observation case matrix')
    return dict(cases=36, packets=packets, retained_time_wait=6, compacted_time_wait=6)


def socket_observations(text):
    scopes = [f'IPV4_OPTIONS_SCOPE_PASS protocol={protocol} privileged={privileged} observations=7110'
              for protocol in ('udp', 'tcp', 'raw') for privileged in (1, 0)]
    require(all(text.count(value) == 1 for value in scopes) and text.count('IPV4_OPTIONS_SCOPE_PASS ') == 6 and
            text.count('IPV4_OPTIONS_PASS protocols=3 observations=42660 scopes=6') == 1 and
            all(text.count(f'IPV4_OPTIONS_WIRE_PASS cases=8 uid={uid} ') == 1 for uid in (0, 65534)) and
            'IPV4_OPTIONS_FAIL' not in text, 'complete original option syscalls and loopback packet observations')


def compilation(path, program, source, inputs, profile):
    compiled = load(path)
    require(compiled['product'] == dict(bytes=program.stat().st_size, sha256=digest(program)) and
            compiled['sources'].get(source) == inputs[source] and
            all(inputs.get(name) == value for name, value in compiled['sources'].items()) and
            [name for name in compiled['command'] if name.endswith('.c')] == [source] and
            ('-static' in compiled['command']) == (profile == 'static'), 'actual compiler product and complete public inputs')


def verify(directory):
    record = load(directory / 'results.json')
    require(record['passed'] is True and record['native_profiles'] == 3 and record['guest_profiles'] == 4 and
            record['native_executions'] == 6 and record['guest_boots'] == 4 and
            record['socket_observations_each'] == 42660 and record['actual_loopback_wire_cases_each'] == 16 and
            record['tcp_response_cases_each'] == 36 and record['ethernet_and_full_feature_acceptance'] is False,
            'complete bounded local cohort without a full-feature claim')
    frozen = directory / 'source'
    inputs = load(frozen / 'source-inputs.json')
    source = record['source']
    require(source['files'] == len(inputs) and 1600 <= len(inputs) < 10000 and
            source['source_inputs_sha256'] == digest(frozen / 'source-inputs.json') and
            source['source_zip_sha256'] == digest(frozen / 'source.zip'), 'complete original source fingerprints')
    with zipfile.ZipFile(frozen / 'source.zip') as archive:
        require(len(archive.infolist()) == len(inputs) and set(archive.namelist()) == set(inputs) and
                archive.testzip() is None, 'all original source archive members and CRCs')
        for name, fingerprint in inputs.items():
            path = PurePosixPath(name)
            require(not path.is_absolute() and '..' not in path.parts and '\\' not in name and
                    not set(path.parts) & {'.local', '.git', 'build', 'downloads', '__pycache__'} and
                    hashlib.sha256(archive.read(name)).hexdigest() == fingerprint,
                    'complete public source member bytes and boundary')
        for field, name in (('socket_fixture_sha256', SOCKET.name),
                            ('legacy_socket_fixture_sha256', LEGACY_SOCKET.name),
                            ('receive_fixture_sha256', 'ipv4-options-receive-linux6687.json.gz')):
            require(inputs['scripts/tests/fixtures/' + name] == record[field], 'actual pinned native corpus bytes')
        tables = {name: socket_table_bytes(archive.read('scripts/tests/fixtures/' + name))
                  for name in (SOCKET.name, LEGACY_SOCKET.name)}
    require(digest(directory / 'options-oracle.tsv') == record['table_sha256'], 'original executed option table')
    require((directory / 'options-oracle.tsv').read_bytes() == tables[SOCKET.name],
            'guest executes the complete fixed current Linux option table')
    policy = load(directory / 'native-policy.json')
    native_fixture = verify_policy(policy)
    require(digest(directory / 'native-policy.json') == record['native_policy_sha256'] and
            native_fixture.name == record['native_fixture'] and
            digest(directory / 'native-options-oracle.tsv') == record['native_table_sha256'] and
            (directory / 'native-options-oracle.tsv').read_bytes() == tables[native_fixture.name],
            'actual fixed native policy probes select one complete retained table')
    executions = {}
    for result in record['executions']:
        require(result['status'] == 'completed' and 0 < result['elapsed_ns'] < 120 * 10**9,
                'completed actual process inside original deadline')
        if result['native']:
            require(result['suites'] in (['socket'], ['tcp']) and result['profile'] in ('native', 'static', 'dynamic') and
                    result['returncode'] == 0 and result['kernel'] == policy['kernel'] and
                    result['native_fixture'] == native_fixture.name, 'actual native profile identity, policy and exit')
            name = 'linux-' + result['suites'][0] + '-' + result['profile']
        else:
            require(result['suites'] == ['socket', 'tcp'] and result['profile'] in ('static', 'dynamic') and
                    result['firmware'] in ('bios', 'uefi') and result['returncode'] == 1,
                    'actual guest profile identity and QEMU exit')
            name = result['profile'] + '-' + result['firmware']
        require(name not in executions and load(directory / name / 'results.json') == result,
                'one unchanged original result for every actual execution')
        executions[name] = result
    expected = {'linux-' + suite + '-' + profile for suite in ('socket', 'tcp') for profile in ('native', 'static', 'dynamic')}
    expected |= {profile + '-' + firmware for profile in ('static', 'dynamic') for firmware in ('bios', 'uefi')}
    require(set(executions) == expected, 'all six native processes and four guest boots')
    images, tcp, native_loaders, guest_loaders = [], {}, set(), set()
    script = b'#!/bin/sh\nset -e\n/bin/ipv4-options /etc/options-oracle.tsv && /bin/ipv4-tcp-options\necho AXIOM64_TESTS_PASS\n'
    for name, result in executions.items():
        case = directory / name
        process = load(case / 'process.json')
        require(all(result.get(key) == value for key, value in process.items()) and
                digest(case / 'client.log') == result['log_sha256'] and
                digest(case / 'program.elf') == result['program_sha256'], 'original process, log and executable bytes')
        text = (case / 'client.log').read_text()
        require('PANIC:' not in text and 'Page fault' not in text, 'no guest kernel failure')
        if 'socket' in result['suites']:
            socket_observations(text)
        if 'tcp' in result['suites']:
            tcp[name] = tcp_observations(text)
        profile = result['profile']
        if result['native']:
            runtime = result['runtime']
            command = load(case / 'command.json')
            program_at = int(profile == 'dynamic')
            program_name = 'ipv4-' + ('tcp-options' if result['suites'] == ['tcp'] else 'options') + '-' + profile
            require(len(command) == 1 + program_at + int(result['suites'] == ['socket']) and
                    Path(command[program_at]).name == program_name and runtime['executable'] == command[0],
                    'actual native command selects its observed executable and client')
            if result['suites'] == ['socket']:
                require(Path(command[-1]).name == 'native-options-oracle.tsv' and
                        Path(command[-1]).parent.name == directory.name,
                        'actual native socket command selects its complete retained policy table')
            require(runtime['maps_sha256'] == digest(case / 'runtime-maps.txt'), 'actual native mapped-runtime observation')
            maps = (case / 'runtime-maps.txt').read_text()
            mapped_paths = {line.split(None, 5)[-1] for line in maps.splitlines() if len(line.split(None, 5)) == 6}
            require(command[program_at] in mapped_paths and command[0] in mapped_paths,
                    'both commanded program and executable occur in actual process mappings')
            require(Path(runtime['executable']).name == ('ld-musl-x86_64.so.1' if profile == 'dynamic' else
                    'ipv4-' + ('tcp-options' if result['suites'] == ['tcp'] else 'options') + '-' + profile),
                    'observed native executable matches its selected linkage')
            for path, provider in runtime['providers'].items():
                require(PurePosixPath(path).parent == PurePosixPath('runtime') and
                        digest(case / path) == provider['sha256'] and any(
                            line.split(None, 5)[-1] == provider['source'] and line.split()[4] == str(provider['inode'])
                            for line in maps.splitlines() if len(line.split(None, 5)) == 6),
                        'retained bytes belong to actual mapped provider inodes')
            require(profile != 'native' or any(Path(value['source']).name == 'libc.so.6'
                    for value in runtime['providers'].values()), 'native GNU libc provider is retained')
            if profile != 'native':
                compilation(case / 'program.inputs.json', case / 'program.elf',
                            'userspace/tests/net/ipv4/' + ('tcp_options.c' if result['suites'] == ['tcp'] else 'options.c'), inputs, profile)
            if profile == 'dynamic':
                require((case / 'loader.elf').is_file(), 'actual dynamic native loader retained')
                native_loaders.add(digest(case / 'loader.elf'))
        else:
            require(text.count('Firmware: ' + result['firmware'].upper()) == 1 and
                    text.count('AXIOM64_TESTS_PASS') == 1 and text.count('AXIOM64_EXIT status=0') == 1 and
                    result['kernel_sha256'] == record['kernel_sha256'] and
                    set(result['products']) == {'kernel.elf', 'root.cpio', 'image.iso'} and
                    all(digest(case / path) == value for path, value in result['products'].items()) and
                    digest(case / 'kernel.elf') == record['kernel_sha256'] and
                    digest(case / 'tcp-program.elf') == result['tcp_program_sha256'], 'actual guest firmware and retained boot products')
            compilation(case / 'program.inputs.json', case / 'program.elf', 'userspace/tests/net/ipv4/options.c', inputs, profile)
            compilation(case / 'tcp-program.inputs.json', case / 'tcp-program.elf', 'userspace/tests/net/ipv4/tcp_options.c', inputs, profile)
            products = load(case / 'products.json')
            command = load(case / 'command.json')
            require(command[0] == 'qemu-system-x86_64' and command[command.index('-nic') + 1] == 'none' and
                    Path(command[command.index('-cdrom') + 1]).parent.name == name and
                    Path(command[command.index('-cdrom') + 1]).name == 'image.iso' and
                    any('pflash' in item for item in command) == (result['firmware'] == 'uefi'),
                    'recorded guest boot command selects the actual image and requested firmware')
            entries = archive_entries(case / 'root.cpio')
            required = {'sbin/init', 'bin/busybox', 'lib/ld-musl-x86_64.so.1', 'bin/ipv4-options',
                        'bin/ipv4-tcp-options', 'etc/options-oracle.tsv', 'kernel.elf', 'root.cpio', 'image.iso'}
            require(set(products) == required, 'complete original fixture products')
            for path, value in products.items():
                data = entries[path][1] if path in entries else (case / path).read_bytes()
                require(value == dict(bytes=len(data), sha256=hashlib.sha256(data).hexdigest()), 'actual complete fixture member bytes')
            require(entries['etc/options-oracle.tsv'][1] == (directory / 'options-oracle.tsv').read_bytes() and
                    products['bin/ipv4-options']['sha256'] == result['program_sha256'] and
                    products['bin/ipv4-tcp-options']['sha256'] == result['tcp_program_sha256'], 'both actual clients and table inside initramfs')
            executables = {path: products[path]['sha256'] for path in required if path.startswith(('bin/', 'sbin/', 'lib/'))}
            images.append(audit_fixture(case / 'image.iso', record['kernel_sha256'], executables, script,
                                        result['products']['root.cpio']))
            guest_loaders.add(products['lib/ld-musl-x86_64.so.1']['sha256'])
    require(len(guest_loaders) == 1 and native_loaders == guest_loaders,
            'native dynamic clients and all guest images retain the same actual musl loader')
    return dict(passed=True, source_files=len(inputs), native_executions=6, actual_images_opened=images,
                tcp=tcp, ethernet_and_full_feature_acceptance=False)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('directory', type=Path)
    parser.add_argument('--output', type=Path)
    args = parser.parse_args()
    record = verify(args.directory)
    if args.output:
        args.output.write_text(json.dumps(record, indent=2) + '\n')
    print(json.dumps(record))


if __name__ == '__main__':
    main()
