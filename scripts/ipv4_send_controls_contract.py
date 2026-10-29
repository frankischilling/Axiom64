# SPDX-License-Identifier: GPL-3.0-or-later
"""Reopen the complete IPv4 send-control cohort and its actual execution inputs."""
import argparse
import hashlib
import json
from pathlib import Path
import zipfile

from disk_root import archive_entries
from ipv4_receive_wire_inputs import digest, load
from ipv4_send_controls_records import require, verify as records
from tcp_fixture_inputs import audit_fixture

CLIENT = 'userspace/tests/net/ipv4_send_controls.c'
DONE = 'IPV4_SEND_CONTROLS_DONE cases=384 observations=768'
PROFILES = {'linux-' + profile for profile in ('native', 'static', 'dynamic')}
PROFILES |= {profile + '-' + firmware for profile in ('static', 'dynamic') for firmware in ('bios', 'uefi')}


def sources(directory, receipt):
    source = receipt['source']
    require(digest(directory / 'source.zip') == source['source_zip_sha256'] and
            digest(directory / 'source-inputs.json') == source['source_inputs_sha256'],
            'original complete source fingerprints')
    inputs = load(directory / 'source-inputs.json')
    require(len(inputs) == source['files'] and 1673 <= len(inputs) < 10000 and CLIENT in inputs and
            all(not Path(name).is_absolute() and '..' not in Path(name).parts and
                not set(Path(name).parts) & {'.git', '.local', 'build', 'downloads'} for name in inputs),
            'complete public source boundary')
    with zipfile.ZipFile(directory / 'source.zip') as archive:
        require(len(archive.namelist()) == len(inputs) and set(archive.namelist()) == set(inputs) and
                sum(item.file_size for item in archive.infolist()) <= 128 * 1024 * 1024,
                'unique bounded complete source archive')
        require(all(hashlib.sha256(archive.read(name)).hexdigest() == value for name, value in inputs.items()),
                'every archived source member fingerprint')
    return inputs


def mapped(directory, row):
    require(digest(directory / 'maps.txt') == row['maps_sha256'], 'original live process maps')
    lines = [line.split(None, 5) for line in (directory / 'maps.txt').read_text().splitlines()]
    paths = {fields[5]: int(fields[4]) for fields in lines if len(fields) == 6 and fields[5].startswith('/')}
    require(row['executed_program'] in paths and paths[row['executed_program']] == row['program_inode'],
            'retained program was mapped by the actual client')
    if row['profile'] == 'dynamic':
        require(row['executed_loader'] in paths and paths[row['executed_loader']] == row['loader_inode'],
                'actual retained dynamic loader mapping')
    runtime = row['runtime']
    require(row['runtime_unchanged'] is True and all(
        Path(name).parts[0] == 'runtime' and '..' not in Path(name).parts and
        paths.get(value['source']) == value['inode'] and digest(directory / name) == value['sha256']
        for name, value in runtime.items()), 'original mapped runtime provider bytes and inodes')
    require((any('libc.so' in value['source'] for value in runtime.values()) and
             any('ld-linux' in value['source'] for value in runtime.values())) if row['profile'] == 'native'
            else not runtime, 'actual selected libc provider')
    configuration = load(directory / 'native-configuration.json')
    require(configuration['namespace_inode'] > 0 and configuration['kernel']['sysname'] == 'Linux' and
            configuration['kernel']['release'] and len(configuration['links']) == 1 and
            configuration['links'][0]['ifname'] == 'lo' and 'UP' in configuration['links'][0]['flags'] and
            all(value['ifname'] == 'lo' for value in configuration['addresses']) and not configuration['routes'],
            'actual isolated loopback namespace and native kernel')
    return configuration['kernel']['release']


def case(directory, row, inputs, kernel):
    native, profile = row['native'], row['profile']
    require(type(native) is bool and profile in ('native', 'static', 'dynamic') and
            (native or profile != 'native'), 'actual supported execution profile')
    firmware = None if native else row['firmware']
    label = 'linux-' + profile if native else profile + '-' + firmware
    require(row['label'] == label and row['passed'] is True and row['status'] == 'completed' and
            row['returncode'] == (0 if native else 1) and row['timed_out'] is False and row['pid'] > 0 and
            row['timeout_seconds'] == (30 if native else 120) and
            0 < row['elapsed_ns'] < row['timeout_seconds'] * 1000000000,
            'successful original process within unchanged deadline')
    require(load(directory / 'process.json') == {name: row[name] for name in
            ('pid', 'status', 'returncode', 'timed_out', 'elapsed_ns', 'timeout_seconds')},
            'terminal original process record')
    require(digest(directory / 'client.log') == row['log_sha256'], 'original common client observations')
    text = (directory / 'client.log').read_text()
    checked = records(text)
    program = (directory / 'program.elf').read_bytes()
    compiled = load(directory / 'program.inputs.json')
    require(program[:6] == b'\x7fELF\x02\x01' and compiled['product'] ==
            dict(bytes=len(program), sha256=hashlib.sha256(program).hexdigest()) and
            compiled['sources'] == {CLIENT: inputs[CLIENT]} and
            [value for value in compiled['command'] if value.endswith(('.c', '.cpp'))] == [CLIENT] and
            ('-static' in compiled['command']) == (profile == 'static') and
            compiled['command'][-2:] == ['-o', 'build/ipv4-send-controls-' + profile],
            'actual compile binds the complete common C client and selected linkage')
    products = {'program.elf', 'program.inputs.json'} | ({'loader.elf'} if profile == 'dynamic' else set())
    if not native:
        products |= {'kernel.elf', 'image.iso', 'root.cpio'}
    require(set(row['products']) == products and all(digest(directory / name) == value
            for name, value in row['products'].items()), 'complete actual execution product fingerprints')
    command = load(directory / 'command.json')
    require(command == row['command'], 'original executed command')
    if native:
        execution = ([row['executed_loader']] if profile == 'dynamic' else []) + [row['executed_program']]
        require(command[:2] == ['unshare', '--net'] and command[-len(execution):] == execution and
                Path(execution[-1]).name == 'program.elf' and
                (profile != 'dynamic' or Path(execution[0]).name == 'loader.elf'), 'exact retained native execution')
        checked['native_kernel_release'] = mapped(directory, row)
    else:
        require(firmware in ('bios', 'uefi') and text.splitlines().count('Firmware: ' + firmware.upper()) == 1 and
                text.splitlines().count('AXIOM64_TESTS_PASS') == 1 and 'AXIOM64_EXIT status=0' in text and
                not any(value in text for value in ('PANIC:', 'FAULT pid=')), 'actual complete requested guest boot')
        require(command[0] == 'qemu-system-x86_64' and command[command.index('-nic') + 1] == 'none' and
                Path(command[command.index('-cdrom') + 1]).name == 'image.iso' and
                command[command.index('-cpu') + 1] == 'max', 'actual isolated guest boot command')
        drives = [command[at + 1] for at, value in enumerate(command[:-1]) if value == '-drive']
        require((len(drives) == 2 and 'readonly=on' in drives[0] and 'OVMF_CODE_4M.fd' in drives[0] and
                drives[1].endswith('/OVMF_VARS.fd')) if firmware == 'uefi' else not drives,
                'actual selected firmware command')
        require(row['products']['kernel.elf'] == kernel, 'one immutable guest kernel')
        entries = archive_entries(directory / 'root.cpio')
        products_record = load(directory / 'products.json')
        names = {'sbin/init', 'bin/busybox', 'bin/ipv4-send-controls', 'lib/ld-musl-x86_64.so.1'}
        require(set(products_record) == names | {'kernel.elf', 'image.iso', 'root.cpio'}, 'complete guest product inventory')
        for name, value in products_record.items():
            data = entries[name][1] if name in names else (directory / name).read_bytes()
            require(value == dict(bytes=len(data), sha256=hashlib.sha256(data).hexdigest()), 'actual guest product bytes')
        bindings = {name: products_record[name]['sha256'] for name in names}
        require(bindings['bin/ipv4-send-controls'] == row['products']['program.elf'] and
                (profile != 'dynamic' or bindings['lib/ld-musl-x86_64.so.1'] == row['products']['loader.elf']),
                'guest executes the compiler-bound program and loader')
        audit_fixture(directory / 'image.iso', kernel, bindings,
                      b'#!/bin/sh\nset -e\n/bin/ipv4-send-controls\necho AXIOM64_TESTS_PASS\n',
                      row['products']['root.cpio'])
    return dict(label=label, **checked)


def verify(directory):
    receipt = load(directory / 'acceptance.json')
    require(receipt['passed'] is True and receipt['source_unchanged'] is True and
            set(receipt['cases']) == PROFILES and len(receipt['cases']) == 7, 'complete three-native/four-guest cohort')
    inputs = sources(directory, receipt)
    values = []
    for label in receipt['cases']:
        require(label in PROFILES, 'bounded original case path')
        values.append(case(directory / label, load(directory / label / 'results.json'), inputs, receipt['kernel_sha256']))
    require({row['label'] for row in values} == PROFILES, 'unique complete actual execution grid')
    return dict(passed=True, profiles=7, original_cases_each=384, observations_each=768,
                actual_kernel_sha256=receipt['kernel_sha256'], source=receipt['source'],
                native_kernels={row['label']: row['native_kernel_release'] for row in values if row['label'].startswith('linux-')},
                full_feature_acceptance=False)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--directory', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    result = verify(args.directory)
    args.output.write_text(json.dumps(result, indent=2) + '\n')
    print(json.dumps(result), flush=True)
