# SPDX-License-Identifier: GPL-3.0-or-later
"""Independently qualify a complete IPv4 Ethernet metadata comparison cohort."""
import argparse
import hashlib
import json
from pathlib import Path
import shutil
import struct
import subprocess
import tempfile
import zipfile

from ipv4_receive_wire_inputs import digest, load, verify as inputs
from ipv4_receive_wire_packets import verify as packets
from ipv4_receive_wire_records import read, require


def verify(directory):
    metadata = load(directory / 'results.json')
    records = read((directory / 'client.log').read_text(), metadata['native'], metadata['firmware'])
    captures = [packets(directory, lane, metadata['native'], metadata['capture_statistics'][lane]
                if metadata['native'] else None) for lane in range(2)]
    checked, sources = inputs(directory)
    if metadata['native']:
        config = load(directory / 'native-configuration.json')
        require(records['indices'] == [item['ifindex'] for item in config['interfaces'][1:]] and
                records['identity']['release'] == metadata['native_kernel_release'], 'native kernel and TAP identity binding')
    return dict(directory=str(directory), native=metadata['native'], profile=metadata['profile'],
                firmware=metadata['firmware'], transport=metadata['transport'], source=metadata['source'],
                products=metadata['products'], observations=records['observations'], indices=records['indices'],
                captures=captures, source_inputs=sources)


def cohort(values):
    expected = {(True, profile, 'bios', 'modern') for profile in ('native', 'static', 'dynamic')}
    expected |= {(False, profile, firmware, transport) for profile in ('static', 'dynamic')
                 for firmware in ('bios', 'uefi') for transport in ('modern', 'legacy')}
    require(len(values) == 11 and {(item['native'], item['profile'], item['firmware'], item['transport'])
                for item in values} == expected, 'complete distinct three-native/eight-guest cohort')
    reference = values[0]
    for item in values:
        require(item['source_inputs'] == reference['source_inputs'], 'same complete corresponding source for every profile')
        for actual, original in zip(item['observations'], reference['observations']):
            expected_row = dict(original, index=item['indices'][original['lane']])
            data = bytearray.fromhex(expected_row['control_hex'])
            if original['prepared']:
                struct.pack_into('<I', data, 16, expected_row['index'])
            expected_row['control_hex'] = data.hex()
            require(actual == expected_row, 'native/guest control-byte equality with only actual ingress index mapping')
    guests = [item for item in values if not item['native']]
    require(len({item['products']['kernel.elf'] for item in guests}) == 1, 'one unchanged actual guest kernel')
    return dict(passed=True, profiles=11, native_profiles=3, guest_profiles=8, receives_each=156,
                address_route_inventories_each=180, physical_data_packets_each=156,
                physical_barriers_each=936, kernel_sha256=guests[0]['products']['kernel.elf'],
                only_actual_ingress_index_mapping=True, full_feature_acceptance=False)


def observations(data, kind, predicate, change):
    lines = data.decode().splitlines()
    for at, line in enumerate(lines):
        if line.startswith('{'):
            row = json.loads(line)
            if row.get('kind') == kind and predicate(row):
                change(row)
                lines[at] = json.dumps(row, separators=(',', ':'))
                return ('\n'.join(lines) + '\n').encode()
    raise ValueError('negative control has no actual original observation')


def change_control(row, offset, data):
    value = bytearray.fromhex(row['control_hex'])
    value[offset:offset + len(data)] = data
    row['control_hex'] = value.hex()


def remove_barrier(data):
    frames = json.loads(data)
    for at, item in enumerate(frames):
        if bytes.fromhex(item['data'])[12:14] == b'\x88\xb9':
            del frames[at]
            return json.dumps(frames).encode()
    raise ValueError('negative control has no actual barrier')


def damaged(directory, values, destination):
    receive = lambda predicate, change: lambda data: observations(data, 'receive-wire', predicate, change)
    at = lambda scenario: lambda row: row['lane'] == 0 and row['prepared'] == 1 and row['scenario'] == scenario
    changes = [
        ('receive-flags', 'client.log', receive(at(0), lambda row: row.update(flags=8))),
        ('receive-size', 'client.log', receive(at(0), lambda row: row.update(result=15))),
        ('control-size', 'client.log', receive(at(0), lambda row: row.update(control_length=79))),
        ('packet-payload', 'client.log', receive(at(0), lambda row: row.update(payload='00' * 16))),
        ('weak-host-ingress', 'client.log', receive(at(9), lambda row: change_control(row, 16, struct.pack('<I', 99)))),
        ('alias-retirement-specific-destination', 'client.log', receive(at(10), lambda row: change_control(row, 20, bytes(4)))),
        ('prefix-retirement-specific-destination', 'client.log', receive(at(11), lambda row: change_control(row, 20, b'\x0a\x4d\x01\x02'))),
        ('route-replacement-specific-destination', 'client.log', receive(at(12), lambda row: change_control(row, 20, b'\x0a\x4d\x01\x02'))),
        ('broadcast-destination', 'client.log', receive(at(3), lambda row: change_control(row, 24, b'\x0a\x4d\x01\x02'))),
        ('packet-ttl', 'client.log', receive(at(0), lambda row: change_control(row, 48, bytes(4)))),
        ('packet-tos', 'client.log', receive(at(0), lambda row: change_control(row, 72, b'\0'))),
        ('alignment-padding', 'client.log', receive(at(0), lambda row: change_control(row, 28, bytes(4)))),
        ('late-preparation', 'client.log', receive(lambda row: row['lane'] == 0 and row['case'] == 0,
             lambda row: change_control(row, 16, struct.pack('<I', row['index'])))),
        ('firmware', 'client.log', lambda data: data.replace(b'Firmware: BIOS', b'Firmware: UEFI')),
        ('failed-boot', 'client.log', lambda data: data.replace(b'AXIOM64_EXIT status=0', b'AXIOM64_EXIT status=1')),
        ('missing-receive', 'client.log', lambda data: b'\n'.join(line for line in data.splitlines()
             if not (line.startswith(b'{"kind":"receive-wire"') and b'"case":77,' in line)) + b'\n'),
        ('false-state-summary', 'client.log', lambda data: observations(data, 'state', lambda row: row['phase'] == 1,
             lambda row: row.update(index=99))),
        ('raw-dump-status', 'client.log', lambda data: observations(data, 'inventory', lambda row: row['phase'] == 1,
             lambda row: row.update(hex=row['hex'][:-2] + '01'))),
        ('program-bytes', 'program.elf', lambda data: data[:-1] + bytes([data[-1] ^ 1])),
        ('source-archive', 'source.zip', lambda data: bytes([data[0] ^ 1]) + data[1:]),
        ('kernel-bytes', 'kernel.elf', lambda data: data[:-1] + bytes([data[-1] ^ 1])),
        ('boot-image', 'image.iso', lambda data: data[:32768] + b'\0' * 2048 + data[34816:]),
        ('missing-control-barrier', 'lane0-frames.json', remove_barrier),
        ('capture-packet', 'lane0.pcap', lambda data: data.replace(b'AXRXDATA', b'AXRXDATB', 1)),
        ('wrong-transport', 'results.json', lambda data: json.dumps(dict(json.loads(data), transport='legacy')).encode()),
        ('compile-input', 'program.inputs.json', lambda data: json.dumps(dict(json.loads(data), sources={})).encode()),
    ]
    rejected = []
    with zipfile.ZipFile(destination, 'x', compression=zipfile.ZIP_DEFLATED) as archive:
        for label, name, change in changes:
            original = (directory / name).read_bytes()
            altered = change(original)
            require(altered != original, 'negative control must change an actual input: ' + label)
            archive.writestr(label + '/' + name, altered)
            with tempfile.TemporaryDirectory(prefix='axiom-ipv4-wire-control-') as temporary:
                scratch = Path(temporary) / 'case'
                shutil.copytree(directory, scratch)
                target = scratch / name
                target.unlink()
                target.write_bytes(altered)
                try:
                    verify(scratch)
                except (ValueError, KeyError, TypeError, IndexError, struct.error, zipfile.BadZipFile, subprocess.CalledProcessError):
                    rejected.append(label)
                else:
                    raise ValueError('altered original was accepted: ' + label)
        changed = [values[0]] * 11
        archive.writestr('duplicate-cohort.json', json.dumps([item['directory'] for item in changed]))
        try:
            cohort(changed)
        except ValueError:
            rejected.append('duplicate-cohort')
        else:
            raise ValueError('duplicate cohort was accepted')
    return rejected


def protected(directories):
    result = {}
    for directory in directories:
        for path in sorted(directory.rglob('*')):
            require(not path.is_symlink(), 'original evidence contains no external links')
            if path.is_file():
                info = path.stat()
                result[str(path)] = dict(sha256=digest(path), bytes=info.st_size, uid=info.st_uid,
                                        gid=info.st_gid, mode=info.st_mode & 0o7777)
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--case', type=Path, action='append', required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--damaged', type=Path, required=True)
    args = parser.parse_args()
    require(len({path.resolve() for path in args.case}) == 11, 'eleven distinct original evidence directories')
    before = protected(args.case)
    values = [verify(path) for path in args.case]
    result = cohort(values)
    guest = next(path for path, item in zip(args.case, values) if not item['native'] and
                 item['profile'] == 'static' and item['firmware'] == 'bios' and item['transport'] == 'modern')
    result['serialized_controls_rejected'] = damaged(guest, values, args.damaged)
    require(protected(args.case) == before, 'all original evidence bytes, owners and modes unchanged')
    result['protected_inputs'] = before
    result['source'] = values[0]['source']
    args.output.write_text(json.dumps(result, indent=2) + '\n')
    print(json.dumps({key: value for key, value in result.items() if key != 'protected_inputs'}), flush=True)
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
