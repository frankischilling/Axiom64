# SPDX-License-Identifier: GPL-3.0-or-later
"""Reopen actual source-route packets, source clocks, raw records and products."""
import argparse
import json
from pathlib import Path
import re
import zipfile

from ipv4_source_route.artifacts import compilation, providers
from ipv4_source_route.controls import decode, fingerprint, require
from ipv4_source_route.corpus import cases, option_fields
from ipv4_source_route.packets import CLOCK_BOUND_NS, client_trace, clocks, normalized
from tcp6.inputs import digest
from tcp_fixture_inputs import audit_fixture

CLIENT = 'userspace/tests/net/ipv4/source_route_wire.c'


def integer(value, minimum=0):
    require(type(value) is int and minimum <= value < 1 << 63, 'bounded actual integer observation')
    return value


def router(frame, index):
    return frame[6:12] == bytes((2, 0, 0, 0, 0, index + 1))


def observations(text, wire, results, native):
    definitions = cases()
    raw = client_trace(text, definitions, native)
    require(type(wire) is list and type(results) is list and len(results) == len(definitions),
            'complete actual packet observation matrix')
    previous = -1
    for value in wire:
        require(set(value) == {'case', 'index', 'direction', 'frame', 'monotonic_ns', 'realtime_ns', 'packet_type'} and
                type(value['case']) is int and 0 <= value['case'] < len(definitions) and
                type(value['index']) is int and value['index'] in (0, 1) and
                value['direction'] in ('input', 'output') and
                isinstance(value['frame'], str) and re.fullmatch(r'[0-9a-f]{28,131106}', value['frame']) and
                len(value['frame']) % 2 == 0, 'complete bounded original Ethernet observation')
        integer(value['realtime_ns'])
        now = integer(value['monotonic_ns'])
        require(now >= previous, 'ordered original packet monotonic observations')
        previous = now
        packet_type = value['packet_type']
        require(packet_type is None or
                (native and value['direction'] == 'output' and type(packet_type) is int and 0 <= packet_type <= 4),
                'actual native packet-socket metadata')
    total = 0
    for number, (row, result) in enumerate(zip(definitions, results)):
        require(set(result) == {'name', 'case', 'packets', 'matched_native_reference', 'input_began_ns',
                               'input_realtime_ns', 'observation_began_ns', 'observation_seconds', 'ended_ns',
                               'raw_inputs', 'source_clocks', 'clock_request_ns', 'clock_response_ns',
                               'timestamp_receipts'} and
                result['name'] == row['name'] and type(result['case']) is int and result['case'] == number,
                'exact ordered complete case result')
        began = integer(result['input_began_ns'])
        observed = integer(result['observation_began_ns'])
        ended = integer(result['ended_ns'])
        integer(result['input_realtime_ns'])
        seconds = 5 if row['kind'] == 'held' else 1
        require(type(result['observation_seconds']) is int and result['observation_seconds'] == seconds and
                began <= observed <= ended and ended - observed >= seconds * 1000000000,
                'original full one/five-second observations')
        source = clocks(text, number, len(definitions))
        require(result['source_clocks'] == source, 'actual client source clocks match the retained observations')
        before = source['before']['realtime_ns'] // 1000000
        after = source.get('after', {}).get('realtime_ns', 0) // 1000000
        values = [value for value in wire if value['case'] == number]
        inputs = [value for value in values if value['direction'] == 'input' and value['frame'][24:28] == '0800']
        require([value['frame'] for value in inputs] == row['transmitted'] and
                all(value['index'] == 0 and began <= value['monotonic_ns'] <= observed for value in inputs),
                'every original input byte, identifier, fragment and ingress')
        actual, timestamps, requests = [], [], []
        for value in values:
            frame, index = bytes.fromhex(value['frame']), value['index']
            if value['direction'] != 'output' or not router(frame, index):
                continue
            if frame[12:14] == b'\x08\x06':
                require(len(frame) >= 42 and frame[14:22] == bytes.fromhex('0001080006040001') and
                        frame[38:42] == bytes((10, index, 0, 2)), 'actual expected next-hop ARP request')
                requests.append(value)
            elif frame[12:14] == b'\x08\x00':
                require(began <= value['monotonic_ns'] <= ended, 'actual output within its full observation')
                actual.append((index, *normalized(frame, source_before_ms=before, source_after_ms=after)))
                if any(kind == 68 for _, kind, _ in option_fields(frame[14:])):
                    timestamps.append(value['monotonic_ns'])
        expected = [(value['index'], *normalized(value['frame'], reference=True)) for value in row['expected']]
        require(actual == expected, 'every actual Ethernet and IPv4 output matches the independent native bytes')
        require(type(result['packets']) is int and result['packets'] == len(actual) and
                result['matched_native_reference'] is True and
                raw[number] == row['raw_inputs'] == result['raw_inputs'], 'actual wire/raw bytes and declared counts')
        require(result['timestamp_receipts'] == timestamps, 'original timestamp output receipts')
        if row['clocked']:
            requested = integer(result['clock_request_ns'])
            response = integer(result['clock_response_ns'])
            require(timestamps and timestamps[0] <= requested <= response <= ended and
                    response - timestamps[0] <= CLOCK_BOUND_NS,
                    'actual prompt source-clock response within the original one-second bound')
        else:
            require(result['clock_request_ns'] is result['clock_response_ns'] is None and not timestamps,
                    'no invented source-clock request')
        if row['kind'] == 'held':
            require(requests and requests[0]['frame'][:84] == row['arp_request'][:84],
                    'actual complete held next-hop request')
        total += len(actual)
    if not native:
        lines = text.replace('\r\n', '\n').splitlines()
        require(lines.count('AXIOM64_TESTS_PASS') == lines.count('AXIOM64_EXIT status=0') == 1,
                'successful actual guest process and init')
    return dict(cases=len(definitions), packets=total, raw_packets=sum(map(len, raw)),
                timestamp_cases=sum(row['clocked'] for row in definitions))


def snapshot(directory, binding):
    source = directory / 'source'
    require(digest(source / 'source.zip') == binding['source_zip_sha256'] and
            digest(source / 'source-inputs.json') == binding['source_inputs_sha256'], 'exact complete source snapshot')
    inputs = decode((source / 'source-inputs.json').read_text())
    require(type(binding['files']) is int and len(inputs) == binding['files'], 'complete source inventory count')
    with zipfile.ZipFile(source / 'source.zip') as archive:
        require(len(archive.namelist()) == len(inputs) and set(archive.namelist()) == set(inputs),
                'source inventory and exact archive membership')
        for name, expected in inputs.items():
            path = Path(name)
            require(path.parts and not path.is_absolute() and '..' not in path.parts and
                    '\\' not in name and ':' not in path.parts[0] and path.as_posix() == name and
                    path.parts[0] not in ('.git', '.local', 'build', 'downloads') and
                    fingerprint(archive.read(name)) == expected, 'bounded public source name and actual bytes')
    for name in ('corpus.py', 'packets.json', 'packets.py'):
        require(inputs.get('scripts/ipv4_source_route/' + name) == digest(Path(__file__).with_name(name)),
                'same complete fixed native fixture and packet decoding rules')
    return inputs


def verify(directory, *, definitions=None, observe=None):
    directory = Path(directory)
    definitions = cases() if definitions is None else definitions
    observe = observations if observe is None else observe
    receipt = decode((directory / 'completed.json').read_text())
    require(receipt['mode'] in ('native', 'guest') and receipt['profile'] in ('native', 'static', 'dynamic') and
            receipt['passed'] is receipt['source_stable'] is True and receipt['full_source_route_acceptance'] is False,
            'completed actual campaign with its explicit acceptance boundary')
    native, profile = receipt['mode'] == 'native', receipt['profile']
    require(native or profile != 'native', 'target musl guest linkage')
    inputs = snapshot(directory, receipt['source'])
    require(digest(directory / 'controller.py') == receipt['controller_sha256'] and
            digest(directory / 'program') == receipt['program_sha256'], 'exact producer and executable bytes')
    compilation(directory, inputs, profile, CLIENT)
    process = decode((directory / 'process.json').read_text())
    require(process['status'] == 'completed' and type(process['returncode']) is int and
            process['returncode'] == (0 if native else 1) and
            process['log_sha256'] == digest(directory / 'client.log'), 'actual terminal process and original log')
    integer(process['elapsed_ns'], 1)
    command = decode((directory / 'command.json').read_text())
    if native:
        runtime = decode((directory / 'runtime.json').read_text())
        require(type(runtime['namespace']) is int and type(runtime['parent_namespace']) is int and
                runtime['namespace'] != runtime['parent_namespace'] and
                runtime['maps_sha256'] == digest(directory / 'runtime-maps.txt') and
                command[0] == runtime['executable'] and command[-1] == str(len(definitions)),
                'actual private namespace and mapped native executable')
        maps = (directory / 'runtime-maps.txt').read_text()
        require(command[-2] in maps and bool(runtime['providers']) == (profile != 'static'), 'actual native linkage')
        providers(directory, runtime, maps, profile, command[:-1], command[0])
    else:
        products = decode((directory / 'products.json').read_text())
        require(command[0] == 'qemu-system-x86_64' and '-cdrom' in command and
                Path(command[command.index('-cdrom') + 1]).name == 'image.iso' and
                not any('icount' in value or value == '-rtc' for value in command), 'actual guest and unchanged clocks')
        require(all(digest(directory / name) == products[name]['sha256'] for name in ('image.iso', 'root.cpio', 'kernel.elf')) and
                products['bin/ipv4-source-wire']['sha256'] == digest(directory / 'program'), 'actual guest products and client')
        executables = {name: value['sha256'] for name, value in products.items()
                       if name not in ('image.iso', 'root.cpio', 'kernel.elf')}
        script = f'#!/bin/sh\nset -e\n/bin/ipv4-source-wire {len(definitions)}\necho AXIOM64_TESTS_PASS\n'.encode()
        audit_fixture(directory / 'image.iso', products['kernel.elf']['sha256'], executables, script,
                      products['root.cpio']['sha256'])
    proof = observe((directory / 'client.log').read_text(), decode((directory / 'wire.json').read_text()),
                    decode((directory / 'results.json').read_text()), native)
    require(type(receipt['cases']) is int and receipt['cases'] == proof['cases'], 'complete declared campaign count')
    return dict(passed=True, mode=receipt['mode'], profile=profile, **proof,
                source=receipt['source'], program_sha256=receipt['program_sha256'], full_source_route_acceptance=False)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('directory', type=Path)
    args = parser.parse_args()
    print(json.dumps(verify(args.directory)), flush=True)


if __name__ == '__main__':
    main()
