# SPDX-License-Identifier: GPL-3.0-or-later
"""Exercise production forwarding ownership with ASan and fatal UBSan."""
import argparse
import copy
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import zipfile

from fetch import ROOT
from ipv4_source_route.controls import decode, require
from ipv4_source_route.corpus import cases, option_fields
from ipv4_source_route.packets import normalized
from ipv4_source_route.queues import canonical_ip, definitions
from tcp6.inputs import digest, freeze, write


def specifications():
    rows = [('packets', row, row['name'] if row['kind'] == 'held' else '') for row in cases()]
    rows += [('queues', row, ('held-egress-alias' if row['prepare_alias'] else 'held-' + row['mutation'])
              if row['kind'] == 'held' else 'unanswered-arp')
             for row in definitions()]
    for name in ('egress-address', 'down', 'mtu'):
        row = copy.deepcopy(next(row for row in cases() if row['name'] == 'held-' + name))
        rows.append(('packets', row, 'reentrant-' + name))
    rows.append(('queues', definitions()[0], 'reentrant-egress-alias'))
    require(len(rows) == 67, 'all packet queue and reentrant ownership model cases')
    return rows


def read(log, phase, row, mutation):
    text = log.read_text()
    output, retries = [], []
    intervals = dict(early=(1000, 1000), late=(4000, 4000))
    for line in text.splitlines():
        if not line.startswith('{'):
            continue
        value = decode(line)
        require(set(value) == {'index', 'frame'} and type(value['index']) is int and value['index'] in (1, 2),
                'actual model output and adapter')
        frame = bytes.fromhex(value['frame'])
        require(len(frame) >= 14, 'complete model Ethernet header')
        if frame[12:14] == b'\x08\x06' and value['index'] == 2:
            retries.append(frame)
        if frame[12:14] != b'\x08\x00':
            continue
        if phase == 'queues':
            length = int.from_bytes(frame[16:18], 'big')
            output.append(dict(index=value['index'] - 1, ethernet=frame[:14].hex(),
                               ip=canonical_ip(frame[14:14 + length], 'wire-error', row, intervals)))
        else:
            for at, kind, _ in option_fields(frame[14:]):
                if kind == 68:
                    stamp = 14 + at + frame[14 + at + 2] - 5
                    require(int.from_bytes(frame[stamp:stamp + 4], 'big') == 1000,
                            'explicit model timestamp stub')
            output.append((value['index'] - 1, *normalized(frame, reference=True)))
    raw = [line.split(' data=')[1] for line in text.splitlines() if line.startswith('IPV4_SOURCE_ROUTE_RAW ')]
    require(text.splitlines().count(f'IPV4_SOURCE_ROUTE_MODEL raw_deliveries={len(raw)}') == 1,
            'complete model raw delivery count')
    if phase == 'queues':
        expected = row['expected']
        actual = dict(output=output, raw=[canonical_ip(bytes.fromhex(value),
                      'input-raw' if n == 0 else 'local-error', row, intervals) for n, value in enumerate(raw)])
        require(actual == expected, 'all production queue model packets and raw bytes match native Linux')
        if row['suppress_arp']:
            require(len(retries) == 3, 'three model neighbor retries at original logical ticks')
    else:
        expected = [(value['index'], *normalized(value['frame'], reference=True)) for value in row['expected']]
        require(output == expected and raw == row['raw_inputs'], 'every production model packet and raw byte matches native Linux')
    if mutation.startswith('held-'):
        require(len(retries) == 1 and retries[0][:42] == bytes.fromhex(row['arp_request'])[:42],
                'actual model held next-hop request')
    require(text.splitlines().count('IPV4_SOURCE_ROUTE_BORROWED_STORAGE_RETAINED') == int(mutation.startswith('reentrant-')),
            'borrowed storage survives each reentrant invalidation callback')
    return dict(packets=len(output), raw_packets=len(raw))


def verify(directory):
    directory = Path(directory)
    saved = decode((directory / 'completed.json').read_text())
    inputs = decode((directory / 'source-inputs.json').read_text())
    source = saved['source']
    require(digest(directory / 'source.zip') == source['source_zip_sha256'] and
            digest(directory / 'source-inputs.json') == source['source_inputs_sha256'], 'exact original model source archive')
    with zipfile.ZipFile(directory / 'source.zip') as archive:
        require(len(archive.namelist()) == source['files'] == len(inputs) and set(archive.namelist()) == set(inputs),
                'complete model source inventory')
        for name, expected_hash in inputs.items():
            require(hashlib.sha256(archive.read(name)).hexdigest() == expected_hash, 'every original model source byte')
    require(saved['passed'] is True and saved['source_stable'] is True and
            saved['physical_clock_acceptance'] is False and saved['stub_clock_ms'] == 1000 and
            digest(directory / 'program') == saved['program_sha256'], 'exact sanitized model and explicit clock boundary')
    records = saved['results']
    expected = specifications()
    require(len(records) == len(expected) == 67, 'complete sanitized model inventory')
    for number, ((phase, row, mutation), record) in enumerate(zip(expected, records)):
        log = directory / f'{number:02d}.log'
        require(record['case'] == number and type(record['case']) is int and record['phase'] == phase and
                record['name'] == row['name'] and record['mutation'] == mutation and record['returncode'] == 0 and
                type(record['returncode']) is int and digest(log) == record['log_sha256'] and
                record['observations'] == read(log, phase, row, mutation), 'exact original successful model case')
    return dict(passed=True, cases=67, physical_clock_acceptance=False, allocations_and_reentrant_lifetimes_checked=True,
                program_sha256=saved['program_sha256'])


def produce(directory):
    directory = Path(directory)
    require(directory.resolve().is_relative_to((ROOT / 'build').resolve()), 'designated ignored model output')
    directory.mkdir(parents=True, exist_ok=False)
    source = freeze(directory)
    with (directory / 'build.log').open('xb') as stream:
        subprocess.run(['make', '-s', '-j4', 'build/ipv4-source-route-host'], cwd=ROOT, stdin=subprocess.DEVNULL,
                       stdout=stream, stderr=subprocess.STDOUT, check=True)
    shutil.copy2(ROOT / 'build/ipv4-source-route-host', directory / 'program')
    results = []
    for number, (phase, row, mutation) in enumerate(specifications()):
        policy = row['policy']
        forward = policy.get('forwarding', 1)
        command = [str(directory / 'program'), str(policy.get('all_source', 1)), str(policy.get('link_source', 1)),
                   str(forward), str(policy.get('link_forwarding', forward))]
        environment = dict(os.environ, ASAN_OPTIONS='detect_leaks=1', UBSAN_OPTIONS='halt_on_error=1:print_stacktrace=1',
                           IPV4_SOURCE_ROUTE_MUTATION=mutation)
        with (directory / f'{number:02d}.log').open('xb') as stream:
            result = subprocess.run(command, cwd=ROOT, input=('\n'.join(row['transmitted']) + '\n').encode(),
                                    stdout=stream, stderr=subprocess.STDOUT, env=environment, timeout=30)
        require(result.returncode == 0, 'sanitized production forwarding model process success')
        log = directory / f'{number:02d}.log'
        results.append(dict(case=number, phase=phase, name=row['name'], mutation=mutation, returncode=result.returncode,
                            log_sha256=digest(log), observations=read(log, phase, row, mutation)))
        write(directory / 'results.json', results)
    inputs = decode((directory / 'source-inputs.json').read_text())
    require(all(digest(ROOT / name) == value for name, value in inputs.items()), 'unchanged complete model source')
    write(directory / 'completed.json', dict(passed=True, source=source, source_stable=True,
          program_sha256=digest(directory / 'program'), stub_clock_ms=1000, physical_clock_acceptance=False, results=results))
    proof = verify(directory)
    write(directory / 'verified.json', proof)
    return proof


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('directory', type=Path)
    parser.add_argument('--produce', action='store_true')
    args = parser.parse_args()
    print(json.dumps(produce(args.directory) if args.produce else verify(args.directory)), flush=True)


if __name__ == '__main__':
    main()
