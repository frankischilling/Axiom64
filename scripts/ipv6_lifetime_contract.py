# SPDX-License-Identifier: GPL-3.0-or-later
"""Compare raw address lifetimes and source choices with an executed Linux reference."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import struct
import zipfile
from fetch import ROOT
from ipv6_extension_execution import verify_execution
from ipv6_lifetime_capture import records as wire_records

SOURCE = 'userspace/tests/net/ipv6_address_lifetimes.c'
HOST = 'userspace/tests/net/ipv6_host.c'
FIXTURE = ROOT / 'scripts/tests/fixtures/ipv6-address-lifetimes-linux7.json'
PREFIX = 'IPV6_LIFETIME_'
FIELDS = {'lane', 'case', 'kind', 'result', 'present', 'prefix', 'flags', 'cache',
          'preferred', 'valid', 'cstamp', 'tstamp', 'raw'}


def require(value, reason):
    if not value:
        raise ValueError(reason)


def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def fields(line, marker, wanted):
    pairs = [word.split('=', 1) for word in line.removeprefix(marker).split()]
    require(all(len(pair) == 2 for pair in pairs), 'complete lifetime fields')
    row = dict(pairs)
    require(len(pairs) == len(row) and set(row) == wanted, 'exact lifetime field inventory')
    return row


def cache_values(row):
    require(re.fullmatch('[0-9a-f]{32}', row['raw']), 'complete raw cacheinfo bytes')
    values = [int(row[key]) for key in ('preferred', 'valid', 'cstamp', 'tstamp')]
    require(all(0 <= value <= 0xffffffff for value in values), '32-bit lifetime cache fields')
    require(bytes.fromhex(row['raw']) == struct.pack('<IIII', *values),
            'every raw cacheinfo byte matches its decoded fields')
    require(row['present'] in ('0', '1'), 'address presence')
    if row['present'] == '1':
        require(row['cache'] == '1' and 0 < values[2] <= values[3] and
                values[2] not in (0x12345678, 0x87654321) and
                values[3] not in (0x12345678, 0x87654321), 'kernel-created address timestamps')
    else:
        require(row['cache'] == '0' and not any(values), 'absent address has no cacheinfo')
    return values


def finite_remaining(row, elapsed):
    remaining = max(0, 8 - elapsed // 1000000000)
    require(int(row['preferred']) == 0 and max(0, remaining - 1) <= int(row['valid']) <= remaining,
            'remaining lifetime follows original elapsed time without renewal')


def records(text):
    require(PREFIX + 'FAIL' not in text and text.splitlines().count(
        PREFIX + 'DONE cases=58 samples=6') == 1, 'all original lifetime observations completed')
    rows, sources, times, samples = [], [], [], []
    births, temporal = {}, {}
    for line in text.splitlines():
        if line.startswith(PREFIX + 'CASE '):
            row = fields(line, PREFIX + 'CASE ', FIELDS)
            require(all(re.fullmatch('-?[0-9]+', row[key]) for key in FIELDS - {'kind', 'raw'}),
                    'integer lifetime observation')
            at, lane = len(rows), len(rows) // 29
            require(at < 58 and (int(row['case']), int(row['lane'])) == (at, lane),
                    'all ordered lifetime cases on both adapters')
            position = at % 29
            kind = ('lifetime' if position < 9 else 'create' if position < 15 else
                    'replace' if position < 21 else 'cache-size' if position < 26 else 'temporal')
            require(row['kind'] == kind, 'original lifetime case kind')
            values = cache_values(row)
            if row['present'] == '1':
                births.setdefault(lane, values[2])
                if kind == 'temporal':
                    require(temporal.setdefault(lane, values[2:]) == values[2:],
                            'observation does not renew address birth or update time')
            if position == 27:
                require(times and times[-1]['lane'] == str(lane) and times[-1]['stage'] == '1',
                        'deprecation observation has its original elapsed sample')
                finite_remaining(row, int(times[-1]['elapsed_ns']))
                require(row['present'] == '1' and row['flags'] == '34' and int(row['valid']) > 0,
                        'deprecated address remains valid before expiry')
                row['valid'] = 'elapsed'
            rows.append({key: value for key, value in row.items() if key not in ('raw', 'cstamp', 'tstamp')})
        elif line.startswith(PREFIX + 'SOURCE '):
            row = fields(line, PREFIX + 'SOURCE ',
                         {'lane', 'stage', 'result', 'errno', 'got', 'get_errno', 'length', 'address'})
            at = len(sources)
            require(at < 6 and (int(row['lane']), int(row['stage'])) == (at // 3, at % 3),
                    'all ordered source choices')
            require(re.fullmatch('[0-9a-f]{32}', row['address']), 'complete selected source bytes')
            require(all(re.fullmatch('-?[0-9]+', value) for key, value in row.items() if key != 'address'),
                    'integer source observations')
            sources.append(row)
        elif line.startswith(PREFIX + 'TIME '):
            row = fields(line, PREFIX + 'TIME ', {'lane', 'stage', 'elapsed_ns'})
            require(all(re.fullmatch('[0-9]+', value) for value in row.values()), 'real elapsed sample')
            at = len(times)
            require(at < 6 and (int(row['lane']), int(row['stage'])) == (at // 3, at % 3),
                    'all ordered elapsed observations')
            require(int(row['elapsed_ns']) >= (0, 4200000000, 9200000000)[at % 3],
                    'configured preferred and valid lifetimes remain real elapsed observations')
            if at % 3:
                require(int(row['elapsed_ns']) <= (8000000000 if at % 3 == 1 else 15000000000),
                        'bounded observed deprecation and deletion')
            times.append(row)
        elif line.startswith(PREFIX + 'SAMPLE '):
            row = fields(line, PREFIX + 'SAMPLE ',
                         {'lane', 'stage', 'elapsed_ns', 'present', 'prefix', 'flags', 'cache',
                          'preferred', 'valid', 'cstamp', 'tstamp', 'raw'})
            require(all(re.fullmatch('[0-9]+', value) for key, value in row.items() if key != 'raw'),
                    'integer scheduled lifetime observations')
            at = len(samples)
            require(at < 6 and (int(row['lane']), int(row['stage'])) == (at // 3, at % 3),
                    'all scheduled observations remain visible')
            elapsed = int(row['elapsed_ns'])
            require(elapsed >= (0, 4200000000, 9200000000)[at % 3], 'original fixed observation times')
            values = cache_values(row)
            if at % 3 == 0:
                require(row['present'] == '1' and row['flags'] == '2' and values[:2] == [2, 8],
                        'finite address begins preferred with its original lifetimes')
            else:
                finite_remaining(row, elapsed)
                if at % 3 == 1:
                    require(row['present'] == '1' and int(row['valid']) > 0, 'preferred sample precedes valid expiry')
            if row['present'] == '1':
                require(row['prefix'] == '96' and row['flags'] in ('2', '34'), 'scheduled finite-address state')
                lane = at // 3
                require(temporal.setdefault(lane, values[2:]) == values[2:], 'sampling cannot renew address clocks')
            samples.append(row)
    require(len(rows) == 58 and len(sources) == len(times) == len(samples) == 6, 'complete lifetime matrix')
    require(set(births) == set(temporal) == {0, 1} and
            (births[1] - births[0]) % (1 << 32) >= 900, 'address timestamps advance across the real first interval')
    return dict(rows=rows, sources=sources, samples=samples, transitions=times)


def fixture():
    saved = json.loads(FIXTURE.read_text())
    reference = saved['reference']
    require(saved['schema'] == 3 and reference['kernel'] == '7.0.0-1017-azure' and
            reference['actual_program_completed'] and reference['actual_cpio_reopened'] and
            reference['complete_host_client'] and reference['source_sha256'] == digest(ROOT / SOURCE) and
            reference['host_source_sha256'] == digest(ROOT / HOST), 'executed complete source-bound Linux7 lifetime reference')
    require(len(saved['observations']['rows']) == 58 and len(saved['observations']['sources']) == 6,
            'complete Linux7 reference inventory')
    return saved


def verify_log(text):
    saved = fixture()
    actual = records(text)
    wire = wire_records(text)
    require(saved['reference']['wire_observations'] == len(wire) == 18 and
            [{key: value for key, value in row.items() if key != 'elapsed_ns'} for row in wire] ==
            saved['wire_observations'], 'wire observations differ from executed complete Linux7 client')
    require({key: actual[key] for key in ('rows', 'sources')} == saved['observations'],
            'lifetime observations differ from executed Linux7')
    return dict(passed=True, address_cases=58, source_cases=6, actual_timestamps_validated=True,
                raw_cacheinfo_bytes=16, real_valid_seconds=8, scheduled_samples=actual['samples'],
                bounded_transitions=actual['transitions'], packet_clock_acceptance=False)


def compare(native_directory, guest_directory, output):
    saved = fixture()
    paths = [(True, native_directory / profile / 'client.log') for profile in ('native', 'static', 'dynamic')]
    paths += [(False, guest_directory / f'{linkage}-{firmware}-{transport}' / 'guest.log')
              for linkage in ('static', 'dynamic') for firmware in ('bios', 'uefi') for transport in ('modern', 'legacy')]
    require(len({str(path) for _, path in paths}) == 11, 'eleven distinct complete clients')
    originals = {str(path): digest(path) for _, path in paths}
    output.mkdir(parents=True, exist_ok=False)
    rejected, proofs = [], []
    with zipfile.ZipFile(output / 'damaged.zip', 'x', zipfile.ZIP_DEFLATED) as archive:
        for number, (native, path) in enumerate(paths):
            verify_execution(path, native, SOURCE, saved['reference']['source_sha256'])
            verify_execution(path, native, HOST, saved['reference']['host_source_sha256'])
            text = path.read_text()
            proofs.append(dict(path=str(path), native=native, audit=verify_log(text)))
            lines = text.splitlines()
            case_at = next(at for at, line in enumerate(lines) if line.startswith(PREFIX + 'CASE '))
            source_at = next(at for at, line in enumerate(lines) if line.startswith(PREFIX + 'SOURCE '))
            time_at = next(at for at, line in enumerate(lines) if line.startswith(PREFIX + 'TIME lane=0 stage=1 '))
            sample_at = next(at for at, line in enumerate(lines) if line.startswith(PREFIX + 'SAMPLE lane=0 stage=1 '))
            for kind in ('missing-case', 'duplicate-case', 'case-order', 'result', 'preferred', 'valid', 'flags',
                         'raw-byte', 'birth-time', 'update-time', 'source-byte', 'short-observation', 'missing-completion',
                         'missing-sample', 'sample-raw-byte', 'sample-short-time', 'late-transition', 'renewed-clock'):
                changed = list(lines)
                if kind == 'missing-case': del changed[case_at]
                elif kind == 'duplicate-case': changed.insert(case_at, changed[case_at])
                elif kind == 'case-order': changed[case_at], changed[case_at + 1] = changed[case_at + 1], changed[case_at]
                elif kind == 'missing-completion': changed.remove(PREFIX + 'DONE cases=58 samples=6')
                elif kind == 'short-observation': changed[time_at] = PREFIX + 'TIME lane=0 stage=1 elapsed_ns=4199999999'
                elif kind == 'late-transition': changed[time_at] = PREFIX + 'TIME lane=0 stage=1 elapsed_ns=8000000001'
                elif kind == 'missing-sample': del changed[sample_at]
                elif kind in ('sample-raw-byte', 'sample-short-time', 'renewed-clock'):
                    row = fields(changed[sample_at], PREFIX + 'SAMPLE ',
                                 {'lane', 'stage', 'elapsed_ns', 'present', 'prefix', 'flags', 'cache',
                                  'preferred', 'valid', 'cstamp', 'tstamp', 'raw'})
                    if kind == 'sample-raw-byte': row['raw'] = 'ff' + row['raw'][2:]
                    elif kind == 'sample-short-time': row['elapsed_ns'] = '4199999999'
                    else:
                        row['tstamp'] = str(int(row['tstamp']) + 1)
                        row['raw'] = struct.pack('<IIII', *(int(row[key]) for key in
                            ('preferred', 'valid', 'cstamp', 'tstamp'))).hex()
                    changed[sample_at] = PREFIX + 'SAMPLE ' + ' '.join(key + '=' + value for key, value in row.items())
                elif kind == 'source-byte':
                    row = fields(changed[source_at], PREFIX + 'SOURCE ', set(saved['observations']['sources'][0]))
                    row['address'] = '00' * 16
                    changed[source_at] = PREFIX + 'SOURCE ' + ' '.join(key + '=' + value for key, value in row.items())
                else:
                    row = fields(changed[case_at], PREFIX + 'CASE ', FIELDS)
                    field = {'birth-time': 'cstamp', 'update-time': 'tstamp'}.get(kind, kind)
                    if kind == 'raw-byte': row['raw'] = ('ff' if row['raw'][:2] != 'ff' else '00') + row['raw'][2:]
                    else: row[field] = '0' if kind in ('birth-time', 'update-time') else str(int(row[field]) ^ 1)
                    changed[case_at] = PREFIX + 'CASE ' + ' '.join(key + '=' + value for key, value in row.items())
                archive.writestr(f'{number}-{kind}.log', '\n'.join(changed) + '\n')
    with zipfile.ZipFile(output / 'damaged.zip') as archive:
        for name in archive.namelist():
            try: verify_log(archive.read(name).decode())
            except ValueError as error: rejected.append(dict(name=name, reason=str(error)))
            else: raise ValueError('accepted serialized damaged lifetime observation: ' + name)
    require(len(rejected) == 198 and all(digest(Path(path)) == value for path, value in originals.items()),
            'all damaged lifetime controls rejected and originals unchanged')
    result = dict(passed=True, address_cases_each=58, source_cases_each=6, native_profiles=3, guest_profiles=8,
                  damaged_rejected=len(rejected), proofs=proofs, reference=saved['reference'],
                  original_sha256=originals, damaged_sha256=digest(output / 'damaged.zip'),
                  packet_clock_acceptance=False, full_F12_complete=False)
    (output / 'result.json').write_text(json.dumps(result, indent=2) + '\n')
    print('IPV6_LIFETIME_CONTRACT_PASS addresses=58 sources=6 native=3 guests=8 damaged=198', flush=True)
    return result


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--native-directory', type=Path, required=True)
    parser.add_argument('--guest-directory', type=Path, required=True)
    parser.add_argument('--output-directory', type=Path, required=True)
    arguments = parser.parse_args()
    compare(arguments.native_directory, arguments.guest_directory, arguments.output_directory)
