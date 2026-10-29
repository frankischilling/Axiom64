# SPDX-License-Identifier: GPL-3.0-or-later
"""Compare complete local extension observations with an executed Linux7 reference."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import zipfile
from ipv6_extension_execution import verify_execution

ROOT = Path(__file__).resolve().parents[1]
SOURCE = 'userspace/tests/net/ipv6_extension_controls.c'
FIXTURE = ROOT / 'scripts/tests/fixtures/ipv6-extension-controls-linux7.json'
PREFIX = 'IPV6_EXTENSION_LOCAL_CASE '


def require(value, reason):
    if not value:
        raise ValueError(reason)


def digest(path):
    with Path(path).open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def records(text):
    lines = text.replace('\r\n', '\n').splitlines()
    require(lines.count('IPV6_EXTENSION_LOCAL_DONE cases=256') == 1 and
            not any(line.startswith('IPV6_EXTENSION_LOCAL_FAIL') for line in lines),
            'complete original local extension execution')
    fields = {'case', 'raw', 'named', 'drop', 'variant', 'uid', 'hop_errno', 'destination_errno',
              'result', 'errno', 'received', 'receive_errno', 'flags', 'length', 'unchanged',
              'control', 'payload'}
    rows = []
    for line in lines:
        if not line.startswith(PREFIX):
            continue
        pairs = [field.split('=', 1) for field in line.removeprefix(PREFIX).split()]
        row = dict(pairs)
        require(len(pairs) == len(fields) and set(row) == fields and all(
            re.fullmatch('-?[0-9]+', row[key]) for key in fields - {'control', 'payload'}),
            'exact original extension observation fields')
        number = len(rows)
        require(tuple(int(row[key]) for key in ('case', 'raw', 'named', 'drop', 'variant')) ==
                (number, number // 128, number // 64 % 2, number // 32 % 2, number % 32),
                'ordered unique extension observation matrix')
        require(row['uid'] == ('65534' if int(row['drop']) else '0') and row['unchanged'] == '1',
                'actual ordinary identity and original input preservation')
        require(re.fullmatch('[0-9a-f]*', row['control']) is not None and
                re.fullmatch('[0-9a-f]{128}', row['payload']) is not None,
                'complete original control and payload bytes')
        require(len(row['control']) == (2 * int(row['length']) if int(row['received']) >= 0 else 0),
                'actual returned extension control length')
        rows.append(row)
    require(len(rows) == 256, 'all 256 original local extension observations')
    return rows


def fixture():
    saved = json.loads(FIXTURE.read_text())
    require(saved['schema'] == 1 and saved['reference']['kernel'] == '7.0.0-1017-azure' and
            saved['reference']['actual_program_completed'] is True and
            saved['reference']['actual_cpio_reopened'] is True and
            saved['reference']['source_sha256'] == digest(ROOT / SOURCE),
            'executed Linux7 extension reference bound to the current probe source')
    require(len(saved['rows']) == 256, 'complete saved Linux7 reference observations')
    # Run the same syntax/matrix checks on the frozen original reference rows.
    text = '\n'.join(PREFIX + ' '.join(key + '=' + value for key, value in row.items())
                     for row in saved['rows']) + '\nIPV6_EXTENSION_LOCAL_DONE cases=256\n'
    require(records(text) == saved['rows'], 'original reference row schema')
    return saved


def compare(native_paths, guest_paths, output):
    output = Path(output)
    output.mkdir(parents=True, exist_ok=False)
    saved = fixture()
    wanted = saved['rows']
    require(len(native_paths) == 3 and len(guest_paths) == 8, 'all native and guest extension profiles')
    require(len(set(map(str, [*native_paths, *guest_paths]))) == 11, 'distinct original extension profiles')
    original = {str(path): digest(path) for path in [*native_paths, *guest_paths]}
    profiles = []
    for native, paths in ((True, native_paths), (False, guest_paths)):
        for path in paths:
            verify_execution(path, native, SOURCE, saved['reference']['source_sha256'])
            rows = records(path.read_text())
            differences = [dict(case=n, fields={key: dict(reference=reference[key], actual=actual[key])
                                                for key in reference if reference[key] != actual[key]})
                           for n, (reference, actual) in enumerate(zip(wanted, rows)) if reference != actual]
            profiles.append(dict(path=str(path), native=native, differences=differences))
    require(all(not row['differences'] for row in profiles), 'native/guest extension rows differ from the executed Linux7 reference')
    names = ('missing-case', 'duplicate-case', 'admission-result', 'admission-error', 'control-byte',
             'control-length', 'control-flags', 'payload-byte', 'raw-checksum', 'untouched-tail',
             'ordinary-identity', 'input-changed', 'routing-result')
    rejected = []
    with zipfile.ZipFile(output / 'damaged.zip', 'w', zipfile.ZIP_DEFLATED) as archive:
        for profile, path in enumerate([*native_paths, *guest_paths]):
            text = path.read_text()
            for name in names:
                lines = text.splitlines()
                number = 1 if name.startswith('control-') else 128 if name == 'raw-checksum' else 32 if name == 'ordinary-identity' else 25 if name == 'routing-result' else 27 if name == 'admission-error' else 0
                at = next(n for n, line in enumerate(lines) if line.startswith(PREFIX + f'case={number} '))
                if name == 'missing-case':
                    del lines[at]
                elif name == 'duplicate-case':
                    lines.insert(at, lines[at])
                else:
                    row = dict(value.split('=', 1) for value in lines[at].removeprefix(PREFIX).split())
                    if name in ('control-byte', 'payload-byte', 'raw-checksum', 'untouched-tail'):
                        key = 'control' if name == 'control-byte' else 'payload'
                        data = bytearray.fromhex(row[key])
                        data[-1 if name == 'untouched-tail' else 2 if name == 'raw-checksum' else 0] ^= 1
                        row[key] = data.hex()
                    elif name == 'ordinary-identity':
                        row['uid'] = '0'
                    elif name == 'input-changed':
                        row['unchanged'] = '0'
                    else:
                        key = {'admission-result': 'result', 'admission-error': 'errno',
                               'control-length': 'length', 'control-flags': 'flags', 'routing-result': 'result'}[name]
                        row[key] = str(int(row[key]) ^ 1)
                    lines[at] = PREFIX + ' '.join(key + '=' + value for key, value in row.items())
                damaged = '\n'.join(lines) + '\n'
                archive.writestr(f'{profile}-{name}.log', damaged)
                try:
                    require(records(damaged) == wanted, 'changed Linux7 extension observation')
                except ValueError as failure:
                    rejected.append(dict(profile=profile, name=name, reason=str(failure)))
                else:
                    raise ValueError('accepted damaged local extension evidence: ' + name)
        archive.writestr('rejections.json', json.dumps(rejected, indent=2))
    require(all(digest(Path(name)) == value for name, value in original.items()), 'every original extension log remains unchanged')
    result = dict(passed=True, cases_each=256, native_profiles=3, guest_profiles=8, profiles=profiles,
                  damaged_rejected=len(rejected), reference_fixture_sha256=digest(FIXTURE), reference=saved['reference'],
                  original_sha256=original, native_packet_clock_acceptance=False, full_F12_complete=False)
    (output / 'result.json').write_text(json.dumps(result, indent=2) + '\n')
    print('IPV6_EXTENSION_LOCAL_CONTRACT_PASS cases_each=256 native=3 guests=8 damaged=143', flush=True)
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--native-directory', type=Path, required=True)
    parser.add_argument('--guest-directory', type=Path, required=True)
    parser.add_argument('--output-directory', type=Path, required=True)
    args = parser.parse_args()
    native = [args.native_directory / profile / 'client.log' for profile in ('native', 'static', 'dynamic')]
    guests = [args.guest_directory / f'{linkage}-{firmware}-{transport}' / 'guest.log'
              for linkage in ('static', 'dynamic') for firmware in ('bios', 'uefi') for transport in ('modern', 'legacy')]
    compare(native, guests, args.output_directory)


if __name__ == '__main__':
    main()
