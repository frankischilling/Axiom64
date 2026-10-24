# SPDX-License-Identifier: GPL-3.0-or-later
"""Compare every visible sticky-extension byte with an executed Linux7 reference."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import zipfile
from ipv6_extension_execution import verify_execution
from fetch import ROOT

SOURCE = 'userspace/tests/net/ipv6_sticky_controls.c'
FIXTURE = ROOT / 'scripts/tests/fixtures/ipv6-sticky-controls-linux7.json'
PREFIX = 'IPV6_STICKY_LOCAL_CASE '
SCALARS = {'case', 'raw', 'drop', 'option', 'variant', 'uid', 'seeded', 'seed_errno',
           'action', 'set_length', 'result', 'errno', 'got', 'get_errno', 'length',
           'unchanged', 'after_result', 'after_errno', 'after_length'}
BUFFERS = {'lengthbytes': 8, 'output': 2048, 'after_output': 64}


def require(value, reason):
    if not value:
        raise ValueError(reason)


def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def records(text):
    require('IPV6_STICKY_LOCAL_FAIL' not in text and text.splitlines().count(
        'IPV6_STICKY_LOCAL_DONE cases=1024') == 1, 'complete original sticky observation')
    rows = []
    for line in text.splitlines():
        if not line.startswith(PREFIX):
            continue
        fields = [value.split('=', 1) for value in line.removeprefix(PREFIX).split()]
        require(all(len(field) == 2 for field in fields), 'complete sticky fields')
        row = dict(fields)
        require(len(fields) == len(SCALARS) + len(BUFFERS) and set(row) == SCALARS | BUFFERS.keys(),
                'exact sticky observation field inventory')
        require(all(re.fullmatch('-?[0-9]+', row[key]) is not None for key in SCALARS), 'integer original sticky observations')
        at = len(rows)
        require(at < 1024 and (int(row['case']), int(row['raw']), int(row['drop']), int(row['option']), int(row['variant'])) ==
                (at, at // 512, at // 256 % 2, (54, 55, 57, 59)[at // 64 % 4], at % 64),
                'all ordered original sticky header, identity and transport variants')
        require(row['uid'] == ('65534' if int(row['drop']) else '0') and row['unchanged'] == '1',
                'actual ordinary/root identity and untouched input')
        for key, size in BUFFERS.items():
            require(re.fullmatch('[0-9a-f]{' + str(size * 2) + '}', row[key]) is not None,
                    'every original visible ' + key + ' byte')
        rows.append(row)
    require(len(rows) == 1024, 'all 1024 original sticky observations')
    return rows


def fixture():
    saved = json.loads(FIXTURE.read_text())
    require(saved['schema'] == 1 and saved['reference']['kernel'] == '7.0.0-1017-azure' and
            saved['reference']['actual_program_completed'] and saved['reference']['actual_cpio_reopened'] and
            saved['reference']['source_sha256'] == digest(ROOT / SOURCE), 'executed source-bound Linux7 sticky reference')
    rows = []
    for original in saved['rows']:
        row = dict(original)
        for key, size in (('output', 2048), ('after_output', 64)):
            encoded = row[key]
            require(set(encoded) == {'prefix', 'tail_a5'} and type(encoded['tail_a5']) is int and
                    0 <= encoded['tail_a5'] <= size and re.fullmatch('[0-9a-f]*', encoded['prefix']) is not None and
                    len(encoded['prefix']) % 2 == 0 and len(encoded['prefix']) // 2 + encoded['tail_a5'] == size,
                    'lossless complete reference buffer with an explicit untouched suffix')
            row[key] = encoded['prefix'] + 'a5' * encoded['tail_a5']
        rows.append(row)
    text = '\n'.join(PREFIX + ' '.join(key + '=' + value for key, value in row.items()) for row in rows)
    require(records(text + '\nIPV6_STICKY_LOCAL_DONE cases=1024\n') == rows, 'complete decoded reference matrix')
    return saved, rows


def compare(native_paths, guest_paths, output):
    output = Path(output)
    output.mkdir(parents=True, exist_ok=False)
    saved, wanted = fixture()
    require(len(native_paths) == 3 and len(guest_paths) == 8 and
            len(set(map(str, [*native_paths, *guest_paths]))) == 11, 'all eleven distinct original sticky profiles')
    original = {str(path): digest(path) for path in [*native_paths, *guest_paths]}
    profiles = []
    for native, paths in ((True, native_paths), (False, guest_paths)):
        for path in paths:
            verify_execution(path, native, SOURCE, saved['reference']['source_sha256'])
            actual = records(path.read_text())
            differences = [dict(case=n, fields=[key for key in reference if reference[key] != row[key]])
                           for n, (reference, row) in enumerate(zip(wanted, actual)) if reference != row]
            profiles.append(dict(path=str(path), native=native, differences=differences))
    require(all(not row['differences'] for row in profiles), 'sticky observations differ from the executed Linux7 reference')
    names = ('missing-case', 'duplicate-case', 'seed-result', 'set-result', 'set-error', 'getter-result',
             'getter-error', 'getter-length', 'output-byte', 'output-tail', 'long-header-tail',
             'after-state', 'length-store-byte', 'ordinary-identity', 'input-changed', 'SRH-output')
    rejected = []
    with zipfile.ZipFile(output / 'damaged.zip', 'w', zipfile.ZIP_DEFLATED) as archive:
        for profile, path in enumerate([*native_paths, *guest_paths]):
            text = path.read_text()
            for name in names:
                lines = text.splitlines()
                case = {'set-error': 5, 'getter-result': 49, 'getter-error': 38, 'long-header-tail': 11,
                        'after-state': 14, 'length-store-byte': 50, 'ordinary-identity': 257, 'SRH-output': 181}.get(name, 1)
                at = next(n for n, line in enumerate(lines) if line.startswith(PREFIX + f'case={case} '))
                if name == 'missing-case':
                    del lines[at]
                elif name == 'duplicate-case':
                    lines.insert(at, lines[at])
                else:
                    row = dict(value.split('=', 1) for value in lines[at].removeprefix(PREFIX).split())
                    if name in ('output-byte', 'output-tail', 'long-header-tail', 'after-state', 'length-store-byte', 'SRH-output'):
                        key = 'after_output' if name == 'after-state' else 'lengthbytes' if name == 'length-store-byte' else 'output'
                        data = bytearray.fromhex(row[key])
                        offset = 2047 if name == 'output-tail' else 2039 if name == 'long-header-tail' else 2 if name == 'SRH-output' else 0
                        data[offset] ^= 1
                        row[key] = data.hex()
                    elif name == 'ordinary-identity':
                        row['uid'] = '0'
                    elif name == 'input-changed':
                        row['unchanged'] = '0'
                    else:
                        key = {'seed-result': 'seeded', 'set-result': 'result', 'set-error': 'errno',
                               'getter-result': 'got', 'getter-error': 'get_errno', 'getter-length': 'length'}[name]
                        row[key] = str(int(row[key]) ^ 1)
                    lines[at] = PREFIX + ' '.join(key + '=' + value for key, value in row.items())
                damaged = '\n'.join(lines) + '\n'
                archive.writestr(f'{profile}-{name}.log', damaged)
                try:
                    require(records(damaged) == wanted, 'changed original sticky observation')
                except ValueError as error:
                    rejected.append(dict(profile=profile, name=name, reason=str(error)))
                else:
                    raise ValueError('accepted damaged sticky evidence: ' + name)
        archive.writestr('rejections.json', json.dumps(rejected, indent=2))
    require(all(digest(Path(path)) == value for path, value in original.items()), 'all original sticky logs remain unchanged')
    result = dict(passed=True, cases_each=1024, native_profiles=3, guest_profiles=8, profiles=profiles,
                  damaged_rejected=len(rejected), reference=saved['reference'], reference_fixture_sha256=digest(FIXTURE),
                  original_sha256=original, native_packet_clock_acceptance=False, full_F12_complete=False)
    (output / 'result.json').write_text(json.dumps(result, indent=2) + '\n')
    print('IPV6_STICKY_LOCAL_CONTRACT_PASS cases_each=1024 native=3 guests=8 damaged=176', flush=True)
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
