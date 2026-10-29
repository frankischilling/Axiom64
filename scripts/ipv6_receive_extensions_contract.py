# SPDX-License-Identifier: GPL-3.0-or-later
"""Compare all visible receive-extension bytes with an executed Linux 7 client."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import zipfile
from fetch import ROOT
from ipv6_extension_execution import verify_execution

SOURCE = 'userspace/tests/net/ipv6_receive_extensions.c'
FIXTURE = ROOT / 'scripts/tests/fixtures/ipv6-receive-extensions-linux7.json'
PREFIX = 'IPV6_RECEIVE_EXTENSION_LOCAL_CASE '
DONE = 'IPV6_RECEIVE_EXTENSION_LOCAL_DONE cases=272'
SCALARS = {'case', 'raw', 'ordinary', 'variant', 'uid', 'set', 'set_errno', 'got',
           'get_errno', 'scalar_length', 'result', 'errno', 'flags', 'length', 'visible',
           'later', 'later_errno'}
BUFFERS = {'scalar': 8, 'control': 512, 'payload': 64, 'after': 64}


def require(value, reason):
    if not value:
        raise ValueError(reason)


def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def records(text):
    lines = text.splitlines()
    require(lines.count(DONE) == 1 and 'IPV6_RECEIVE_EXTENSION_LOCAL_FAIL' not in text,
            'complete original receive-extension execution')
    result = []
    for line in lines:
        if not line.startswith(PREFIX):
            continue
        fields = [item.split('=', 1) for item in line.removeprefix(PREFIX).split()]
        require(all(len(field) == 2 for field in fields), 'complete receive observation fields')
        row = dict(fields)
        require(len(fields) == len(SCALARS) + len(BUFFERS) and set(row) == SCALARS | BUFFERS.keys(),
                'exact receive observation inventory')
        require(all(re.fullmatch('-?[0-9]+', row[key]) for key in SCALARS),
                'integer original receive observations')
        number = len(result)
        require(number < 272 and tuple(int(row[key]) for key in ('case', 'raw', 'ordinary', 'variant')) ==
                (number, number // 136, number // 68 % 2, number % 68),
                'every ordered unique receive variant and transport')
        require(row['uid'] == ('65534' if int(row['ordinary']) else '0'),
                'actual root and ordinary receive identities')
        for key, size in BUFFERS.items():
            require(re.fullmatch('[0-9a-f]{' + str(size * 2) + '}', row[key]),
                    'complete original ' + key + ' bytes')
        result.append(row)
    require(len(result) == 272, 'all 272 receive observations')
    return result


def fixture():
    saved = json.loads(FIXTURE.read_text())
    reference = saved['reference']
    require(saved['schema'] == 1 and reference['kernel'] == '7.0.0-1017-azure' and
            reference['kernel_sha256'] == '1499d4e93269e5607c0aed401f55a6c256d4ca82e91b6b79f4032d0a181f22e5' and
            reference['actual_program_completed'] and reference['actual_cpio_reopened'] and
            reference['complete_error_client'] and reference['source_sha256'] == digest(ROOT / SOURCE),
            'actual complete Linux 7 client bound to the current receive probe')
    text = '\n'.join(PREFIX + ' '.join(key + '=' + value for key, value in row.items())
                     for row in saved['rows']) + '\n' + DONE + '\n'
    require(records(text) == saved['rows'], 'complete frozen reference row schema')
    return saved


def compare(native_paths, guest_paths, output):
    saved = fixture()
    wanted = saved['rows']
    paths = [*native_paths, *guest_paths]
    require(len(native_paths) == 3 and len(guest_paths) == 8 and len(set(map(str, paths))) == 11,
            'three distinct native and eight distinct guest receive profiles')
    originals = {str(path): digest(path) for path in paths}
    profiles = []
    for native, selected in ((True, native_paths), (False, guest_paths)):
        for path in selected:
            verify_execution(path, native, SOURCE, saved['reference']['source_sha256'])
            actual = records(path.read_text())
            changed = [number for number, (before, after) in enumerate(zip(wanted, actual)) if before != after]
            require(not changed, f'original receive profile differs from Linux 7: {path}: {changed}')
            profiles.append(dict(path=str(path), native=native, cases=272))
    output = Path(output)
    output.mkdir(parents=True, exist_ok=False)
    rejected = []
    mutations = ('missing-case', 'duplicate-case', 'case-order', 'missing-completion',
                 *sorted(SCALARS - {'case'}), *BUFFERS)
    with zipfile.ZipFile(output / 'damaged.zip', 'w', zipfile.ZIP_DEFLATED) as archive:
        for profile, path in enumerate(paths):
            text = path.read_text()
            for name in mutations:
                lines = text.splitlines()
                number = 68 if name in ('uid', 'ordinary') else 61 if name == 'scalar' else 7
                at = next(n for n, line in enumerate(lines) if line.startswith(PREFIX + f'case={number} '))
                if name == 'missing-case':
                    del lines[at]
                elif name == 'duplicate-case':
                    lines.insert(at, lines[at])
                elif name == 'case-order':
                    lines[at], lines[at + 1] = lines[at + 1], lines[at]
                elif name == 'missing-completion':
                    lines.remove(DONE)
                else:
                    row = dict(item.split('=', 1) for item in lines[at].removeprefix(PREFIX).split())
                    if name in BUFFERS:
                        data = bytearray.fromhex(row[name])
                        data[-1 if name in ('payload', 'after') else 0] ^= 1
                        row[name] = data.hex()
                    else:
                        row[name] = str(int(row[name]) ^ 1)
                    lines[at] = PREFIX + ' '.join(key + '=' + value for key, value in row.items())
                damaged = '\n'.join(lines) + '\n'
                archive.writestr(f'{profile}-{name}.log', damaged)
                try:
                    require(records(damaged) == wanted, 'changed Linux 7 receive observation')
                except ValueError as error:
                    rejected.append(dict(profile=profile, name=name, reason=str(error)))
                else:
                    raise ValueError('accepted damaged receive observations: ' + name)
        archive.writestr('rejections.json', json.dumps(rejected, indent=2))
    require(all(digest(Path(name)) == value for name, value in originals.items()),
            'every original receive log remains unchanged')
    result = dict(passed=True, cases_each=272, native_profiles=3, guest_profiles=8,
                  profiles=profiles, damaged_rejected=len(rejected), original_sha256=originals,
                  fixture_sha256=digest(FIXTURE), reference=saved['reference'],
                  native_packet_clock_acceptance=False, full_F12_complete=False)
    (output / 'result.json').write_text(json.dumps(result, indent=2) + '\n')
    print(f'IPV6_RECEIVE_EXTENSIONS_CONTRACT_PASS cases_each=272 native=3 guests=8 damaged={len(rejected)}', flush=True)
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
