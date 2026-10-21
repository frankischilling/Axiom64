# SPDX-License-Identifier: GPL-3.0-or-later
"""Compare complete observed Linux and guest IPv6 receive-control copies."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import zipfile


def require(value, message):
    if not value:
        raise ValueError(message)


def parse(text):
    interfaces = [match.group(1) for line in text.splitlines()
                  if (match := re.fullmatch(r'IPV6_CONTROL_INTERFACE loopback=(\d+)', line))]
    require(len(interfaces) == 1 and 0 < int(interfaces[0]) < 256, 'one actual loopback identity')
    rows = []
    fields = {'case', 'kind', 'mask', 'mode', 'capacity', 'visible', 'input_flags',
              'wanted', 'result', 'errno', 'length', 'flags', 'bytes', 'data'}
    for line in text.splitlines():
        if not line.startswith('IPV6_CONTROL_LOCAL case='):
            continue
        parts = [item.split('=', 1) for item in line.split()[1:]]
        require(all(len(item) == 2 for item in parts), 'complete observed local fields')
        row = dict(parts)
        require(len(parts) == len(fields) and set(row) == fields, 'exact local field inventory')
        require(int(row['case']) == len(rows) and int(row['kind']) == len(rows) // 325,
                'complete ordered raw and UDP cases')
        require(re.fullmatch(r'[0-9a-f]*', row['bytes']) and
                len(row['bytes']) == 2 * int(row['visible']), 'complete original visible bytes')
        require(re.fullmatch(r'[0-9a-f]*', row['data']) is not None and
                len(row['data']) == (0 if int(row['mode']) == 6 and int(row['result']) < 0
                                     else 2 * int(row['wanted'])), 'complete actual payload bytes')
        rows.append(row)
    require(len(rows) == 650 and text.count('IPV6_CONTROL_LOCAL_DONE cases=650 transports=2 capacities=34 guards=40') == 1,
            'all local receive-control cases completed')
    require('IPV6_CONTROL_FAIL' not in text, 'local application reports no failure')
    return int(interfaces[0]), rows


def reference(logs):
    parsed = [parse(text) for text in logs]
    require(len(parsed) == 3 and all(index == 1 for index, _ in parsed),
            'all three native linkages use the actual Linux loopback identity')
    require(all(rows == parsed[0][1] for _, rows in parsed), 'all native observations agree exactly')
    return parsed[0][1]


def compare(expected, text):
    index, rows = parse(text)
    for original, actual in zip(expected, rows):
        wanted = dict(original)
        data = bytearray.fromhex(wanted['bytes'])
        # The first packet-info body stores its interface index at byte32.
        # Failed later controls may leave that earlier prefix visible. Linux
        # loopback is 1; translate only that observed byte to the guest index.
        # Header values, other data, faults and untouched padding stay exact.
        if len(data) > 32 and int(wanted['mask']) & 1 and data[32] == 1:
            data[32] = index
        wanted['bytes'] = data.hex()
        require(wanted == actual, 'receive-control result differs from Linux at case ' + actual['case'])
    return dict(passed=True, cases=len(rows), loopback=index)


def damage(text, name):
    lines = text.splitlines()
    selected = [n for n, line in enumerate(lines) if line.startswith('IPV6_CONTROL_LOCAL case=')]
    at = selected[269]  # UDP, all three controls, capacity 88.
    row = dict(item.split('=', 1) for item in lines[at].split()[1:])
    if name == 'missing-case':
        del lines[at]
    elif name == 'duplicate-case':
        lines.insert(at, lines[at])
    else:
        if name == 'wrong-result':
            row['result'] = '31'
        elif name == 'wrong-flags':
            row['flags'] = str(int(row['flags']) ^ 8)
        elif name == 'wrong-length':
            row['length'] = str(int(row['length']) + 1)
        else:
            if name == 'wrong-fault-prefix':
                at = selected[282]
                row = dict(item.split('=', 1) for item in lines[at].split()[1:])
                byte = 16
            else:
                byte = 37 if name == 'written-padding' else 16
            data = bytearray.fromhex(row['bytes']); data[byte] ^= 1; row['bytes'] = data.hex()
        lines[at] = 'IPV6_CONTROL_LOCAL ' + ' '.join(key + '=' + value for key, value in row.items())
    return '\n'.join(lines) + '\n'


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--native', type=Path, action='append', required=True)
    parser.add_argument('--guest', type=Path, action='append', required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--damaged', type=Path, required=True)
    args = parser.parse_args()
    paths = [*args.native, *args.guest]
    require(len(set(paths)) == len(paths), 'distinct original observations')
    original = {str(path): path.read_bytes() for path in paths}
    expected = reference([original[str(path)].decode() for path in args.native])
    results, rejected = [], []
    names = ('missing-case', 'duplicate-case', 'wrong-result', 'wrong-flags',
             'wrong-length', 'wrong-data', 'written-padding', 'wrong-fault-prefix')
    with zipfile.ZipFile(args.damaged, 'w', zipfile.ZIP_DEFLATED) as saved:
        for number, path in enumerate(args.guest):
            text = original[str(path)].decode(errors='replace')
            results.append(dict(path=str(path), **compare(expected, text)))
            for name in names:
                changed = damage(text, name)
                saved.writestr(str(number) + '-' + name + '.log', changed)
                try:
                    compare(expected, changed)
                except ValueError as error:
                    rejected.append(dict(profile=number, name=name, reason=str(error)))
                else:
                    raise ValueError('accepted damaged local control evidence: ' + name)
        saved.writestr('rejections.json', json.dumps(rejected, indent=2))
    require(all(path.read_bytes() == original[str(path)] for path in paths), 'original observations unchanged')
    result = dict(passed=True, native_linkages=3, local_guest_profiles=len(results), cases_each=650,
                  damaged_rejected=len(rejected), local_only=True, full_F12_complete=False,
                  original_sha256={name: hashlib.sha256(data).hexdigest() for name, data in original.items()},
                  profiles=results)
    args.output.write_text(json.dumps(result, indent=2) + '\n')
    print(json.dumps({key: value for key, value in result.items() if key not in ('profiles', 'original_sha256')}))


if __name__ == '__main__':
    main()
