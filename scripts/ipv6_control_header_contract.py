# SPDX-License-Identifier: GPL-3.0-or-later
"""Compare original Linux and guest IPv6 receive-header fault observations."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import zipfile

PREFIXES = (0, 1, 4, 7, 8, 9, 11, 12, 15, 16, 39, 40, 41, 47, 48, 49, 51, 52, 55, 56)
BUFFERS = {'before_header': 56, 'header': 56, 'name': 40, 'control': 96,
           'payload': 32, 'drain': 32}
FIELDS = {'case', 'kind', 'peek', 'mode', 'prefix', 'result', 'errno', 'name_length',
          'length', 'flags', 'queued', 'queue_errno'} | set(BUFFERS)
DONE = 'IPV6_CONTROL_HEADER_DONE cases=96 transports=2 headers=20 names=4 peek=2'


def require(condition, reason):
    if not condition:
        raise ValueError(reason)


def integer(data, offset, size):
    return int.from_bytes(data[offset:offset + size], 'little')


def parse(text):
    indices = [match.group(1) for line in text.splitlines()
               if (match := re.fullmatch(r'IPV6_CONTROL_HEADER_INTERFACE loopback=(\d+)', line))]
    require(len(indices) == 1 and 0 < int(indices[0]) < 256, 'one actual loopback interface')
    rows = []
    for line in text.splitlines():
        if not line.startswith('IPV6_CONTROL_HEADER case='):
            continue
        items = [item.split('=', 1) for item in line.split()[1:]]
        require(all(len(item) == 2 for item in items), 'complete header fault fields')
        row = dict(items)
        require(len(items) == len(FIELDS) and set(row) == FIELDS, 'exact header field inventory')
        at = len(rows)
        scenario = at % 24
        require(int(row['case']) == at and int(row['kind']) == at // 48 and
                int(row['peek']) == at % 48 // 24 and
                int(row['mode']) == (0 if scenario < 20 else scenario - 19) and
                int(row['prefix']) == (PREFIXES[scenario] if scenario < 20 else 56),
                'ordered transports, peeking, header guards and name modes')
        for field, size in BUFFERS.items():
            require(re.fullmatch(r'[0-9a-f]+', row[field]) is not None and
                    len(row[field]) == 2 * size, 'complete original ' + field)
        for field in FIELDS - set(BUFFERS):
            require(re.fullmatch(r'-?\d+', row[field]) is not None, 'complete scalar ' + field)
        before = bytes.fromhex(row['before_header'])
        after = bytes.fromhex(row['header'])
        mode = int(row['mode'])
        require(integer(before, 8, 4) == (0 if mode >= 2 else 40) and
                integer(before, 24, 8) == 1 and integer(before, 40, 8) == 96 and
                integer(before, 48, 4) == 0x5a5a, 'exact initial Linux message fields')
        for offset in (0, 16, 32):
            pointer = integer(before, offset, 8)
            require((pointer == 0 if offset == 0 and mode in (1, 2)
                     else 0 < pointer < 2**47), 'original argument pointer')
            require(before[offset:offset + 8] == after[offset:offset + 8],
                    'header pointers remain unchanged')
        require(before[12:16] == after[12:16] == b'\xa5' * 4 and
                before[24:32] == after[24:32] and
                before[52:56] == after[52:56] == b'\xa5' * 4,
                'message padding and input vector count remain unchanged')
        require(integer(after, 8, 4) == int(row['name_length']) and
                integer(after, 40, 8) == int(row['length']) and
                integer(after, 48, 4) == int(row['flags']), 'raw header agrees with scalars')
        # Keep original bytes in the logs. Only address-valued input slots differ
        # between processes; their unchanged output was checked above.
        for field in ('before_header', 'header'):
            data = bytearray.fromhex(row[field])
            for offset in (0, 16, 32):
                data[offset:offset + 8] = b'\0' * 8
            row[field] = data.hex()
        rows.append(row)
    require(len(rows) == 96 and text.count(DONE) == 1, 'all ninety-six header observations')
    require('IPV6_CONTROL_HEADER_FAIL' not in text, 'application observation completed')
    return int(indices[0]), rows


def reference(texts):
    parsed = [parse(text) for text in texts]
    require(len(parsed) == 3 and all(index == 1 for index, _ in parsed),
            'three actual Linux linkage observations')
    require(all(rows == parsed[0][1] for _, rows in parsed), 'native header observations agree')
    return parsed[0][1]


def differences(expected, text):
    index, rows = parse(text)
    changed = []
    for wanted, actual in zip(expected, rows):
        wanted = dict(wanted)
        control = bytearray.fromhex(wanted['control'])
        if control[32:36] == b'\x01\0\0\0':
            control[32:36] = index.to_bytes(4, 'little')
        wanted['control'] = control.hex()
        fields = sorted(key for key in FIELDS if wanted[key] != actual[key])
        if fields:
            changed.append(dict(case=int(actual['case']), fields=fields))
    return changed


def damage(text, name):
    lines = text.splitlines()
    selected = [at for at, line in enumerate(lines)
                if line.startswith('IPV6_CONTROL_HEADER case=')]
    at = selected[14]
    if name == 'missing-case':
        del lines[at]
    elif name == 'duplicate-case':
        lines.insert(at, lines[at])
    else:
        row = dict(item.split('=', 1) for item in lines[at].split()[1:])
        scalar = {'wrong-result': 'result', 'wrong-queue': 'queued',
                  'wrong-flags': 'flags', 'wrong-result-length': 'length'}
        if name in scalar:
            field = scalar[name]
            row[field] = str(int(row[field]) ^ 1)
        else:
            field, offset = {
                'wrong-control': ('control', 0), 'wrong-name': ('name', 0),
                'wrong-payload': ('payload', 0), 'wrong-header-padding': ('header', 12),
                'changed-header-pointer': ('header', 0),
                'wrong-initial-length': ('before_header', 40)}[name]
            value = bytearray.fromhex(row[field])
            value[offset] ^= 1
            row[field] = value.hex()
        lines[at] = 'IPV6_CONTROL_HEADER ' + ' '.join(key + '=' + value
                                                     for key, value in row.items())
    return '\n'.join(lines) + '\n'


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--native', type=Path, action='append', required=True)
    parser.add_argument('--guest', type=Path, action='append', required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--damaged', type=Path, required=True)
    args = parser.parse_args()
    paths = [*args.native, *args.guest]
    require(len(set(paths)) == len(paths), 'distinct original header observations')
    original = {str(path): path.read_bytes() for path in paths}
    expected = reference([original[str(path)].decode() for path in args.native])
    results = [dict(path=str(path), differences=differences(
        expected, original[str(path)].decode(errors='replace'))) for path in args.guest]
    rejected = []
    if all(not row['differences'] for row in results):
        names = ('missing-case', 'duplicate-case', 'wrong-result', 'wrong-control',
                 'wrong-name', 'wrong-payload', 'wrong-queue', 'wrong-flags',
                 'wrong-header-padding', 'changed-header-pointer',
                 'wrong-initial-length', 'wrong-result-length')
        with zipfile.ZipFile(args.damaged, 'w', zipfile.ZIP_DEFLATED) as archive:
            for number, path in enumerate(args.guest):
                for name in names:
                    altered = damage(original[str(path)].decode(), name)
                    archive.writestr(str(number) + '-' + name + '.log', altered)
                    try:
                        changed = differences(expected, altered)
                    except ValueError:
                        changed = True
                    require(changed, 'damaged header evidence rejected: ' + name)
                    rejected.append(dict(profile=number, name=name))
            archive.writestr('rejections.json', json.dumps(rejected, indent=2))
    require(all(path.read_bytes() == original[str(path)] for path in paths),
            'original header observations remain unchanged')
    result = dict(passed=all(not row['differences'] for row in results), cases_each=96,
                  native_linkages=3, guest_profiles=len(results), local_only=True,
                  full_F12_complete=False, damaged_rejected=len(rejected), profiles=results,
                  original_sha256={name: hashlib.sha256(data).hexdigest()
                                   for name, data in original.items()})
    args.output.write_text(json.dumps(result, indent=2) + '\n')
    print(json.dumps({key: value for key, value in result.items()
                      if key not in ('profiles', 'original_sha256')}),
          'differences_each=' + str([len(row['differences']) for row in results]))
    return 0 if result['passed'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
