# SPDX-License-Identifier: GPL-3.0-or-later
"""Compare actual Linux and guest receive address/control fault visibility."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import zipfile
from ipv6_copy_model import canonical_faults

PREFIXES = (0, 1, 4, 7, 8, 15, 16, 23, 24, 27, 28, 40)
FIELDS = {'case', 'kind', 'operation', 'peek', 'prefix', 'length_mode', 'result', 'errno', 'name_length',
          'length', 'flags', 'queued', 'queue_errno', 'name', 'control', 'payload', 'drain'}


def require(condition, reason):
    if not condition:
        raise ValueError(reason)


def parse(text):
    indices = [match.group(1) for line in text.splitlines()
               if (match := re.fullmatch(r'IPV6_CONTROL_FAULT_INTERFACE loopback=(\d+)', line))]
    require(len(indices) == 1 and 0 < int(indices[0]) < 256, 'one actual loopback interface')
    rows = []
    for line in text.splitlines():
        if not line.startswith('IPV6_CONTROL_FAULT case='):
            continue
        items = [item.split('=', 1) for item in line.split()[1:]]
        require(all(len(item) == 2 for item in items), 'complete receive-fault fields')
        row = dict(items)
        require(len(items) == len(FIELDS) and set(row) == FIELDS, 'exact fault field inventory')
        at = len(rows)
        local = at % 54
        operation = local // 24 if local < 48 else 1
        peek = local % 24 // 12 if local < 48 else (local - 48) // 3
        length_mode = 0 if local < 48 else (local - 48) % 3 + 1
        prefix = PREFIXES[local % 12] if local < 48 else (40, 1, 0)[length_mode - 1]
        require(int(row['case']) == at and int(row['kind']) == at // 54 and
                int(row['operation']) == operation and int(row['peek']) == peek and
                int(row['prefix']) == prefix and int(row['length_mode']) == length_mode,
                'ordered transports, operations, peek, address and length guards')
        for field, size in [('name', int(row['prefix'])), ('control', 96),
                            ('payload', 32), ('drain', 32)]:
            require(re.fullmatch(r'[0-9a-f]*', row[field]) is not None and
                    len(row[field]) == 2 * size, 'complete visible ' + field)
        for field in FIELDS - {'name', 'control', 'payload', 'drain'}:
            require(re.fullmatch(r'-?\d+', row[field]) is not None, 'complete scalar ' + field)
        rows.append(row)
    require(len(rows) == 108 and text.count(
        'IPV6_CONTROL_FAULT_DONE cases=108 transports=2 prefixes=12 peek=2 operations=2 length_faults=12') == 1,
        'all 108 receive-address and output-length fault observations')
    require('IPV6_CONTROL_FAULT_FAIL' not in text, 'application fault observation completed')
    return int(indices[0]), rows


def reference(texts, native_copy_order='length-first'):
    parsed = [parse(text) for text in texts]
    require(len(parsed) == 3 and all(index == 1 for index, _ in parsed),
            'three actual Linux linkage observations')
    require(all(rows == parsed[0][1] for _, rows in parsed), 'all native fault observations agree')
    return canonical_faults(parsed[0][1], native_copy_order)


def differences(expected, text):
    index, rows = parse(text)
    changed = []
    for wanted, actual in zip(expected, rows):
        wanted = dict(wanted)
        control = bytearray.fromhex(wanted['control'])
        if control[32] == 1:
            control[32] = index
        wanted['control'] = control.hex()
        fields = sorted(key for key in FIELDS if wanted[key] != actual[key])
        if fields:
            changed.append(dict(case=int(actual['case']), fields=fields))
    return changed


def damage(text, name):
    lines = text.splitlines()
    selected = [i for i, line in enumerate(lines) if line.startswith('IPV6_CONTROL_FAULT case=')]
    at = selected[48] if name == 'wrong-length-order' else selected[1]
    if name == 'missing-case':
        del lines[at]
    elif name == 'duplicate-case':
        lines.insert(at, lines[at])
    else:
        row = dict(item.split('=', 1) for item in lines[at].split()[1:])
        if name == 'wrong-result':
            row['result'] = '32'
        elif name == 'wrong-queue':
            row['queued'] = '32'
        elif name == 'wrong-flags':
            row['flags'] = str(int(row['flags']) ^ 8)
        elif name == 'wrong-operation':
            row['operation'] = '1'
        elif name == 'wrong-length-order':
            value = bytearray.fromhex(row['name'])
            value[0] = 10
            row['name'] = value.hex()
        else:
            field = {'wrong-control': 'control', 'wrong-name-prefix': 'name',
                     'wrong-payload': 'payload'}[name]
            value = bytearray.fromhex(row[field])
            value[0] ^= 1
            row[field] = value.hex()
        lines[at] = 'IPV6_CONTROL_FAULT ' + ' '.join(key + '=' + value for key, value in row.items())
    return '\n'.join(lines) + '\n'


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--native-copy-order', choices=('address-first', 'length-first'), default='length-first')
    parser.add_argument('--native', type=Path, action='append', required=True)
    parser.add_argument('--guest', type=Path, action='append', required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--damaged', type=Path, required=True)
    args = parser.parse_args()
    paths = [*args.native, *args.guest]
    require(len(set(paths)) == len(paths), 'distinct original fault observations')
    original = {str(path): path.read_bytes() for path in paths}
    expected = reference([original[str(path)].decode() for path in args.native], args.native_copy_order)
    results = [dict(path=str(path), differences=differences(
        expected, original[str(path)].decode(errors='replace'))) for path in args.guest]
    rejected = []
    if all(not row['differences'] for row in results):
        names = ('missing-case', 'duplicate-case', 'wrong-result', 'wrong-control',
                 'wrong-name-prefix', 'wrong-payload', 'wrong-queue', 'wrong-flags',
                 'wrong-operation', 'wrong-length-order')
        with zipfile.ZipFile(args.damaged, 'w', zipfile.ZIP_DEFLATED) as archive:
            for number, path in enumerate(args.guest):
                for name in names:
                    altered = damage(original[str(path)].decode(), name)
                    archive.writestr(str(number) + '-' + name + '.log', altered)
                    try:
                        changed = differences(expected, altered)
                    except ValueError:
                        changed = True
                    require(changed, 'damaged fault evidence rejected: ' + name)
                    rejected.append(dict(profile=number, name=name))
            archive.writestr('rejections.json', json.dumps(rejected, indent=2))
    require(all(path.read_bytes() == original[str(path)] for path in paths),
            'original fault observations remain unchanged')
    result = dict(passed=all(not row['differences'] for row in results), cases_each=108,
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
