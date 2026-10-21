# SPDX-License-Identifier: GPL-3.0-or-later
"""Compare original Linux and guest IPv6 error-queue control observations."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import zipfile

CAPACITIES = (0, 1, 7, 15, 16, 17, 19, 20, 23, 24, 35, 36,
              37, 39, 40, 55, 56, 63, 64, 87, 88, 151, 152, 192)
CONTROLS = (0, 1, 7, 8, 9, 11, 12, 13, 15, 16, 17, 19, 20, 23, 24, 25,
            31, 32, 33, 35, 36, 37, 39, 40, 41, 47, 48, 55, 56, 63,
            64, 67, 79, 80, 83, 84, 87, 88, 89, 96, 103, 104, 127,
            128, 151, 152, 160)
NAMES = (0, 1, 4, 7, 8, 15, 16, 23, 24, 27, 28, 40)
HEADERS = (0, 1, 4, 7, 8, 9, 11, 12, 15, 16, 39, 40, 41, 47, 48, 49, 51, 52, 55, 56)
CONFIGURATIONS = ([(0, mask, 192, 0) for mask in range(8)] +
                  [(0, 7, capacity, 0) for capacity in CAPACITIES] +
                  [(1, 7, 192, prefix) for prefix in CONTROLS] +
                  [(2, 7, 192, prefix) for prefix in NAMES] +
                  [(3, 7, 192, prefix) for prefix in HEADERS] +
                  [(mode, 0 if mode == 9 else 7, 192, 0) for mode in range(4, 11)])
BUFFERS = {'before_header', 'header', 'name', 'name_prefix', 'control', 'payload', 'drain'}
FIELDS = {'case', 'kind', 'peek', 'mode', 'mask', 'capacity', 'prefix', 'operation',
          'result', 'errno', 'name_length', 'length', 'flags', 'queued', 'queue_errno',
          'control_visible', 'name_visible'} | BUFFERS
DONE = ('IPV6_ERROR_CONTROLS_DONE cases=472 origins=2 masks=8 capacities=24 controls=47 '
        'names=12 headers=20 peek=2')


def require(condition, reason):
    if not condition:
        raise ValueError(reason)


def parse(text):
    indices = [match.group(1) for line in text.splitlines()
               if (match := re.fullmatch(r'IPV6_ERROR_CONTROLS_INTERFACE loopback=(\d+)', line))]
    require(len(indices) == 1 and 0 < int(indices[0]) < 256, 'one actual loopback identity')
    rows = []
    for line in text.splitlines():
        if not line.startswith('IPV6_ERROR_CONTROLS case='):
            continue
        pairs = [item.split('=', 1) for item in line.split()[1:]]
        require(all(len(pair) == 2 for pair in pairs), 'complete error-control fields')
        row = dict(pairs)
        require(len(pairs) == len(FIELDS) and set(row) == FIELDS, 'exact error-control inventory')
        require(all(re.fullmatch(r'-?\d+', row[key]) for key in FIELDS - BUFFERS),
                'integer error-control result fields')
        at = len(rows)
        mode, mask, capacity, prefix = CONFIGURATIONS[at % 118]
        require((int(row['case']), int(row['kind']), int(row['peek']), int(row['mode']),
                 int(row['mask']), int(row['capacity']), int(row['prefix']), int(row['operation'])) ==
                (at, at // 236, at % 236 // 118, mode, mask, capacity, prefix,
                 int(mode in (7, 10))), 'ordered complete error-control cases')
        sizes = dict(before_header=56, header=56, name=40, payload=32, drain=32,
                     control=prefix if mode == 1 else 192,
                     name_prefix=prefix if mode == 2 else 1 if mode == 10 else 0)
        for field, size in sizes.items():
            require(re.fullmatch(r'[0-9a-f]*', row[field]) is not None and
                    len(row[field]) == size * 2, 'complete visible original ' + field)
        require(int(row['control_visible']) == sizes['control'] and
                int(row['name_visible']) == sizes['name_prefix'], 'actual visible guard spans')
        before, after = bytes.fromhex(row['before_header']), bytes.fromhex(row['header'])
        require(before[8:12] == (0 if mode == 6 else 40).to_bytes(4, 'little') and
                before[24:32] == (1).to_bytes(8, 'little') and
                before[40:48] == capacity.to_bytes(8, 'little') and
                before[48:52] == (0x5a5a).to_bytes(4, 'little'), 'original message inputs')
        for offset in (0, 16, 32):
            pointer = int.from_bytes(before[offset:offset + 8], 'little')
            require((pointer == 0 if offset == 0 and mode == 5 else 0 < pointer < 2**47) and
                    before[offset:offset + 8] == after[offset:offset + 8],
                    'unchanged original message pointers')
        require(before[12:16] == after[12:16] == b'\xa5' * 4 and
                before[52:56] == after[52:56] == b'\xa5' * 4 and
                before[24:32] == after[24:32], 'unchanged message padding and input vector count')
        if mode not in (7, 10):
            require(int.from_bytes(after[8:12], 'little') == int(row['name_length']),
                    'raw output source length agrees with its scalar')
        require(int.from_bytes(after[40:48], 'little') == int(row['length']) and
                int.from_bytes(after[48:52], 'little') == int(row['flags']),
                'raw result fields agree with scalars')
        for field in ('before_header', 'header'):
            data = bytearray.fromhex(row[field])
            for offset in (0, 16, 32):
                data[offset:offset + 8] = bytes(8)
            row[field] = data.hex()
        rows.append(row)
    require(len(rows) == 472 and text.splitlines().count(DONE) == 1,
            'all original error-control observations')
    require('IPV6_ERROR_CONTROLS_FAIL' not in text, 'actual error-control client completed')
    return int(indices[0]), rows


def differences(expected, text):
    index, rows = parse(text)
    changed = []
    for wanted, actual in zip(expected, rows):
        wanted = dict(wanted)
        control = bytearray.fromhex(wanted['control'])
        # Translate only an observed packet-info interface byte. Original Linux
        # loopback is 1; every other field, fault prefix and padding stays exact.
        if len(control) > 32 and control[32] == 1:
            control[32] = index
        wanted['control'] = control.hex()
        fields = sorted(field for field in FIELDS if wanted[field] != actual[field])
        if fields:
            changed.append(dict(case=int(actual['case']), fields=fields))
    return changed


def damage(text, name):
    lines = text.splitlines()
    selected = [i for i,line in enumerate(lines) if line.startswith('IPV6_ERROR_CONTROLS case=')]
    at = selected[114] if name == 'wrong-length-order' else selected[7]
    if name == 'missing-case':
        del lines[at]
    elif name == 'duplicate-case':
        lines.insert(at, lines[at])
    else:
        row = dict(item.split('=', 1) for item in lines[at].split()[1:])
        if name in ('wrong-result', 'wrong-flags', 'wrong-length', 'wrong-queue'):
            field = {'wrong-result':'result', 'wrong-flags':'flags',
                     'wrong-length':'length', 'wrong-queue':'queued'}[name]
            row[field] = str(int(row[field]) ^ 1)
        else:
            field, offset = {'wrong-control':('control',16), 'wrong-packet-index':('control',32),
                'written-padding':('control',37), 'wrong-name':('name',0),
                'wrong-length-order':('name',0), 'wrong-payload':('payload',0),
                'wrong-header-padding':('header',12), 'changed-header-pointer':('header',0)}[name]
            data = bytearray.fromhex(row[field])
            data[offset] = 10 if name == 'wrong-length-order' else data[offset] ^ 1
            row[field] = data.hex()
        lines[at] = 'IPV6_ERROR_CONTROLS ' + ' '.join(key+'='+value for key,value in row.items())
    return '\n'.join(lines)+'\n'


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--native', type=Path, action='append', required=True)
    parser.add_argument('--guest', type=Path, action='append', required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--damaged', type=Path, required=True)
    args = parser.parse_args()
    paths = [*args.native, *args.guest]
    require(len(set(paths)) == len(paths), 'distinct original error observations')
    original = {str(path):path.read_bytes() for path in paths}
    native = [parse(original[str(path)].decode()) for path in args.native]
    require(len(native) == 3 and all(index == 1 for index,_ in native) and
            all(rows == native[0][1] for _,rows in native), 'three agreeing Linux linkages')
    expected = native[0][1]
    results = [dict(path=str(path),differences=differences(expected,original[str(path)].decode()))
               for path in args.guest]
    rejected = []
    names = ('missing-case','duplicate-case','wrong-result','wrong-flags','wrong-length',
             'wrong-queue','wrong-control','wrong-packet-index','written-padding','wrong-name',
             'wrong-length-order','wrong-payload','wrong-header-padding','changed-header-pointer')
    if all(not row['differences'] for row in results):
        with zipfile.ZipFile(args.damaged,'w',zipfile.ZIP_DEFLATED) as archive:
            for number,path in enumerate(args.guest):
                for name in names:
                    altered=damage(original[str(path)].decode(),name)
                    archive.writestr(f'{number}-{name}.log',altered)
                    try:
                        changed=differences(expected,altered)
                    except ValueError:
                        changed=True
                    require(changed,'damaged error-control evidence rejected: '+name)
                    rejected.append(dict(profile=number,name=name))
            archive.writestr('rejections.json',json.dumps(rejected,indent=2))
    require(all(path.read_bytes()==original[str(path)] for path in paths),'original evidence unchanged')
    result=dict(passed=all(not row['differences'] for row in results),cases_each=472,
                native_profiles=3,guest_profiles=len(results),damaged_rejected=len(rejected),
                profiles=results,full_F12_complete=False,
                original_sha256={name:hashlib.sha256(data).hexdigest() for name,data in original.items()})
    args.output.write_text(json.dumps(result,indent=2)+'\n')
    print(json.dumps({k:v for k,v in result.items() if k not in ('profiles','original_sha256')}),
          'differences_each='+str([len(row['differences']) for row in results]))
    return 0 if result['passed'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
