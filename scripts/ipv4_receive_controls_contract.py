# SPDX-License-Identifier: GPL-3.0-or-later
"""Compare complete IPv4 receive-control observations against actual Linux runs.

Only the interface number returned by each client's real loopback lookup changes
between systems. Packet bytes, copied fault prefixes, lengths, flags, errors and
description state must otherwise agree. Runtime producers bind these logs to
their actual source, executables, kernel and boot products separately.
"""
import argparse
import hashlib
import json
from pathlib import Path
import struct
import zipfile

DONE = 'IPV4_RECEIVE_CONTROLS_PASS observations=1395 faults=468 checks=206648'
COUNTS = {'kernel': 1, 'option': 63, 'receive': 1395, 'description': 3, 'accepted': 1, 'fault': 468}


def require(value, reason):
    if not value:
        raise ValueError(reason)


def unique_object(pairs):
    result = dict(pairs)
    require(len(result) == len(pairs), 'duplicate observation field')
    return result


def read(text, native):
    rows = [json.loads(line, object_pairs_hook=unique_object)
            for line in text.splitlines() if line.startswith('{')]
    require(text.count(DONE) == 1 and 'IPV4_RECEIVE_CONTROLS_FAIL' not in text,
            'complete successful client execution')
    require(len(rows) == sum(COUNTS.values()), 'complete observation inventory')
    require({kind: sum(row.get('kind') == kind for row in rows) for kind in COUNTS} == COUNTS,
            'all option, receive, fault and lifetime observations')
    if not native:
        require(text.count('AXIOM64_EXIT status=0') == 1,
                'successful actual guest exit')
        require(sum(text.count('Firmware: ' + value) for value in ('BIOS', 'UEFI')) == 1,
                'one actual guest firmware identity')
    identity = rows[0]
    require(set(identity) == {'kind', 'sysname', 'release', 'loopback'} and
            identity['kind'] == 'kernel' and identity['sysname'] == ('Linux' if native else 'Axiom64') and
            isinstance(identity['release'], str) and bool(identity['release']) and
            type(identity['loopback']) is int and identity['loopback'] > 0,
            'actual kernel and loopback identity')
    for kind, count in (('receive', 1395), ('fault', 468)):
        selected = [row for row in rows if row['kind'] == kind]
        require([row.get('case') for row in selected] == list(range(count)),
                'complete ordered ' + kind + ' cases')
    require([row for row in rows if row['kind'] == 'description'] ==
            [dict(kind='description', transport=kind, duplicate=True, fork=True) for kind in range(3)],
            'all shared-description lifetime observations')
    require([row for row in rows if row['kind'] == 'accepted'] ==
            [dict(kind='accepted', snapshot=5, listener=2, independent=True)],
            'established child snapshot and independent listener')
    return identity, rows


def receive_controls(row, index):
    data = bytes.fromhex(row['control_hex'])
    require(len(data) == row['control_length'] <= row['capacity'] and row['flags'] in (0, 8),
            'bounded receive controls and flags')
    require(row['transport'] in (0, 1, 2) and row['prepared'] in (0, 1) and 0 <= row['mask'] < 8,
            'receive transport and option selection')
    require(row['result'] == (44 if row['transport'] else 16) and len(bytes.fromhex(row['payload'])) == 16,
            'complete actual packet payload')
    seen = []
    at = 0
    while len(data) - at >= 16:
        length, level, kind = struct.unpack_from('<Qii', data, at)
        require(level == 0 and kind in (8, 2, 1) and 16 <= length <= len(data) - at,
                'IPv4 control header and bounded original payload')
        expected = ((struct.pack('<I', index if row['prepared'] else 0) +
                     (b'\x7f\0\0\x02' if row['prepared'] else bytes(4)) + b'\x7f\0\0\x02')
                    if kind == 8 else struct.pack('<i', 37) if kind == 2 else b'\x6e')
        payload = data[at + 16:at + length]
        require(len(payload) <= len(expected) and payload == expected[:len(payload)],
                'arrival-prepared packet information and original TTL/TOS')
        require(kind not in seen, 'no duplicate receive controls')
        seen.append(kind)
        aligned = min(len(data), at + ((length + 7) & ~7))
        require(data[at + length:aligned] == b'\xa5' * (aligned - at - length),
                'unwritten alignment padding')
        at = aligned
    require(data[at:] == b'\xa5' * (len(data) - at), 'unwritten control suffix')
    enabled = [kind for bit, kind in enumerate((8, 2, 1)) if row['mask'] & (1 << bit)]
    require(seen == enabled[:len(seen)], 'Linux receive-control ordering')


def map_index(row, original, selected):
    result = dict(row)
    if row['kind'] not in ('receive', 'fault'):
        return result
    data = bytearray.fromhex(row['control_hex'])
    at = 0
    while len(data) - at >= 16:
        length, level, kind = struct.unpack_from('<Qii', data, at)
        if level != 0 or kind not in (8, 2, 1) or length < 16:
            break
        if kind == 8 and (row['kind'] == 'fault' or row['prepared']):
            copied = min(4, max(0, len(data) - at - 16), length - 16)
            require(data[at + 16:at + 16 + copied] == struct.pack('<I', original)[:copied],
                    'actual packet-info interface, including partial fault copies')
            data[at + 16:at + 16 + copied] = struct.pack('<I', selected)[:copied]
        at += (length + 7) & ~7
    result['control_hex'] = bytes(data).hex()
    return result


def verify(native_texts, guest_texts):
    require(len(native_texts) == 3 and len(guest_texts) == 4, 'complete native/guest cohort')
    natives = [read(text, True) for text in native_texts]
    require(all(value == natives[0] for value in natives[1:]), 'native libc profiles agree')
    identity, reference = natives[0]
    for row in reference:
        if row['kind'] == 'receive':
            receive_controls(row, identity['loopback'])
    require(sum('Firmware: BIOS' in text for text in guest_texts) == 2 and
            sum('Firmware: UEFI' in text for text in guest_texts) == 2,
            'complete BIOS/UEFI guest cohort')
    for text in guest_texts:
        guest_identity, candidate = read(text, False)
        for actual, expected in zip(candidate[1:], reference[1:]):
            require(actual == map_index(expected, identity['loopback'], guest_identity['loopback']),
                    'native/guest difference in ' + actual['kind'] + ' observation ' + str(actual.get('case', '')))
    return dict(passed=True, native_profiles=3, guest_profiles=4, receives_each=1395,
                control_faults_each=468, lifetime_cases_each=4,
                only_actual_loopback_index_mapping=True, full_feature_acceptance=False)


def altered(text, kind, change, predicate=lambda row: True):
    lines = text.splitlines()
    for index, line in enumerate(lines):
        if not line.startswith('{'):
            continue
        row = json.loads(line)
        if row['kind'] == kind and predicate(row):
            change(row)
            lines[index] = json.dumps(row, separators=(',', ':'))
            return '\n'.join(lines) + '\n'
    raise ValueError('negative control has no original case')


def damaged_controls(native_texts, guest_texts, archive):
    def flip(row):
        data = bytearray.fromhex(row['control_hex'])
        data[-1] ^= 1
        row['control_hex'] = data.hex()

    mutations = [
        ('receive-flags', 'receive', lambda row: row.update(flags=row['flags'] ^ 8), lambda row: True),
        ('receive-length', 'receive', lambda row: row.update(control_length=row['control_length'] + 1), lambda row: True),
        ('receive-payload', 'receive', lambda row: row.update(payload='00' * 16), lambda row: True),
        ('prepared-selection', 'receive', lambda row: row.update(prepared=1 - row['prepared']), lambda row: row['mask'] == 7 and row['capacity'] == 96),
        ('packet-info-byte', 'receive', flip, lambda row: row['mask'] == 1 and row['capacity'] == 28),
        ('ttl-byte', 'receive', flip, lambda row: row['mask'] == 2 and row['capacity'] == 20),
        ('tos-byte', 'receive', flip, lambda row: row['mask'] == 4 and row['capacity'] == 17),
        ('fault-flags', 'fault', lambda row: row.update(flags=row['flags'] ^ 8), lambda row: True),
        ('fault-result', 'fault', lambda row: row.update(result=row['result'] + 1), lambda row: True),
        ('fault-error', 'fault', lambda row: row.update(errno=14), lambda row: True),
        ('fault-prefix', 'fault', flip, lambda row: row['visible'] == 17),
        ('fault-consumption', 'fault', lambda row: row.update(queued=16), lambda row: row['input_flags'] == 0),
        ('peek-consumption', 'fault', lambda row: row.update(queued=-1), lambda row: row['input_flags'] == 2),
        ('shared-description', 'description', lambda row: row.update(fork=False), lambda row: True),
        ('accepted-snapshot', 'accepted', lambda row: row.update(snapshot=2), lambda row: True),
        ('accepted-independence', 'accepted', lambda row: row.update(independent=False), lambda row: True),
    ]
    rejected = []
    with zipfile.ZipFile(archive, 'x', compression=zipfile.ZIP_DEFLATED) as bundle:
        for label, kind, change, predicate in mutations:
            damaged = altered(guest_texts[0], kind, change, predicate)
            bundle.writestr(label + '.log', damaged)
            try:
                verify(native_texts, [damaged, *guest_texts[1:]])
            except (ValueError, KeyError, TypeError, struct.error):
                rejected.append(label)
            else:
                raise ValueError('altered original was accepted: ' + label)
        boot_changes = {
            'wrong-firmware': [guest_texts[0].replace('Firmware: BIOS', 'Firmware: UEFI'), *guest_texts[1:]],
            'unsuccessful-guest-exit': [guest_texts[0].replace('AXIOM64_EXIT status=0', 'AXIOM64_EXIT status=1'), *guest_texts[1:]],
            'duplicate-guest-cohort': [guest_texts[0]] * 4,
        }
        for label, changed in boot_changes.items():
            bundle.writestr(label + '.json', json.dumps(changed))
            try:
                verify(native_texts, changed)
            except (ValueError, KeyError, TypeError, struct.error):
                rejected.append(label)
            else:
                raise ValueError('altered guest boot identity was accepted: ' + label)
    return rejected


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--native', type=Path, action='append', required=True)
    parser.add_argument('--guest', type=Path, action='append', required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--damaged', type=Path, required=True)
    args = parser.parse_args()
    paths = args.native + args.guest
    require(len({path.resolve() for path in paths}) == len(paths), 'distinct original profile files')
    require(all(path.is_file() and not path.is_symlink() and path.stat().st_size <= 4 * 1024 * 1024
                for path in paths), 'bounded regular original observation files')
    originals = {str(path): path.read_bytes() for path in paths}
    native = [originals[str(path)].decode() for path in args.native]
    guests = [originals[str(path)].decode() for path in args.guest]
    result = verify(native, guests)
    result['serialized_controls_rejected'] = damaged_controls(native, guests, args.damaged)
    result['original_sha256'] = {name: hashlib.sha256(data).hexdigest() for name, data in originals.items()}
    require(all(path.read_bytes() == originals[str(path)] for path in paths), 'original observations unchanged')
    args.output.write_text(json.dumps(result, indent=2) + '\n')
    print(json.dumps({key: value for key, value in result.items() if key != 'original_sha256'}))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
