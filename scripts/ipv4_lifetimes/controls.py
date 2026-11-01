# SPDX-License-Identifier: GPL-3.0-or-later
"""Retain serialized malformed observations and require the offline reader to reject them."""
import argparse
import copy
import json
from pathlib import Path
import struct

from ipv4_lifetimes.reader import decode, messages, require, specifications, verify
from tcp6.inputs import digest, write

PREFIX = 'IPV4_LIFETIME_RECORD '
NAMES = ('missing-request', 'duplicate-request', 'wrong-sequence', 'wrong-request-flags',
         'truncated-request', 'wrong-error', 'wrong-port', 'wrong-caller-cache',
         'finite-permanent-flag', 'initial-valid', 'initial-preferred', 'caller-creation-stamp',
         'renewal-created', 'renewal-updated', 'wrong-deprecation-countdown', 'clock-jump',
         'shortened-observation', 'later-send-error', 'fresh-bind-error', 'missing-completion',
         'permanent-countdown', 'secondary-not-promoted', 'policy-scope', 'policy-restore')


def record(lines, phase, direction='request', selected=None):
    sequence = None
    if selected is not None:
        matches = [number + 1 for number, spec in enumerate(specifications())
                   if spec['phase'] == phase and spec['kind'] == 22 and spec['address'] == selected]
        require(len(matches) == 1, 'one selected original dump for a rejection control')
        sequence = matches[0]
    for at, line in enumerate(lines):
        if not line.startswith(PREFIX):
            continue
        value = decode(line[len(PREFIX):])
        if value['lane'] != 0 or value['phase'] != phase or value['direction'] != direction:
            continue
        data = messages(bytes.fromhex(value['bytes']))
        if sequence is None or (data[0]['sequence'] == sequence and data[0]['kind'] == 20):
            return at, value
    raise ValueError('missing original observation for rejection control')


def replace(lines, at, value):
    lines[at] = PREFIX + json.dumps(value, separators=(',', ':'))


def message(lines, phase, direction, mutation, selected=None):
    at, value = record(lines, phase, direction, selected)
    data = bytearray.fromhex(value['bytes'])
    mutation(data)
    value['bytes'] = data.hex()
    replace(lines, at, value)


def attribute(data, address, kind, offset, replacement):
    at = 0
    while at < len(data):
        length, message_kind = struct.unpack_from('<IH', data, at)
        if message_kind == 20:
            fields = {}
            field = at + 24
            while field < at + length:
                size, field_kind = struct.unpack_from('<HH', data, field)
                fields[field_kind] = (field, bytes(data[field + 4:field + size]))
                field += (size + 3) & ~3
            if fields.get(2, (0, None))[1] == struct.pack('>I', address):
                require(kind in fields and offset + len(replacement) <= len(fields[kind][1]),
                        'rejection control targets complete original attribute bytes')
                start = fields[kind][0] + 4 + offset
                data[start:start + len(replacement)] = replacement
                if kind == 8:
                    data[at + 18] = replacement[0]
                return
        at += (length + 3) & ~3
    raise ValueError('missing original address attribute for rejection control')


def corrupt(original, name):
    lines = copy.deepcopy(original)
    if name == 'missing-request':
        lines.pop(record(lines, 'invalid-zero')[0])
    elif name == 'duplicate-request':
        at, _ = record(lines, 'invalid-zero')
        lines.insert(at, lines[at])
    elif name in ('wrong-sequence', 'wrong-request-flags', 'truncated-request', 'wrong-error',
                  'wrong-port', 'wrong-caller-cache'):
        phase, direction, mutation = {
            'wrong-sequence': ('finite-create', 'request', lambda data: struct.pack_into('<I', data, 8, 99)),
            'wrong-request-flags': ('finite-renew', 'request', lambda data: struct.pack_into('<H', data, 6, 5)),
            'truncated-request': ('finite-create', 'request', lambda data: data.pop()),
            'wrong-error': ('invalid-zero', 'reply', lambda data: struct.pack_into('<i', data, 16, 0)),
            'wrong-port': ('finite-create', 'reply', lambda data: struct.pack_into('<I', data, 12, 0)),
            'wrong-caller-cache': ('finite-create', 'request', lambda data: data.__setitem__(-16, 9)),
        }[name]
        message(lines, phase, direction, mutation)
    elif name in ('clock-jump', 'shortened-observation'):
        at, value = record(lines, 'renewed-deprecated' if name == 'clock-jump' else 'finite-deprecated')
        for clock in (('realtime',) if name == 'clock-jump' else ('monotonic', 'realtime')):
            for suffix in ('_before_ns', '_after_ns'):
                value[clock + suffix] += 1_000_000_000 if name == 'clock-jump' else -1_000_000_000
        replace(lines, at, value)
    elif name in ('later-send-error', 'fresh-bind-error', 'missing-completion', 'policy-scope', 'policy-restore'):
        prefix, old, new = {
            'later-send-error': ('IPV4_LIFETIME_SEND ', 'errno=101', 'errno=99'),
            'fresh-bind-error': ('IPV4_LIFETIME_BIND ', 'errno=99', 'errno=101'),
            'missing-completion': ('IPV4_LIFETIME_PASS ', '', ''),
            'policy-scope': ('IPV4_LIFETIME_POLICY lane=0 phase=device-promote-create ', 'scope=eth0', 'scope=all'),
            'policy-restore': ('IPV4_LIFETIME_POLICY lane=0 phase=cleanup scope=eth0 ', 'value=', 'value=1'),
        }[name]
        at = next(at for at, line in enumerate(lines) if line.startswith(prefix))
        if name == 'missing-completion':
            lines.pop(at)
        elif name == 'policy-restore':
            lines[at] = lines[at].split('value=')[0] + 'value=2147483647'
        else:
            lines[at] = lines[at].replace(old, new)
    else:
        phase, selected, kind, offset, value = {
            'finite-permanent-flag': ('finite-create', 'first', 8, 0, 128),
            'initial-valid': ('finite-create', 'first', 6, 4, 10),
            'initial-preferred': ('finite-create', 'first', 6, 0, 0),
            'caller-creation-stamp': ('finite-create', 'first', 6, 8, 0x12345678),
            'renewal-created': ('finite-renew', 'first', 6, 8, 0x76543210),
            'renewal-updated': ('finite-renew', 'first', 6, 12, 0),
            'wrong-deprecation-countdown': ('renewed-deprecated', 'first', 6, 0, 2),
            'permanent-countdown': ('finite-deprecated', 'permanent', 6, 0, 1),
            'secondary-not-promoted': ('device-promoted', 'alias', 8, 0, 129),
        }[name]
        address = 0xc6122002 + dict(first=0, alias=1, permanent=256)[selected]
        message(lines, phase, 'reply', lambda data: attribute(data, address, kind, offset, struct.pack('<I', value)), selected)
    require(lines != original, 'every rejection control changes original bytes')
    return '\n'.join(lines) + '\n'


def run(log, directory):
    log, directory = Path(log), Path(directory)
    before = digest(log)
    accepted = verify(log)
    directory.mkdir(exist_ok=False)
    lines = log.read_text().replace('\r\n', '\n').splitlines()
    rows = []
    for name in NAMES:
        path = directory / (name + '.log')
        path.write_text(corrupt(lines, name))
        try:
            verify(path)
        except ValueError as error:
            rows.append(dict(name=name, rejected=True, reason=str(error), sha256=digest(path)))
        else:
            raise ValueError('accepted damaged lifetime evidence: ' + name)
    require(digest(log) == before, 'original observation bytes survive every rejection control')
    result = dict(passed=True, original_sha256=before, accepted=accepted, controls=rows,
                  original_unchanged=True, count=len(NAMES))
    write(directory / 'completed.json', result)
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('log', type=Path)
    parser.add_argument('directory', type=Path)
    args = parser.parse_args()
    print(json.dumps(run(args.log, args.directory)), flush=True)


if __name__ == '__main__':
    main()
