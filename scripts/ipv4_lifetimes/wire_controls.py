# SPDX-License-Identifier: GPL-3.0-or-later
"""Serialize damaged real captures and require independent wire readers to reject them."""
import argparse
import copy
import json
from pathlib import Path
import struct

from ipv4_lifetimes.reader import decode, require
from ipv4_lifetimes.wire_evidence import json_lines, verify
from ipv4_lifetimes.wire_packets import checksum, ipv4
from ipv4_lifetimes.wire_trace import clocks, protocol
from tcp6.inputs import digest, write

NAMES = ('missing-control', 'wrong-control-sequence', 'wrong-control-error', 'wrong-control-port',
         'wrong-lifetime-input', 'expired-source-still-assigned', 'lost-survivor', 'shortened-lifetime',
         'shortened-tcp-absence', 'wrong-bind-error', 'wrong-later-send-error', 'wrong-policy',
         'damaged-raw-receive', 'damaged-stream-receive', 'missing-completion', 'missing-physical-guard',
         'bad-ip-checksum', 'bad-transport-checksum', 'repaired-wrong-datagram-bytes', 'repaired-wrong-source',
         'missing-held-datagram', 'duplicate-held-datagram', 'repaired-wrong-tcp-sequence',
         'repaired-wrong-tcp-ack', 'early-tcp-output', 'wrong-adapter', 'damaged-arp-reply',
         'early-held-arp-reply', 'shortened-held-observation', 'wrong-command-byte', 'missing-command',
         'missing-event-receipt', 'boolean-event', 'extra-event-field', 'noncanonical-wire-bytes',
         'missing-withdrawal', 'late-withdrawal', 'repaired-reserved-ip-flag', 'repaired-zero-ip-ttl',
         'unowned-arp-source', 'unowned-arp-target', 'unowned-arp-destination', 'wrong-arp-sender')
CLOCK_NAMES = ('source-clock-jump', 'observer-clock-jump', 'backward-source-clock', 'backward-observer-clock')


def inputs(directory):
    return dict(text=(directory / 'client.log').read_text(), wire=json_lines(directory / 'wire.jsonl'),
                ingress=json_lines(directory / 'ingress.jsonl'), events=decode((directory / 'events.json').read_text()),
                commands=decode((directory / 'commands.json').read_text()),
                native=decode((directory / 'captured.json').read_text())['mode'] == 'native')


def check(value, clock=False):
    arguments = [value[key] for key in ('text', 'wire', 'ingress', 'events', 'commands')]
    return clocks(*arguments) if clock else protocol(*arguments, value['native'])


def log_change(value, kind, selected, change):
    prefix = 'LIFETIME_WIRE_' + kind + ' '
    lines = value['text'].splitlines()
    for at, line in enumerate(lines):
        if not line.startswith(prefix):
            continue
        row = decode(line[len(prefix):])
        if selected(row):
            original = copy.deepcopy(row)
            change(row)
            lines[at] = prefix + json.dumps(row)
            value['text'] = '\n'.join(lines) + '\n'
            if kind == 'EVENT':
                candidates = [item for item in value['events'] if
                              {key: data for key, data in item.items() if not key.startswith('receipt_')} == original]
                require(len(candidates) == 1, 'one original event for semantic corruption')
                candidates[0].update(row)
            return
    raise ValueError('missing actual log input for corruption')


def frame(value, selected, change, repair=False):
    for row in value['wire']:
        raw = bytearray.fromhex(row['frame'])
        if raw[12:14] == b'\x08\x00' and selected(row, ipv4(raw)):
            change(raw)
            if repair:
                header = (raw[14] & 15) * 4
                length = int.from_bytes(raw[16:18], 'big')
                raw[24:26] = bytes(2)
                struct.pack_into('!H', raw, 24, checksum(bytes(raw[14:14 + header])))
                protocol = raw[23]
                if protocol in (6, 17):
                    start = 14 + header
                    at = start + (16 if protocol == 6 else 6)
                    raw[at:at + 2] = bytes(2)
                    pseudo = raw[26:34] + bytes((0, protocol)) + (length - header).to_bytes(2, 'big')
                    result = checksum(bytes(pseudo + raw[start:14 + length]))
                    struct.pack_into('!H', raw, at, result or 65535)
            row['frame'] = raw.hex()
            return row
    raise ValueError('missing actual packet for corruption')


def datagram(row, packet):
    return row['direction'] == 'output' and packet['protocol'] == 17 and packet['payload'][8:10] == b'\1\2'


def stream(row, packet):
    return row['direction'] == 'output' and packet['protocol'] == 6 and packet['payload'][8:10] == b'\10\5'


def mutation(value, name):
    def raw_record(kind, selected, field, offset, replacement):
        def change(row):
            raw = bytearray.fromhex(row[field])
            raw[offset:offset + len(replacement)] = replacement
            row[field] = raw.hex()
        log_change(value, kind, selected, change)
    if name == 'missing-control':
        lines = value['text'].splitlines()
        at = next(at for at, line in enumerate(lines) if line.startswith('LIFETIME_WIRE_CONTROL '))
        del lines[at]
        value['text'] = '\n'.join(lines) + '\n'
    elif name.startswith('wrong-control-'):
        field, offset, replacement = {'wrong-control-sequence': ('request', 8, struct.pack('<I', 999)),
            'wrong-control-error': ('reply', 16, struct.pack('<i', -22)),
            'wrong-control-port': ('reply', 12, bytes(4))}[name]
        raw_record('CONTROL', lambda row: row['case'] == 0, field, offset, replacement)
    elif name == 'wrong-lifetime-input':
        raw_record('CONTROL', lambda row: bytes.fromhex(row['request'])[6:8] == b'\5\1', 'request', 44, struct.pack('<I', 2))
    elif name in ('expired-source-still-assigned', 'lost-survivor'):
        log_change(value, 'IFCONF', lambda row: row['case'] == 1,
                   lambda row: row.update(bytes='' if name == 'lost-survivor' else
                       row['bytes'].replace('c6124102', 'c6124002')))
    elif name in ('shortened-lifetime', 'shortened-tcp-absence', 'wrong-bind-error', 'wrong-later-send-error', 'wrong-policy'):
        number, phase = {'shortened-lifetime': (0, 'lifetime-start'), 'shortened-tcp-absence': (8, 'absence-end'),
            'wrong-bind-error': (0, 'fresh-bind'), 'wrong-later-send-error': (0, 'expired'),
            'wrong-policy': (3, 'policy-write')}[name]
        def change(row):
            if name == 'shortened-lifetime':
                row['monotonic_ns'] += 500_000_000
            elif name == 'shortened-tcp-absence':
                row['monotonic_ns'] -= 500_000_000
            else:
                row['status'] = 0
        log_change(value, 'EVENT', lambda row: row['case'] == number and row['phase'] == phase, change)
    elif name in ('damaged-raw-receive', 'damaged-stream-receive'):
        raw_record('RECEIVE', lambda row: row['tag'] == (1 if name == 'damaged-raw-receive' else 5), 'bytes', 0, b'\x99')
    elif name == 'missing-completion':
        value['text'] = value['text'].replace('LIFETIME_WIRE_PASS cases=24', 'LIFETIME_WIRE_REMOVED cases=24')
    elif name == 'missing-physical-guard':
        row = frame(value, lambda row, packet: row['direction'] == 'output' and packet['protocol'] == 254,
                    lambda raw: None)
        value['wire'].remove(row)
    elif name in ('bad-ip-checksum', 'bad-transport-checksum', 'repaired-wrong-datagram-bytes', 'repaired-wrong-source'):
        offset = {'bad-ip-checksum': 24, 'bad-transport-checksum': 40,
                  'repaired-wrong-datagram-bytes': 60, 'repaired-wrong-source': 29}[name]
        frame(value, datagram, lambda raw: raw.__setitem__(offset, raw[offset] ^ 1), name.startswith('repaired-'))
    elif name in ('missing-held-datagram', 'duplicate-held-datagram'):
        row = frame(value, datagram, lambda raw: None)
        if name.startswith('missing-'):
            value['wire'].remove(row)
        else:
            value['wire'].insert(value['wire'].index(row), copy.deepcopy(row))
    elif name in ('repaired-wrong-tcp-sequence', 'repaired-wrong-tcp-ack'):
        offset = 38 if name.endswith('sequence') else 42
        frame(value, stream, lambda raw: raw.__setitem__(offset, raw[offset] ^ 1), True)
    elif name == 'early-tcp-output':
        row = frame(value, stream, lambda raw: None)
        row['monotonic_ns'] = next(row['receipt_monotonic_ns'] for row in value['events'] if row['case'] == 8 and row['phase'] == 'expired')
        value['wire'].sort(key=lambda row: row['monotonic_ns'])
    elif name == 'wrong-adapter':
        frame(value, datagram, lambda raw: None)['index'] = 1
    elif name in ('repaired-reserved-ip-flag', 'repaired-zero-ip-ttl'):
        frame(value, datagram, lambda raw: raw.__setitem__(20, raw[20] | 128) if name.endswith('flag')
              else raw.__setitem__(22, 0), True)
    elif name == 'damaged-arp-reply':
        row = next(row for row in value['wire'] if row['direction'] == 'input' and row['frame'][24:28] == '0806')
        raw = bytearray.fromhex(row['frame']); raw[29] ^= 1; row['frame'] = raw.hex()
    elif name in ('unowned-arp-source', 'unowned-arp-target', 'unowned-arp-destination', 'wrong-arp-sender'):
        row = next(row for row in value['wire'] if row['direction'] == 'output' and
                   row['packet_type'] != 4 and row['frame'][24:28] == '0806')
        raw = bytearray.fromhex(row['frame'])
        if name == 'unowned-arp-source':
            raw[28:32] = bytes.fromhex('c6124103')
        elif name == 'unowned-arp-target':
            raw[38:42] = bytes.fromhex('c61240c8')
        else:
            raw[0 if name == 'unowned-arp-destination' else 22] ^= 2
        row['frame'] = raw.hex()
    elif name in ('early-held-arp-reply', 'shortened-held-observation'):
        row = next(row for row in value['wire'] if row['direction'] == 'input' and row['frame'][24:28] == '0806' and
                   bytes.fromhex(row['frame'])[28:32] == bytes.fromhex('c6124010'))
        expired = next(row['receipt_monotonic_ns'] for row in value['events'] if row['case'] == 0 and row['phase'] == 'expired')
        row['monotonic_ns'] = expired - 1 if name.startswith('early-') else value['commands'][1]['before_ns'] - 400_000_000
        value['wire'].sort(key=lambda row: row['monotonic_ns'])
    elif name == 'wrong-command-byte':
        value['commands'][0]['bytes'] = '0a'
    elif name == 'missing-command':
        del value['commands'][0]
    elif name == 'missing-event-receipt':
        del value['events'][0]
    elif name == 'boolean-event':
        log_change(value, 'EVENT', lambda row: row['phase'] == 'begin', lambda row: row.update(lane=False))
    elif name == 'extra-event-field':
        log_change(value, 'EVENT', lambda row: row['phase'] == 'begin', lambda row: row.update(extra=0))
    elif name == 'noncanonical-wire-bytes':
        log_change(value, 'RECEIVE', lambda row: row['tag'] == 1, lambda row: row.update(bytes=' ' + row['bytes']))
    elif name == 'missing-withdrawal':
        log_change(value, 'EVENT', lambda row: row['phase'] == 'withdrawn', lambda row: row.update(phase='unobserved'))
    elif name == 'late-withdrawal':
        log_change(value, 'EVENT', lambda row: row['phase'] == 'withdrawn',
                   lambda row: row.update(monotonic_ns=row['monotonic_ns'] + 2_000_000_000))
    elif name == 'source-clock-jump':
        log_change(value, 'EVENT', lambda row: row['phase'] == 'expired',
                   lambda row: row.update(realtime_ns=row['realtime_ns'] + 200_000_000))
    elif name == 'observer-clock-jump':
        value['wire'][0]['realtime_ns'] += 200_000_000
    elif name == 'backward-source-clock':
        log_change(value, 'EVENT', lambda row: row['phase'] == 'expired', lambda row: row.update(monotonic_ns=0))
    elif name == 'backward-observer-clock':
        value['wire'][0]['monotonic_ns'] = value['wire'][1]['monotonic_ns'] + 1_000_000_000
    else:
        raise ValueError('unknown serialized wire control')


def run(directory, destination, protocol_only=False):
    directory, destination = Path(directory).resolve(), Path(destination).resolve()
    require(not destination.is_relative_to(directory), 'controls preserve every original capture file')
    original = inputs(directory)
    check(original)
    if not protocol_only:
        verify(directory)
        check(original, True)
    destination.mkdir(parents=True, exist_ok=False)
    before = {path.relative_to(directory).as_posix(): digest(path) for path in directory.rglob('*') if path.is_file()}
    results = []
    for name in NAMES + (() if protocol_only else CLOCK_NAMES):
        damaged = copy.deepcopy(original)
        mutation(damaged, name)
        path = destination / (name + '.json')
        write(path, damaged)
        reopened = decode(path.read_text())
        try:
            check(reopened, name in CLOCK_NAMES)
        except ValueError as error:
            results.append(dict(name=name, rejected=True, reason=str(error), sha256=digest(path)))
        else:
            raise ValueError('wire reader accepted serialized corruption: ' + name)
    require(before == {path.relative_to(directory).as_posix(): digest(path) for path in directory.rglob('*') if path.is_file()},
            'all original evidence bytes remain unchanged')
    proof = dict(passed=True, count=len(results), controls=results, protocol_only=protocol_only, full_wire_acceptance=False)
    write(destination / 'completed.json', proof)
    return proof


def reopen(directory, destination):
    directory, destination = Path(directory).resolve(), Path(destination).resolve()
    saved = decode((destination / 'completed.json').read_text())
    original = inputs(directory)
    check(original)
    require(saved['passed'] is True and type(saved['protocol_only']) is bool, 'original serialized wire control result')
    if not saved['protocol_only']:
        verify(directory)
        check(original, True)
    names = NAMES + (() if saved['protocol_only'] else CLOCK_NAMES)
    require(saved['count'] == len(names) and [row['name'] for row in saved['controls']] == list(names),
            'complete exact serialized wire fault inventory')
    for row in saved['controls']:
        name = row['name']
        path = destination / (name + '.json')
        require(row['rejected'] is True and digest(path) == row['sha256'], 'every original serialized wire fault byte')
        value = decode(path.read_text())
        expected = copy.deepcopy(original)
        mutation(expected, name)
        require(value == expected, 'serialized wire fault is the named mutation of the actual original capture')
        try:
            check(value, name in CLOCK_NAMES)
        except ValueError:
            pass
        else:
            raise ValueError('published wire fault no longer rejects: ' + name)
    return dict(passed=True, count=len(names), protocol_only=saved['protocol_only'])


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('directory', type=Path)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--protocol-only', action='store_true', help='development diagnostic; does not qualify clocks or artifacts')
    args = parser.parse_args()
    print(json.dumps(run(args.directory, args.output, args.protocol_only)), flush=True)


if __name__ == '__main__':
    main()
