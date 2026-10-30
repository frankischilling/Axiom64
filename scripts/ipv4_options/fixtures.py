# SPDX-License-Identifier: GPL-3.0-or-later
"""Translate retained native syscalls and packets into option-model inputs."""
import gzip
import json
from pathlib import Path

from fetch import ROOT


LEGACY_SOCKET = ROOT / 'scripts/tests/fixtures/ipv4-options-linux6687.json.gz'
SOCKET = ROOT / 'scripts/tests/fixtures/ipv4-options-linux7014.json.gz'
RECEIVE = ROOT / 'scripts/tests/fixtures/ipv4-options-receive-linux6687.json.gz'


def socket_table_bytes(data):
    fixture = json.loads(gzip.decompress(data))
    rows = []
    for profile in ('root', 'ordinary'):
        if len(fixture[profile]) != 7110:
            raise ValueError('incomplete native option corpus')
        rows.extend(' '.join((row['name'], str(int(profile == 'root')), row['input'] or '-',
                              str(row['result']), row['output'] or '-'))
                    for row in fixture[profile])
    return ('\n'.join(rows) + '\n').encode()


def socket_table(path=SOCKET):
    return socket_table_bytes(path.read_bytes())


def receive_table():
    fixture = json.loads(gzip.decompress(RECEIVE.read_bytes()))
    rows = []
    for row in fixture['rows']:
        # Packets rejected by source-route admission do not establish a syntax
        # result. Accepted completed routes still exercise reversal and echo.
        source_route = row['name'].startswith(('route-', 'type-131-', 'type-137-'))
        if source_route and 'raw' not in row:
            continue
        timestamp, parameter = 12345, -1
        raw = row.get('raw')
        if raw:
            packet = bytes.fromhex(raw['data'])
            actual = packet[20:4 * (packet[0] & 15)]
            returned = next((bytes.fromhex(item['data']) for item in raw['control']
                             if item['type'] == 7), b'')
            valid = not bool(raw['flags'] & 8)
            low = (row['before_ns'] // 1000000) % 86400000
            high = (row['after_ns'] // 1000000) % 86400000
            candidates = {int.from_bytes(actual[at:at + 4], 'big')
                          for at in range(len(actual) - 3)
                          if low - 2 <= int.from_bytes(actual[at:at + 4], 'big') <= high + 2}
            if len(candidates) > 1:
                raise ValueError('ambiguous native receive timestamp')
            if candidates:
                timestamp = candidates.pop()
            result = 0
        else:
            actual = returned = b''
            valid, result = True, -22
            if 'icmp' in row:
                packet = bytes.fromhex(row['icmp']['data'])
                header = 4 * (packet[0] & 15)
                if packet[header:header + 2] == b'\x0c\0':
                    parameter = packet[header + 4]
        rows.append(' '.join((row['name'], row['input'] or '-', str(result), actual.hex() or '-',
                              str(int(valid)), returned.hex() or '-', str(timestamp), str(parameter))))
    if len(rows) != 214:
        raise ValueError('incomplete native receive corpus')
    return ('\n'.join(rows) + '\n').encode()
