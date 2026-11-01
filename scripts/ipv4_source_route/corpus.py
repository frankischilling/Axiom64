# SPDX-License-Identifier: GPL-3.0-or-later
"""Fixed native packet observations with a unique identifier for every case."""
import copy
import json
from pathlib import Path

from ipv4_source_route.controls import require


def checksum(data):
    data = data + bytes(len(data) & 1)
    total = sum(int.from_bytes(data[at:at + 2], 'big') for at in range(0, len(data), 2))
    while total >> 16:
        total = (total & 65535) + (total >> 16)
    return total ^ 65535


def replace_word(value, old, new):
    # RFC 1624 preserves the received checksum's residual even when input option
    # processing deliberately leaves a raw observer's header checksum stale.
    total = (value ^ 65535) + (old ^ 65535) + new
    while total >> 16:
        total = (total & 65535) + (total >> 16)
    return total ^ 65535


def option_fields(packet):
    require(len(packet) >= 20, 'complete IPv4 option header')
    header = (packet[0] & 15) * 4
    require(20 <= header <= len(packet), 'bounded IPv4 option header')
    at = 20
    while at < header and packet[at]:
        kind = packet[at]
        if kind == 1:
            yield at, kind, 1
            at += 1
            continue
        require(at + 2 <= header, 'complete option length')
        length = packet[at + 1]
        require(length >= 2 and at + length <= header, 'complete bounded option')
        yield at, kind, length
        at += length


def identification(packet, old, new, *, quoted=False):
    value = bytearray(packet)
    require(len(value) >= 20 and value[0] >> 4 == 4, 'native IPv4 corpus packet')
    header, total = (value[0] & 15) * 4, int.from_bytes(value[2:4], 'big')
    require(20 <= header <= len(value) and header <= total and (quoted or total == len(value)),
            'bounded native IPv4 header and declared length')
    if value[12:16] == bytes((10, 0, 0, 2)):
        previous = int.from_bytes(value[4:6], 'big')
        require(previous == old, 'original native input identification')
        check = replace_word(int.from_bytes(value[10:12], 'big'), previous, new)
        value[4:6], value[10:12] = new.to_bytes(2, 'big'), check.to_bytes(2, 'big')
    if value[9] == 1 and not (int.from_bytes(value[6:8], 'big') & 0x1fff) and len(value) >= header + 8:
        kind = value[header]
        if kind in (0, 8):
            previous = int.from_bytes(value[header + 4:header + 6], 'big')
            require(previous == old, 'original native echo identifier')
            check = replace_word(int.from_bytes(value[header + 2:header + 4], 'big'), previous, new)
            value[header + 4:header + 6] = new.to_bytes(2, 'big')
            value[header + 2:header + 4] = check.to_bytes(2, 'big')
        elif kind in (3, 11, 12):
            require(not quoted and len(value) >= header + 28, 'complete ICMP error and quoted header')
            value[header + 8:] = identification(value[header + 8:], old, new, quoted=True)
            value[header + 2:header + 4] = bytes(2)
            value[header + 2:header + 4] = checksum(bytes(value[header:])).to_bytes(2, 'big')
    return bytes(value)


def frame_identification(frame, old, new):
    value = bytes.fromhex(frame) if isinstance(frame, str) else frame
    require(len(value) >= 34 and value[12:14] == b'\x08\x00', 'native IPv4 Ethernet frame')
    length = int.from_bytes(value[16:18], 'big')
    require(20 <= length <= len(value) - 14, 'complete native IPv4 datagram')
    return value[:14] + identification(value[14:14 + length], old, new) + value[14 + length:]


def cases():
    saved = json.loads(Path(__file__).with_name('packets.json').read_text())
    rows = copy.deepcopy(saved['cases'])
    require(saved['schema'] == 1 and len(rows) == 47 and len({row['name'] for row in rows}) == 47,
            'complete fixed native source-route corpus')
    for number, row in enumerate(rows):
        require(row['kind'] in ('packet', 'raw', 'held') and row['name'], 'known complete source-route case')
        row['case'] = number
        row['clocked'] = any(kind == 68 for value in row['expected']
                             for _, kind, _ in option_fields(bytes.fromhex(value['frame'])[14:]))
        old = int(row['input'][36:40], 16)
        new = 0x7400 + number
        for key in ('input',):
            original = row[key]
            transformed = frame_identification(original, old, new)
            require(frame_identification(transformed, new, old).hex() == original,
                    'reversible native input identifier binding')
            row[key] = transformed.hex()
        for key in ('transmitted',):
            row[key] = [frame_identification(value, old, new).hex() for value in row[key]]
        for value in row['expected']:
            original = value['frame']
            transformed = frame_identification(original, old, new)
            require(frame_identification(transformed, new, old).hex() == original,
                    'reversible native output identifier and quote binding')
            value['frame'] = transformed.hex()
        if row['raw_inputs'] is not None:
            transformed = []
            for value in row['raw_inputs']:
                result = identification(bytes.fromhex(value), old, new)
                require(identification(result, new, old).hex() == value,
                        'reversible processed raw-header identifier binding')
                transformed.append(result.hex())
            row['raw_inputs'] = transformed
    return rows
