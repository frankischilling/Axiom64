# SPDX-License-Identifier: GPL-3.0-or-later
"""Reopen complete literal-header observations from actual socket clients."""
import re


def require(condition, message):
    if not condition:
        raise ValueError(message)


def checksum(data):
    value = sum(int.from_bytes(data[at:at + 2], 'big') for at in range(0, len(data), 2))
    while value >> 16:
        value = (value & 65535) + (value >> 16)
    return (~value) & 65535


def verify(text, *, native=False):
    require('IPV4_RAW_HEADERS_FAIL' not in text and
            text.count('IPV4_RAW_HEADERS_ORDINARY_PASS') == 1 and
            text.count('IPV4_RAW_HEADERS_PASS ') == 1 and
            text.count('IPV4_RAW_HEADERS_PASS cases=' + str(356 if native else 355)) == 1,
            'complete raw-header scalar, pointer, inherited-description and output cases')
    pattern = r'^IPV4_RAW_HEADERS_BYTES uid=(\d+) protocol=(\d+) case=(\d+) length=(\d+) bytes=([0-9a-f]+)$'
    rows = list(re.finditer(pattern, text, re.M))
    expected = {(uid, protocol, case) for uid, protocol in ((0, 75), (0, 255), (65534, 255))
                for case in range(4)}
    require(len(rows) == len(expected) and text.count('IPV4_RAW_HEADERS_BYTES ') == len(rows),
            'all twelve original literal-header packets')
    seen = set()
    for row in rows:
        uid, protocol, case, length = map(int, row.groups()[:4])
        key = uid, protocol, case
        require(key in expected and key not in seen, 'unique raw-header packet and credential scope')
        seen.add(key)
        packet = bytes.fromhex(row[5])
        header = 60 if case == 3 else 20
        require(length == len(packet) == (68 if case == 3 else 28), 'actual complete packet length')
        identity = 0x1357 if case in (0, 3) else 0
        expected_packet = bytearray(length)
        expected_packet[0:4] = bytes((0x40 | header // 4, 0x5a, 0, length))
        expected_packet[4:6] = identity.to_bytes(2, 'big') if case != 1 else packet[4:6]
        expected_packet[6:10] = bytes((0x40 if case == 2 else 0, 0, 35, protocol))
        expected_packet[12:20] = bytes((127, 0, 0, 1)) * 2
        expected_packet[20:header] = b'\1' * (header - 20)
        expected_packet[header:] = bytes((at * 37 + 11) & 255 for at in range(header, length))
        expected_packet[10:12] = checksum(expected_packet[:header]).to_bytes(2, 'big')
        require(packet == expected_packet, 'literal fields, filled source/length/checksum and complete owned payload')
    return dict(packets=len(seen), credential_scopes=2, inherited_output_packets=4)


def damaged_controls(text):
    pattern = r'(^IPV4_RAW_HEADERS_BYTES uid=0 protocol=75 case=0 length=28 bytes=)([0-9a-f]+)$'
    match = re.search(pattern, text, re.M)
    require(match is not None, 'actual raw-header packet for negative controls')
    controls = {}
    for name, at in (('source', 15), ('destination', 19), ('ttl', 8), ('tos', 1),
                     ('protocol', 9), ('identity', 4), ('payload', 24), ('ihl', 0), ('length', 3)):
        packet = bytearray.fromhex(match[2])
        packet[at] ^= 1
        packet[10:12] = b'\0\0'
        packet[10:12] = checksum(packet[:20]).to_bytes(2, 'big')
        controls[name + '-repaired-checksum'] = text[:match.start(2)] + packet.hex() + text[match.end(2):]
    controls['missing-packet'] = text[:match.start()] + text[match.end():]
    controls['missing-inherited-scope'] = text.replace('uid=65534 protocol=255', 'uid=65533 protocol=255')
    controls['incomplete-cases'] = text.replace('IPV4_RAW_HEADERS_PASS cases=', 'IPV4_RAW_HEADERS_PASS omitted=')
    return controls
