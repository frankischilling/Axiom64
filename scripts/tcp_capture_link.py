# SPDX-License-Identifier: GPL-3.0-or-later
"""Reconcile non-IPv4 driver receipts with original Ethernet capture records."""
from collections import Counter
import re
import struct


def require(value, reason):
    if not value:
        raise ValueError(reason)


def fnv(frame):
    result = 0xcbf29ce484222325
    for byte in frame:
        result = (result ^ byte) * 0x100000001b3 & 0xffffffffffffffff
    return f'{result:016x}'


def ethernet_records(path):
    raw = path.read_bytes()
    require(len(raw) >= 24 and raw[:4] == bytes.fromhex('d4c3b2a1'), 'link Ethernet PCAP header')
    header = struct.unpack_from('<IHHIIII', raw)
    require(header[1:3] == (2, 4) and header[6] == 1 and 1514 <= header[5] <= 65536,
            'link Ethernet PCAP version and snapshot bound')
    at, index = 24, 0
    while at < len(raw):
        require(at + 16 <= len(raw), 'complete link PCAP record')
        seconds, micros, size, original = struct.unpack_from('<IIII', raw, at)
        at += 16
        require(micros < 1000000 and 14 <= size == original <= header[5] and at + size <= len(raw),
                'complete original link Ethernet frame')
        yield dict(record_index=index, stamp=seconds * 1000000 + micros, frame=raw[at:at + size])
        at += size
        index += 1


def audit_link_receipts(text, prefix, path, lane, index, packets, ipv4):
    matches = list(re.finditer(
        rf'^{prefix}_LINK_FRAME lane=(\d+) index=(\d+) length=(\d+) kind=(\d+) '
        r'ether_type=([0-9a-f]{4}) hash=([0-9a-f]{16}) monotonic_ms=(\d+)\r?$', text, re.M))
    require(len(matches) == text.count(prefix + '_LINK_FRAME ') and
            all(int(value[1]) in (0, 1) and int(value[2]) > 0 and int(value[3]) >= 14 and
                int(value[4]) in range(5) and value[5] != '0800' for value in matches),
            'complete non-IPv4 driver receipts')
    rows = [value for value in matches if int(value[1]) == lane]
    require(all(int(value[2]) == index for value in rows), 'non-IPv4 driver interface identity')
    require(packets == ipv4 + len(rows), 'exact IPv4 and non-IPv4 driver packet accounting')
    clocks = [int(value[7]) for value in rows]
    require(clocks == sorted(clocks), 'ordered non-IPv4 driver receipt clocks')
    actual = Counter((int(value[3]), int(value[4]), value[5], value[6]) for value in rows)
    guest = bytes([0x52, 0x54, 0, 0x12, 0x34, 0x10 + lane])
    available = Counter()
    for item in ethernet_records(path):
        frame = item['frame']
        if frame[12:14] == b'\x08\x00':
            continue
        kind = (4 if frame[6:12] == guest else
                0 if frame[:6] == guest else
                1 if frame[:6] == b'\xff' * 6 else 2 if frame[0] & 1 else 3)
        available[(len(frame), kind, frame[12:14].hex(), fnv(frame))] += 1
    # Captures may begin before the application's observers are armed. Each
    # claimed non-IPv4 receipt must still own an original physical frame.
    require(not actual - available, 'every non-IPv4 driver receipt owns an original Ethernet frame')
    return len(rows)


def write_ipv4_candidate(path, items, original):
    """Change selected IPv4 records while retaining every unrelated raw record."""
    records = list(ethernet_records(original))
    replacements = {item['record_index']: item for item in items}
    require(len(replacements) == len(items) and set(replacements) <=
            {item['record_index'] for item in records if item['frame'][12:14] == b'\x08\x00'},
            'candidate records retain their original IPv4 owner')
    with path.open('wb') as output:
        output.write(original.read_bytes()[:24])
        for item in records:
            if item['frame'][12:14] == b'\x08\x00':
                item = replacements.get(item['record_index'])
                if item is None:
                    continue
            stamp, frame = item['stamp'], item['frame']
            output.write(struct.pack('<IIII', stamp // 1000000, stamp % 1000000,
                                     len(frame), len(frame)) + frame)
