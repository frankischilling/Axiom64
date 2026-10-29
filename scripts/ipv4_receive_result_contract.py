# SPDX-License-Identifier: GPL-3.0-or-later
"""Check actual IPv4 receive side effects against the observed Linux copy order."""
import struct

from ipv4_receive_copy_model import require

PAYLOAD_PREFIXES = (0, 1, 2, 7, 8, 15, 16, 19, 20, 27, 28, 43, 44)
NAME_PREFIXES = (0, 1, 2, 3, 7, 8, 15, 16, 17, 40)
HEADER_PREFIXES = (0, 1, 7, 8, 9, 10, 11, 12, 39, 40, 41, 44, 47, 48, 49, 52, 56)
COUNTS = (28, 21, 34, 29)
CASES = 1344
FIELDS = {'kind', 'case', 'transport', 'phase', 'mode', 'input_flags', 'result', 'errno',
          'queued', 'queue_errno', 'input', 'payload', 'payload_guard', 'name', 'name_guard',
          'control_hex', 'header', 'length_hex'}


def checksum(data):
    if len(data) & 1:
        data += b'\0'
    value = sum(struct.unpack('!' + 'H' * (len(data) // 2), data))
    while value >> 16:
        value = (value & 65535) + (value >> 16)
    return (~value) & 65535


def original_packet(row):
    data = bytes.fromhex(row['input'])
    body = b'AXRESULT' + bytes((row['case'] * 31 + n * 17) & 255 for n in range(8, 16))
    kind = row['transport']
    if not kind:
        require(data == body, 'exact original UDP input')
    else:
        require(len(data) == 44 and data[:4] == b'\x45\x6e\0\x2c' and
                data[8] == 37 and data[9] == (1 if kind == 1 else 17) and
                data[12:20] == b'\x7f\0\0\1\x7f\0\0\2' and not checksum(data[:20]) and
                data[28:] == body, 'owned raw header, checksum and complete original payload')
        if kind == 1:
            require(data[20:22] == b'\x08\0' and data[24:28] == b'QB\0\0' and
                    not checksum(data[20:]), 'original raw ICMP packet')
        else:
            pseudo = data[12:20] + b'\0\x11\0\x18'
            require(data[20:22] == (41001).to_bytes(2, 'big') and data[24:26] == b'\0\x18' and
                    data[26:28] != b'\0\0' and not checksum(pseudo + data[20:]),
                    'original raw UDP header and pseudoheader checksum')
    return data


def controls(index):
    data = bytearray(b'\xa5' * 96)
    struct.pack_into('<Qii', data, 0, 28, 0, 8)
    struct.pack_into('<I', data, 16, index)
    data[20:28] = b'\x7f\0\0\2' * 2
    struct.pack_into('<Qiii', data, 32, 20, 0, 2, 37)
    struct.pack_into('<Qii', data, 56, 17, 0, 1)
    data[72] = 0x6e
    return bytes(data)


def inspect(row, index, order):
    require(set(row) == FIELDS and all(type(row[key]) is int for key in
            ('case', 'transport', 'phase', 'mode', 'input_flags', 'result', 'errno', 'queued', 'queue_errno')),
            'exact result-fault fields and scalar types')
    require(order in ('address-first', 'length-first'), 'independently recognized source order')
    kind, phase, mode = row['transport'], row['phase'], row['mode']
    flags = row['input_flags']
    packet = original_packet(row)
    length = len(packet)
    source = struct.pack('<H', 2) + struct.pack('!H', 53598 if not kind else 0) + b'\x7f\0\0\1' + bytes(8)
    actual = {key: bytes.fromhex(row[key]) for key in
              ('payload', 'payload_guard', 'name', 'name_guard', 'control_hex', 'header', 'length_hex')}
    payload = b'\xa5' * 64
    payload_guard = b''
    name = b'\xa5' * 40
    name_guard = b''
    control = b'\xa5' * 96
    header = bytearray(b'\xa5' * 56)
    header[:8] = header[16:24] = header[32:40] = bytes(8)
    capacity, vectors = 40, 2
    error, copied, guard_copied = 0, length, None
    name_copied, name_guard_copied = 16, None
    imported, header_store, named = True, True, True
    ordinary = 40
    length_bytes = ordinary.to_bytes(4, 'little')
    result = length
    truncated = False
    if phase == 0:
        if mode in (1, 2, 3):
            copied, error = 0 if mode == 1 else 7, 14
            vectors = 1 if mode == 1 else 3 if mode == 3 else 2
        elif mode in (4, 5):
            copied = 0 if mode == 4 else 8
            vectors, truncated = 1, True
            result = length if flags & 32 else copied
        elif 6 <= mode <= 11:
            copied, imported = 0, False
            error = 90 if mode == 9 else 22 if mode == 10 else 14
            vectors = 1025 if mode == 9 else 2 if mode in (8, 11) else 1
        elif mode in (25, 26):
            copied, imported, error, vectors = 0, False, 14, 1
        elif mode == 27:
            copied, vectors, truncated = 0, 0, True
            result = length if flags & 32 else 0
        elif mode >= 12:
            prefix = PAYLOAD_PREFIXES[mode - 12]
            vectors, copied = 1, 0
            payload_guard = b'\xa5' * prefix
            guard_copied = min(prefix, length)
            error = 14 if prefix < length else 0
    elif phase == 1:
        if mode in (1, 2):
            named = False
            capacity = 40 if mode == 1 else 0xffffffff
        elif mode in (3, 4, 5):
            capacity = 1 if mode == 5 else 0
            name_copied = 0
            error = 14 if mode == 5 else 0
        elif mode in (6, 7):
            capacity = 0xffffffff if mode == 6 else 0x80000000
            copied, imported, error = 0, False, 22
        elif mode in (8, 9, 10):
            capacity = 0x7fffffff if mode == 8 else 128 if mode == 9 else 1
            name_copied = min(capacity, 16)
        elif mode >= 11:
            prefix = NAME_PREFIXES[mode - 11]
            name_copied = 0
            name_guard = b'\xa5' * prefix
            name_guard_copied = min(prefix, 16)
            error = 14 if prefix < 16 else 0
    elif phase == 2:
        prefix = HEADER_PREFIXES[mode % len(HEADER_PREFIXES)]
        named = mode < len(HEADER_PREFIXES)
        if named and prefix < 12:
            error = 14
            name_copied = 16 if order == 'address-first' else 0
            header_store = False
        elif named and prefix < 52:
            error = 14
        elif not named and prefix > 40:
            error = 14
    else:
        header_store = False
        if mode in (1, 2, 3):
            named = False
            length_bytes = b'\xff' * 4 if mode == 3 else b''
        elif mode in (4, 5):
            ordinary = 0 if mode == 4 else 1
            error = 0 if mode == 4 else 14
            name_copied = 0
            length_bytes = ordinary.to_bytes(4, 'little')
        elif mode in (6, 7, 12):
            error, name_copied = 14, 0
            length_bytes = b'\x28\0' if mode == 12 else b''
        elif mode == 8:
            error, name_copied = 14, 16 if order == 'address-first' else 0
        elif mode in (9, 10):
            error, name_copied = 22, 0
            ordinary = 0xffffffff if mode == 9 else 0x80000000
            length_bytes = ordinary.to_bytes(4, 'little')
        elif mode == 11:
            ordinary = 0x7fffffff
            length_bytes = ordinary.to_bytes(4, 'little')
        elif mode == 13:
            error, copied, name_copied = 14, 0, 0
        elif mode in (14, 15):
            prefix = 7 if mode == 14 else length
            copied, guard_copied = 0, prefix
            payload_guard = b'\xa5' * prefix
            if mode == 14:
                error, name_copied = 14, 0
        elif mode in (26, 27):
            error, copied, name_copied, imported = 14, 0, 0, False
        elif mode == 28:
            copied = 0
            result = length if flags & 32 else 0
        elif mode >= 16:
            prefix = NAME_PREFIXES[mode - 16]
            name_copied = 0
            name_guard = b'\xa5' * prefix
            name_guard_copied = min(prefix, 16)
            error = 14 if prefix < 16 else 0

    struct.pack_into('<I', header, 8, capacity)
    struct.pack_into('<Q', header, 24, vectors)
    struct.pack_into('<Q', header, 40, 96)
    struct.pack_into('<I', header, 48, 0x5a5a)
    payload = packet[:copied] + payload[copied:]
    if guard_copied is not None:
        payload_guard = packet[:guard_copied] + payload_guard[guard_copied:]
    payload_fault = phase == 0 and error or phase == 3 and mode in (13, 14)
    if not imported or payload_fault:
        name_copied, name_guard_copied = 0, 0 if name_guard_copied is not None else None
    if not named:
        name_copied = 0
    if phase != 3 and imported and not payload_fault:
        control = controls(index)
        # Source length is the only observed native-version-dependent store.
        store_length = named and (not error or order == 'length-first')
        if phase == 2:
            store_length = named and HEADER_PREFIXES[mode] >= 12 if named else False
        if store_length:
            struct.pack_into('<I', header, 8, 16)
        store_flags, store_control = not error, not error
        if phase == 2 and mode >= len(HEADER_PREFIXES):
            prefix = HEADER_PREFIXES[mode - len(HEADER_PREFIXES)]
            store_flags, store_control = prefix <= 48, prefix <= 40
        if store_flags:
            struct.pack_into('<I', header, 48, 32 if truncated else 0)
        if store_control:
            struct.pack_into('<Q', header, 40, 80)
    if phase == 3 and named and mode not in (6, 7, 8, 9, 10, 12, 13, 14, 26, 27):
        if not error or order == 'length-first':
            length_bytes = (16).to_bytes(4, 'little')
    name = source[:name_copied] + name[name_copied:]
    if name_guard_copied is not None:
        name_guard = source[:name_guard_copied] + name_guard[name_guard_copied:]
    expected = dict(payload=payload, payload_guard=payload_guard, name=name, name_guard=name_guard,
                    control_hex=control, header=bytes(header), length_hex=length_bytes)
    for field, wanted in expected.items():
        require(actual[field] == wanted, 'exact ' + field + ' effects at result case ' + str(row['case']))
    require(row['result'] == (-1 if error else result) and row['errno'] == error,
            'actual result and errno at result case ' + str(row['case']))
    retained = not imported or flags & 2
    require(row['queued'] == (length if retained else -1) and row['queue_errno'] == (0 if retained else 11),
            'exact input validation/dequeue/peek ownership at result case ' + str(row['case']))


def verify(rows, index, order):
    require(len(rows) == CASES, 'complete result-fault inventory')
    cursor = 0
    for kind in range(3):
        for flags in (0, 2, 32, 34):
            for phase, count in enumerate(COUNTS):
                for mode in range(count):
                    row = rows[cursor]
                    require((row['case'], row['transport'], row['input_flags'], row['phase'], row['mode']) ==
                            (cursor, kind, flags, phase, mode), 'complete ordered real fault matrix')
                    inspect(row, index, order)
                    cursor += 1
    return dict(result_faults_each=CASES, original_packets_and_copy_prefixes_verified=True)
