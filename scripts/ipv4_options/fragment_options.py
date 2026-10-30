# SPDX-License-Identifier: GPL-3.0-or-later
"""Option values used by the ordinary Ethernet fragmentation workload."""


def kind(test):
    if test < 21:
        return 0
    if test <= 34:
        return 1
    return {35: 2, 36: 3, 37: 4, 38: 5, 39: 3, 40: 3, 41: 2, 42: 2, 43: 6, 44: 6}[test]


def value(test):
    selected = kind(test)
    if selected == 0:
        return b''
    if selected == 1:
        return (bytes.fromhex('94040000 07070400000000 01 4408050000000000 9e041234 1e045678') +
                b'\1' * 12)
    return {2: bytes.fromhex('0707040000000000'), 3: bytes.fromhex('4408050000000000'),
            4: bytes.fromhex('94040000'), 5: bytes.fromhex('9e04aabb1e04ccdd'), 6: b'\1' * 40}[selected]


def wire_value(test, lane, offset, actual):
    """Check emitted slots and retain alignment after non-copied options become NOPs."""
    expected = bytearray(value(test))
    if len(expected) != len(actual):
        raise ValueError('fragment option header length differs')
    at = 0
    stamps = []
    while at < len(expected):
        option = expected[at]
        if option == 0:
            break
        if option == 1:
            at += 1
            continue
        size = expected[at + 1]
        if offset and not option & 128:
            expected[at:at + size] = b'\1' * size
        elif option == 7:
            expected[at + 2] = 8
            expected[at + 3:at + 7] = bytes((10, 23, lane + 1, 2))
        elif option == 68:
            expected[at + 2] = 9
            stamp = int.from_bytes(actual[at + 4:at + 8], 'big')
            if stamp >= 86400000:
                raise ValueError('fragment timestamp is outside UTC milliseconds since midnight')
            expected[at + 4:at + 8] = actual[at + 4:at + 8]
            stamps.append(stamp)
        at += size
    if actual != expected:
        raise ValueError('fragment copied flags, recorded source, option pointer or complete bytes differ')
    return stamps
