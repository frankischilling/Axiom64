# SPDX-License-Identifier: GPL-3.0-or-later
"""Native IPv4 option setter/query vectors; no packets are sent."""
import os
import platform
import socket
from pathlib import Path


def vectors():
    vectors = []
    def add(name, value):
        assert len(value) <= 40
        vectors.append(dict(name=name, input=bytes(value).hex()))
    for length in range(41):
        add('nops-' + str(length), [1] * length)
    add('end-clears-tail', [0, 255, 255, 255])
    for kind in range(2, 256):
        for length in (2, 3, 4, 6, 7, 8, 12, 40):
            value = [kind, length] + [0] * (length - 2)
            if kind in (7, 131, 137) and length >= 3:
                value[2] = 4
            if kind == 68 and length >= 3:
                value[2] = 5
            add('type-' + str(kind) + '-length-' + str(length), value)
    for length in range(3, 41):
        for pointer in range(44):
            add('rr-' + str(length) + '-' + str(pointer), [7, length, pointer] + [0xa5] * (length - 3))
    for kind in (131, 137):
        for length in range(3, 41):
            for pointer in sorted({0, 3, 4, 5, length + 1, 255}):
                add('route-' + str(kind) + '-' + str(length) + '-' + str(pointer),
                    [kind, length, pointer] + [0xa5] * (length - 3))
    for length in range(4, 41):
        for pointer in sorted({0, 4, 5, 6, length - 3, length, length + 1, 255}):
            for flag in (0, 1, 2, 3, 15, 0xf0, 0xf1, 0xf2, 0xf3, 0xff):
                add('ts-' + str(length) + '-' + str(pointer) + '-' + str(flag),
                    [68, length, pointer, flag] + [0xa5] * (length - 4))
    for address in (0, 0x7f000001, 0x7f000009, 0xe0000001, 0xffffffff, 0xc0000201):
        add('prespecified-' + hex(address), [68, 12, 5, 3] + list(address.to_bytes(4, 'big')) + [0xa5] * 4)
    for kind, option in [(7, [7, 3, 4]), (68, [68, 4, 5, 0]), (131, [131, 7, 4, 127, 0, 0, 1]),
                         (137, [137, 7, 4, 127, 0, 0, 1]), (148, [148, 4, 0, 0])]:
        add('duplicate-' + str(kind), option + option)
    for doi in (0, 1, 0xffffffff):
        for tail in ([], [0, 2], [1, 2], [1, 4, 0, 0], [2, 4, 0, 0], [5, 4, 0, 0], [255, 2]):
            value = [134, 6 + len(tail)] + list(doi.to_bytes(4, 'big')) + tail
            add('cipso-' + str(doi) + '-' + bytes(tail).hex(), value)
    return vectors


def capture():
    rows = []
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as descriptor:
        for vector in vectors():
            descriptor.setsockopt(socket.IPPROTO_IP, socket.IP_OPTIONS, b'\1' * 4)
            try:
                descriptor.setsockopt(socket.IPPROTO_IP, socket.IP_OPTIONS, bytes.fromhex(vector['input']))
                result = 0
            except OSError as error:
                result = -error.errno
            value = descriptor.getsockopt(socket.IPPROTO_IP, socket.IP_OPTIONS, 40)
            rows.append(dict(**vector, result=result, output=value.hex()))
    capabilities = next(line.split()[1] for line in Path('/proc/self/status').read_text().splitlines()
                        if line.startswith('CapEff:'))
    return dict(kernel=platform.release(), uid=os.geteuid(), effective_capabilities=capabilities,
                vectors=len(rows), rows=rows)
