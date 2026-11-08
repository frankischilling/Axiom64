#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Independently reopen retained Unix datagram sources, clients, images and serial logs."""
import argparse
import hashlib
import itertools
import json
from pathlib import Path
import struct

from disk_root import archive_entries
from tcp_fixture_inputs import audit_fixture, digest
from unix_datagram_contract import CLIENTS, boot_body, check_log


def binary_linkage(program):
    data = program.read_bytes()
    if len(data) < 64 or data[:6] != b'\x7fELF\x02\x01' or struct.unpack_from('<H', data, 18)[0] != 62:
        raise ValueError('Unix client is not a little-endian x86-64 ELF')
    offset = struct.unpack_from('<Q', data, 32)[0]
    size, count = struct.unpack_from('<HH', data, 54)
    if size != 56 or offset > len(data) or count * size > len(data) - offset:
        raise ValueError('Unix client has an invalid ELF program header table')
    interpreters = []
    for index in range(count):
        kind, _, start, _, _, length, _, _ = struct.unpack_from('<IIQQQQQQ', data, offset + index * size)
        if kind == 3:
            if start > len(data) or length > len(data) - start:
                raise ValueError('Unix client has an invalid ELF interpreter segment')
            interpreters.append(data[start:start + length])
    if not interpreters:
        return 'static'
    if interpreters != [b'/lib/ld-musl-x86_64.so.1\0']:
        raise ValueError('Unix client does not use the controlled musl interpreter')
    return 'dynamic'


def verify(directory):
    source = json.loads((directory / 'source-inputs.json').read_text())
    for name, value in source.items():
        path = Path(name)
        if path.is_absolute() or '..' in path.parts or digest(directory / 'inputs' / path) != value:
            raise ValueError('retained Unix input does not match its source manifest')
    sdk = json.loads((directory / 'sdk.json').read_text())
    if len(sdk['products']) != 977:
        raise ValueError('incomplete target UAPI header inventory')
    for name, value in sdk['products'].items():
        path = Path(name)
        if path.is_absolute() or '..' in path.parts or digest(directory / 'sdk' / path) != value:
            raise ValueError('retained Unix SDK header differs from compilation input')
    rows = json.loads((directory / 'results.json').read_text())
    expected = set(itertools.product(('build', 'runtime'), ('static', 'dynamic'), ('bios', 'uefi')))
    keys = [(row['provider'], row['linkage'], row['firmware']) for row in rows]
    if len(keys) != 8 or set(keys) != expected:
        raise ValueError('incomplete or repeated Unix guest profile inventory')
    script = ('#!/bin/sh\nset -e\n' + boot_body() + '\necho AXIOM64_TESTS_PASS\n').encode()
    kernels = set()
    for provider, linkage in itertools.product(('build', 'runtime'), ('static', 'dynamic')):
        case = directory / (provider + '-' + linkage)
        products = json.loads((case / 'products.json').read_text())
        entries = archive_entries(case / 'root.cpio')
        for name, value in products.items():
            if name in ('image.iso', 'root.cpio', 'kernel.elf'):
                data = (case / name).read_bytes()
            else:
                data = entries[name][1]
            if len(data) != value['bytes'] or hashlib.sha256(data).hexdigest() != value['sha256']:
                raise ValueError('retained Unix product differs from its fingerprint: ' + name)
        required = {'bin/' + name.replace('_', '-') for name in CLIENTS}
        required |= {'sbin/init', 'bin/busybox', 'lib/ld-musl-x86_64.so.1',
                     'image.iso', 'root.cpio', 'kernel.elf'}
        required |= {'source/' + name + '.inputs.json' for name in CLIENTS}
        if set(products) != required:
            raise ValueError('unexpected Unix boot product inventory')
        for name in CLIENTS:
            program = case / name
            compiled = json.loads(program.with_suffix('.inputs.json').read_text())
            relative = 'userspace/tests/ipc/' + name + '.c'
            if compiled['sources'] != {relative: source[relative]} or compiled['uapi'] != sdk:
                raise ValueError('Unix client does not bind retained source and SDK')
            if compiled['product']['sha256'] != digest(program):
                raise ValueError('Unix client executable differs from compilation')
            if binary_linkage(program) != linkage:
                raise ValueError('actual Unix ELF linkage differs from its guest profile')
            if digest(program) != products['bin/' + name.replace('_', '-')]['sha256']:
                raise ValueError('compiled Unix client differs from actual boot product')
            if program.with_suffix('.inputs.json').read_bytes() != entries['source/' + name + '.inputs.json'][1]:
                raise ValueError('boot image contains a different client compilation record')
        kernel = products['kernel.elf']['sha256']
        kernels.add(kernel)
        audit_fixture(case / 'image.iso', kernel, {name: value['sha256'] for name, value in products.items()
                      if name not in ('image.iso', 'root.cpio', 'kernel.elf')}, script,
                      initramfs_sha256=products['root.cpio']['sha256'])
        for row in rows:
            if (row['provider'], row['linkage']) != (provider, linkage):
                continue
            log = case / (row['firmware'] + '.log')
            if row['case'] != case.name or row['kernel_sha256'] != kernel or digest(log) != row['log_sha256']:
                raise ValueError('Unix run is not bound to retained products and serial output')
            invocations = check_log(log.read_text(), row['firmware'], row['returncode'])
            if any(actual != linkage for _, actual in invocations):
                raise ValueError('guest did not execute the recorded client linkage')
    if len(kernels) != 1:
        raise ValueError('Unix guest profiles did not use one kernel')
    return dict(passed=True, profiles=8, public_client_executions=96, full_unix_acceptance=False)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('directory', type=Path)
    print(json.dumps(verify(parser.parse_args().directory)))
