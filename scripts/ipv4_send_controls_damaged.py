# SPDX-License-Identifier: GPL-3.0-or-later
"""Serialize and reopen altered original send-control observations and inputs."""
import hashlib
import json
import os
from pathlib import Path
import shutil
import struct
import subprocess
import tempfile
import zipfile

from ipv4_send_controls_contract import require, verify


def encoded(value):
    return (json.dumps(value, indent=2) + '\n').encode()


def damaged(directory, destination):
    verify(directory)
    controls = []
    selected = directory / 'static-bios'
    original = (selected / 'client.log').read_bytes()
    replacements = [
        ('shared-default', b' ttl=63 tos=34 unchanged=1 ', b' ttl=62 tos=34 unchanged=1 '),
        ('input-ownership', b' unchanged=1 packet=', b' unchanged=0 packet='),
        ('error-order', b' variant=1 baseline=0 result=24 error=0 ', b' variant=1 baseline=0 result=-1 error=95 '),
        ('automatic-binding', b' before=00000000:0 ', b' before=00000000:1 '),
        ('vector-limit', b' vector_count=1025 ', b' vector_count=1024 '),
        ('ancillary-bytes', b' control=1400000000000000000000000200000025000000', b' control=1400000000000000000000000200000026000000'),
        ('complete-cases', b'IPV4_SEND_CONTROLS_DONE cases=384 observations=768', b'IPV4_SEND_CONTROLS_DONE cases=383 observations=766'),
        ('actual-firmware', b'Firmware: BIOS', b'Firmware: UEFI')]
    for label, before, after in replacements:
        require(before in original, 'actual original observation target')
        changed = original.replace(before, after, 1)
        result = json.loads((selected / 'results.json').read_bytes())
        result['log_sha256'] = hashlib.sha256(changed).hexdigest()
        controls.append((label, {'static-bios/client.log': changed, 'static-bios/results.json': encoded(result)}))
    for label, name in [('program', 'program.elf'), ('kernel', 'kernel.elf'), ('boot-image', 'image.iso'), ('complete-root', 'root.cpio')]:
        data = (selected / name).read_bytes()
        position = 32768 if name == 'image.iso' else len(data) - 1
        changed = data[:position] + bytes((data[position] ^ 1,)) + data[position + 1:]
        changes = {'static-bios/' + name: changed}
        if name in ('image.iso', 'root.cpio'):
            result = json.loads((selected / 'results.json').read_bytes())
            result['products'][name] = hashlib.sha256(changed).hexdigest()
            products = json.loads((selected / 'products.json').read_bytes())
            products[name] = dict(bytes=len(changed), sha256=hashlib.sha256(changed).hexdigest())
            changes.update({'static-bios/results.json': encoded(result), 'static-bios/products.json': encoded(products)})
        controls.append((label, changes))
    for label in ('compile-source', 'compile-linkage', 'compile-output'):
        value = json.loads((selected / 'program.inputs.json').read_bytes())
        if label == 'compile-source':
            value['sources'] = {}
        elif label == 'compile-linkage':
            value['command'].remove('-static')
        else:
            value['command'][-1] = 'build/another-client'
        changed = encoded(value)
        result = json.loads((selected / 'results.json').read_bytes())
        result['products']['program.inputs.json'] = hashlib.sha256(changed).hexdigest()
        controls.append((label, {'static-bios/program.inputs.json': changed, 'static-bios/results.json': encoded(result)}))
    receipt = json.loads((directory / 'acceptance.json').read_bytes())
    omitted = dict(receipt, cases=receipt['cases'][:-1])
    controls.append(('profile-grid', {'acceptance.json': encoded(omitted)}))
    result = json.loads((selected / 'results.json').read_bytes())
    result['timeout_seconds'] = 121
    controls.append(('deadline', {'static-bios/results.json': encoded(result)}))
    data = (directory / 'source.zip').read_bytes()
    controls.append(('source-archive', {'source.zip': bytes((data[0] ^ 1,)) + data[1:]}))
    native = directory / 'linux-native'
    value = json.loads((native / 'native-configuration.json').read_bytes())
    value['links'][0]['flags'].remove('UP')
    controls.append(('native-loopback', {'linux-native/native-configuration.json': encoded(value)}))
    value = json.loads((native / 'results.json').read_bytes())
    value['runtime'] = {}
    controls.append(('native-provider', {'linux-native/results.json': encoded(value)}))
    value = json.loads((directory / 'dynamic-bios/results.json').read_bytes())
    value['products']['loader.elf'] = '0' * 64
    controls.append(('dynamic-loader', {'dynamic-bios/results.json': encoded(value)}))
    require(len(controls) == 21, 'all original and execution-binding negative controls')
    with zipfile.ZipFile(destination, 'x', zipfile.ZIP_DEFLATED) as archive:
        for label, changes in controls:
            for name, data in changes.items():
                require(data != (directory / name).read_bytes(), 'changed actual original evidence')
                archive.writestr(label + '/' + name, data)
    rejected = []
    with zipfile.ZipFile(destination) as archive:
        for label, changes in controls:
            with tempfile.TemporaryDirectory(prefix='axiom-send-controls-') as temporary:
                scratch = Path(temporary) / 'cohort'
                def copy(source, target):
                    try:
                        os.link(source, target)
                    except OSError:
                        shutil.copy2(source, target)
                    return target
                shutil.copytree(directory, scratch, copy_function=copy,
                                ignore=shutil.ignore_patterns(destination.name))
                for name in changes:
                    target = scratch / name
                    target.unlink()
                    target.write_bytes(archive.read(label + '/' + name))
                try:
                    verify(scratch)
                except (ValueError, KeyError, IndexError, TypeError, struct.error, zipfile.BadZipFile, subprocess.CalledProcessError):
                    rejected.append(label)
                else:
                    raise ValueError('changed original send-control evidence accepted: ' + label)
    return rejected
