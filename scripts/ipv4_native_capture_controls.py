# SPDX-License-Identifier: GPL-3.0-or-later
"""Reopen altered original CPU ownership records for native IPv4 observers."""
import json
import os
from pathlib import Path
import shutil
import tempfile
import zipfile


def damaged(directory, destination, verify):
    verify(directory)
    original = json.loads((directory / 'native-configuration.json').read_text())
    controls = []
    for label in ('client-cpu', 'collector-cpu', 'parent-namespace'):
        value = json.loads(json.dumps(original))
        if label == 'client-cpu':
            value['packet_cpu']['client']['actual'] = [value['packet_cpu']['selected'] + 4096]
        elif label == 'collector-cpu':
            value['packet_cpu']['tasks'][0]['actual'] = []
        else:
            value['parent_namespace_inode'] = value['namespace_inode']
        controls.append((label, json.dumps(value).encode()))
    with zipfile.ZipFile(destination, 'x', zipfile.ZIP_DEFLATED) as archive:
        for label, data in controls:
            if data == (directory / 'native-configuration.json').read_bytes():
                raise ValueError('native CPU control must change original input')
            archive.writestr(label + '/native-configuration.json', data)
    rejected = []
    with zipfile.ZipFile(destination) as archive:
        for label, _ in controls:
            with tempfile.TemporaryDirectory(prefix='axiom-ipv4-cpu-') as temporary:
                scratch = Path(temporary) / 'case'
                def copy(source, target):
                    try:
                        os.link(source, target)
                    except OSError:
                        shutil.copy2(source, target)
                    return target
                shutil.copytree(directory, scratch, copy_function=copy)
                target = scratch / 'native-configuration.json'
                target.unlink()
                target.write_bytes(archive.read(label + '/native-configuration.json'))
                try:
                    verify(scratch)
                except (ValueError, KeyError, IndexError, TypeError):
                    rejected.append(label)
                else:
                    raise ValueError('changed native CPU input accepted: ' + label)
    return rejected
