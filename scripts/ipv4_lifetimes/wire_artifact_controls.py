# SPDX-License-Identifier: GPL-3.0-or-later
"""Reopen serialized artifact faults against one disposable copy of a real wire matrix."""
import argparse
import copy
import hashlib
import json
import os
from pathlib import Path
import shutil
import stat
import tempfile

from ipv4_lifetimes.artifact_controls import reconstruct
from ipv4_lifetimes.protected import inventory
from ipv4_lifetimes.reader import decode, require
from ipv4_lifetimes.wire_evidence import CLIENT, ordinary_tree, read_artifacts
from ipv4_lifetimes.wire_matrix import identity, inspect, products, specifications
from tcp6.inputs import digest, write

NAMES = ('schema', 'profiles', 'original-directory', 'source-member', 'source-reader', 'missing-source',
         'shared-source-alias', 'common-kernel', 'firmware-bytes', 'common-client', 'compiler-source',
         'compiler-linkage', 'program-header', 'guest-program-product', 'runtime-provider', 'native-namespace',
         'native-kernel-config', 'native-offload', 'native-drop', 'native-count', 'guest-image',
         'guest-initramfs', 'guest-kernel', 'guest-client', 'guest-firmware-command', 'guest-device',
         'worker-command', 'worker-status', 'worker-result', 'process-result', 'missing-guest-image', 'program-alias',
         'compiler-uapi-package', 'compiler-uapi-products', 'compiler-host-include')


def patches(directory, name):
    changes = {}
    native, static, uefi = 'native-native', 'guest-static-bios-modern', 'guest-dynamic-uefi-modern'
    selected = native

    def edit(path, mutation):
        value = decode((directory / path).read_text())
        mutation(value)
        changes[path] = (json.dumps(value, indent=2) + '\n').encode()
        return value

    def flip(path, at=0):
        value = bytearray((directory / path).read_bytes())
        value[at] ^= 1
        changes[path] = bytes(value)

    if name == 'schema':
        edit('inputs.json', lambda value: value.update(schema=True)); selected = None
    elif name == 'profiles':
        edit('inputs.json', lambda value: value['profiles'].pop()); selected = None
    elif name == 'original-directory':
        edit('inputs.json', lambda value: value.update(original_directory='/unrelated/build/capture')); selected = None
    elif name in ('source-member', 'source-reader'):
        value = edit('source/source-inputs.json', lambda value: value.pop(CLIENT) if name == 'source-member' else
                     value.update({'scripts/ipv4_lifetimes/wire_evidence.py': '0' * 64}))
        source = copy.deepcopy(decode((directory / 'inputs.json').read_text())['source'])
        source['source_inputs_sha256'] = hashlib.sha256(changes['source/source-inputs.json']).hexdigest()
        source['files'] = len(value)
        edit('inputs.json', lambda value: value.update(source=source))
        for spec in specifications():
            edit(spec['path'] + '/captured.json', lambda value: value.update(source=source))
        selected = None
    elif name == 'missing-source':
        changes['source/source.zip'] = None; selected = None
    elif name == 'shared-source-alias':
        changes['source/source.zip'] = 'alias'; selected = None
    elif name == 'common-kernel':
        edit('inputs.json', lambda value: value.update(kernel_sha256='0' * 64)); selected = None
    elif name == 'firmware-bytes':
        flip('OVMF_CODE.fd'); selected = None
    elif name == 'common-client':
        edit('inputs.json', lambda value: value['programs'].update(static='0' * 64)); selected = None
    elif name == 'compiler-source':
        edit(native + '/program.inputs.json', lambda value: value['sources'].update({CLIENT: '0' * 64}))
    elif name == 'compiler-linkage':
        selected = 'native-static'
        edit(selected + '/program.inputs.json', lambda value: value['command'].remove('-static'))
    elif name == 'compiler-uapi-package':
        edit(native + '/program.inputs.json', lambda value: value['uapi']['package'].update(version='unrelated'))
    elif name == 'compiler-uapi-products':
        edit(native + '/program.inputs.json', lambda value: value['uapi']['products'].update({'usr/include/linux/if_addr.h': '0' * 64}))
    elif name == 'compiler-host-include':
        edit(native + '/program.inputs.json', lambda value: value['command'].insert(1, '-I/usr/include'))
    elif name == 'program-header':
        path = native + '/program'
        flip(path, 18)
        product = dict(bytes=len(changes[path]), sha256=hashlib.sha256(changes[path]).hexdigest())
        edit(native + '/program.inputs.json', lambda value: value.update(product=product))
        edit('inputs.json', lambda value: value['programs'].update(native=product['sha256']))
    elif name == 'guest-program-product':
        selected = static
        path = static + '/program'
        flip(path, 7)
        product = dict(bytes=len(changes[path]), sha256=hashlib.sha256(changes[path]).hexdigest())
        edit(static + '/program.inputs.json', lambda value: value.update(product=product))
        edit('static/products.json', lambda value: value.update({'bin/ipv4-lifetime-wire': product}))
        edit('inputs.json', lambda value: value['programs'].update(static=product['sha256']))
    elif name == 'runtime-provider':
        runtime = decode((directory / native / 'runtime.json').read_text())
        flip(native + '/' + next(iter(runtime['providers'])))
    elif name == 'native-namespace':
        edit(native + '/runtime.json', lambda value: value.update(namespace=value['namespace'] + 1))
    elif name == 'native-kernel-config':
        changes[native + '/kernel.config'] = b'CONFIG_HZ=42\nCONFIG_64BIT=y\n'
        edit(native + '/native.json', lambda value: value.update(kernel_config_sha256=hashlib.sha256(changes[native + '/kernel.config']).hexdigest()))
    elif name == 'native-offload':
        edit(native + '/offloads.json', lambda value: value['eth0'].update(after=value['eth0']['after'].replace('tx-checksumming: off', 'tx-checksumming: on')))
    elif name in ('native-drop', 'native-count'):
        edit(native + '/packet-statistics.json', lambda value: value['client1'].update(
            drops=1) if name == 'native-drop' else value['client1'].update(packets=value['client1']['packets'] - 1))
    elif name in ('guest-image', 'guest-initramfs'):
        selected = static
        path = 'static/' + ('image.iso' if name == 'guest-image' else 'root.cpio')
        data = (directory / path).read_bytes()
        program = (directory / static / 'program').read_bytes()
        require(data.count(program) == 1, 'one actual embedded client for byte-damage control')
        flip(path, data.index(program))
        key = Path(path).name
        edit('static/products.json', lambda value: value[key].update(sha256=hashlib.sha256(changes[path]).hexdigest()))
    elif name == 'guest-kernel':
        selected = static
        flip('static/kernel.elf')
        edit('static/products.json', lambda value: value['kernel.elf'].update(sha256=hashlib.sha256(changes['static/kernel.elf']).hexdigest()))
    elif name == 'guest-client':
        selected = static
        edit('static/products.json', lambda value: value['bin/ipv4-lifetime-wire'].update(sha256='0' * 64))
    elif name in ('guest-firmware-command', 'guest-device'):
        selected = uefi
        def command(value):
            if name == 'guest-firmware-command':
                at = value.index('-drive') + 1
                value[at] = value[at].replace('readonly=on', 'readonly=off')
            else:
                at = next(at for at, item in enumerate(value) if item.startswith('virtio-net-pci,'))
                value[at] = value[at].replace('disable-legacy=on', 'disable-modern=on')
        edit(selected + '/command.json', command)
    elif name == 'worker-command':
        edit(native + '.worker.json', lambda value: value['command'].__setitem__(value['command'].index('--profile') + 1, 'static'))
    elif name == 'worker-status':
        edit(native + '.worker.json', lambda value: value.update(timed_out=True))
    elif name == 'worker-result':
        edit(native + '.worker.json', lambda value: value.update(returncode=False))
    elif name == 'process-result':
        edit(native + '/process.json', lambda value: value.update(returncode=1))
    elif name == 'missing-guest-image':
        selected = static; changes['static/image.iso'] = None
    elif name == 'program-alias':
        changes[native + '/program'] = 'alias'
    else:
        raise ValueError('unknown wire artifact fault')
    # Repair outer hashes so inner source/compiler/image/runtime checks must run.
    for spec in specifications():
        prefix = spec['path'] + '/'
        relevant = {path[len(prefix):]: data for path, data in changes.items()
                    if path.startswith(prefix) and path != prefix + 'captured.json' and isinstance(data, bytes)}
        if relevant:
            path = prefix + 'captured.json'
            captured = decode(changes.get(path, (directory / path).read_bytes()).decode())
            for filename, data in relevant.items():
                captured['artifacts'][filename] = hashlib.sha256(data).hexdigest()
                if filename == 'command.json': captured['command_sha256'] = hashlib.sha256(data).hexdigest()
            changes[path] = (json.dumps(captured, indent=2) + '\n').encode()
    return changes, selected


def check(directory, selected):
    index = decode((directory / 'inputs.json').read_text())
    if selected is None:
        products(directory, index)
        identity(directory, index, specifications()[0])
    else:
        spec = next(value for value in specifications() if value['path'] == selected)
        identity(directory, index, spec)
        read_artifacts(directory / selected)


def run(directory, destination, *, reopening=False):
    directory, destination = Path(directory).resolve(), Path(destination).resolve()
    require(not destination.is_relative_to(directory), 'artifact controls preserve every original input')
    baseline = inspect(directory)
    before = inventory(directory)
    saved = decode((destination / 'completed.json').read_text()) if reopening else None
    if reopening:
        require(saved['passed'] is True and saved['count'] == len(NAMES) and
                [row['name'] for row in saved['controls']] == list(NAMES), 'complete original wire artifact-fault inventory')
        work = Path(tempfile.mkdtemp(prefix='axiom-ipv4-wire-artifacts-'))
    else:
        destination.mkdir(parents=True, exist_ok=False)
        work = destination
    scratch = work / 'copy'
    shutil.copytree(directory, scratch)
    rows = []
    try:
        for name in NAMES:
            changed, selected = patches(scratch, name)
            originals = {path: ((scratch / path).read_bytes(), stat.S_IMODE((scratch / path).stat().st_mode)) for path in changed}
            entries = []
            for path, replacement in changed.items():
                original = originals[path][0]
                entry = dict(path=path, original_bytes=len(original), original_sha256=hashlib.sha256(original).hexdigest(), removed=replacement is None)
                if replacement == 'alias':
                    entry['link_target'] = os.path.relpath(work / 'alias-target', (scratch / path).parent)
                elif replacement is not None:
                    differences = [[at, old, new] for at, (old, new) in enumerate(zip(original, replacement)) if old != new]
                    if len(original) == len(replacement) and len(differences) <= 16:
                        entry['byte_changes'] = differences
                    else:
                        entry['replacement_hex'] = replacement.hex()
                entries.append(entry)
            expected = dict(selected=selected, files=entries)
            if not reopening: write(destination / (name + '.json'), expected)
            try:
                reopened = decode((destination / (name + '.json')).read_text())
                require(reopened == expected, 'serialized artifact control is the exact named mutation of original inputs')
                if reopening:
                    row = next(row for row in saved['controls'] if row['name'] == name)
                    require(row['rejected'] is True and digest(destination / (name + '.json')) == row['sha256'],
                            'every original published wire artifact-fault byte')
                for entry in reopened['files']:
                    path = entry['path']; target = scratch / path; original = originals[path][0]
                    require(target.resolve().is_relative_to(scratch), 'fault target stays in its disposable copy')
                    target.unlink()
                    if 'link_target' in entry:
                        require(changed[path] == 'alias' and entry['original_sha256'] == hashlib.sha256(original).hexdigest() and
                                entry['original_bytes'] == len(original) and entry['link_target'] ==
                                os.path.relpath(work / 'alias-target', target.parent), 'one exact serialized alias fault')
                        (work / 'alias-target').write_bytes(original)
                        target.symlink_to(entry['link_target'])
                    else:
                        replacement = reconstruct(original, entry)
                        require(replacement == changed[path], 'serialized artifact fault recreates exact changed bytes')
                        if replacement is not None: target.write_bytes(replacement)
                try:
                    check(scratch, selected)
                except (ValueError, FileNotFoundError) as error:
                    rows.append(dict(name=name, rejected=True, reason=str(error), sha256=digest(destination / (name + '.json'))))
                else:
                    raise ValueError('wire reader accepted damaged artifact: ' + name)
            finally:
                for path, (original, mode) in originals.items():
                    target = scratch / path
                    if target.exists() or target.is_symlink(): target.unlink()
                    target.write_bytes(original); target.chmod(mode)
                alias = work / 'alias-target'
                if alias.exists(): alias.unlink()
        require(inspect(scratch) == baseline and inventory(directory) == inventory(scratch) == before,
                'all original artifacts restored and every original input preserved')
    finally:
        require(scratch.parent == work and scratch.name == 'copy' and scratch.resolve().is_relative_to(work),
                'dispose only the exact owned scratch copy')
        ordinary_tree(scratch)
        shutil.rmtree(scratch)
        if reopening: work.rmdir()
    result = dict(passed=True, count=len(rows), controls=rows, baseline_clock_qualified=baseline['passed'],
                  full_wire_acceptance=False, scratch_removed=True, originals_unchanged=True)
    if not reopening: write(destination / 'completed.json', result)
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('directory', type=Path)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    print(json.dumps(run(args.directory, args.output)), flush=True)


if __name__ == '__main__':
    main()
