# SPDX-License-Identifier: GPL-3.0-or-later
"""Reject damaged source, compiler, boot-product and execution bindings offline."""
import argparse
import hashlib
import json
from pathlib import Path
import shutil
import tempfile

from ipv4_lifetimes import controls, guest
from ipv4_lifetimes.reader import decode, require
from tcp6.inputs import digest, write

NAMES = ('schema', 'profiles', 'original-directory', 'command-bytes', 'compiler-source',
         'image', 'initramfs', 'kernel', 'firmware', 'source-member', 'source-reader',
         'executable-product', 'finite-flags', 'clock-jump', 'profile-receipt', 'missing-image')


def patches(directory, name):
    changes = {}

    def edit(path, mutation):
        value = decode((directory / path).read_text())
        mutation(value)
        changes[path] = (json.dumps(value, indent=2) + '\n').encode()

    if name == 'schema':
        edit('completed.json', lambda value: value.update(schema=1))
    elif name == 'profiles':
        edit('completed.json', lambda value: value['profiles'].pop())
    elif name == 'original-directory':
        edit('completed.json', lambda value: value.update(original_directory='/unrelated/build/evidence'))
    elif name == 'command-bytes':
        path = 'static-bios-modern/command.json'
        value = decode((directory / path).read_text())
        value[value.index('-m') + 1] = '128M'
        changes[path] = (json.dumps(value, indent=2) + '\n').encode()
    elif name == 'compiler-source':
        edit('static/program.inputs.json', lambda value: value['sources'].update({guest.CLIENT: '0' * 64}))
    elif name in ('image', 'initramfs', 'kernel', 'firmware'):
        path = {'image': 'static/image.iso', 'initramfs': 'static/root.cpio',
                'kernel': 'static/kernel.elf', 'firmware': 'OVMF_CODE.fd'}[name]
        value = bytearray((directory / path).read_bytes())
        value[0] ^= 1
        changes[path] = bytes(value)
    elif name in ('source-member', 'source-reader'):
        path = 'source/source-inputs.json'
        value = decode((directory / path).read_text())
        if name == 'source-member':
            value.pop(guest.CLIENT)
        else:
            value['scripts/ipv4_lifetimes/reader.py'] = '0' * 64
        changes[path] = (json.dumps(value, indent=2) + '\n').encode()
        edit('completed.json', lambda value: value['source'].update(
            source_inputs_sha256=hashlib.sha256(changes[path]).hexdigest()))
    elif name == 'executable-product':
        fake = dict(bytes=1, sha256='0' * 64)
        edit('static/products.json', lambda value: value.update({'bin/ipv4-address-lifetimes': fake}))
        edit('static/program.inputs.json', lambda value: value.update(product=fake))
    elif name in ('finite-flags', 'clock-jump'):
        path = 'static-bios-modern/serial.log'
        lines = (directory / path).read_text().replace('\r\n', '\n').splitlines()
        changes[path] = controls.corrupt(lines, 'finite-permanent-flag' if name == 'finite-flags' else 'clock-jump').encode()
        edit('static-bios-modern/completed.json', lambda value: value.update(
            log_sha256=hashlib.sha256(changes[path]).hexdigest()))
    elif name == 'profile-receipt':
        edit('static-bios-modern/completed.json', lambda value: value['profile'].update(transport='legacy'))
    elif name == 'missing-image':
        changes['static/image.iso'] = None
    else:
        raise ValueError('unknown artifact rejection control')
    return changes


def reconstruct(original, entry):
    require(entry['original_bytes'] == len(original) and
            entry['original_sha256'] == hashlib.sha256(original).hexdigest(),
            'serialized fault binds its complete original file')
    if entry['removed']:
        return None
    if 'replacement_hex' in entry:
        replacement = bytes.fromhex(entry['replacement_hex'])
    else:
        replacement = bytearray(original)
        touched = set()
        for at, old, new in entry['byte_changes']:
            require(type(at) is int and type(old) is int and type(new) is int and
                    0 <= at < len(replacement) and at not in touched and
                    replacement[at] == old and 0 <= new <= 255,
                    'serialized fault changes each bounded original byte once')
            touched.add(at)
            replacement[at] = new
        replacement = bytes(replacement)
    require(replacement != original, 'serialized fault changes actual retained bytes')
    return replacement


def run(directory, destination):
    directory, destination = Path(directory).resolve(), Path(destination).resolve()
    baseline = guest.verify(directory)
    destination.mkdir(exist_ok=False)
    scratch = destination / 'copy'
    shutil.copytree(directory, scratch)
    rows = []
    try:
        for name in NAMES:
            changed = patches(scratch, name)
            originals = {path: (scratch / path).read_bytes() for path in changed}
            serialized = []
            try:
                for path, replacement in changed.items():
                    target = scratch / path
                    before = originals[path]
                    if replacement is None:
                        differences = []
                    else:
                        differences = [[at, old, new] for at, (old, new) in enumerate(zip(before, replacement)) if old != new]
                    # A one-byte image fault needs only its original binding and byte delta.
                    entry = dict(path=path, original_sha256=hashlib.sha256(before).hexdigest(),
                                 original_bytes=len(before), removed=replacement is None)
                    if replacement is not None and len(replacement) == len(before) and len(differences) <= 16:
                        entry['byte_changes'] = differences
                    elif replacement is not None:
                        entry['replacement_hex'] = replacement.hex()
                    serialized.append(entry)
                write(destination / (name + '.json'), serialized)
                for entry in decode((destination / (name + '.json')).read_text()):
                    path = entry['path']
                    require(path in changed, 'serialized fault names only its selected retained files')
                    replacement = reconstruct(originals[path], entry)
                    require(replacement == changed[path], 'reopened serialized fault recreates exact changed bytes')
                    target = scratch / path
                    target.unlink()
                    if replacement is not None:
                        target.write_bytes(replacement)
                try:
                    guest.verify(scratch)
                except (ValueError, FileNotFoundError) as error:
                    rows.append(dict(name=name, rejected=True, reason=str(error),
                                     patch_sha256=digest(destination / (name + '.json'))))
                else:
                    raise ValueError('accepted damaged guest artifact: ' + name)
            finally:
                for path, original in originals.items():
                    target = scratch / path
                    if target.exists():
                        target.unlink()
                    target.write_bytes(original)
        require(guest.verify(scratch) == baseline, 'restored scratch evidence accepts its complete original observations')
    finally:
        require(scratch.parent == destination and scratch.name == 'copy' and not scratch.is_symlink(),
                'dispose only the exact task-owned scratch copy')
        shutil.rmtree(scratch)
    result = dict(passed=True, count=len(NAMES), controls=rows, scratch_removed=True, originals_unchanged=True)
    write(destination / 'completed.json', result)
    return result


def reopen(directory, destination):
    directory, destination = Path(directory), Path(destination)
    saved = decode((destination / 'completed.json').read_text())
    require(saved['passed'] is True and saved['count'] == len(NAMES) and
            [row['name'] for row in saved['controls']] == list(NAMES), 'complete original guest artifact-fault inventory')
    with tempfile.TemporaryDirectory(prefix='axiom-ipv4-control-artifacts-') as temporary:
        replay = Path(temporary) / 'reopened'
        result = run(directory, replay)
        for row in saved['controls']:
            path = destination / (row['name'] + '.json')
            require(row['rejected'] is True and digest(path) == row['patch_sha256'] and
                    decode(path.read_text()) == decode((replay / path.name).read_text()),
                    'every published guest artifact fault matches the named original mutation')
    return dict(passed=True, count=result['count'])


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('directory', type=Path)
    parser.add_argument('destination', type=Path)
    args = parser.parse_args()
    print(json.dumps(run(args.directory, args.destination)), flush=True)


if __name__ == '__main__':
    main()
