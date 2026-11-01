# SPDX-License-Identifier: GPL-3.0-or-later
"""Reopen damaged actual archives, executables, images and runtime records."""
import argparse
import copy
import json
import os
from pathlib import Path
import shutil
import struct
import subprocess
import sys

from ipv4_source_route import matrix, model
from ipv4_source_route.controls import decode, require
from tcp6.inputs import digest, write


def check(request):
    require((os.geteuid() == 0) == (request['identity'] == 'root'), 'actual requested reader identity')
    path = Path(request['directory'])
    kind = request['kind']
    if kind == 'matrix':
        return matrix.verify(path)
    if kind == 'case':
        return matrix.observe(path, request['phase'])
    if kind == 'native':
        matrix.native_wire(path)
        return dict(passed=True)
    if kind == 'boot':
        matrix.boot(path, request['spec'], request['firmware'])
        return dict(passed=True)
    if kind == 'controls':
        from ipv4_source_route.evidence import verify
        return verify(path)
    require(kind == 'model', 'known independent artifact reader')
    return model.verify(path)


def damage_requests(directory):
    index = decode((directory / 'matrix.json').read_text())
    static = directory / 'packets-guest-static-bios-modern'
    dynamic = directory / 'packets-native-dynamic'
    native = directory / 'packets-native-native'
    uefi = directory / 'queues-guest-dynamic-uefi-legacy'
    spec = next(value for value in matrix.specifications() if value['path'] == uefi.name)
    result = []
    def add(label, source, kind, file, change, **extra):
        result.append(dict(label=label, source=source, request=dict(kind=kind, **extra), file=file, change=change))
    def altered(file, operation):
        value = decode(file.read_text())
        operation(value)
        return (json.dumps(value, indent=2) + '\n').encode()
    def flip(file):
        value = bytearray(file.read_bytes())
        require(value, 'actual nonempty binary artifact')
        value[0] ^= 1
        return bytes(value)
    for label, change in (
            ('missing-profile', lambda value: value['profiles'].pop()),
            ('duplicate-profile', lambda value: value['profiles'].append(value['profiles'][0])),
            ('incomplete', lambda value: value.update(complete=False)),
            ('boolean-schema', lambda value: value.update(schema=True)),
            ('missing-phase', lambda value: value.update(profiles=[row for row in value['profiles'] if row['phase'] != 'queues']))):
        add(label, directory, 'matrix', 'matrix.json', lambda file, op=change: altered(file, op))
    for label, file in (('source-archive', 'source/source.zip'), ('actual-program', 'program'),
                        ('actual-image', 'image.iso'), ('actual-kernel', 'kernel.elf'), ('actual-root', 'root.cpio')):
        add(label, static, 'case', file, flip, phase='packets')
    add('compile-source', static, 'case', 'program.inputs.json', lambda file: altered(file, lambda value:
        value['sources'].update({'userspace/tests/net/ipv4/source_route_wire.c': '0' * 64})), phase='packets')
    add('source-inventory', static, 'case', 'source/source-inputs.json', lambda file: altered(file, lambda value:
        value.pop(next(iter(value)))), phase='packets')
    add('actual-loader', dynamic, 'case', 'runtime/ld-musl-x86_64.so.1', flip, phase='packets')
    provider = next((native / 'runtime').iterdir()).relative_to(native).as_posix()
    add('actual-native-provider', native, 'case', provider, flip, phase='packets')
    for label, file in (('actual-firmware', 'OVMF_CODE.fd'), ('original-firmware-variables', 'OVMF_VARS.original.fd')):
        add(label, uefi, 'boot', file, flip, spec=spec, firmware=index['firmware'])
    add('wrong-firmware-log', uefi, 'boot', 'client.log', lambda file:
        file.read_bytes().replace(b'Firmware: UEFI', b'Firmware: BIOS'), spec=spec, firmware=index['firmware'])
    add('wrong-device-log', uefi, 'boot', 'client.log', lambda file:
        file.read_bytes().replace(b'virtio-net: index=1 transport=legacy', b'virtio-net: index=1 transport=modern'),
        spec=spec, firmware=index['firmware'])
    add('wrong-device-command', uefi, 'boot', 'command.json', lambda file:
        file.read_bytes().replace(b'disable-modern=on', b'disable-legacy=on'), spec=spec, firmware=index['firmware'])
    add('missing-device', uefi, 'boot', 'client.log', lambda file:
        b'\n'.join(line for line in file.read_bytes().splitlines() if not line.startswith(b'NET_DEVICE index=2')) + b'\n',
        spec=spec, firmware=index['firmware'])
    add('native-timer-config', native, 'native', 'native-kernel-config.txt', lambda file:
        file.read_bytes().replace(b'CONFIG_HZ=', b'CONFIG_HZ_INVALID='))
    add('native-timer-policy', native, 'native', 'native-timer-policy.json', lambda file:
        altered(file, lambda value: value['after']['interfaces']['eth1'].update(retrans_time_ms=100)))
    first = decode((native / 'results.json').read_text())[0]['input_began_ns']
    last = decode((native / 'results.json').read_text())[-1]['ended_ns']
    add('native-late-initial-policy', native, 'native', 'native-timer-policy.json', lambda file:
        altered(file, lambda value: value['before'].update(begin_ns=first + 1, end_ns=first + 2)))
    add('native-premature-final-policy', native, 'native', 'native-timer-policy.json', lambda file:
        altered(file, lambda value: value['after'].update(begin_ns=last - 2, end_ns=last - 1)))
    add('native-missing-ingress', native, 'native', 'ingress-wire.json', lambda file:
        altered(file, lambda value: value.clear()))
    add('native-ingress-drops', native, 'native', 'ingress-statistics.json', lambda file:
        altered(file, lambda value: value['0'].update(drops=1)))
    add('native-drops', native, 'native', 'packet-statistics.json', lambda file: altered(file, lambda value: value['0'].update(drops=1)))
    add('native-offloads', native, 'native', 'offloads.json', lambda file:
        file.read_bytes().replace(b'tx-checksumming: off', b'tx-checksumming: on'))
    def checksum_not_ready(file):
        value = decode(file.read_text())
        data = bytearray.fromhex(value[0]['controls'][0]['data'])
        struct.pack_into('I', data, 0, struct.unpack_from('I', data)[0] | 8)
        value[0]['controls'][0]['data'] = data.hex()
        return (json.dumps(value, indent=2) + '\n').encode()
    add('unchecked-native-checksum', native, 'native', 'auxiliary.json', checksum_not_ready)
    def guard_byte(file):
        return altered(file, lambda value: next(row for row in value if row['command'].startswith('guard ')).update(input_hex='3f'))
    def guard_time(file):
        def change(value):
            row = next(row for row in value if row['command'].startswith('guard '))
            row['monotonic_ns'] -= 200000000
        return altered(file, change)
    add('actual-guard-byte', uefi, 'case', 'commands.json', guard_byte, phase='queues')
    add('actual-guard-command-time', uefi, 'case', 'commands.json', guard_time, phase='queues')
    add('missing-model-case', directory / 'model', 'model', 'completed.json', lambda file:
        altered(file, lambda value: value['results'].pop()))
    add('actual-model-program', directory / 'model', 'model', 'program', flip)
    require(len(result) == 33, 'complete archive product linkage firmware device matrix and model faults')
    return result


def invoke(request, directory, public_source, ordinary):
    request = copy.deepcopy(request)
    request['identity'] = 'ordinary' if ordinary else 'root'
    path = directory / ('ordinary-request.json' if ordinary else 'root-request.json')
    write(path, request)
    command = [sys.executable, '-B', '-m', 'ipv4_source_route.faults', '--check', str(path)]
    if ordinary:
        command = ['runuser', '-u', 'nobody', '--', *command]
    result = subprocess.run(command, cwd=directory, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE, env=dict(os.environ, PYTHONPATH=str(public_source / 'scripts')), timeout=180)
    prefix = 'ordinary' if ordinary else 'root'
    (directory / (prefix + '.stdout')).write_bytes(result.stdout)
    (directory / (prefix + '.stderr')).write_bytes(result.stderr)
    require(result.returncode in (0, 2), 'artifact checker must report acceptance or a validation rejection, not crash')
    report = decode(result.stdout.decode())
    require(type(report['uid']) is int and (report['uid'] == 0) != ordinary and
            report['accepted'] is (result.returncode == 0), 'actual reader identity and explicit validation outcome')
    return dict(returncode=result.returncode, uid=report['uid'], accepted=report['accepted'],
                stdout_sha256=digest(directory / (prefix + '.stdout')), stderr_sha256=digest(directory / (prefix + '.stderr')))


def audit(directory, output, public_source):
    output.mkdir()
    results = []
    for item in damage_requests(directory):
        case = output / item['label']
        case.mkdir()
        target = case / 'evidence'
        if item['request']['kind'] == 'matrix':
            target.mkdir()
            os.link(item['source'] / item['file'], target / item['file'])
        else:
            shutil.copytree(item['source'], target, copy_function=os.link)
        path = target / item['file']
        original = path.read_bytes()
        changed = item['change'](path)
        require(changed != original, 'negative control changes actual retained bytes')
        # Break this clone's hardlink before changing it. The original stays immutable.
        path.unlink()
        path.write_bytes(changed)
        request = dict(item['request'], directory=str(target))
        checks = [invoke(request, case, public_source, ordinary) for ordinary in (False, True)]
        require(all(value['accepted'] is False for value in checks), 'both identities reject every artifact fault')
        differences = [dict(offset=n, before=left, after=right)
                       for n, (left, right) in enumerate(zip(original, changed)) if left != right]
        patch = dict(original_sha256=__import__('hashlib').sha256(original).hexdigest(), damaged_sha256=digest(path),
                     original_bytes=len(original), damaged_bytes=len(changed), checks=checks)
        if len(differences) < 256 and len(original) == len(changed):
            patch['bytes'] = differences
        else:
            # These edits are to small text records; keep their exact replacement.
            require(len(original) < 2000000 and len(changed) < 2000000, 'bounded exact text fault')
            patch.update(before=original.decode(), after=changed.decode())
        write(case / 'patch.json', patch)
        require(digest(item['source'] / item['file']) == patch['original_sha256'], 'original artifact bytes preserved')
        require(target.resolve().is_relative_to(output.resolve()) and not target.is_symlink(), 'owned temporary fault snapshot')
        shutil.rmtree(target)
        results.append(dict(label=item['label'], document=item['file'], patch_sha256=digest(case / 'patch.json'), checks=checks))
    proof = dict(passed=True, serialized_reopened_faults=len(results), actual_reader_identities=2,
                 original_artifacts_preserved=True, results=results)
    write(output / 'verified.json', proof)
    return proof


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--check', required=True, type=Path)
    args = parser.parse_args()
    try:
        check(decode(args.check.read_text()))
    except ValueError as error:
        print(json.dumps(dict(accepted=False, uid=os.geteuid(), error=str(error))), flush=True)
        raise SystemExit(2)
    print(json.dumps(dict(accepted=True, uid=os.geteuid())), flush=True)


if __name__ == '__main__':
    main()
