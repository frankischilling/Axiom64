#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Audit complete multicast evidence normally and through a protected ordinary reader."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import struct
import subprocess
import sys
import tempfile
import zipfile

from fetch import ROOT
from ipv4_multicast_capture import require, verify
from tcp6.inputs import source_names


CONTROL_ERRORS = {
    "missing-product-inventory": "complete actual multicast product inventory",
    "malformed-ELF-with-refreshed-fingerprints": "actual x86-64 ELF product",
    "foreign-compiled-source": "actual multicast compilation tied to complete original source",
    "different-actual-ISO-kernel": "actual booted ISO contains retained kernel and initramfs",
    "different-actual-initramfs-program": "actual executable inside guest initramfs",
    "missing-client-completion": "actual multicast client completed every contract",
    "false-delivery-observation": "actual socket delivery and quiet observations",
    "failed-actual-process": "actual multicast process completion",
    "omitted-original-input": "actual ingress before acknowledgment",
    "duplicate-physical-output": "one physical multicast transmission per send",
    "foreign-input-MAC": "actual external multicast input",
    "foreign-input-IP-checksum-valid": "actual external multicast input",
    "wrong-input-payload-checksum-valid": "unique phase-owned multicast input",
    "wrong-output-TTL-checksum-valid": "actual external multicast output",
    "wrong-Router-Alert-checksum-valid": "actual IGMP Router Alert, TTL, control class and checksum",
    "wrong-join-record-checksum-valid": "actual ASM group record",
    "omitted-current-state-response": "actual query response before acknowledgment",
    "late-original-query-response": "actual unscaled query-response interval",
    "wrong-query-group-checksum-valid": "actual unique router query",
    "empty-original-capture": "nonempty original multicast capture",
    "native-capture-drop": "complete lossless native capture and clock counts",
    "altered-original-native-clock": "unchanged original native kernel packet timestamp",
    "omitted-native-clock-receipt": "one native receipt for every captured frame"
}


def create_controls(cohort, destination):
    guest = cohort / 'guest-static-bios-modern'
    native = cohort / 'linux-static'
    controls = []
    def encoded(value):
        return (json.dumps(value, indent=2) + '\n').encode()

    def add(label, changes, base='guest-static-bios-modern'):
        controls.append(dict(label=label, base=base, changes=changes))

    def fingerprints(changes, case=guest):
        inputs = json.loads((case / 'inputs.json').read_text())
        for name, data in changes.items():
            if name in inputs['products']:
                inputs['products'][name] = hashlib.sha256(data).hexdigest()
        return dict(changes, **{'inputs.json': encoded(inputs)})

    inputs = json.loads((guest / 'inputs.json').read_text())
    inputs['products'] = {}
    add('missing-product-inventory', {'inputs.json': encoded(inputs)})
    binary = bytearray((guest / 'ipv4-multicast-static').read_bytes())
    binary[0] ^= 1
    manifest = json.loads((guest / 'ipv4-multicast-static.inputs.json').read_text())
    manifest['product']['sha256'] = hashlib.sha256(binary).hexdigest()
    add('malformed-ELF-with-refreshed-fingerprints', fingerprints({
        'ipv4-multicast-static': bytes(binary), 'ipv4-multicast-static.inputs.json': encoded(manifest)}))
    manifest = json.loads((guest / 'ipv4-multicast-static.inputs.json').read_text())
    manifest['sources']['userspace/tests/net/ipv4_multicast.c'] = '0' * 64
    add('foreign-compiled-source', fingerprints({'ipv4-multicast-static.inputs.json': encoded(manifest)}))
    image = bytearray((guest / 'guest.iso').read_bytes())
    kernel = (guest / 'axiom64.elf').read_bytes()
    offset = image.find(kernel)
    require(offset >= 0 and offset == image.rfind(kernel), 'unique embedded ISO kernel for control')
    image[offset] ^= 1
    add('different-actual-ISO-kernel', fingerprints({'guest.iso': bytes(image)}))
    archive = bytearray((guest / 'rootfs-network.cpio').read_bytes())
    program = (guest / 'ipv4-multicast-static').read_bytes()
    offset = archive.find(program)
    require(offset >= 0 and offset == archive.rfind(program), 'unique embedded initramfs program for control')
    archive[offset] ^= 1
    add('different-actual-initramfs-program', fingerprints({'rootfs-network.cpio': bytes(archive)}))
    log = (guest / 'client.log').read_bytes()
    add('missing-client-completion', {'client.log': log.replace(b'MULTICAST_TESTS_PASS', b'OMITTED_CLIENT_PASS')})
    add('false-delivery-observation', {'client.log': log.replace(b'phase=1 receivers=1', b'phase=1 receivers=2')})
    metadata = json.loads((guest / 'results.json').read_text())
    metadata['returncode'] = 3
    add('failed-actual-process', {'results.json': encoded(metadata)})

    def checksum(data):
        if len(data) & 1:
            data += b'\0'
        value = sum(struct.unpack('!' + 'H' * (len(data) // 2), data))
        while value >> 16:
            value = (value & 65535) + (value >> 16)
        return value ^ 65535

    original = (guest / 'lane0.pcap').read_bytes()
    require(original[:4] == b'\xd4\xc3\xb2\xa1', 'little-endian original control capture')
    records = []
    offset = 24
    while offset < len(original):
        seconds, micros, size, full = struct.unpack_from('<IIII', original, offset)
        require(size == full, 'complete original control frame')
        records.append([seconds, micros, bytearray(original[offset + 16:offset + 16 + size])])
        offset += 16 + size

    def serialize(rows):
        return original[:24] + b''.join(struct.pack('<IIII', seconds, micros, len(frame), len(frame)) + frame
                                          for seconds, micros, frame in rows)

    def ipv4(frame):
        return len(frame) >= 34 and frame[12:14] == b'\x08\x00'

    def udp(frame, marker):
        return ipv4(frame) and frame[23] == 17 and bytes(frame[42:47]) == marker

    def igmp(frame, kind):
        return ipv4(frame) and frame[23] == 2 and len(frame) >= 39 and frame[38] == kind

    def repair(frame):
        header = (frame[14] & 15) * 4
        total = int.from_bytes(frame[16:18], 'big')
        body = 14 + header
        if frame[23] == 17:
            frame[body + 6:body + 8] = b'\0\0'
            pseudo = bytes(frame[26:34]) + b'\0\x11' + struct.pack('!H', total - header)
            frame[body + 6:body + 8] = struct.pack('!H', checksum(pseudo + bytes(frame[body:14 + total])) or 65535)
        elif frame[23] == 2:
            frame[body + 2:body + 4] = b'\0\0'
            frame[body + 2:body + 4] = struct.pack('!H', checksum(bytes(frame[body:14 + total])))
        frame[24:26] = b'\0\0'
        frame[24:26] = struct.pack('!H', checksum(bytes(frame[14:14 + header])))

    def packet_control(label, predicate, change=None, remove=False, duplicate=False, late=False):
        rows = [[seconds, micros, bytearray(frame)] for seconds, micros, frame in records]
        index = next(n for n, (_, _, frame) in enumerate(rows) if predicate(frame))
        if remove:
            del rows[index]
        elif duplicate:
            rows.insert(index + 1, [rows[index][0], rows[index][1], bytearray(rows[index][2])])
        elif late:
            rows[index][0] += 2
        else:
            change(rows[index][2])
            repair(rows[index][2])
        add(label, {'lane0.pcap': serialize(rows)})

    packet_control('omitted-original-input', lambda frame: udp(frame, b'AXMCW'), remove=True)
    packet_control('duplicate-physical-output', lambda frame: udp(frame, b'AXMCO'), duplicate=True)
    packet_control('foreign-input-MAC', lambda frame: udp(frame, b'AXMCW'), lambda frame: frame.__setitem__(6, frame[6] ^ 4))
    packet_control('foreign-input-IP-checksum-valid', lambda frame: udp(frame, b'AXMCW'), lambda frame: frame.__setitem__(29, frame[29] ^ 4))
    packet_control('wrong-input-payload-checksum-valid', lambda frame: udp(frame, b'AXMCW'), lambda frame: frame.__setitem__(48, 99))
    packet_control('wrong-output-TTL-checksum-valid', lambda frame: udp(frame, b'AXMCO'), lambda frame: frame.__setitem__(22, 6))
    packet_control('wrong-Router-Alert-checksum-valid', lambda frame: igmp(frame, 0x22), lambda frame: frame.__setitem__(34, 0x93))
    packet_control('wrong-join-record-checksum-valid', lambda frame: igmp(frame, 0x22) and frame[46] == 4, lambda frame: frame.__setitem__(46, 5))
    packet_control('omitted-current-state-response', lambda frame: igmp(frame, 0x22) and frame[46] == 2, remove=True)
    packet_control('late-original-query-response', lambda frame: igmp(frame, 0x22) and frame[46] == 2, late=True)
    packet_control('wrong-query-group-checksum-valid', lambda frame: igmp(frame, 0x11), lambda frame: frame.__setitem__(42, 239))
    add('empty-original-capture', {'lane0.pcap': original[:24]})
    metadata = json.loads((native / 'results.json').read_text())
    metadata['capture_statistics'][0]['dropped'] = 1
    add('native-capture-drop', {'results.json': encoded(metadata)}, 'linux-static')
    metadata = json.loads((native / 'results.json').read_text())
    clock_name = metadata['capture_statistics'][0]['monotonic_receipts']
    clocks = [json.loads(line) for line in (native / clock_name).read_text().splitlines()]
    clocks[0]['kernel_realtime_ns'] += 1000000
    damaged = b''.join(encoded(row).replace(b'\n', b'') + b'\n' for row in clocks)
    metadata['capture_statistics'][0]['monotonic_receipts_sha256'] = hashlib.sha256(damaged).hexdigest()
    add('altered-original-native-clock', {clock_name: damaged, 'results.json': encoded(metadata)}, 'linux-static')
    metadata = json.loads((native / 'results.json').read_text())
    damaged = b'\n'.join((native / clock_name).read_bytes().splitlines()[1:]) + b'\n'
    metadata['capture_statistics'][0]['monotonic_receipts_sha256'] = hashlib.sha256(damaged).hexdigest()
    add('omitted-native-clock-receipt', {clock_name: damaged, 'results.json': encoded(metadata)}, 'linux-static')

    require({control['label'] for control in controls} == set(CONTROL_ERRORS) and
            len(controls) == len(CONTROL_ERRORS), 'complete unique multicast rejection controls')
    with zipfile.ZipFile(destination, 'x', zipfile.ZIP_DEFLATED) as archive:
        manifest = []
        for control in controls:
            changes = []
            for name, data in control['changes'].items():
                entry = control['label'] + '/' + name
                archive.writestr(entry, data)
                changes.append(dict(name=name, entry=entry, sha256=hashlib.sha256(data).hexdigest()))
            manifest.append(dict(label=control['label'], base=control['base'],
                                 expected_error=CONTROL_ERRORS[control['label']], changes=changes))
        archive.writestr('manifest.json', encoded(manifest))
    return len(controls)


def digest(path):
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def write(path, value):
    path.write_text(json.dumps(value, indent=2) + '\n')


def inventory(tree):
    records = {}
    for path in [tree, *sorted(tree.rglob('*'))]:
        require(not path.is_symlink(), 'retained multicast inputs have no symbolic links')
        value = path.stat()
        records[path.relative_to(tree).as_posix()] = dict(
            uid=value.st_uid, gid=value.st_gid, mode=value.st_mode,
            bytes=value.st_size, sha256=digest(path) if path.is_file() else None)
    return records



def protected_inventory(workspace):
    records = {}
    for name in ('source', 'inputs'):
        records.update({name + '/' + key: value for key, value in inventory(workspace / name).items()})
    path = workspace / 'controls.zip'
    value = path.stat()
    records['controls.zip'] = dict(uid=value.st_uid, gid=value.st_gid, mode=value.st_mode,
                                  bytes=value.st_size, sha256=digest(path))
    return records


def retain_outputs(source, destination):
    before = inventory(source)
    if source.stat().st_dev == destination.parent.stat().st_dev:
        source.rename(destination)
    else:
        shutil.copytree(source, destination)
        for name, value in before.items():
            os.chown(destination / name, value['uid'], value['gid'])
    after = inventory(destination)
    require(set(before) == set(after), 'complete retained multicast reader output')
    for name, expected in before.items():
        actual = after[name]
        # Directory allocation sizes can differ across filesystems; input/output
        # bytes, original owners and permission bits remain the evidence contract.
        keys = ('uid', 'gid', 'mode', 'sha256') if expected['sha256'] is None else tuple(expected)
        require(all(actual[key] == expected[key] for key in keys),
                'retained reader output bytes, owners and modes unchanged')


def matrix_cases():
    cases = {f'linux-{profile}': (True, profile, 'bios', 'modern')
             for profile in ('native', 'static', 'dynamic')}
    cases.update({f'guest-{profile}-{firmware}-{transport}': (False, profile, firmware, transport)
                  for profile in ('static', 'dynamic') for firmware in ('bios', 'uefi')
                  for transport in ('modern', 'legacy')})
    return cases


def prepare(cohort, destination, workspace):
    expected = matrix_cases()
    matrix = json.loads((cohort / 'matrix-results.json').read_text())
    require(isinstance(matrix, list) and len(matrix) == len(expected) and
            {row['label'] for row in matrix} == set(expected) and
            all(row['returncode'] == 0 for row in matrix), 'complete successful multicast runtime matrix')
    require({path.name for path in cohort.iterdir() if path.is_dir()} == set(expected),
            'exactly the required multicast profile directories')
    names, _ = source_names()
    sources = {name: digest(ROOT / name) for name in names}
    require('scripts/ipv4_multicast_evidence.py' in sources and len(sources) >= 1543,
            'complete current public source including the actual multicast auditor')
    source_zip = None
    for label, (native, profile, firmware, transport) in expected.items():
        case = cohort / label
        metadata = json.loads((case / 'results.json').read_text())
        require((metadata['native'], metadata['profile'], metadata['firmware'], metadata['transport']) ==
                (native, profile, firmware, transport), 'actual complete multicast profile identity')
        require(json.loads((case / 'source-inputs.json').read_text()) == sources,
                'every multicast profile used the exact complete current public source')
        fingerprint = digest(case / 'source.zip')
        require(source_zip is None or source_zip == fingerprint,
                'one immutable complete source epoch for every multicast profile')
        source_zip = fingerprint
    source = workspace / 'source'
    source.mkdir()
    with zipfile.ZipFile(cohort / 'linux-native/source.zip') as archive:
        require(archive.testzip() is None and len(archive.namelist()) == len(sources) and
                set(archive.namelist()) == set(sources), 'complete original source export for audit')
        for name in archive.namelist():
            target = source / name
            require(not Path(name).is_absolute() and target.resolve().is_relative_to(source.resolve()),
                    'bounded public source export member')
            data = archive.read(name)
            require(hashlib.sha256(data).hexdigest() == sources[name], 'original public audit source bytes')
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(data)
    inputs = workspace / 'inputs'
    inputs.mkdir()
    for label in expected:
        shutil.copytree(cohort / label, inputs / label)
    create_controls(cohort, workspace / 'controls.zip')
    shutil.copy2(workspace / 'controls.zip', destination / 'controls.zip')
    for tree in (source, inputs):
        for path in tree.rglob('*'):
            require(not path.is_symlink(), 'protected multicast copies contain no symbolic links')
            path.chmod(0o555 if path.is_dir() else 0o444)
        tree.chmod(0o555)
    (workspace / 'controls.zip').chmod(0o444)
    before = protected_inventory(workspace)
    # Workspace itself stays searchable; every source/input file and directory
    # beneath the two protected roots is owned by root and has no write bits.
    for name, row in before.items():
        if name.startswith(('source/', 'inputs/')) or name in ('source', 'inputs', 'controls.zip'):
            require(row['uid'] == row['gid'] == 0 and not row['mode'] & 0o222,
                    'root-owned nonwritable protected multicast evidence')
    write(destination / 'protected-inputs-before.json', before)
    return workspace, sources, source_zip


def worker(workspace, ordinary):
    destination = workspace / ('ordinary' if ordinary else 'normal')
    namespace = None
    if ordinary:
        subprocess.run(['ip', 'link', 'set', 'lo', 'up'], check=True)
        links = json.loads(subprocess.check_output(['ip', '-json', 'link', 'show'], text=True))
        require(len(links) == 1 and links[0]['ifname'] == 'lo', 'isolated reader has only loopback')
        for family in ('-4', '-6'):
            require(not subprocess.check_output(['ip', family, 'route', 'show', 'default'], text=True).strip(),
                    'isolated reader has no external default route')
        namespace = os.readlink('/proc/self/ns/net')
        os.setgroups([])
        os.setgid(65534)
        os.setuid(65534)
    require(os.getuid() == (65534 if ordinary else 0), 'actual requested multicast reader identity')
    os.environ['TMPDIR'] = str(destination)
    tempfile.tempdir = str(destination)
    positives = []
    for label in sorted(matrix_cases()):
        value = verify(workspace / 'inputs' / label)
        write(destination / (label + '.json'), value)
        positives.append(dict(label=label, result=value))
    rejected = []
    with zipfile.ZipFile(workspace / 'controls.zip') as archive:
        require(archive.testzip() is None, 'freshly reopened serialized multicast controls')
        manifest = json.loads(archive.read('manifest.json'))
        require(len(manifest) == len(CONTROL_ERRORS) and
                {row['label'] for row in manifest} == set(CONTROL_ERRORS),
                'complete unique serialized multicast controls')
        for control in manifest:
            label, base = control['label'], control['base']
            require(base in matrix_cases() and control['expected_error'] == CONTROL_ERRORS[label],
                    'known multicast control target and rejection reason')
            with tempfile.TemporaryDirectory(prefix='damaged-', dir=destination) as temporary:
                case = Path(temporary) / 'case'
                shutil.copytree(workspace / 'inputs' / base, case)
                case.chmod(0o755)
                for change in control['changes']:
                    name = change['name']
                    require(Path(name).name == name, 'bounded multicast control filename')
                    data = archive.read(change['entry'])
                    require(hashlib.sha256(data).hexdigest() == change['sha256'],
                            'fresh serialized multicast control bytes')
                    staged = case / (name + '.replacement')
                    staged.write_bytes(data)
                    staged.replace(case / name)
                try:
                    verify(case)
                except ValueError as error:
                    require(str(error) == CONTROL_ERRORS[label],
                            f'multicast control rejects for its intended reason: {label}: {error}')
                    (destination / (label + '.log')).write_text(f'{type(error).__name__}: {error}\n')
                    rejected.append(dict(label=label, reason=str(error)))
                else:
                    raise ValueError('damaged multicast evidence accepted: ' + label)
    value = dict(passed=True, uid=os.getuid(), gid=os.getgid(), isolated_namespace=namespace,
                 positive_cases=positives, rejected_controls=rejected)
    write(destination / 'results.json', value)
    print(json.dumps(dict(passed=True, uid=os.getuid(), cases=len(positives), rejected=len(rejected))), flush=True)


def audit(cohort, destination):
    require(os.geteuid() == 0, 'protected ordinary-reader audit requires root; use sudo -n')
    require(not destination.is_relative_to(cohort), 'audit output is separate from original multicast inputs')
    destination.mkdir(parents=True, exist_ok=False)
    probe = destination / '.ownership-probe'
    try:
        probe.write_bytes(b'')
        probe.chmod(0o444)
        os.chown(probe, 65534, 65534)
        require(probe.stat().st_uid == 65534 and not probe.stat().st_mode & 0o222,
                'audit output must preserve POSIX ownership and permission bits')
    finally:
        probe.unlink(missing_ok=True)
    original = inventory(cohort)
    write(destination / 'original-inputs-before.json', original)
    workspace = Path(tempfile.mkdtemp(prefix='axiom-multicast-audit-', dir='/var/tmp'))
    workspace.chmod(0o755)
    write(destination / 'workspace.json', dict(path=str(workspace)))
    try:
        workspace, sources, source_zip = prepare(cohort, destination, workspace)
        normal, ordinary = workspace / 'normal', workspace / 'ordinary'
        normal.mkdir()
        ordinary.mkdir()
        os.chown(ordinary, 65534, 65534)
        exported = workspace / 'source/scripts/ipv4_multicast_evidence.py'
        for role in ('normal', 'ordinary'):
            command = [sys.executable, '-B', str(exported), '--worker', role, '--workspace', str(workspace)]
            if role == 'ordinary':
                command = ['unshare', '--net', *command]
            result = subprocess.run(command, cwd=workspace / 'source', stdout=subprocess.PIPE,
                                    stderr=subprocess.STDOUT, text=True)
            (destination / (role + '-reader.log')).write_text(result.stdout)
            result.check_returncode()
        privileged = json.loads((normal / 'results.json').read_text())
        unprivileged = json.loads((ordinary / 'results.json').read_text())
        require(privileged['positive_cases'] == unprivileged['positive_cases'] and
                privileged['rejected_controls'] == unprivileged['rejected_controls'] and
                (privileged['uid'], unprivileged['uid']) == (0, 65534),
                'identical privileged and actual ordinary multicast evidence decisions')
        before = json.loads((destination / 'protected-inputs-before.json').read_text())
        require(protected_inventory(workspace) == before, 'protected source and input bytes, owners and modes unchanged')
        require(inventory(cohort) == original, 'all original multicast inputs unchanged')
        require(all(path.stat().st_uid == 65534 for path in ordinary.rglob('*')),
                'ordinary reader writes only its owned output')
        write(destination / 'protected-inputs-after.json', before)
        rows = privileged['positive_cases']
        result = dict(passed=True, cases=len(rows), native_profiles=3, guest_profiles=8,
                      source_files=len(sources), source_zip_sha256=source_zip,
                      public_reader_sha256=sources['scripts/ipv4_multicast_capture.py'],
                      public_auditor_sha256=sources['scripts/ipv4_multicast_evidence.py'],
                      controls=len(privileged['rejected_controls']),
                      controls_sha256=digest(destination / 'controls.zip'), ordinary_uid=65534,
                      normal_and_ordinary_identical=True, native_clock_gates=6,
                      original_packet_times_not_rescaled=True, protected_inputs_unchanged=True,
                      original_inputs_unchanged=True, full_feature_acceptance=False)
        retain_outputs(normal, destination / 'normal')
        retain_outputs(ordinary, destination / 'ordinary')
        write(destination / 'summary.json', result)
        # Only these byte-verified task-owned copies are disposable. The complete
        # original sources, products, captures, controls and audit logs remain.
        require(workspace.resolve().parent == Path('/var/tmp').resolve() and
                workspace.name.startswith('axiom-multicast-audit-'),
                'confined completed multicast audit workspace')
        shutil.rmtree(workspace)
        print(json.dumps(result, indent=2))
    except Exception as error:
        if workspace.exists():
            require(workspace.resolve().parent == Path('/var/tmp').resolve() and
                    workspace.name.startswith('axiom-multicast-audit-'),
                    'confined failed multicast audit workspace')
            retain_outputs(workspace, destination / 'failed-work')
            if workspace.exists():
                shutil.rmtree(workspace)
        write(destination / 'summary.json', dict(passed=False, error=f'{type(error).__name__}: {error}',
                                                failed_inputs_retained=True,
                                                retained_workspace='failed-work'))
        raise


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('cohort', nargs='?', type=Path)
    parser.add_argument('--output', type=Path)
    parser.add_argument('--worker', choices=('normal', 'ordinary'), help=argparse.SUPPRESS)
    parser.add_argument('--workspace', type=Path, help=argparse.SUPPRESS)
    args = parser.parse_args()
    if args.worker:
        require(args.workspace is not None and args.cohort is None and args.output is None,
                'bounded internal multicast reader invocation')
        worker(args.workspace.resolve(), args.worker == 'ordinary')
    else:
        require(args.cohort is not None and args.output is not None and args.workspace is None,
                'multicast cohort and new audit output are required')
        audit(args.cohort.resolve(), args.output.resolve())


if __name__ == '__main__':
    main()
