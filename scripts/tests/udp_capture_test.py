# SPDX-License-Identifier: GPL-3.0-or-later
"""Archive and freshly reopen corruptions of complete actual UDP wire evidence."""
import argparse
import copy
import hashlib
import json
from pathlib import Path
import struct
import sys
import tempfile
import zipfile

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from fetch import ROOT
from ipv4_expiry_capture import read_capture, encode_capture, checksum, require
from udp_capture import audit, audit_capture


def payload_tag(lane, phase):
    return b'UD' + phase.encode() + bytes([lane])


def udp_data(frame):
    return frame[42:34 + int.from_bytes(frame[38:40], 'big')] if len(frame) >= 42 and frame[12:14] == b'\x08\x00' and (frame[23] == 17) else None


def repaired(frame):
    frame = bytearray(frame)
    ip = frame[14:]
    total = int.from_bytes(ip[2:4], 'big')
    frame[24:26] = bytes(2)
    frame[24:26] = checksum(frame[14:34]).to_bytes(2, 'big')
    if ip[9] == 17 and total >= 28:
        size = int.from_bytes(frame[38:40], 'big')
        frame[40:42] = bytes(2)
        frame[40:42] = (checksum(frame[26:34] + bytes([0, 17]) + size.to_bytes(2, 'big') + frame[34:34 + size]) or 65535).to_bytes(2, 'big')
    return bytes(frame)


def damage_cases(rows, lane, fault, companion):
    guest = bytes([82, 84, 0, 18, 52, 16 + lane])
    cases = []

    def first(predicate):
        return next((i for i, v in enumerate(rows) if predicate(v['frame'])))

    def add(label, changed, expected=None):
        cases.append((label, changed, expected))

    def delete(label, index):
        changed = copy.deepcopy(rows)
        del changed[index]
        add(label, changed)

    def duplicate(label, index):
        changed = copy.deepcopy(rows)
        changed.insert(index, copy.deepcopy(changed[index]))
        add(label, changed)

    def damage(label, index, transform, expected=None):
        changed = copy.deepcopy(rows)
        changed[index]['frame'] = transform(changed[index]['frame'])
        add(label, changed, expected)
    request = first(lambda f: f[12:14] == b'\x08\x06' and f[20:22] == b'\x00\x01')
    reply = first(lambda f: f[12:14] == b'\x08\x06' and f[20:22] == b'\x00\x02')
    delete('missing-route-ARP-request', request)
    delete('missing-route-ARP-reply', reply)
    damage('poisoned-route-ARP', reply, lambda f: f[:27] + bytes([f[27] ^ 1]) + f[28:])
    changed = copy.deepcopy(rows)
    changed[1]['ns'] = changed[0]['ns'] - 1000
    add('reversed-capture-clock', changed, 'original UDP capture clocks are ordered')
    if not fault:
        targets = []
        for phase, sequence in [('E', 0), ('E', 1), ('E', 2), ('M', 0), ('V', 0), ('F', 0), ('S', 0), ('O', 0), ('C', 0), ('I', 0), ('L', 0), ('R', 0), ('Q', 0), ('B', 0), ('B', 1), ('B', 2), ('K', 0), ('K', 47), ('P', 0), ('P', 32)]:
            index = first(lambda f: f[6:12] == guest and udp_data(f) is not None and udp_data(f).startswith(b'UD' + phase.encode() + bytes([lane]) + sequence.to_bytes(2, 'big')))
            targets.append((phase + str(sequence), index))
        targets += [('zero-payload', first(lambda f: f[6:12] == guest and udp_data(f) == b'')), ('computed-zero', first(lambda f: f[6:12] == guest and f[36:38] == 9001 .to_bytes(2, 'big')))]
        for label, index in targets:
            delete('omitted-' + label, index)
            duplicate('duplicated-' + label, index)

            def poison(f):
                raw = bytearray(f)
                if int.from_bytes(raw[16:18], 'big') > 28:
                    raw[14 + int.from_bytes(raw[16:18], 'big') - 1] ^= 1
                else:
                    raw[35] ^= 1
                return repaired(raw)
            damage('checksum-valid-poison-' + label, index, poison, 'exact complete ordered UDP datagrams')
        for identifier in [*range(28672, 28687), *range(28928, 28931), 29439, 29438, 29440]:
            index = first(lambda f: f[6:12] != guest and f[12:14] == b'\x08\x00' and (int.from_bytes(f[18:20], 'big') == identifier))
            delete('omitted-input-' + hex(identifier), index)
        incoming_errors = [i for i, v in enumerate(rows) if v['frame'][6:12] != guest and v['frame'][12:14] == b'\x08\x00' and (v['frame'][23] == 1)]
        assert len(incoming_errors) == 8
        for ordinal, index in enumerate(incoming_errors):
            delete('omitted-quote-' + str(ordinal), index)
        index = targets[0][1]
        damage('bad-outgoing-IP-checksum', index, lambda f: f[:24] + bytes([f[24] ^ 1]) + f[25:], 'complete UDP IPv4 header')
        damage('bad-outgoing-UDP-checksum', index, lambda f: f[:40] + bytes([f[40] ^ 1]) + f[41:], 'UDP guest complete segment')
        damage('wrong-output-MAC', index, lambda f: bytes([f[0] ^ 1]) + f[1:], 'UDP guest Ethernet route')
        pressure = first(lambda f: f[6:12] == guest and udp_data(f) is not None and udp_data(f).startswith(b'UDP' + bytes([lane]) + bytes(2)))
        resolved = first(lambda f: f[12:14] == b'\x08\x06' and f[20:22] == b'\x00\x02' and (f[28:32] == bytes([10, 23, lane + 1, 3])))
        changed = copy.deepcopy(rows)
        changed[resolved]['frame'], changed[pressure]['frame'] = (changed[pressure]['frame'], changed[resolved]['frame'])
        add('pressure-before-ARP-reply', changed, 'all retained pending outputs follow resolved pressure neighbor')
        for label, phase, sequence, kind, expected in [('server-before-trigger', 'S', 0, 'server', 'UDP incoming response follows its actual original request'), ('broadcast-ACK-before-ingress', 'K', 0, 'broadcast', 'active broadcast acknowledgment follows exact ingress')]:
            if kind == 'server':
                one = first(lambda f: f[6:12] == guest and udp_data(f) is not None and udp_data(f).startswith(payload_tag(lane, 'S')))
                two = first(lambda f: f[6:12] != guest and udp_data(f) is not None and udp_data(f).startswith(payload_tag(lane, 'Q')))
            else:
                one = first(lambda f: f[6:12] != guest and udp_data(f) is not None and udp_data(f).startswith(payload_tag(lane, 'K')))
                two = first(lambda f: f[6:12] == guest and udp_data(f) is not None and udp_data(f).startswith(payload_tag(lane, 'K')))
            changed = copy.deepcopy(rows)
            changed[one]['frame'], changed[two]['frame'] = (changed[two]['frame'], changed[one]['frame'])
            add(label, changed, expected)
        wrong_order = [i for i, v in enumerate(rows) if v['frame'][6:12] == guest and v['frame'][36:38] == 9004 .to_bytes(2, 'big') and (udp_data(v['frame']) is not None)]
        assert len(wrong_order) == 4
        changed = copy.deepcopy(rows)
        changed[wrong_order[0]]['frame'], changed[wrong_order[1]]['frame'] = (changed[wrong_order[1]]['frame'], changed[wrong_order[0]]['frame'])
        add('reordered-server-datagrams', changed, 'exact complete ordered UDP datagrams')
    elif lane == 1:
        index = first(lambda f: f[6:12] == guest and udp_data(f) is not None)
        delete('missing-healthy-adapter-request', index)
        duplicate('duplicate-healthy-adapter-request', index)
        damage('poisoned-healthy-adapter-request', index, lambda f: repaired(f[:-1] + bytes([f[-1] ^ 1])), 'exact complete ordered UDP datagrams')
    else:
        healthy = companion
        frame = next((v['frame'] for v in healthy if v['frame'][6:12] != guest and udp_data(v['frame']) is not None))
        changed = copy.deepcopy(rows)
        changed.append(dict(ns=rows[-1]['ns'] + 1000, frame=frame))
        add('unexpected-failed-adapter-datagram', changed)
    return cases


def raw_damage_cases(data):
    require(data[:4] == bytes.fromhex('d4c3b2a1'), 'actual little-endian UDP fixture capture')
    at, last = 24, None
    while at < len(data):
        last = at
        at += 16 + struct.unpack_from('<I', data, at + 8)[0]
    require(last is not None and at == len(data), 'actual complete UDP records to damage')
    seconds, fraction = struct.unpack_from('<II', data, last)
    require(seconds > 0 and fraction < 1000000, 'actual bounded UDP packet clock')
    changed = bytearray(data)
    # The old parser normalized these invalid fields to the same absolute time.
    struct.pack_into('<II', changed, last, seconds - 1, fraction + 1000000)
    cases = [('invalid-clock-fraction', bytes(changed), 'bounded original UDP PCAP clock fraction')]
    for label, offset, code, value in (('wrong-version', 4, 'H', 3),
                                      ('wrong-link-type', 20, 'I', 101),
                                      ('short-snapshot', 16, 'I', 14)):
        changed = bytearray(data)
        struct.pack_into('<' + code, changed, offset, value)
        cases.append((label, bytes(changed), 'UDP Ethernet PCAP format and snapshot bound'))
    changed = bytearray(data)
    size = struct.unpack_from('<I', data, last + 8)[0]
    struct.pack_into('<I', changed, last + 12, size + 1)
    cases.append(('truncated-original-frame', bytes(changed), 'complete original UDP captured frame'))
    return cases


def reject_capture(archive, candidate, lane, fault, expected=None):
    with tempfile.TemporaryDirectory(prefix='udp-damaged-reopen-') as temporary:
        fresh = Path(temporary)
        with zipfile.ZipFile(archive, 'x', zipfile.ZIP_DEFLATED) as saved:
            saved.writestr('capture.pcap', candidate)
            saved.writestr('case.json', json.dumps(dict(lane=lane, fault=fault,
                sha256=hashlib.sha256(candidate).hexdigest())) + '\n')
        with zipfile.ZipFile(archive) as saved:
            saved.extractall(fresh)
        meta = json.loads((fresh / 'case.json').read_text())
        require(hashlib.sha256((fresh / 'capture.pcap').read_bytes()).hexdigest() == meta['sha256'],
                'freshly extracted UDP corruption has its exact serialized bytes')
        try:
            audit_capture(fresh / 'capture.pcap', meta['lane'], meta['fault'])
        except ValueError as error:
            reason = str(error)
            require(expected is None or expected in reason, 'intended UDP corruption guard: ' + reason)
            return reason
    raise AssertionError('damaged complete UDP capture accepted')


def profile_controls(directory, reports, destination):
    """Serialize whole original case files with one damaged result or observation."""
    from udp_capture import audit_case

    controls = []
    for row in reports:
        phase = 'fault' if row['fault'] else 'normal'
        relative = phase + '/' + row['firmware'] + '-' + row['transport']
        case = directory / relative
        originals = {relative + '/' + path.name: path.read_bytes()
                     for path in case.iterdir() if path.is_file()}
        text = (case / row['log']).read_text()
        variants = []
        for field, value in (('returncode', 99), ('passed', False), ('timed_out', True),
                             ('missing', ['UDP_TESTS_PASS']), ('seconds', 91)):
            changed = copy.deepcopy(row)
            changed[field] = value
            variants.append((field, changed, {}, 'actual complete UDP client status'))
        for field, expected in (('debugger_delay', 'original delayed UEFI UDP fault setup'),
                                ('wire_datagrams', 'original complete UDP producer counters'),
                                ('firmware_frames', 'original UDP bootstrap counters')):
            changed = copy.deepcopy(row)
            if isinstance(changed[field], list):
                changed[field][0] += 1
            else:
                changed[field] += 1
            variants.append((field, changed, {}, expected))
        markers = [line for line in text.splitlines() if
                   (line.startswith('UDP_') and ('_PASS' in line or line.startswith('UDP_LINK_'))) or
                   line in ('AXIOM64_TESTS_PASS', 'AXIOM64_EXIT status=0')]
        # Administrative query records have a separate numeric corruption below.
        markers = [line for line in markers if not line.startswith(('UDP_LINK_DOWN', 'UDP_LINK_UP')) or
                   not row['fault']]
        for ordinal, marker in enumerate(markers):
            require(text.splitlines().count(marker) == 1, 'one actual UDP record to omit')
            changed = '\n'.join(line for line in text.splitlines() if line != marker) + '\n'
            variants.append(('omitted-record-' + str(ordinal), row,
                             {relative + '/' + row['log']: changed.encode()},
                             'every exact original UDP assertion'))
        command = json.loads((case / 'command.json').read_text())
        for label, flag, value, expected in (
                ('changed-image-directory', '-cdrom',
                 '/tmp/unrelated/' + phase + '/image.iso', 'both original passive UDP physical captures'),
                ('changed-CPU', '-cpu', 'host', 'original UDP emulator'),
                ('changed-memory', '-m', '128M', 'original UDP emulator'),
                ('changed-physical-capture', '-object',
                 next(value for value in command if value.startswith('filter-dump,')).replace('netdev=peer0', 'netdev=peer1'),
                 'both original passive UDP physical captures')):
            changed = list(command)
            changed[changed.index(flag) + 1] = value
            variants.append((label, row, {relative + '/command.json':
                                         (json.dumps(changed) + '\n').encode()}, expected))
        if row['fault']:
            name = row['log'][:-4] + '-gdb.log'
            changed = (case / name).read_text().replace('PACKET_FAULT_INJECTED model=virtio kind=id', 'removed')
            variants.append(('missing-injection', row, {relative + '/' + name: changed.encode()},
                             'actual retained UDP device fault injection'))
        else:
            for index in (1, 2):
                for flags in ('1003', '1042', '1043'):
                    changed = text.replace(f'UDP_ADMIN_DOWN index={index} flags=1002',
                                           f'UDP_ADMIN_DOWN index={index} flags={flags}')
                    variants.append((f'wrong-administrative-{index}-{flags}', row,
                                     {relative + '/' + row['log']: changed.encode()},
                                     'exact original UDP administrative-down query flags'))
        for label, candidate, changed_files, expected in variants:
            files = dict(originals)
            files.update(changed_files)
            files[relative + '/result.json'] = (json.dumps(candidate) + '\n').encode()
            archive = destination / (relative.replace('/', '-') + '-metadata-' + label + '.zip')
            with zipfile.ZipFile(archive, 'x', zipfile.ZIP_DEFLATED) as saved:
                for name, data in files.items():
                    saved.writestr(name, data)
                saved.writestr('candidate-row.json', json.dumps(candidate) + '\n')
            with tempfile.TemporaryDirectory(prefix='udp-profile-reopen-') as temporary:
                fresh = Path(temporary)
                with zipfile.ZipFile(archive) as saved:
                    saved.extractall(fresh)
                loaded = json.loads((fresh / 'candidate-row.json').read_text())
                require(loaded == candidate, 'serialized original UDP profile corruption')
                try:
                    audit_case(fresh, loaded)
                except ValueError as error:
                    reason = str(error)
                    require(expected in reason, 'intended UDP profile corruption guard: ' + reason)
                else:
                    raise AssertionError('damaged original UDP profile accepted: ' + label)
            controls.append(dict(kind='profile', control=label, reason=reason,
                                 archive=archive.name, sha256=hashlib.sha256(archive.read_bytes()).hexdigest()))
    return controls


def input_controls(directory, input_root, destination):
    """Reopen serialized input changes with unchanged positive products rehashed."""
    import os
    from udp_inputs import audit as audit_inputs

    controls = []
    for phase in ('normal', 'fault'):
        source = directory / phase
        original = json.loads((source / 'inputs.json').read_text())
        variants = []
        for label in ('missing-source', 'changed-source', 'changed-product', 'short-deadline',
                      'wrong-linkage', 'wrong-mode', 'changed-compiler-source', 'forged-UAPI-pin',
                      'missing-static-compile', 'changed-provider', 'unowned-image-client'):
            value = copy.deepcopy(original)
            changed = {}
            if label == 'missing-source':
                del value['sources']['userspace/tests/net/udp.c']
                expected = 'complete UDP fixture source inventory'
            elif label == 'changed-source':
                value['sources']['userspace/tests/net/udp.c'] = '0' * 64
                expected = 'actual UDP fixture source:'
            elif label == 'changed-product':
                value['products']['client.elf']['sha256'] = '0' * 64
                expected = 'actual retained UDP product:'
            elif label == 'short-deadline':
                value['guest_deadline_seconds'] = 89
                expected = 'original complete UDP fixture contract'
            elif label == 'wrong-linkage':
                value['linkage'] = 'dynamic'
                expected = 'original complete UDP fixture contract'
            elif label == 'wrong-mode':
                value['fault'] = not value['fault']
                expected = 'original complete UDP fixture contract'
            elif label == 'changed-provider':
                provider = json.loads((source / 'musl-manifest.json').read_text())
                provider['products']['sysroot/usr/lib/libc.a'] = '0' * 64
                changed['musl-manifest.json'] = (json.dumps(provider) + '\n').encode()
                expected = 'actual UDP static libc and required notice'
            else:
                compilation = value['compilation']
                if label == 'changed-compiler-source':
                    compilation['sources']['userspace/tests/net/udp.c'] = '0' * 64
                    expected = 'actual original UDP compiler source:'
                elif label == 'forged-UAPI-pin':
                    compilation['uapi']['package']['sha256'] = '0' * 64
                    expected = 'pinned target Linux UAPI compilation inputs'
                elif label == 'missing-static-compile':
                    compilation['command'].remove('-static')
                    expected = 'actual original static UDP compile manifest'
                else:
                    program = bytearray((source / 'client.elf').read_bytes())
                    program[-1] ^= 1
                    changed['client.elf'] = bytes(program)
                    compilation['product']['sha256'] = hashlib.sha256(program).hexdigest()
                    expected = 'actual ISO contains the exact executable: bin/udp-tests'
                changed['client.inputs.json'] = (json.dumps(compilation) + '\n').encode()
            for name, data in changed.items():
                value['products'][name] = dict(bytes=len(data), sha256=hashlib.sha256(data).hexdigest())
            changed['inputs.json'] = (json.dumps(value) + '\n').encode()
            archive = destination / (phase + '-inputs-' + label + '.zip')
            metadata = dict(phase=phase, control=label, expected=expected,
                            original_products=original['products'],
                            files={name: hashlib.sha256(data).hexdigest() for name, data in changed.items()})
            with zipfile.ZipFile(archive, 'x', zipfile.ZIP_DEFLATED) as saved:
                for name, data in changed.items():
                    saved.writestr(name, data)
                saved.writestr('case.json', json.dumps(metadata) + '\n')
            with tempfile.TemporaryDirectory(prefix='udp-inputs-reopen-', dir=directory.parent) as temporary:
                fresh = Path(temporary) / phase
                fresh.mkdir()
                for name, product in original['products'].items():
                    require(hashlib.sha256((source / name).read_bytes()).hexdigest() == product['sha256'],
                            'unchanged positive UDP products back the serialized input control')
                    if name not in changed:
                        os.link(source / name, fresh / name)
                with zipfile.ZipFile(archive) as saved:
                    saved.extractall(fresh)
                loaded = json.loads((fresh / 'case.json').read_text())
                require(loaded == metadata and all(
                    hashlib.sha256((fresh / name).read_bytes()).hexdigest() == value
                    for name, value in loaded['files'].items()), 'serialized UDP input control reopens exactly')
                try:
                    audit_inputs(fresh, input_root)
                except ValueError as error:
                    reason = str(error)
                    require(expected in reason, 'intended UDP input corruption guard: ' + reason)
                else:
                    raise AssertionError('damaged actual UDP inputs accepted: ' + label)
            controls.append(dict(kind='inputs', phase=phase, control=label, reason=reason,
                                 archive=archive.name, sha256=hashlib.sha256(archive.read_bytes()).hexdigest()))
    return controls


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--directory', type=Path, default=ROOT / 'build/udp-wire')
    parser.add_argument('--destination', type=Path)
    parser.add_argument('--input-root', type=Path, default=ROOT)
    args = parser.parse_args()
    positive = audit(args.directory, args.input_root)
    (args.directory / 'audit.json').write_text(json.dumps(positive, indent=2) + '\n')
    destination = args.destination or args.directory / 'damaged'
    destination.mkdir(parents=True, exist_ok=False)
    reports = json.loads((args.directory / 'results.json').read_text())
    controls, originals = [], {}
    for row in reports:
        case = args.directory / ('fault' if row['fault'] else 'normal') / (row['firmware'] + '-' + row['transport'])
        for lane in range(2):
            original = case / f'lane{lane}.pcap'
            original_hash = hashlib.sha256(original.read_bytes()).hexdigest()
            originals[str(original)] = original_hash
            rows = read_capture(original)
            candidates = [(label, encode_capture(changed), expected) for label, changed, expected in
                          damage_cases(rows, lane, row['fault'], read_capture(case / 'lane1.pcap'))]
            candidates += raw_damage_cases(original.read_bytes())
            for label, data, expected in candidates:
                require(data != original.read_bytes(), 'an original actual UDP capture was changed')
                archive = destination / (('fault-' if row['fault'] else 'normal-') +
                    row['firmware'] + '-' + row['transport'] + f'-lane{lane}-' + label + '.zip')
                reason = reject_capture(archive, data, lane, row['fault'], expected)
                controls.append(dict(control=label, lane=lane, firmware=row['firmware'],
                    transport=row['transport'], fault=row['fault'], reason=reason, archive=archive.name,
                    sha256=hashlib.sha256(archive.read_bytes()).hexdigest()))
    require(len(controls) == 976, 'all complete UDP physical capture corruption cases')
    physical_controls = len(controls)
    controls += profile_controls(args.directory, reports, destination)
    controls += input_controls(args.directory, args.input_root, destination)
    require(all(hashlib.sha256(Path(name).read_bytes()).hexdigest() == value
                for name, value in originals.items()), 'all original UDP captures remain unchanged')
    result = dict(passed=True, profiles=positive['profiles'], captures=positive['captures'],
                  negative_cases=len(controls), physical_controls=physical_controls, cases=controls, originals=originals)
    (destination / 'results.json').write_text(json.dumps(result, indent=2) + '\n')
    print(json.dumps({key: result[key] for key in ('passed', 'profiles', 'captures', 'negative_cases')}))


if __name__ == '__main__':
    main()
