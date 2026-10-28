#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Reject serialized changes to actual source-change packets and boot products."""
import argparse
import hashlib
import json
from pathlib import Path
import shutil
import struct
import sys
import zipfile

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from fetch import ROOT
from ipv4_multicast.source_capture import verify
from ipv4_multicast_capture import checksum, records


def encoded(value):
    return (json.dumps(value, indent=2) + '\n').encode()


def pcap(rows):
    body = bytearray(struct.pack('<IHHIIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1))
    for row in rows:
        frame, stamp = row['frame'], row['stamp']
        body.extend(struct.pack('<IIII', stamp // 1_000_000, stamp % 1_000_000, len(frame), len(frame)))
        body.extend(frame)
    return bytes(body)


def mutate_report(frame, *, source=None, kind=None):
    frame = bytearray(frame)
    offset = 14 + 24
    if source is not None:
        struct.pack_into('!I', frame, offset + 16, source)
    if kind is not None:
        frame[offset + 8] = kind
    total = int.from_bytes(frame[16:18], 'big')
    frame[offset + 2:offset + 4] = b'\0\0'
    struct.pack_into('!H', frame, offset + 2, checksum(bytes(frame[offset:14 + total])))
    return bytes(frame)


def replace_sources(frame, sources):
    """Serialize one complete group record with valid IPv4 and IGMP checksums."""
    assert frame[38] == 0x22 and int.from_bytes(frame[44:46], 'big') == 1
    frame = bytearray(frame[:54])
    frame.extend(b''.join(struct.pack('!I', source) for source in sources))
    struct.pack_into('!H', frame, 48, len(sources))
    struct.pack_into('!H', frame, 16, len(frame) - 14)
    frame[24:26] = frame[40:42] = b'\0\0'
    struct.pack_into('!H', frame, 24, checksum(bytes(frame[14:38])))
    struct.pack_into('!H', frame, 40, checksum(bytes(frame[38:])))
    return bytes(frame).ljust(60, b'\0')


def bundle_reports(first, second):
    """Keep valid checksums while collapsing two transmissions into one."""
    assert all(int.from_bytes(frame[44:46], 'big') == 1 for frame in (first, second))
    end = lambda frame: 14 + int.from_bytes(frame[16:18], 'big')
    frame = bytearray(first[:end(first)] + second[46:end(second)])
    struct.pack_into('!H', frame, 44, 2)
    struct.pack_into('!H', frame, 16, len(frame) - 14)
    frame[24:26] = frame[40:42] = b'\0\0'
    struct.pack_into('!H', frame, 24, checksum(bytes(frame[14:38])))
    struct.pack_into('!H', frame, 40, checksum(bytes(frame[38:])))
    return bytes(frame).ljust(60, b'\0')


def run(source, output):
    source, output = source.resolve(), output.resolve()
    if not source.is_relative_to(ROOT / 'build') or not output.is_relative_to(ROOT / 'build') or output.is_relative_to(source):
        raise ValueError('source corpus and fresh controls must stay separately below build/')
    positive = verify(source)
    assert not positive['native'], 'packet semantic controls use the actual guest capture'
    originals = {path.relative_to(source).as_posix(): hashlib.sha256(path.read_bytes()).hexdigest()
                 for path in source.rglob('*') if path.is_file()}
    variants = []
    rows = records(source / 'lane0.pcap')
    reports = [n for n, row in enumerate(rows) if row['frame'][12:14] == b'\x08\x00' and row['frame'][38] == 0x22]
    assert len(reports) == {'settled': 14, 'queries': 14, 'mtu': 38, 'overlap': 12}[positive['scenario']]
    reports_by_stage, queries_by_stage = {}, {}
    stage = None
    for n, row in enumerate(rows):
        frame = row['frame']
        if frame[14:18] == b'AXSB':
            stage = frame[19]
        elif frame[12:14] == b'\x08\x00':
            if frame[38] == 0x11:
                queries_by_stage[stage] = n
            elif frame[38] == 0x22:
                reports_by_stage.setdefault(stage, []).append(n)
    first_source = next(n for n in reports if int.from_bytes(rows[n]['frame'][48:50], 'big'))
    for label, change in (('different-source-valid-checksum', dict(source=0xc0000265)),
                          ('opposite-record-valid-checksum', dict(kind=6))):
        changed = [dict(row) for row in rows]
        changed[first_source]['frame'] = mutate_report(changed[first_source]['frame'], **change)
        variants.append((label, {'lane0.pcap': pcap(changed)}, 'native-derived exact source transition and retransmission'))
    changed = rows[:reports[1]] + rows[reports[1] + 1:]
    variants.append(('missing-retransmission', {'lane0.pcap': pcap(changed)},
                     'native-derived exact source transition and retransmission'))
    changed = [dict(row) for row in rows]
    full_stage = 2 if positive['scenario'] == 'overlap' else 1
    ack = next(row for row in changed if row['frame'][14:18] == b'AXSA' and row['frame'][19:21] == bytes([full_stage, ord('D')]))
    ack['stamp'] -= 1_500_000
    variants.append(('short-real-observation', {'lane0.pcap': pcap(changed)},
                     'complete unscaled three-second source observation'))
    changed = [dict(row) for row in rows]
    begin = next(row for row in changed if row['frame'][14:18] == b'AXSB')
    frame = bytearray(begin['frame']);frame[19] = 2;begin['frame'] = bytes(frame)
    variants.append(('missing-first-stage', {'lane0.pcap': pcap(changed)},
                     'ordered physical source start request'))
    prefix = {'settled': b'IPV4_SOURCE_WIRE_PASS stages=7',
              'queries': b'IPV4_SOURCE_WIRE_QUERY_PASS stages=12',
              'mtu': b'IPV4_SOURCE_WIRE_MTU_PASS stages=7',
              'overlap': b'IPV4_SOURCE_WIRE_OVERLAP_PASS stages=7'}[positive['scenario']]
    body = (source / 'client.log').read_bytes().replace(prefix, prefix.replace(b'stages=', b'stages=0'))
    variants.append(('missing-completion', {'client.log': body}, 'actual source multicast client completion'))
    program = 'ipv4-multicast-source-wire-' + positive['profile']
    manifest = json.loads((source / (program + '.inputs.json')).read_text())
    manifest['sources']['userspace/tests/net/ipv4_multicast_source_wire.c'] = '0' * 64
    variants.append(('foreign-compiler-source', {program + '.inputs.json': encoded(manifest)},
                     'actual multicast compilation tied to complete original source'))
    kernel = (source / 'axiom64.elf').read_bytes()
    image = bytearray((source / 'guest.iso').read_bytes())
    offset = image.find(kernel);assert offset >= 0 and image.find(kernel, offset + 1) == -1
    image[offset] ^= 1
    variants.append(('different-actual-iso-kernel', {'guest.iso': bytes(image)},
                     'actual booted ISO contains retained kernel and initramfs'))
    if positive['scenario'] == 'queries':
        changed = [dict(row) for row in rows]
        n = reports_by_stage[8][0]
        changed[n]['frame'] = mutate_report(changed[n]['frame'], source=0xc0000201, kind=2)
        variants.append(('native-exclude-exception-forged-as-guest', {'lane0.pcap': pcap(changed)},
                         'RFC 9776 source-query record'))
        n = queries_by_stage[4]
        variants.append(('omitted-original-silent-query', {'lane0.pcap': pcap(rows[:n] + rows[n + 1:])},
                         'every original source query captured'))
        n = queries_by_stage[9]
        forged = dict(rows[reports_by_stage[8][0]])
        forged['frame'] = mutate_report(forged['frame'], source=0xc0000201, kind=1)
        forged['stamp'] = rows[n]['stamp'] + 100_000
        variants.append(('blocked-source-query-echo', {'lane0.pcap': pcap(rows[:n + 1] + [forged] + rows[n + 1:])},
                         'RFC 9776 source-query record'))
        changed = [dict(row) for row in rows]
        changed[reports_by_stage[3][0]]['stamp'] = rows[queries_by_stage[3]]['stamp'] + 1_500_000
        variants.append(('late-source-query-response', {'lane0.pcap': pcap(changed)},
                         'actual unscaled source query response interval'))
    if positive['scenario'] == 'mtu':
        n = reports_by_stage[2][3]
        variants.append(('missing-include-fragment', {'lane0.pcap': pcap(rows[:n] + rows[n + 1:])},
                         'native-derived exact source transition and retransmission'))
        changed = [dict(row) for row in rows]
        n = reports_by_stage[2][1]
        changed[n]['frame'] = mutate_report(changed[n]['frame'], source=0xc0000201)
        variants.append(('overlapping-include-fragments', {'lane0.pcap': pcap(changed)},
                         'native-derived exact source transition and retransmission'))
        changed = [dict(row) for row in rows]
        n = reports_by_stage[2][0]
        changed[n]['frame'] = replace_sources(changed[n]['frame'], range(0xc0000201, 0xc0000209))
        variants.append(('eight-sources-exceed-minimum-mtu', {'lane0.pcap': pcap(changed)},
                         'source IGMP original IPv4 bounds and checksum'))
        n = reports_by_stage[4][0]
        extra = dict(rows[n])
        extra['frame'] = replace_sources(extra['frame'], [0xc0000208])
        extra['stamp'] += 1
        variants.append(('split-exclude-record', {'lane0.pcap': pcap(rows[:n + 1] + [extra] + rows[n + 1:])},
                         'native-derived exact source transition and retransmission'))
        changed = [dict(row) for row in rows]
        n = reports_by_stage[6][0]
        changed[n]['frame'] = replace_sources(changed[n]['frame'], range(0xc0000201, 0xc0000208))
        variants.append(('still-truncated-after-mtu-increase', {'lane0.pcap': pcap(changed)},
                         'RFC 9776 source-query record'))
        lines = (source / 'client.log').read_text().splitlines()
        changed = []
        for line in lines:
            if line.startswith('{'):
                row = json.loads(line)
                if row.get('kind') == 'policy' and row['phase'] == 'restored':
                    row['value'] = 64
                    line = json.dumps(row)
            changed.append(line)
        variants.append(('source-policy-not-restored', {'client.log': ('\n'.join(changed) + '\n').encode()},
                         'actual configured source capacity and restored policy'))
        changed = []
        for line in lines:
            if line.startswith('{'):
                row = json.loads(line)
                if row.get('kind') == 'mtu-change' and row['lane'] == 0:
                    row['mtu'] = 68
                    line = json.dumps(row)
            changed.append(line)
        variants.append(('live-mtu-change-not-confirmed', {'client.log': ('\n'.join(changed) + '\n').encode()},
                         'actual live source interface MTU change'))
    if positive['scenario'] == 'overlap':
        n = reports_by_stage[1][0]
        variants.append(('missing-first-packet-barrier-report', {'lane0.pcap': pcap(rows[:n] + rows[n + 1:])},
                         'actual first report precedes source update barrier'))
        changed = [dict(row) for row in rows]
        n = reports_by_stage[6][0]
        changed[n]['frame'] = mutate_report(changed[n]['frame'], kind=6)
        variants.append(('stale-opposite-direction-after-first-packet', {'lane0.pcap': pcap(changed)},
                         'native-derived exact source transition and retransmission'))
        n = reports_by_stage[6][1]
        variants.append(('missing-restarted-source-retransmission', {'lane0.pcap': pcap(rows[:n] + rows[n + 1:])},
                         'native-derived exact source transition and retransmission'))
        changed = [dict(row) for row in rows]
        n = reports_by_stage[2][1]
        changed[n]['frame'] = mutate_report(changed[n]['frame'], kind=4)
        variants.append(('flattened-mode-and-source-counters', {'lane0.pcap': pcap(changed)},
                         'native-derived exact source transition and retransmission'))
        changed = [dict(row) for row in rows]
        ack = next(row for row in changed if row['frame'][14:18] == b'AXSA' and row['frame'][19:21] == b'\x01D')
        ack['stamp'] = rows[reports_by_stage[1][0]]['stamp'] - 1
        variants.append(('first-packet-ack-precedes-report', {'lane0.pcap': pcap(changed)},
                         'actual first report precedes source update barrier'))
        lines = (source / 'client.log').read_text().splitlines()
        changed = []
        for line in lines:
            if line.startswith('{'):
                row = json.loads(line)
                if row.get('kind') == 'observation' and row['stage'] == 2:
                    row['end_ns'] = row['begin_ns']
                    line = json.dumps(row)
            changed.append(line)
        variants.append(('zero-clock-duration-full-observation', {'client.log': ('\n'.join(changed) + '\n').encode()},
                         'actual guest or native observation clock'))
    pair = next(indices[:2] for indices in reports_by_stage.values() if len(indices) >= 2 and
                rows[indices[0]]['frame'][46:14 + int.from_bytes(rows[indices[0]]['frame'][16:18], 'big')] ==
                rows[indices[1]]['frame'][46:14 + int.from_bytes(rows[indices[1]]['frame'][16:18], 'big')])
    first, second = pair
    changed = [dict(row) for row in rows]
    changed[first]['frame'] = bundle_reports(changed[first]['frame'], changed[second]['frame'])
    changed.pop(second)
    variants.append(('bundled-retransmission-valid-checksums', {'lane0.pcap': pcap(changed)},
                     'separate physical source report transmissions'))
    output.mkdir()
    results = []
    for label, changes, reason in variants:
        case = output / label;case.mkdir()
        for name in originals:
            path = case / name;path.parent.mkdir(parents=True, exist_ok=True);path.symlink_to(source / name)
        inputs = json.loads((source / 'inputs.json').read_text())
        metadata = json.loads((source / 'results.json').read_text())
        for name, body in changes.items():
            if name in inputs['products']:
                inputs['products'][name] = hashlib.sha256(body).hexdigest()
        metadata['products'] = inputs['products']
        changes = dict(changes, **{'inputs.json': encoded(inputs), 'results.json': encoded(metadata)})
        for name in changes:
            (case / name).unlink()
        archive = case / 'changed.zip'
        with zipfile.ZipFile(archive, 'x', zipfile.ZIP_DEFLATED) as bundle:
            for name, body in changes.items():bundle.writestr(name, body)
        with zipfile.ZipFile(archive) as bundle:
            for name in bundle.namelist():(case / name).write_bytes(bundle.read(name))
        try:
            verify(case)
        except ValueError as failure:
            assert str(failure) == reason, (label, str(failure), reason)
            results.append(dict(label=label, rejected=True, reason=reason,
                serialized_sha256=hashlib.sha256(archive.read_bytes()).hexdigest()))
        else:
            raise AssertionError('counterfeit source multicast evidence accepted: ' + label)
    assert originals == {path.relative_to(source).as_posix(): hashlib.sha256(path.read_bytes()).hexdigest()
                         for path in source.rglob('*') if path.is_file()}
    report = dict(passed=True, serialized_reopened_controls=len(results), originals_unchanged=True, controls=results)
    (output / 'results.json').write_bytes(encoded(report))
    return report


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--directory', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    report = run(args.directory, args.output)
    print('IPV4_SOURCE_WIRE_CONTROLS_PASS serialized_reopened=' + str(report['serialized_reopened_controls']) + ' originals_unchanged=1')
