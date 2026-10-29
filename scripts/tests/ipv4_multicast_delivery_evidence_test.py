#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Serialize delivery evidence counterfeits and reopen every changed input."""
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
from ipv4_multicast.source_controls import copy_input
from ipv4_multicast.delivery_capture import verify
from ipv4_multicast_capture import checksum, records


# Every counterfeit must reach its intended semantic guard.
REASONS = {'wire:source': 'delivery exact injected source datagram and checksum', 'wire:destination': 'delivery exact wire multicast destination', 'wire:protocol': 'delivery actual complete IPv4 UDP header and checksum', 'wire:raw-port': 'delivery real guest raw and UDP output payloads', 'wire:payload': 'delivery packet belongs to its physical interface and open stage', 'wire:bad-UDP': 'delivery exact injected source datagram and checksum', 'wire:wrong-interface': 'delivery real guest raw and UDP output payloads', 'wire:missing-injection': 'delivery every real source injection and guest output captured', 'wire:missing-output': 'delivery every real source injection and guest output captured', 'wire:repeat-injection': 'delivery exactly one injection per source and stage', 'wire:repeat-output': 'delivery exactly one output per socket protocol and stage', 'wire:before-done': 'delivery exact injected source datagram and checksum', 'wire:short-window': 'delivery complete unscaled three-second observation', 'wire:reserved-IGMP': 'delivery IGMP addresses Router Alert and checksum', 'wire:fragmented-IGMP': 'delivery IGMP addresses Router Alert and checksum', 'log:quiet': 'delivery complete masks and unscaled 200ms quiet observation', 'log:action': 'delivery complete ordered source and description operations', 'log:missing': 'delivery every allowed source and independent receive queue', 'log:raw-copy': 'delivery complete received bytes match actual injected packet', 'log:raw-truncated': 'delivery complete received bytes match actual injected packet', 'log:peer-port': 'delivery complete received bytes match actual injected packet', 'log:fresh': 'delivery source filters final close and fresh-description isolation', 'log:all-zero': 'delivery source filters final close and fresh-description isolation', 'log:last-close': 'delivery source filters final close and fresh-description isolation', 'transport': 'delivery actual paired device and virtio transport command', 'source': 'actual multicast compilation tied to complete original source', 'ISO-kernel': 'actual booted ISO contains retained kernel and initramfs', 'CPIO-program': 'actual executable inside guest initramfs', 'guest-policy': 'native timer proof cannot alter a guest query interval', 'native:offset': 'one stable native realtime-to-monotonic offset', 'native:drop': 'complete lossless native capture and clock counts', 'native:missing': 'one native receipt for every captured frame', 'native:order': 'ordered bounded native monotonic receipt pairs', 'native:timestamp': 'unchanged original native kernel packet timestamp', 'native:latency': 'bounded independent native workload reader latency', 'native:policy': 'native multicast timer policy: actual supported reference kernel'}

def encoded(value):
    return (json.dumps(value, indent=2) + '\n').encode()


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def pcap(rows):
    body = bytearray(struct.pack('<IHHIIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1))
    for row in rows:
        frame, stamp = row['frame'], row['stamp']
        body.extend(struct.pack('<IIII', stamp // 1_000_000, stamp % 1_000_000, len(frame), len(frame)))
        body.extend(frame)
    return bytes(body)


def sums(frame, udp=True):
    frame = bytearray(frame)
    header = (frame[14] & 15) * 4
    frame[24:26] = b'\0\0'
    struct.pack_into('!H', frame, 24, checksum(bytes(frame[14:14 + header])))
    if udp:
        size = int.from_bytes(frame[16:18], 'big') - header
        frame[40:42] = b'\0\0'
        pseudo = bytes(frame[26:34]) + b'\0\x11' + struct.pack('!H', size)
        struct.pack_into('!H', frame, 40, checksum(pseudo + frame[34:34 + size]) or 65535)
    return bytes(frame)


def selected(rows, tag, stage=1, which=None):
    return next(n for n, row in enumerate(rows) if len(row['frame']) >= 50 and
                row['frame'][12:14] == b'\x08\x00' and row['frame'][42:46] == tag and
                row['frame'][47] == stage and (which is None or row['frame'][48] == which))


def mutate(candidate, mutation, save):
    metadata = json.loads((candidate / 'results.json').read_text())
    inputs = json.loads((candidate / 'inputs.json').read_text())
    rows = records(candidate / 'lane0.pcap')
    log = (candidate / 'client.log').read_text()
    def product(name, body):
        save(name, body)
        value = hashlib.sha256(body).hexdigest()
        metadata['products'][name] = inputs['products'][name] = value
        save('inputs.json', encoded(inputs))
        save('results.json', encoded(metadata))
    if mutation.startswith('wire:'):
        kind = mutation[5:]
        tag, which = (b'AXSO', ord('R')) if kind in ('protocol', 'raw-port', 'missing-output') else (b'AXSO', ord('U')) if kind in ('repeat-output', 'wrong-interface') else (b'AXSI', 0)
        index = selected(rows, tag, which=which)
        frame = bytearray(rows[index]['frame'])
        if kind in ('missing-injection', 'missing-output'):
            rows.pop(index)
        elif kind in ('repeat-injection', 'repeat-output'):
            rows.insert(index, dict(rows[index]))
        elif kind == 'before-done':
            item = rows.pop(index)
            position = next(n for n, row in enumerate(rows) if row['frame'][12:18] == b'\x88\xb9AXSD')
            item['stamp'] = rows[position]['stamp'] - 1
            rows.insert(position, item)
        elif kind == 'short-window':
            start = next(row['stamp'] for row in rows if row['frame'][12:18] == b'\x88\xb9AXSD')
            target = next(row for row in rows if row['frame'][12:18] == b'\x88\xb9AXSA' and row['frame'][20] == ord('D'))
            target['stamp'] = start + 2_999_999
        elif kind in ('reserved-IGMP', 'fragmented-IGMP'):
            index = next(n for n, row in enumerate(rows) if len(row['frame']) >= 46 and row['frame'][23] == 2)
            frame = bytearray(rows[index]['frame'])
            frame[20:22] = b'\x80\0' if kind == 'reserved-IGMP' else b'\x20\0'
            rows[index]['frame'] = sums(frame, False)
        else:
            if kind == 'source':frame[26:30] = bytes([10, 67, 1, 3])
            elif kind == 'destination':frame[33] ^= 1
            elif kind == 'protocol':frame[23] = 1
            elif kind == 'raw-port':struct.pack_into('!H', frame, 34, 41002)
            elif kind == 'payload':frame[49] ^= 1
            elif kind == 'bad-UDP':frame[41] ^= 1
            elif kind == 'wrong-interface':frame[11] ^= 1
            else:raise AssertionError(kind)
            rows[index]['frame'] = bytes(frame) if kind == 'bad-UDP' else sums(frame, kind not in ('raw-port', 'protocol'))
        save('lane0.pcap', pcap(rows))
    elif mutation.startswith('log:'):
        kind = mutation[4:]
        lines = log.splitlines()
        objects = [(n, json.loads(line)) for n, line in enumerate(lines) if line.startswith('{')]
        if kind == 'quiet':
            index, row = next((n, row) for n, row in objects if row['kind'] == 'delivery-phase')
            row['quiet_end_ns'] = row['quiet_begin_ns'] + 199_999_999
        elif kind == 'action':
            index, row = next((n, row) for n, row in objects if row.get('operation') == 'close-original-raw')
            row['operation'] = 'final-close-raw'
        else:
            raw = kind in ('raw-copy', 'raw-truncated')
            index, row = next((n, row) for n, row in objects if row['kind'] == 'delivery-data' and
                              row['lane'] == 0 and row['stage'] == 1 and row['slot'] == (4 if raw else 0))
            if kind == 'missing':lines.pop(index)
            elif kind == 'raw-copy':row['hex'] = row['hex'][:-2] + '7f'
            elif kind == 'raw-truncated':row['hex'] = row['hex'][:-2];row['bytes'] -= 1
            elif kind == 'peer-port':row['source_port'] = 0
            elif kind in ('fresh', 'all-zero', 'last-close'):
                stage, slot = {'fresh': (3, 0), 'all-zero': (7, 2), 'last-close': (4, 2)}[kind]
                row.update(stage=stage, slot=slot, hex=(b'AXSI' + bytes([0, stage, 0, 0x7e])).hex())
                position = next(n for n, value in objects if value['kind'] == 'delivery-phase' and value['lane'] == 0 and value['stage'] == stage)
                lines.insert(position, json.dumps(row))
            else:raise AssertionError(kind)
        if kind not in ('missing', 'fresh', 'all-zero', 'last-close'):
            lines[index] = json.dumps(row)
        save('client.log', ('\n'.join(lines) + '\n').encode())
    elif mutation == 'transport':
        metadata['transport'] = 'legacy' if metadata['transport'] == 'modern' else 'modern'
        save('results.json', encoded(metadata))
    elif mutation == 'source':
        name = 'ipv4-multicast-source-wire-' + metadata['profile'] + '.inputs.json'
        value = json.loads((candidate / name).read_text())
        value['sources']['userspace/tests/net/ipv4_multicast_source_delivery.c'] = '0' * 64
        product(name, encoded(value))
    elif mutation == 'ISO-kernel':
        kernel = (candidate / 'axiom64.elf').read_bytes()
        body = bytearray((candidate / 'guest.iso').read_bytes())
        offset = body.find(kernel)
        assert offset >= 0
        body[offset + 9] ^= 1
        product('guest.iso', bytes(body))
    elif mutation == 'CPIO-program':
        name = 'ipv4-multicast-source-wire-' + metadata['profile']
        binary = (candidate / name).read_bytes()
        body = bytearray((candidate / 'rootfs-network.cpio').read_bytes())
        offset = body.find(binary)
        assert offset >= 0
        body[offset + 9] ^= 1
        product('rootfs-network.cpio', bytes(body))
    elif mutation in ('guest-policy', 'native:policy'):
        metadata['native_timer_policy'] = dict(schema=1, kernel='0.0.0-unmeasured', config_sha256='0' * 64,
                                               before_ns=1, after_ns=2, upper_us=1075000)
        save('results.json', encoded(metadata))
    elif mutation.startswith('native:'):
        kind = mutation[7:]
        statistics = metadata['capture_statistics'][0]
        name = statistics['monotonic_receipts']
        receipts = [json.loads(line) for line in (candidate / name).read_text().splitlines()]
        index = len(receipts) // 2
        if kind == 'offset':statistics['clock_end']['receipt_realtime_ns'] += 1_000_000_000
        elif kind == 'drop':statistics['dropped'] = 1
        elif kind == 'missing':receipts.pop()
        elif kind == 'order':
            receipts[index]['receipt_monotonic_ns'] = receipts[index - 1]['receipt_monotonic_ns'] - 1
            receipts[index]['receipt_monotonic_after_ns'] = receipts[index]['receipt_monotonic_ns'] + 1000
        elif kind == 'timestamp':rows[index]['stamp'] += 1
        elif kind == 'latency':
            receipts[index]['kernel_realtime_ns'] -= 1_001_000_000
            rows[index]['stamp'] = receipts[index]['kernel_realtime_ns'] // 1000
        else:raise AssertionError(kind)
        if kind in ('timestamp', 'latency'):save('lane0.pcap', pcap(rows))
        if kind in ('missing', 'order', 'latency'):
            body = b''.join((json.dumps(row) + '\n').encode() for row in receipts)
            save(name, body)
            statistics['monotonic_receipts_sha256'] = hashlib.sha256(body).hexdigest()
        save('results.json', encoded(metadata))
    else:
        raise AssertionError(mutation)


def run(directory, native_directory, output):
    directory, native_directory, output = map(lambda p: Path(p).resolve(), (directory, native_directory, output))
    if not all(p.is_relative_to((ROOT / 'build').resolve()) for p in (directory, native_directory, output)):
        raise ValueError('delivery controls require separate owned build paths')
    if output == directory or output == native_directory or output in directory.parents or output in native_directory.parents:
        raise ValueError('delivery control output must not contain original inputs')
    positive, native = verify(directory), verify(native_directory)
    assert not positive['native'] and native['native']
    output.mkdir(parents=True, exist_ok=False)
    snapshots = [{str(p.relative_to(folder)): digest(p) for p in folder.rglob('*') if p.is_file()}
                 for folder in (directory, native_directory)]
    guest_controls = [*('wire:' + name for name in ('source', 'destination', 'protocol', 'raw-port', 'payload',
        'bad-UDP', 'wrong-interface', 'missing-injection', 'missing-output', 'repeat-injection',
        'repeat-output', 'before-done', 'short-window', 'reserved-IGMP', 'fragmented-IGMP')),
        *('log:' + name for name in ('quiet', 'action', 'missing', 'raw-copy', 'raw-truncated', 'peer-port',
                                    'fresh', 'all-zero', 'last-close')),
        'transport', 'source', 'ISO-kernel', 'CPIO-program', 'guest-policy']
    native_controls = ['native:' + name for name in ('offset', 'drop', 'missing', 'order', 'timestamp', 'latency', 'policy')]
    results = []
    for number, mutation in enumerate([*guest_controls, *native_controls]):
        original = native_directory if mutation.startswith('native:') else directory
        candidate = output / f'case-{number:02d}'
        shutil.copytree(original, candidate, copy_function=copy_input)
        changed = {}
        def save(name, body):
            path = candidate / name
            if path.exists():path.unlink()
            path.write_bytes(body)
            changed[name] = body
        mutate(candidate, mutation, save)
        archive = output / (candidate.name + '.zip')
        with zipfile.ZipFile(archive, 'x', zipfile.ZIP_DEFLATED) as bundle:
            for name, body in changed.items():bundle.writestr(name, body)
        for name in changed:(candidate / name).unlink()
        with zipfile.ZipFile(archive) as bundle:
            for name in bundle.namelist():(candidate / name).write_bytes(bundle.read(name))
        try:
            verify(candidate)
        except ValueError as failure:
            assert str(failure) == REASONS[mutation], (mutation, str(failure))
            results.append(dict(label=mutation, rejected=True, reason=str(failure),
                                serialized_sha256=digest(archive)))
            print('DELIVERY_CONTROL_REJECTED ' + mutation, flush=True)
        else:
            raise AssertionError('changed delivery evidence accepted: ' + mutation)
    for folder, before in zip((directory, native_directory), snapshots):
        assert before == {str(p.relative_to(folder)): digest(p) for p in folder.rglob('*') if p.is_file()}
    result = dict(passed=True, positive=positive, native=native, controls=results,
                  serialized_reopened_controls=len(results), originals_unchanged=True)
    (output / 'results.json').write_bytes(encoded(result))
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--directory', type=Path, required=True)
    parser.add_argument('--native-directory', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    result = run(args.directory, args.native_directory, args.output)
    print('IPV4_SOURCE_DELIVERY_CONTROLS_PASS serialized_reopened=' + str(result['serialized_reopened_controls']) +
          ' originals_unchanged=1')


if __name__ == '__main__':
    main()
