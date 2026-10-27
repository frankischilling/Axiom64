#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Reopen original multicast captures, source, products and kernel packet clocks."""
import argparse
import hashlib
import json
from pathlib import Path
import struct
import subprocess
import tempfile
import zipfile

from tcp_capture_clock import bind_native_clock


def require(value, reason):
    if not value:
        raise ValueError(reason)


def checksum(data):
    value = 0
    for offset in range(0, len(data), 2):
        value += data[offset] << 8
        if offset + 1 < len(data):
            value += data[offset + 1]
    while value > 65535:
        value = (value & 65535) + (value >> 16)
    return value ^ 65535


def records(path):
    data = path.read_bytes()
    require(len(data) >= 24 and data[:4] in (b'\xd4\xc3\xb2\xa1', b'\xa1\xb2\xc3\xd4'), 'multicast PCAP header')
    endian = '<' if data[:4] == b'\xd4\xc3\xb2\xa1' else '>'
    major, minor, _, _, snap, link = struct.unpack_from(endian + 'HHIIII', data, 4)
    require((major, minor, link) == (2, 4, 1) and 1514 <= snap <= 65536, 'multicast Ethernet PCAP format')
    rows, offset = [], 24
    while offset < len(data):
        require(offset + 16 <= len(data), 'complete multicast PCAP record')
        seconds, micros, size, original = struct.unpack_from(endian + 'IIII', data, offset)
        offset += 16
        require(micros < 1000000 and 14 <= size == original <= snap and offset + size <= len(data), 'complete original multicast frame')
        rows.append(dict(stamp=seconds * 1000000 + micros, frame=data[offset:offset + size]))
        offset += size
    require(rows, 'nonempty original multicast capture')
    return rows


def lane(path, number, native, statistics):
    rows = records(path)
    clock = None
    if native:
        # All original records are bound; only actual workload frames receive
        # the shared native latency gate. Unrelated IPv6 control stays retained.
        selected = [row for row in rows if row['frame'][12:14] in (b'\x08\x00', b'\x88\xb9')]
        clock = bind_native_clock(path, selected, statistics)
    guest = bytes([0x52, 0x54, 0, 0x12, 0x34, 0x10 + number])
    peer = bytes([2, 0x41, 0x58, 0x4d, 0x43, number])
    local = bytes([10, 67, number + 1, 2])
    remote = bytes([10, 67, number + 1, 1])
    group = bytes.fromhex('ef6a4307')
    requests, acknowledgments, ingress, output, reports = [], [], [], [], []
    pending = {}
    queries = {}
    responses = {}
    for position, row in enumerate(rows):
        frame = row['frame']
        if frame[12:14] == b'\x88\xb9':
            require(len(frame) == 60 and frame[18] == number and not any(frame[20:]), 'actual multicast control envelope')
            phase = frame[19]
            if frame[14:18] == b'AXMC':
                require(frame[:12] == peer + guest and phase not in pending and phase not in requests, 'unique physical multicast request')
                requests.append(phase)
                pending[phase] = position
            else:
                require(frame[14:18] == b'AXMA' and frame[:12] == guest + peer and phase in pending, 'ordered actual multicast acknowledgment')
                if phase <= 9:
                    require(ingress and ingress[-1]['phase'] == phase and ingress[-1]['record'] > pending[phase], 'actual ingress before acknowledgment')
                if phase in (10, 11):
                    require(phase in output, 'physical output before acknowledgment')
                if phase in (200, 201):
                    require(phase in responses, 'actual query response before acknowledgment')
                if phase == 202:
                    require(any(report['kind'] == 0x17 for report in reports), 'actual leave before acknowledgment')
                del pending[phase]
                acknowledgments.append(phase)
            continue
        if frame[12:14] != b'\x08\x00':
            continue
        ip = frame[14:]
        require(len(ip) >= 20 and ip[0] >> 4 == 4, 'actual multicast IPv4 version')
        header, total = (ip[0] & 15) * 4, int.from_bytes(ip[2:4], 'big')
        require(20 <= header <= total <= len(ip) and not checksum(ip[:header]) and not (int.from_bytes(ip[6:8], 'big') & 0x3fff), 'actual multicast IPv4 bounds and checksum')
        body = ip[header:total]
        destination = ip[16:20]
        mac = b'\x01\x00\x5e' + bytes([destination[1] & 127]) + destination[2:]
        require(destination[0] & 0xf0 == 0xe0 and frame[:6] == mac, 'actual multicast Ethernet mapping')
        if ip[9] == 17:
            require(header == 20 and len(body) >= 8 and destination == group, 'actual multicast UDP header')
            source_port, destination_port, length, check = struct.unpack('!HHHH', body[:8])
            require(length == len(body) and destination_port == 46067 and check and not checksum(ip[12:20] + b'\0\x11' + struct.pack('!H', length) + body), 'actual multicast UDP checksum and length')
            payload = body[8:]
            if payload[:5] == b'AXMCW':
                require(frame[6:12] == peer and ip[12:16] == remote and ip[8] == 19 and source_port == 42000 and len(payload) == 7 and payload[5] == number, 'actual external multicast input')
                phase = payload[6]
                require(phase in pending and phase <= 9 and phase not in [entry['phase'] for entry in ingress], 'unique phase-owned multicast input')
                ingress.append(dict(phase=phase, record=position))
            else:
                require(frame[6:12] == guest and ip[12:16] == local and ip[8] == 7 and source_port == 46068 and payload in (b'AXMCO\x0a', b'AXMCO\x0b'), 'actual external multicast output')
                require(payload[-1] not in output, 'one physical multicast transmission per send')
                output.append(payload[-1])
            continue
        require(ip[9] == 2 and header == 24 and ip[20:24] == b'\x94\x04\0\0' and ip[8] == 1 and ip[1] == 0xc0 and len(body) >= 8 and not checksum(body), 'actual IGMP Router Alert, TTL, control class and checksum')
        if body[0] == 0x11:
            phase = 200 if len(body) == 12 else 201
            require(frame[6:12] == peer and ip[12:16] == remote and destination == bytes.fromhex('e0000001') and body[1] == 10 and not any(body[4:8]) and phase in pending and phase not in queries and len(body) in (8, 12), 'actual unique router query')
            queries[phase] = row['stamp']
            continue
        require(frame[6:12] == guest and ip[12:16] == local, 'actual host IGMP source')
        if body[0] == 0x22:
            require(destination == bytes.fromhex('e0000016') and not body[1], 'actual IGMPv3 report destination')
            offset = 8
            for _ in range(int.from_bytes(body[6:8], 'big')):
                require(offset + 8 <= len(body), 'actual complete IGMPv3 group record')
                kind, auxiliary, sources = struct.unpack('!BBH', body[offset:offset + 4])
                end = offset + 8 + 4 * (sources + auxiliary)
                require(kind in range(1, 7) and end <= len(body), 'actual IGMPv3 record bounds')
                if body[offset + 4:offset + 8] == group:
                    require(not auxiliary and not sources and kind in (2, 3, 4), 'actual ASM group record')
                    reports.append(dict(kind=kind, stamp=row['stamp']))
                    if kind == 2 and 200 in queries:
                        responses.setdefault(200, row['stamp'])
                offset = end
            require(offset == len(body), 'all actual IGMPv3 report bytes consumed')
        else:
            require(body[0] in (0x12, 0x16, 0x17) and len(body) == 8 and not body[1] and body[4:8] == group, 'actual legacy membership report')
            require(destination == (bytes.fromhex('e0000002') if body[0] == 0x17 else group), 'actual legacy IGMP destination')
            reports.append(dict(kind=body[0], stamp=row['stamp']))
            if body[0] == 0x16 and 201 in queries:
                responses.setdefault(201, row['stamp'])
    expected = [1, 2, 3, 4, 5, 7, 8, 10, 11, 12, 200, 201, 202] if number == 0 else [6, 9]
    require(requests == acknowledgments == expected and not pending, 'complete ordered physical multicast phases')
    require([row['phase'] for row in ingress] == [phase for phase in expected if phase <= 9], 'all original external datagrams retained')
    require(any(row['kind'] == 4 for row in reports) and any(row['kind'] == 3 for row in reports), 'actual join and leave records on each interface')
    if number == 0:
        require(output == [10, 11] and set(responses) == {200, 201}, 'actual TTL/loop output and query reports')
        for phase in responses:
            require(0 <= responses[phase] - queries[phase] <= 1010000, 'actual unscaled query-response interval')
        require(any(row['kind'] == 0x17 for row in reports), 'actual last-reporter IGMPv2 leave')
    else:
        require(not output and not queries, 'second interface has no foreign multicast output')
    return dict(lane=number, frames=len(rows), ingress=len(ingress), output=len(output), reports=len(reports), native_clock=clock)



def elf(data):
    require(len(data) >= 64 and data[:7] == b'\x7fELF\x02\x01\x01' and
            int.from_bytes(data[18:20], 'little') == 62 and
            int.from_bytes(data[16:18], 'little') in (2, 3), 'actual x86-64 ELF product')
    entry = int.from_bytes(data[24:32], 'little')
    offset = int.from_bytes(data[32:40], 'little')
    size = int.from_bytes(data[54:56], 'little')
    count = int.from_bytes(data[56:58], 'little')
    require(size == 56 and count and offset >= 64 and offset + size * count <= len(data),
            'complete actual ELF program headers')
    executable = False
    for number in range(count):
        kind, flags, start, address, _, files, memory, alignment = struct.unpack_from(
            '<IIQQQQQQ', data, offset + size * number)
        require(start + files <= len(data), 'actual ELF segment file bounds')
        if kind != 1:
            continue
        require(memory >= files and address + memory <= 1 << 64 and
                (alignment in (0, 1) or not alignment & (alignment - 1)),
                'actual ELF load bounds and alignment')
        executable |= bool(flags & 1 and address <= entry < address + memory)
    require(executable, 'actual ELF entry in executable load segment')


def cpio(data):
    entries, offset = {}, 0
    while True:
        require(offset + 110 <= len(data) and data[offset:offset + 6] == b'070701',
                'actual retained newc header')
        fields = [int(data[offset + 6 + n * 8:offset + 14 + n * 8], 16) for n in range(13)]
        size, names = fields[6], fields[11]
        offset += 110
        require(names > 0 and offset + names <= len(data) and not data[offset + names - 1],
                'actual retained newc name')
        name = data[offset:offset + names - 1].decode()
        offset = (offset + names + 3) & ~3
        require(offset + size <= len(data) and name not in entries,
                'unique complete retained newc member')
        body = data[offset:offset + size]
        offset = (offset + size + 3) & ~3
        if name == 'TRAILER!!!':
            require(size == 0 and not any(data[offset:]), 'complete retained newc trailer')
            return entries
        require(name and not name.startswith('/') and '..' not in Path(name).parts,
                'bounded retained newc member')
        entries[name] = (fields[1], body)


def products(directory, metadata, inputs, sources):
    profile = metadata.get('profile', 'static')
    require(profile in ('native', 'static', 'dynamic') and (metadata['native'] or profile != 'native'), 'actual multicast linkage')
    program = 'ipv4-multicast-' + profile
    expected = {program, program + '.inputs.json'}
    if profile == 'dynamic':
        expected |= {'musl-build-loader', 'musl-runtime-loader'}
    if profile == 'native':
        expected |= {'host-libc.so.6', 'host-ld-linux-x86-64.so.2'}
    if not metadata['native']:
        expected |= {'axiom64.elf', 'init', 'rootfs-network.cpio', 'guest.iso'}
    require(set(inputs['products']) == expected, 'complete actual multicast product inventory')
    binary = (directory / program).read_bytes()
    compiled = json.loads((directory / (program + '.inputs.json')).read_text())
    require(compiled['product']['sha256'] == hashlib.sha256(binary).hexdigest() and
            compiled['product']['bytes'] == len(binary), 'actual compiled multicast executable')
    require('userspace/tests/net/ipv4_multicast.c' in compiled['sources'] and
            all(sources.get(name) == value for name, value in compiled['sources'].items()),
            'actual multicast compilation tied to complete original source')
    elf(binary)
    if metadata['native']:
        return
    kernel, init = (directory / 'axiom64.elf').read_bytes(), (directory / 'init').read_bytes()
    elf(kernel)
    elf(init)
    archive = (directory / 'rootfs-network.cpio').read_bytes()
    members = cpio(archive)
    for name, expected_bytes in [('bin/' + program, binary), ('sbin/init', init)]:
        require(name in members and members[name][0] & 0o111 and
                members[name][1] == expected_bytes, 'actual executable inside guest initramfs')
    if profile == 'dynamic':
        require('lib/ld-musl-x86_64.so.1' in members and
                members['lib/ld-musl-x86_64.so.1'][1] == (directory / 'musl-runtime-loader').read_bytes(),
                'actual guest runtime interpreter inside initramfs')
        elf((directory / 'musl-runtime-loader').read_bytes())
    require('bin/busybox' in members and members['bin/busybox'][0] & 0o111,
            'actual guest shell in initramfs')
    elf(members['bin/busybox'][1])
    with tempfile.TemporaryDirectory(prefix='axiom-multicast-image-reader-') as temporary:
        extracted = Path(temporary)
        subprocess.run(['xorriso', '-osirrox', 'on', '-indev', str(directory / 'guest.iso'),
                        '-extract', '/boot/axiom64.elf', str(extracted / 'kernel'),
                        '-extract', '/boot/rootfs.cpio', str(extracted / 'rootfs')],
                       check=True, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
        require((extracted / 'kernel').read_bytes() == kernel and
                (extracted / 'rootfs').read_bytes() == archive,
                'actual booted ISO contains retained kernel and initramfs')


def verify(directory):
    directory = Path(directory)
    metadata = json.loads((directory / 'results.json').read_text())
    inputs = json.loads((directory / 'inputs.json').read_text())
    digest = lambda name: hashlib.sha256((directory / name).read_bytes()).hexdigest()
    require(digest('source.zip') == inputs['source']['source_zip_sha256'] and digest('source-inputs.json') == inputs['source']['source_inputs_sha256'], 'original complete multicast source fingerprints')
    sources = json.loads((directory / 'source-inputs.json').read_text())
    require(len(sources) == inputs['source']['files'] and len(sources) >= 1543, 'complete multicast source inventory')
    with zipfile.ZipFile(directory / 'source.zip') as archive:
        require(len(archive.namelist()) == len(sources) and set(archive.namelist()) == set(sources) and archive.testzip() is None, 'unique complete multicast source ZIP')
        for name, expected in sources.items():
            require(hashlib.sha256(archive.read(name)).hexdigest() == expected, 'original multicast source bytes')
    for name, expected in inputs['products'].items():
        require(Path(name).name == name and digest(name) == expected, 'actual retained multicast product bytes')
    require(type(metadata.get('native')) is bool, 'explicit multicast execution domain')
    products(directory, metadata, inputs, sources)
    text = (directory / 'client.log').read_text()
    require('MULTICAST_FAIL' not in text and text.count('MULTICAST_TESTS_PASS') == 1 and all(text.count(marker) == 1 for marker in ('MULTICAST_ABI_PASS', 'MULTICAST_LIFETIME_PASS', 'MULTICAST_OUTPUT_REPORT_PASS')), 'actual multicast client completed every contract')
    expected_receivers = {1: 1, 2: 2, 3: 1, 4: 0, 5: 0, 6: 2, 7: 2, 8: 0, 9: 2}
    observed = [line for line in text.splitlines() if line.startswith('MULTICAST_INGRESS')]
    require(observed == [f'MULTICAST_INGRESS lane={1 if phase in (6, 9) else 0} phase={phase} receivers={count}' for phase, count in expected_receivers.items()], 'actual socket delivery and quiet observations')
    require(metadata['returncode'] == (0 if metadata['native'] else 1) and metadata['error'] is None, 'actual multicast process completion')
    clocks = metadata['capture_statistics'] if metadata['native'] else [None, None]
    require(len(clocks) == 2, 'both actual multicast captures')
    lanes = [lane(directory / f'lane{number}.pcap', number, metadata['native'], clocks[number]) for number in range(2)]
    return dict(passed=True, source_files=len(sources), native=metadata['native'], lanes=lanes,
                full_feature_acceptance=False, ordinary_reader_and_full_matrix_pending=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('directory', type=Path)
    args = parser.parse_args()
    print(json.dumps(verify(args.directory), indent=2))


if __name__ == '__main__':
    main()
