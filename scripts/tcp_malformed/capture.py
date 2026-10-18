# SPDX-License-Identifier: GPL-3.0-or-later
"""Independently audit malformed wire inputs and exact socket recovery."""
from collections import Counter
from pathlib import Path
import hashlib
import itertools
import json
import re
import struct
import subprocess
import sys
import tempfile

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from fetch import ROOT, LOCK
from tcp_capture import checksum
from tcp_capture_clock import bind_native_clock, milliseconds
from tcp_fault_capture import require, MASK
from tcp_icmp_capture import audit_inputs
from disk_root import archive_entries
from tcp_malformed.inputs import SOURCES


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def expected(lane, direction, offset, size):
    return bytes(((at * 29) ^ (at >> 7) ^ (lane * 53) ^ (direction * 41)) & 255
                 for at in range(offset, offset + size))


def raw_records(path):
    data = path.read_bytes()
    require(len(data) >= 24 and data[:4] in (bytes.fromhex('d4c3b2a1'), bytes.fromhex('a1b2c3d4')),
            'malformed capture retains actual PCAP header')
    endian = '<' if data[:4] == bytes.fromhex('d4c3b2a1') else '>'
    major, minor, _, _, snap, network = struct.unpack_from(endian + 'HHIIII', data, 4)
    require((major, minor, network) == (2, 4, 1) and snap >= 1514,
            'malformed capture has a native or QEMU Ethernet snap length')
    at = 24
    while at < len(data):
        require(at + 16 <= len(data), 'complete malformed capture record header')
        seconds, micros, size, original = struct.unpack_from(endian + 'IIII', data, at)
        at += 16
        require(micros < 1000000 and 14 <= size == original <= snap and at + size <= len(data),
                'complete malformed capture original frame')
        yield dict(stamp=seconds * 1000000 + micros, frame=data[at:at + size])
        at += size


OPTIONS = [b'', bytes.fromhex('fe000000'), bytes.fromhex('fe010000'), bytes.fromhex('fe050000'),
           bytes.fromhex('02030000'), bytes.fromhex('03040100'), bytes.fromhex('fe040000')]
NAMES = ['checksum', 'length-zero', 'length-one', 'length-overrun', 'MSS-length', 'scale-length', 'unknown-valid']


def decode(frame, lane):
    if len(frame) < 34 or frame[12:14] != b'\x08\x00' or frame[23] != 6:
        return None
    ip = frame[14:]
    header, total = (ip[0] & 15) * 4, int.from_bytes(ip[2:4], 'big')
    require(ip[0] >> 4 == 4 and header >= 20 and header + 20 <= total <= len(ip)
            and not checksum(ip[:header]) and not int.from_bytes(ip[6:8], 'big') & 0x3fff,
            'actual malformed fixture retains valid IPv4 ownership and bounds')
    guest, peer = bytes([10, 23, lane + 1, 2]), bytes([10, 23, lane + 1, 1])
    require({ip[12:16], ip[16:20]} == {guest, peer}, 'exact malformed fixture address tuple')
    tcp = ip[header:total]
    source, target, seq, ack, bits, window, _, urgent = struct.unpack_from('!HHIIHHHH', tcp)
    length = (bits >> 12) * 4
    outgoing = ip[12:16] == guest
    require((source, target) == ((48550 + lane, 49550 + lane) if outgoing else (49550 + lane, 48550 + lane))
            and 20 <= length <= len(tcp) and not bits & 0xe00 and not urgent,
            'exact malformed fixture port tuple and TCP header bounds')
    valid = not checksum(ip[12:20] + struct.pack('!BBH', 0, 6, len(tcp)) + tcp)
    require(valid or not outgoing, 'every actual guest segment retains a valid TCP checksum')
    return dict(outgoing=outgoing, seq=seq, ack=ack, flags=bits & 511, window=window,
                data=tcp[length:], options=tcp[20:length], valid_checksum=valid, frame=frame)


def read(path, lane, statistics=None):
    rows = []
    for record in raw_records(path):
        row = decode(record['frame'], lane)
        if row is not None:
            row['stamp'] = record['stamp']
            rows.append(row)
    require(rows, 'real malformed fixture contains TCP packets')
    if statistics is not None:
        bind_native_clock(path, rows, statistics)
    return rows


def reconstruct(rows, lane, native):
    guest, peer = ([row for row in rows if row['outgoing']], [row for row in rows if not row['outgoing']])
    require(guest and peer and not any(row['flags'] & 4 for row in rows), 'malformed input preserves the live stream')
    syn, synack = ([row for row in guest if row['flags'] & 2], [row for row in peer if row['flags'] & 2])
    require(len(syn) == len(synack) == 1 and syn[0]['flags'] == 2 and synack[0]['flags'] == 18
            and synack[0]['valid_checksum'] and synack[0]['options'] == bytes.fromhex('020405b4'),
            'actual malformed input follows one valid MSS handshake')
    origin, reverse = (syn[0]['seq'] + 1) & MASK, (synack[0]['seq'] + 1) & MASK
    require(synack[0]['ack'] == origin, 'actual malformed-input handshake owns the active sequence')
    injections, recoveries = {}, {}
    request = bytearray(16)
    for index, row in enumerate(rows):
        if row['outgoing']:
            require(not row['options'] or row['flags'] & 2, 'outgoing established packets keep valid ordinary headers')
            if row['data']:
                offset = (row['seq'] - origin) & MASK
                require(offset + len(row['data']) <= 16 and row['data'] == expected(lane, 0, offset, len(row['data'])),
                        'exact original request remains uncontaminated')
                request[offset:offset + len(row['data'])] = b'\1' * len(row['data'])
            continue
        if not row['data']:
            require(row['valid_checksum'], 'only the actual injected data frame has a bad checksum')
            continue
        offset = (row['seq'] - reverse) & MASK
        require(len(row['data']) == 16 and offset % 16 == 0 and offset < 112 and row['flags'] == 24,
                'each captured input owns exactly one sixteen-byte case')
        case = offset // 16
        target = injections if not row['valid_checksum'] or row['options'] else recoveries
        require(case not in target, 'one original injection and valid recovery frame per case')
        target[case] = index
        if target is injections:
            require(row['options'] == OPTIONS[case] and row['valid_checksum'] == (case != 0),
                    'all distinct checksum and malformed-option encodings are physically captured')
            data = expected(lane, 1, offset, 16)
            require(row['data'] == (bytes(value ^ 0x80 for value in data) if case == 0 else data),
                    'only the bad-checksum injection carries deliberately poisoned bytes')
        else:
            require(row['valid_checksum'] and row['data'] == expected(lane, 1, offset, 16),
                    'valid recovery preserves every exact application byte')
    require(all(request) and set(injections) == set(recoveries) == set(range(7)),
            'every actual malformed input and its valid recovery is captured')
    observations = []
    for case in range(7):
        start, finish = injections[case], recoveries[case]
        require(start < finish and (case == 6 or finish < injections[case + 1]),
                'each physical injection precedes valid recovery and the next case')
        require(milliseconds(rows[finish]) - milliseconds(rows[start]) >= 95,
                'each original capture observes the malformed-input recovery wait')
        acknowledged = [row for row in rows[start + 1:finish] if row['outgoing'] and row['flags'] & 16
                        and ((row['ack'] - reverse) & MASK) > case * 16]
        require(all(((row['ack'] - reverse) & MASK) == (case + 1) * 16 for row in acknowledged),
                'pre-recovery acknowledgments own only the actual injected sequence range')
        if case == 0 or (not native and case in range(1, 6)):
            require(not acknowledged, 'bad checksum and guest malformed options cannot advance receive ownership')
        elif case == 6:
            require(acknowledged, 'well-formed unsupported option is ignored and its data is accepted')
        observations.append(dict(case=NAMES[case], acknowledged_before_valid=bool(acknowledged),
            original_injection_to_recovery_ms=milliseconds(rows[finish]) - milliseconds(rows[start])))
    for outgoing, size, base in [(True, 16, origin), (False, 112, reverse)]:
        finishes = [row for row in rows if row['outgoing'] == outgoing and row['flags'] & 1]
        require(finishes and all(((row['seq'] + len(row['data']) - base) & MASK) == size for row in finishes),
                'both FINs follow exact unpoisoned application data')
        require(any(row['outgoing'] != outgoing and row['flags'] & 16 and row['ack'] == (base + size + 1) & MASK
                    for row in rows), 'both final FINs are actually acknowledged')
    return dict(passed=True, packets=len(rows), actual_injections=7, malformed_cases=6,
                request_bytes=16, reply_bytes=112, both_FINs_acknowledged=True, cases=observations)


def verify(path, lane, evidence, native=False, statistics=None):
    require(not native or statistics is not None, 'native malformed capture retains independent clocks')
    rows = read(path, lane, statistics if native else None)
    require(evidence['lane'] == lane, 'actual malformed peer lane identity')
    reported = []
    for item in evidence['frames']:
        row = decode(bytes.fromhex(item['frame']), lane)
        if row is not None:
            require(item['direction'] in ('receive', 'send') and
                    row['outgoing'] == (item['direction'] == 'receive'), 'actual malformed peer direction')
            row['ms'] = item['ms']
            reported.append(row)
    # Peer send records precede backend delivery. A queued output can cross an
    # already received ACK; each observer must retain its actual local order.
    require(Counter(row['frame'] for row in rows) == Counter(row['frame'] for row in reported),
            'every original malformed peer frame matches capture multiplicity and bytes')
    result = reconstruct(rows, lane, native)
    peer_result = reconstruct(reported, lane, native)
    require(all(case['original_injection_to_recovery_ms'] >= 100 for case in peer_result['cases']),
            'independent peer observes each complete hundred-millisecond recovery wait')
    result.update(file=path.name, sha256=digest(path), lane=lane, native=native)
    return result


def bounded(root, name):
    require(isinstance(name, str) and name and Path(name).name == name and
            '/' not in name and '\\' not in name, 'bounded malformed report evidence name')
    return root / name


def audit_image(inputs, input_root):
    linkage = inputs['linkage']
    image = input_root / f'build/axiom64-tcp-malformed-{linkage}.iso'
    require(f'build/{image.name}' in inputs['products'], 'actual malformed boot image is fingerprinted')
    with tempfile.TemporaryDirectory(prefix='axiom64-malformed-image-audit-') as temporary:
        directory = Path(temporary)
        subprocess.run(['xorriso', '-osirrox', 'on', '-indev', str(image),
                        '-extract', '/boot/axiom64.elf', str(directory / 'kernel'),
                        '-extract', '/boot/rootfs.cpio', str(directory / 'root.cpio')],
                       check=True, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
        require(digest(directory / 'kernel') == inputs['products']['build/axiom64.elf'],
                'actual ISO contains the fingerprinted running kernel')
        entries = archive_entries(directory / 'root.cpio')
    products = {'sbin/init': 'build/init', 'bin/tcp-malformed': f'build/tcp-malformed-{linkage}',
                'bin/busybox': f'build/busybox-{LOCK["busybox"]["version"]}/busybox'}
    for name, product in products.items():
        require(name in entries and entries[name][0] == 0o100755 and
                hashlib.sha256(entries[name][1]).hexdigest() == inputs['products'][product],
                f'actual ISO contains the exact executable: {name}')
    # The shared fixture selects build_musl.loader() with its build-provider default.
    loaders = [fingerprint for name, fingerprint in inputs['products'].items()
               if '/build/' in name and name.endswith('/ld-musl-x86_64.so.1')]
    require(len(loaders) == 1 and entries['lib/ld-musl-x86_64.so.1'][0] == 0o100755 and
            hashlib.sha256(entries['lib/ld-musl-x86_64.so.1'][1]).hexdigest() == loaders[0],
            'actual ISO contains the recorded build-provider musl loader')
    require(entries['etc/net-test.sh'] == (0o100755,
            b'#!/bin/sh\nset -e\n/bin/tcp-malformed\necho AXIOM64_TESTS_PASS\n'),
            'actual boot script executes the exact malformed socket client')
    return dict(image=image.name, sha256=digest(image), actual_image_opened=True)


def check_results(directory, input_root=None):
    input_root = input_root or ROOT
    checked, images = [], {}
    for native in (True, False):
        report = directory / ('tcp-malformed-native-results.json' if native else 'tcp-malformed-results.json')
        rows = json.loads(report.read_text())
        if native:
            require(len(rows) == 3 and {row['linkage'] for row in rows} == {'native', 'static', 'dynamic'},
                    'all three native malformed libc profiles')
        else:
            expected_profiles = set(itertools.product(('static', 'dynamic'), ('bios', 'uefi'), ('modern', 'legacy')))
            require(len(rows) == 8 and {(row['linkage'], row['firmware'], row['transport']) for row in rows} ==
                    expected_profiles, 'all eight guest malformed linkage/firmware/transport profiles')
        for row in rows:
            require(row['wire'] == 'malformed' and row['passed'] and not row['error'] and not row['missing'] and
                    row['returncode'] == (0 if native else 1), 'actual malformed application and peer succeed')
            if native:
                require(len({row[name] for name in ('parent_namespace', 'peer_namespace', 'client_namespace')}) == 3,
                        'malformed Linux client, peer and parent retain separate namespaces')
            inputs = json.loads(bounded(directory, row['inputs']).read_text())
            require(inputs['linkage'] == row['linkage'] and inputs['native'] == native and
                    set(inputs['sources']) == set(SOURCES) and
                    f'build/tcp-malformed-{row["linkage"]}' in inputs['products'],
                    'malformed evidence retains the complete actual input contract')
            audit_inputs(inputs, input_root)
            text = bounded(directory, row['log']).read_text()
            require(text.count('TCP_MALFORMED_PASS nics=2 cases_each=7') == 1 and
                    set(re.findall(r'TCP_MALFORMED_LANE_PASS lane=(\d) request=16 reply=112 elapsed_ms=\d+', text)) == {'0', '1'}
                    and not any(word in text for word in ('TCP_MALFORMED_FAIL', 'PANIC:', 'FAULT pid=')),
                    'both actual socket streams finish all malformed cases with exact bytes')
            if not native:
                require(all(marker in text for marker in ('AXIOM64_TESTS_PASS', 'AXIOM64_EXIT status=0',
                        f'Firmware: {row["firmware"].upper()}', f'virtio-net: index=1 transport={row["transport"]}',
                        'e1000: index=2 model=82540EM')), 'actual malformed guest firmware and both NIC drivers')
                if row['linkage'] not in images:
                    images[row['linkage']] = audit_image(inputs, input_root)
            peers = json.loads(bounded(directory, row['peer']).read_text())
            require(len(peers) == len(row['captures']) == 2, 'both original malformed adapter captures')
            if native:
                require(len(row['capture_statistics']) == 2, 'both native malformed capture statistics')
            for lane, name in enumerate(row['captures']):
                checked.append(verify(bounded(directory, name), lane, peers[lane], native,
                               row['capture_statistics'][lane] if native else None))
    require(len(checked) == 22 and len(images) == 2, 'complete malformed captures and actual boot images')
    result = dict(passed=True, captures=checked, images=images, actual_injections=154, malformed_inputs=132)
    (directory / 'tcp-malformed-capture-results.json').write_text(json.dumps(result, indent=2) + '\n')
    print('TCP_MALFORMED_CAPTURE_PASS captures=22 injections=154 malformed=132 actual_images=2 exact_bytes')
    return result


if __name__ == '__main__':
    check_results(ROOT / 'build')
