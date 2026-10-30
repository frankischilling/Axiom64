# SPDX-License-Identifier: GPL-3.0-or-later
"""Audit retained raw packets across real held-ARP configuration changes."""
import argparse
import copy
import hashlib
import json
from pathlib import Path
import re
import struct
import tempfile
import zipfile

from ipv4_expiry_capture import read_capture, encode_capture, bind_clocks, checksum, require, elapsed_ns


def audit(rows, lane, text):
    require(lane in (0, 1) and 'IPV4_RAW_QUEUE_FAIL' not in text, 'successful selected queue lane')
    require(text.count(f'IPV4_RAW_QUEUE_PASS index={lane + 1} cases=6 selected=-1') == 1,
            'all six original queued raw-header cases')
    cases = re.findall(r'^IPV4_RAW_QUEUE_CASE_PASS index=' + str(lane + 1) +
                       r' test=(\d+) bytes=(\d+) ordinary=(\d+)\r?$', text, re.M)
    require([tuple(map(int, row)) for row in cases] ==
            [(sample, 1500 if sample == 1 else 28, int(sample == 5)) for sample in range(6)],
            'complete ordered application results and inherited ordinary output')
    guest = bytes((0x52, 0x54, 0, 0x12, 0x34, 0x10 + lane))
    peer = bytes((2, 0x41, 0x58, 0x49, 0x50, lane))
    local = bytes((10, 23, lane + 1, 2))
    sample, state, previous, began = 0, 'start', 0, 0
    controls, requests, replies, packets, timings = [], {}, {}, {}, []
    for position, row in enumerate(rows):
        frame = row['frame']
        kind = frame[12:14]
        control = kind == b'\x88\xb5'
        arp = (kind == b'\x08\x06' and len(frame) >= 42 and
               frame[6:12] in (guest, peer) and
               ((frame[38:41] == local[:3] and 200 <= frame[41] <= 205) or
                (frame[28:31] == local[:3] and 200 <= frame[31] <= 205)))
        data = (kind == b'\x08\0' and len(frame) >= 34 and frame[6:12] == guest and
                (frame[23] == 76 or frame[18:20] == b'\x13\x57' and
                 frame[26:34] == b'\xc0\0\x02\x01' + bytes((10, 23, lane + 1, 77))))
        if not (control or arp or data):
            continue
        now = elapsed_ns(row)
        require(now >= previous, 'monotonic original queue packet order')
        previous = now
        outgoing = frame[:12] == peer + guest
        if control:
            controls.append(position)
            require(len(frame) == 60 and frame[14:19] == b'RHQ1' + bytes((lane,)) and
                    (outgoing or frame[:12] == guest + peer) and frame[19] == sample,
                    'complete ordered queue control Ethernet ownership, lane and case')
            payload = bytearray((at * 19 + sample * 11 + lane * 31) & 255 for at in range(21, 60))
            if not outgoing:
                payload[0] ^= 0x80
            require(frame[21:] == payload, 'original complete queue control payload')
            phase = frame[20]
            if sample == 6:
                require(phase == 0 and state == ('start' if outgoing else 'terminal'),
                        'queue terminal exchange follows every completed case')
                if outgoing:
                    began, state = now, 'terminal'
                else:
                    require(0 <= now - began <= 5_000_000_000, 'original terminal acknowledgement deadline')
                    state = 'done'
                continue
            if outgoing:
                expected = {0: 'start', 1: 'arp-held', 2: 'mutation'}
                require(phase in expected and state == expected[phase],
                        'queue preparation, actual held ARP and mutation precede release')
                began = now
                state = ('prepared', 'held', 'release')[phase]
            else:
                expected = {0: 'prepared', 1: 'held', 2: 'output'}
                require(phase in expected and state == expected[phase] and
                        0 <= now - began <= 5_000_000_000,
                        'queue acknowledgement follows its real observation inside original five-second deadline')
                timings.append(now - began)
                state = ('arp', 'mutation', 'start')[phase]
                if phase == 2:
                    sample += 1
        elif arp:
            require(sample < 6, 'no queue neighbor exchange outside its original case')
            remote = bytes((10, 23, lane + 1, 200 + sample))
            operation = int.from_bytes(frame[20:22], 'big')
            if operation == 1:
                expected = (b'\xff' * 6 + guest + b'\x08\x06' + struct.pack('!HHBBH', 1, 0x0800, 6, 4, 1) +
                            guest + local + b'\0' * 6 + remote)
                require(state == 'arp' and sample not in requests, 'one real unresolved neighbor before mutation')
                requests[sample] = position
                state = 'arp-held'
            else:
                target = bytes((10, 23, lane + 1, 3 if sample == 0 else 2))
                expected = (guest + peer + b'\x08\x06' + struct.pack('!HHBBH', 1, 0x0800, 6, 4, 2) +
                            peer + remote + guest + target)
                require(operation == 2 and state == 'release' and sample not in replies,
                        'one neighbor reply after the mutation release, using surviving address')
                replies[sample] = position
                state = 'data'
            require(42 <= len(frame) <= 60 and frame[:42] == expected and not any(frame[42:]),
                    'original complete selected ARP hardware, addresses and padding')
        else:
            require(sample < 6 and state == 'data' and sample not in packets and outgoing,
                    'one accepted raw packet after actual ARP release and before acknowledgement')
            length = 1500 if sample == 1 else 28
            expected = bytearray(struct.pack('!BBHHHBBH4s4s', 0x45, 0x5a, length, 0x1357, 0, 35, 76, 0,
                                            b'\xc0\0\x02\x01', bytes((10, 23, lane + 1, 77))))
            expected[10:12] = checksum(expected).to_bytes(2, 'big')
            expected.extend((at * 37 + sample * 11 + lane * 31) & 255 for at in range(20, length))
            require(len(frame) >= length + 14 and frame[14:14 + length] == expected and
                    not any(frame[14 + length:]),
                    'complete immutable admitted packet, filled length/checksum and literal route-independent fields')
            packets[sample] = position
            state = 'output'
    require(sample == 6 and state == 'done' and len(controls) == 38 and
            len(requests) == len(replies) == len(packets) == 6,
            'all six held neighbors, six literal outputs,38 controls and terminal acknowledgement')
    return dict(passed=True, lane=lane, cases=6, literal_packets=6, arp_requests=6, arp_replies=6,
                control_packets=38, inherited_ordinary_cases=1, maximum_handshake_ns=max(timings),
                frame_indices=packets, request_indices=requests, reply_indices=replies,
                control_indices=controls, full_feature_acceptance=False)


def damaged_controls(rows, lane, text, original, path):
    changes = {}
    for name, sample, offset in (('source', 0, 29), ('literal-destination', 2, 33),
            ('ttl', 3, 22), ('tos', 4, 15), ('protocol', 0, 23), ('identity', 0, 18),
            ('fragment-flags', 1, 20), ('mtu-payload', 1, 1400), ('ordinary-payload', 5, 40)):
        changed = copy.deepcopy(rows)
        at = original['frame_indices'][sample]
        frame = bytearray(changed[at]['frame'])
        frame[offset] ^= 1
        frame[24:26] = b'\0\0'
        frame[24:26] = checksum(frame[14:34]).to_bytes(2, 'big')
        changed[at]['frame'] = bytes(frame)
        changes[name + '-repaired-checksum'] = changed, text
    for name, at in (('missing-output', original['frame_indices'][1]),
                     ('missing-held-arp', original['request_indices'][0]),
                     ('missing-release', original['reply_indices'][2]),
                     ('missing-terminal-ack', original['control_indices'][-1])):
        changed = copy.deepcopy(rows)
        changed.pop(at)
        changes[name] = changed, text
    changed = copy.deepcopy(rows)
    at = original['reply_indices'][0]
    frame = bytearray(changed[at]['frame'])
    frame[41] = 2
    changed[at]['frame'] = bytes(frame)
    changes['retired-arp-target'] = changed, text
    changed = copy.deepcopy(rows)
    at = original['frame_indices'][3]
    changed.insert(original['reply_indices'][3], changed.pop(at))
    changes['output-before-neighbor-release'] = changed, text
    changes['missing-ordinary-result'] = rows, text.replace(
        f'index={lane + 1} test=5 bytes=28 ordinary=1', f'index={lane + 1} test=5 bytes=28 ordinary=0')
    rejected = []
    with zipfile.ZipFile(path, 'x', compression=zipfile.ZIP_DEFLATED) as archive:
        for name, (changed, changed_text) in changes.items():
            archive.writestr(name + '.pcap', encode_capture(changed))
            archive.writestr(name + '.log', changed_text)
    with zipfile.ZipFile(path) as archive, tempfile.TemporaryDirectory() as temporary:
        for name in changes:
            capture = Path(temporary) / (name + '.pcap')
            capture.write_bytes(archive.read(name + '.pcap'))
            try:
                audit(read_capture(capture), lane, archive.read(name + '.log').decode())
            except ValueError as error:
                rejected.append(dict(control=name, reason=str(error)))
            else:
                raise ValueError('accepted damaged raw-header queue evidence: ' + name)
    require(len(rejected) == 16, 'all16 independently reopened queue damaged controls')
    return dict(rejected=len(rejected), archive_sha256=hashlib.sha256(path.read_bytes()).hexdigest(), controls=rejected)


def verify_capture(path, lane, log, *, native=False, damage_archive=None):
    rows = read_capture(path)
    if native:
        bind_clocks(rows, path.with_suffix('.clocks.jsonl'))
    text = log.read_text()
    result = audit(rows, lane, text)
    if damage_archive is not None:
        result['damaged'] = damaged_controls(rows, lane, text, result, damage_archive)
    for name in ('frame_indices', 'request_indices', 'reply_indices', 'control_indices'):
        result.pop(name)
    result.update(capture_sha256=hashlib.sha256(path.read_bytes()).hexdigest(),
                  log_sha256=hashlib.sha256(log.read_bytes()).hexdigest())
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('capture', type=Path)
    parser.add_argument('lane', type=int, choices=(0, 1))
    parser.add_argument('log', type=Path)
    parser.add_argument('--native', action='store_true')
    parser.add_argument('--damage-archive', type=Path)
    args = parser.parse_args()
    print(json.dumps(verify_capture(args.capture, args.lane, args.log,
                                   native=args.native, damage_archive=args.damage_archive)))
