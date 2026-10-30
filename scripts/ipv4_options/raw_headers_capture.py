# SPDX-License-Identifier: GPL-3.0-or-later
"""Independently reopen raw-header Ethernet packets and their complete handshake."""
import argparse
import copy
import hashlib
import json
from pathlib import Path
import re
import tempfile
import zipfile

from ipv4_expiry_capture import read_capture, encode_capture, bind_clocks, checksum, require, elapsed_ns


LENGTHS = (28, 28, 28, 28, 28, 28, 68, 36, 36, 36, 28, 28, 28,
           28, 28, 28, 1500, 1501, 19, 28, 68, 69, 28, 28, 65535, 65536)
ERRORS = {10: 22, 11: 22, 12: 22, 13: 22, 17: 90, 18: 22, 19: 22, 21: 90, 24: 90, 25: 90}


def literal(packet, sample, lane):
    length = LENGTHS[sample]
    header = 60 if sample == 6 else 28 if 7 <= sample <= 9 else 20
    require(len(packet) == length and (packet[0] & 15) * 4 == header,
            'complete literal raw header, IHL and payload length')
    expected = bytearray(length)
    expected[:4] = bytes(((0x60 if sample == 5 else 0x40) | header // 4, 90)) + length.to_bytes(2, 'big')
    expected[4:6] = packet[4:6] if sample == 1 else (0 if sample == 2 else 0x1357).to_bytes(2, 'big')
    expected[6:10] = bytes((64 if sample == 2 else 0, 0, 35, 75))
    expected[12:16] = bytes((192, 0, 2, 1)) if sample == 3 else bytes((10, 23, lane + 1, 2))
    expected[16:20] = bytes((10, 23, lane + 1, 77 if sample == 4 else 1))
    expected[header:] = bytes((at * 37 + lane * 31 + sample * 11) & 255 for at in range(header, length))
    if sample == 6:
        expected[20:60] = bytes([1]) * 40
    elif sample == 7:
        expected[20:28] = bytes((7, 7, 4, 99, 98, 97, 96, 0))
    elif sample == 8:
        expected[20:28] = bytes((131, 7, 4, 10, 23, 9, 77, 0))
    elif sample == 9:
        expected[20:28] = bytes((134, 8, 0, 0, 0, 0, 0, 0))
    expected[10:12] = checksum(bytes(expected[:header])).to_bytes(2, 'big')
    require(packet == expected, 'literal options and fields, selected zero source, filled length/checksum and owned payload')


def audit(rows, lane, text):
    require(text.count(f'IPV4_RAW_HEADER_OUTPUT_PASS index={lane + 1} cases=26 inherited_cases=1') == 1,
            'complete raw-header Ethernet application result')
    observations = re.findall(r'^IPV4_RAW_HEADER_OUTPUT_CASE index=' + str(lane + 1) +
        r' test=(\d+) result=(-?\d+) error=(\d+) ordinary=(\d+)$', text, re.M)
    require(len(observations) == 26, 'all original raw-header application cases')
    for sample, row in enumerate(observations):
        require(tuple(map(int, row)) == (sample, -1 if sample in ERRORS else LENGTHS[sample],
                                         ERRORS.get(sample, 0), int(sample == 23)),
                'ordered actual send results, errors and inherited ordinary case')
    guest = bytes((0x52, 0x54, 0, 0x12, 0x34, 0x10 + lane))
    peer = bytes((2, 0x41, 0x58, 0x49, 0x50, lane))
    local, remote = bytes((10, 23, lane + 1, 2)), bytes((10, 23, lane + 1, 1))
    current, state = 0, 'idle'
    began = previous = 0
    controls, packets, timings = [], {}, []
    for position, row in enumerate(rows):
        frame = row['frame']
        if len(frame) < 34 or frame[12:14] != b'\x08\0':
            continue
        ip = frame[14:]
        header = (ip[0] & 15) * 4
        is_control = header == 20 and ip[9] == 1 and ip[24:26] == b'RH'
        is_literal = ip[9] == 75 and frame[6:12] == guest
        if not is_control and not is_literal:
            continue
        now = elapsed_ns(row)
        require(now >= previous, 'monotonic original raw-header packet order')
        previous = now
        total = int.from_bytes(ip[2:4], 'big')
        require(20 <= header <= total <= len(ip) and not any(ip[total:]),
                'complete raw-header Ethernet IP length and padding')
        ip = ip[:total]
        require(checksum(ip[:header]) == 0, 'actual raw-header wire checksum')
        if is_literal:
            require(frame[:12] == peer + guest and state == 'data' and current < 26 and
                    current not in ERRORS and current != 14 and current not in packets,
                    'one accepted literal packet inside its acknowledged case and selected Ethernet route')
            literal(ip, current, lane)
            packets[current] = position
            state = 'ack-done'
            continue
        controls.append(position)
        outgoing = frame[:12] == peer + guest
        require(outgoing or frame[:12] == guest + peer, 'raw-header control Ethernet ownership')
        require(ip[0:4] == b'\x45\0\0\x34' and ip[8] == (64 if outgoing else 51) and ip[9] == 1 and
                not int.from_bytes(ip[6:8], 'big') & 0xbfff and
                ip[12:20] == (local + remote if outgoing else remote + local) and
                len(ip[20:]) == 32 and checksum(ip[20:]) == 0 and
                ip[20:22] == (b'\x08\0' if outgoing else b'\0\0') and
                ip[28:] == bytes((at * 17 + lane * 31) & 255 for at in range(8, 32)),
                'complete original raw-header control packet and transport checksum')
        sample, phase = ip[26:28]
        require(sample == current and state != 'done', 'ordered raw-header case and terminal acknowledgement')
        if current == 26:
            require(phase == 0 and state == ('idle' if outgoing else 'terminal'),
                    'raw-header terminal exchange follows every completed case')
            state = 'terminal' if outgoing else 'done'
            continue
        if outgoing and phase == 0:
            require(state == 'idle', 'one original raw-header preparation request')
            began = now
            state = 'ack-start'
        elif not outgoing and phase == 0:
            require(state == 'ack-start' and 0 <= now - began <= 5_000_000_000,
                    'original five-second raw-header preparation acknowledgement')
            state = 'data'
        elif outgoing and phase == 1:
            require(state == 'data' and (current in ERRORS or current == 14),
                    'no-output result has no literal packet on the wire')
            state = 'ack-done'
        else:
            require(not outgoing and phase == 1 and state == 'ack-done' and
                    0 <= now - began <= 5_000_000_000,
                    'complete original raw-header output acknowledgement inside its deadline')
            timings.append(now - began)
            state = 'idle'
            current += 1
    require(current == 26 and state == 'done' and len(controls) == 91 and len(packets) == 15,
            'all26 raw-header cases,15 literal packets,91 control packets and terminal reply')
    return dict(passed=True, lane=lane, cases=current, literal_packets=len(packets),
                control_packets=len(controls), inherited_ordinary_cases=1,
                no_output_cases=11, maximum_handshake_ns=max(timings),
                frame_indices=packets, control_indices=controls, full_feature_acceptance=False)


def damaged_controls(rows, lane, text, original, path):
    changes = {}
    def altered(sample, offset, *, repair=True):
        changed = copy.deepcopy(rows)
        at = original['frame_indices'][sample]
        frame = bytearray(changed[at]['frame'])
        frame[offset] ^= 1
        if repair:
            header = (frame[14] & 15) * 4
            frame[24:26] = b'\0\0'
            frame[24:26] = checksum(bytes(frame[14:14 + header])).to_bytes(2, 'big')
        changed[at]['frame'] = bytes(frame)
        return changed
    for name, sample, offset in (('source', 3, 29), ('destination', 4, 33), ('ttl', 0, 22),
            ('tos', 0, 15), ('protocol', 0, 23), ('identity', 0, 18), ('df', 2, 20),
            ('nop', 6, 34), ('record-route-pointer', 7, 36), ('literal-source-route', 8, 40),
            ('literal-cipso', 9, 36), ('payload', 0, 41), ('inherited-payload', 23, 41)):
        changes[name + '-repaired-checksum'] = altered(sample, offset), text
    changes['wire-checksum'] = altered(0, 24, repair=False), text
    missing = copy.deepcopy(rows)
    missing.pop(original['frame_indices'][0])
    changes['missing-output-packet'] = missing, text
    changes['incomplete-inherited-result'] = rows, text.replace(
        f'index={lane + 1} test=23 result=28 error=0 ordinary=1',
        f'index={lane + 1} test=23 result=28 error=0 ordinary=0')
    rejected = []
    with zipfile.ZipFile(path, 'x', compression=zipfile.ZIP_DEFLATED) as archive:
        for name, (changed, changed_text) in changes.items():
            archive.writestr(name + '.pcap', encode_capture(changed))
            archive.writestr(name + '.log', changed_text)
    with zipfile.ZipFile(path) as archive, tempfile.TemporaryDirectory() as temporary:
        for name in changes:
            capture = Path(temporary) / (name + '.pcap')
            capture.write_bytes(archive.read(name + '.pcap'))
            reopened = archive.read(name + '.log').decode()
            try:
                audit(read_capture(capture), lane, reopened)
            except ValueError as error:
                rejected.append(dict(control=name, reason=str(error)))
            else:
                raise ValueError('accepted damaged original raw-header Ethernet evidence: ' + name)
    require(len(rejected) == 16, 'all16 independently reopened raw-header Ethernet damaged controls')
    return dict(rejected=len(rejected), archive_sha256=hashlib.sha256(path.read_bytes()).hexdigest(), controls=rejected)


def verify_capture(path, lane, log, *, native=False, damage_archive=None):
    rows = read_capture(path)
    if native:
        bind_clocks(rows, path.with_suffix('.clocks.jsonl'))
    text = log.read_text()
    result = audit(rows, lane, text)
    if damage_archive is not None:
        result['damaged'] = damaged_controls(rows, lane, text, result, damage_archive)
    result.pop('frame_indices')
    result.pop('control_indices')
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
