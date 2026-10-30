# SPDX-License-Identifier: GPL-3.0-or-later
"""Independently check original option-bearing Ethernet output and fragment bytes."""
import argparse
import copy
import hashlib
import json
from pathlib import Path
import re
import struct
import tempfile
import zipfile

from ipv4_expiry_capture import read_capture, encode_capture, bind_clocks, checksum, require
from ipv4_fragments import OutputFragmentPeer
from ipv4_options.fragment_options import value as option_value


def options(actual, expected, lane, offset, before, after):
    require(len(actual) == len(expected), 'complete option-bearing fragment IHL')
    recorded = bytearray(expected)
    at = 0
    while at < len(expected):
        kind = expected[at]
        if kind == 0:
            break
        if kind == 1:
            at += 1
            continue
        size = expected[at + 1]
        if offset and kind & 128 == 0:
            recorded[at:at + size] = b'\1' * size
        elif kind == 7:
            recorded[at + 2] = 8
            recorded[at + 3:at + 7] = bytes((10, 23, lane + 1, 2))
        elif kind == 68:
            recorded[at + 2] = 9
            stamp = int.from_bytes(actual[at + 4:at + 8], 'big')
            duration = after - before
            delta = (stamp - before % 86400000 + 86400020) % 86400000
            require(0 <= duration < 5000 and stamp < 86400000 and delta <= duration + 40,
                    'wire timestamp belongs to the actual guest or native send clock interval')
            recorded[at + 4:at + 8] = actual[at + 4:at + 8]
        at += size
    require(actual == recorded, 'complete copied-option, pointer, source and padding bytes')


def input_options_audit(rows, lane, text):
    received = re.findall(r'^IPV4_FRAGMENT_INPUT_OPTIONS index=' + str(lane + 1) +
        r' test=(\d+) utc_before_ms=(\d+) utc_after_ms=(\d+) length=(\d+) bytes=([0-9a-f]+)$', text, re.M)
    require(len(received) == 6 and [int(row[0]) for row in received] == list(range(6, 12)) and
            text.count(f'IPV4_FRAGMENT_PASS index={lane + 1} cases=12 option_cases=6') == 1,
            'six actual option-bearing receives inside the complete twelve-case input corpus')
    guest = bytes((0x52, 0x54, 0, 0x12, 0x34, 0x10 + lane))
    peer = bytes((2, 0x41, 0x58, 0x49, 0x50, lane))
    local, remote = bytes((10, 23, lane + 1, 2)), bytes((10, 23, lane + 1, 1))
    requests = {}
    for position, row in enumerate(rows):
        frame = row['frame']
        if len(frame) >= 66 and frame[:14] == peer + guest + b'\x08\0':
            ip = frame[14:]
            if ip[0] == 0x45 and ip[9] == 1 and ip[24:26] == b'FR' and 6 <= ip[26] <= 12 and ip[27] == 0:
                require(ip[26] not in requests, 'one actual request for each new input case and its terminal control')
                requests[ip[26]] = position
    require(list(requests) == list(range(6, 13)),
            'ordered option-input requests and the actual terminal control')
    frames_by_case = {}
    observations = []
    for sample, before, after, length, encoded in received:
        sample, before, after, length = map(int, (sample, before, after, length))
        data = bytes.fromhex(encoded)
        selected = (35, 35, 36, 36, 21, 35)[sample - 6]
        expected_options = option_value(selected)
        header = 20 + len(expected_options)
        identity = 0x7100 + lane * 32 + sample * 2
        require(len(data) == length == header + 64 and data[0] == 0x40 + header // 4 and data[1] == 0 and
                int.from_bytes(data[2:4], 'big') == length and int.from_bytes(data[4:6], 'big') == identity and
                data[6:10] == bytes((0, 0, 51, 1)) and data[12:20] == remote + local,
                'actual received option packet framing, fragment identity, tuple and complete size')
        options(data[20:header], expected_options, lane, 0, before, after)
        if sample in (6, 8):
            original = data[:20] + expected_options
            require(checksum(original) == 0, 'unfragmented raw input retains the actual original wire checksum')
        else:
            require(checksum(data[:header]) == 0, 'reassembled raw input checksum covers the previously processed option slots')
        body = bytearray((0, 0, 0, 0, 70, 82, sample, lane))
        body.extend((at * 17 + lane * 31 + sample) & 255 for at in range(8, 64))
        body[2:4] = checksum(body).to_bytes(2, 'big')
        require(data[header:] == body, 'every actual delivered option-bearing payload byte')
        pieces = []
        frames_by_case[sample] = []
        for position in range(requests[sample] + 1, requests[sample + 1]):
            frame = rows[position]['frame']
            if len(frame) < 34 or frame[:14] != guest + peer + b'\x08\0':
                continue
            ip = frame[14:]
            if int.from_bytes(ip[4:6], 'big') != identity:
                continue
            part_header = (ip[0] & 15) * 4
            total = int.from_bytes(ip[2:4], 'big')
            flags = int.from_bytes(ip[6:8], 'big')
            offset = (flags & 8191) * 8
            require(20 <= part_header <= 60 and part_header <= total <= len(ip) and
                    ip[0] >> 4 == 4 and ip[1] == 0 and ip[8:10] == bytes((51, 1)) and
                    ip[12:20] == remote + local and checksum(ip[:part_header]) == 0,
                    'actual injected option fragment framing, tuple and original checksum')
            expected = bytearray(expected_options)
            if offset:
                if sample == 11:
                    expected.clear()
                else:
                    at = 0
                    while at < len(expected) and expected[at]:
                        kind = expected[at]
                        size = 1 if kind == 1 else expected[at + 1]
                        if kind & 128 == 0:
                            expected[at:at + size] = b'\1' * size
                        at += size
            require(part_header == 20 + len(expected) and ip[20:part_header] == expected,
                    'actual first and non-first input option copied flags and independently sized headers')
            if sample in (6, 8):
                require(flags == 0 and ip[part_header:total] == body, 'actual unfragmented option input')
            else:
                require(offset in (0, 24) and flags == (8192 if offset == 0 else 3) and
                        ip[part_header:total] == body[offset:24 if offset == 0 else 64],
                        'actual exact fragment offset, MF and payload range')
            pieces.append(offset)
            frames_by_case[sample].append(position)
        expected_order = [0] if sample in (6, 8) else [24, 0] if sample == 10 else [0, 24]
        require(pieces == expected_order, 'complete actual ordered or reverse-ordered option fragment injection')
        observations.append(dict(test=sample, fragments=len(pieces), actual_packet_sha256=hashlib.sha256(data).hexdigest()))
    return dict(passed=True, cases=6, fragmented_cases=4, actual_frames=sum(len(value) for value in frames_by_case.values()),
                observations=observations), frames_by_case


def audit(rows, lane, text):
    require(lane in (0, 1), 'physical interface lane')
    input_audit, input_frames = input_options_audit(rows, lane, text)
    records = re.findall(r'^IPV4_FRAGMENT_OUTPUT_CASE index=' + str(lane + 1) +
        r' test=(\d+) option_bytes=(\d+) utc_before_ms=(\d+) utc_after_ms=(\d+)$', text, re.M)
    require('IPV4_FRAGMENT_FAIL' not in text and len(records) == 45 and
            [int(row[0]) for row in records] == list(range(45)) and
            text.count(f'IPV4_FRAGMENT_OUTPUT_PASS index={lane + 1} cases=45 option_cases=24') == 1,
            'all 45 actual output cases and 24 option cases')
    clocks = {}
    for sample, length, before, after in records:
        sample, length, before, after = map(int, (sample, length, before, after))
        require(length == len(option_value(sample)) and 0 <= after - before < 5000,
                'original option count and real application send interval')
        clocks[sample] = before, after
    guest = bytes((0x52, 0x54, 0, 0x12, 0x34, 0x10 + lane))
    peer = bytes((2, 0x41, 0x58, 0x49, 0x50, lane))
    local, remote = bytes((10, 23, lane + 1, 2)), bytes((10, 23, lane + 1, 1))
    current = 0
    phase = 'idle'
    payload = bytearray()
    identity = None
    complete = False
    final = False
    started = False
    observed = []
    frame_indices = {}
    for position, row in enumerate(rows):
        frame = row['frame']
        if frame[12:14] != b'\x08\0' or len(frame) < 34:
            continue
        ip = frame[14:]
        header = (ip[0] & 15) * 4
        total = int.from_bytes(ip[2:4], 'big')
        if frame[:12] not in (peer + guest, guest + peer):
            continue
        tag_at = header + 4
        control_candidate = header == 20 and ip[9] == 1 and ip[tag_at:tag_at + 2] == b'FO'
        if (not started or final) and not control_candidate:
            continue
        require(ip[0] >> 4 == 4 and 20 <= header <= 60 and header <= total <= len(ip) and
                checksum(ip[:header]) == 0, 'original Ethernet IPv4 framing, total length and checksum')
        ip = ip[:total]
        flags = int.from_bytes(ip[6:8], 'big')
        body = ip[header:]
        is_control = header == 20 and ip[9] == 1 and len(body) == 32 and body[4:6] == b'FO'
        if is_control:
            require(not flags & 0xbfff and checksum(body) == 0 and body[1] == 0 and
                    body[8:] == bytes((at * 17 + lane * 31) & 255 for at in range(8, 32)),
                    'complete original output control bytes')
            sample, step = body[6:8]
            if frame[:12] == peer + guest:
                require(ip[12:20] == local + remote and body[0] == 8 and ip[8] == 64 and flags == 0x4000,
                        'actual guest control tuple, TTL and discovery policy')
                if sample == 45:
                    require(current == 45 and phase == 'idle' and step == 0 and not final,
                            'one terminal acknowledgment after every datagram case')
                    final = True
                    continue
                require(sample == current and sample < 45 and not final, 'ordered original output control identity')
                if step == 0:
                    require(phase == 'idle', 'one opening request per case')
                    started = True
                    payload.clear()
                    identity = None
                    complete = False
                    frame_indices[current] = []
                    phase = 'opening'
                else:
                    require(step == 1 and phase == 'sending' and rejected(current) and not payload,
                            'oversized output rejection has an actual ordered application barrier')
                    phase = 'rejected'
            else:
                require(sample == current and ip[12:20] == remote + local and body[0] == 0 and
                        flags == 0 and ip[8] == 51, 'actual controlled peer acknowledgment')
                if step == 0:
                    require(phase == 'opening', 'peer acknowledgment follows the opening request')
                    phase = 'sending'
                else:
                    require(step == 1 and ((phase == 'sending' and complete) or phase == 'rejected'),
                            'peer acknowledges a complete datagram or the explicit rejection barrier')
                    observed.append(dict(test=current, frames=len(frame_indices[current]), rejected=rejected(current),
                                         option_bytes=len(option_value(current))))
                    current += 1
                    phase = 'idle'
            continue
        if frame[:12] != peer + guest:
            continue
        require(phase == 'sending' and not complete and current < 45 and not rejected(current),
                'actual output belongs to its acknowledged, non-rejected datagram')
        protocol, policy, mtu, length = OutputFragmentPeer.cases[current]
        expected_options = option_value(current)
        original_length = 20 + len(expected_options) + length + (8 if protocol == 17 else 0)
        offset = (flags & 8191) * 8
        more = bool(flags & 8192)
        fragmenting = original_length > mtu
        require(ip[12:20] == local + remote and ip[9] == protocol and ip[1] == 0 and ip[8] == 64 and
                total <= mtu and not flags & 0x8000 and bool(flags & 0x4000) ==
                (policy in (1, 2, 3) and not fragmenting), 'actual output route, protocol, MTU, TTL/TOS and DF policy')
        require(offset == len(payload) and body and (not more or len(body) % 8 == 0),
                'contiguous nonoverlapping fragment offsets and eight-byte alignment')
        options(ip[20:header], expected_options, lane, offset, *clocks[current])
        if identity is None:
            identity = ip[4:6]
        require(ip[4:6] == identity, 'one original identity across the datagram fragments')
        payload.extend(body)
        frame_indices[current].append(position)
        expected_length = length + (8 if protocol == 17 else 0)
        require(len(payload) <= expected_length and (not more or len(payload) < expected_length),
                'fragment boundaries retain the complete original datagram length')
        if more:
            continue
        require(len(payload) == expected_length, 'final fragment closes every payload byte')
        data = bytes(payload)
        if protocol == 17:
            require(data[:6] == struct.pack('!HHH', 45000 + lane, 24000 + lane, expected_length) and
                    data[6:8] != bytes(2) and checksum(local + remote + bytes((0, 17)) +
                        expected_length.to_bytes(2, 'big') + data) == 0,
                    'actual complete UDP tuple, size and pseudo-header checksum')
            data = data[8:]
        expected = bytearray((8, 0, 0, 0, 70, 68, current, lane))
        expected.extend((at * 17 + lane * 31 + current) & 255 for at in range(8, length))
        expected[2:4] = checksum(expected).to_bytes(2, 'big')
        require(data == expected and checksum(data) == 0,
                'every original application byte survives mutation after send returns')
        complete = True
    require(current == 45 and phase == 'idle' and final and len(observed) == 45,
            'complete original output corpus and final captured acknowledgment')
    return dict(passed=True, cases=45, original_cases=21, option_cases=24,
                frames=sum(row['frames'] for row in observed), datagrams=observed,
                input_options=input_audit, frame_indices=frame_indices, input_frame_indices=input_frames,
                full_feature_and_expiry_and_pmtu_acceptance=False)


def rejected(sample):
    protocol, policy, mtu, length = OutputFragmentPeer.cases[sample]
    total = 20 + len(option_value(sample)) + length + (8 if protocol == 17 else 0)
    return total > 65535 or (policy in (2, 3, 4) and total > mtu)


def verify_capture(path, lane, log, *, native=False, damage_archive=None):
    rows = read_capture(path)
    if native:
        bind_clocks(rows, path.with_suffix('.clocks.jsonl'))
    text = log.read_text()
    result = audit(rows, lane, text)
    if damage_archive is not None:
        result['damaged'] = damaged_controls(rows, lane, text, result, damage_archive)
    result.pop('frame_indices')
    result.pop('input_frame_indices')
    result.update(capture_sha256=hashlib.sha256(path.read_bytes()).hexdigest(),
                  log_sha256=hashlib.sha256(log.read_bytes()).hexdigest())
    return result


def damaged_controls(rows, lane, text, original, path):
    changes = {}

    def changed(sample, which, alter, repair=True):
        copied = copy.deepcopy(rows)
        index = original['frame_indices'][sample][which]
        frame = bytearray(copied[index]['frame'])
        alter(frame)
        if repair:
            header = (frame[14] & 15) * 4
            frame[24:26] = bytes(2)
            frame[24:26] = checksum(frame[14:14 + header]).to_bytes(2, 'big')
        copied[index]['frame'] = bytes(frame)
        return copied

    def flip(at):
        return lambda frame: frame.__setitem__(at, frame[at] ^ 1)

    changes['copied-option-repaired'] = changed(21, 1, flip(34))
    changes['recorded-source-repaired'] = changed(21, 0, flip(41))
    changes['record-route-pointer-repaired'] = changed(21, 0, flip(40))
    changes['unknown-copied-value-repaired'] = changed(21, 1, flip(56))
    changes['fragment-offset-repaired'] = changed(21, 1, flip(21))
    changes['fragment-identity-repaired'] = changed(21, 1, flip(18))
    changes['fragment-more-flag-repaired'] = changed(21, -1, lambda frame: frame.__setitem__(20, frame[20] ^ 32))
    changes['fragment-ip-checksum'] = changed(21, 0, flip(24), repair=False)
    changes['fragment-data-byte'] = changed(21, -1, flip(-1))

    def transport_change(frame, *, port=False):
        header = (frame[14] & 15) * 4
        total = int.from_bytes(frame[16:18], 'big')
        start = 14 + header
        if port:
            frame[start] ^= 1
        else:
            frame[14 + total - 1] ^= 1
        if frame[23] == 17:
            frame[start + 6:start + 8] = bytes(2)
            pseudo = frame[26:34] + bytes((0, 17)) + (total - header).to_bytes(2, 'big')
            value = checksum(pseudo + frame[start:14 + total]) or 65535
            frame[start + 6:start + 8] = value.to_bytes(2, 'big')
        else:
            frame[start + 2:start + 4] = bytes(2)
            frame[start + 2:start + 4] = checksum(frame[start:14 + total]).to_bytes(2, 'big')

    changes['UDP-ports-transport-repaired'] = changed(28, 0, lambda frame: transport_change(frame, port=True))
    changes['UDP-payload-transport-repaired'] = changed(28, 0, transport_change)
    changes['raw-payload-transport-repaired'] = changed(27, 0, transport_change)
    copied = copy.deepcopy(rows)
    del copied[original['frame_indices'][21][1]]
    changes['missing-middle-fragment'] = copied
    copied = copy.deepcopy(rows)
    copied.insert(original['frame_indices'][21][1], copy.deepcopy(rows[original['frame_indices'][21][1]]))
    changes['duplicate-middle-fragment'] = copied
    changes['missing-terminal-control'] = [row for row in rows if not (len(row['frame']) >= 66 and
        row['frame'][6:12] == bytes((0x52, 0x54, 0, 0x12, 0x34, 0x10 + lane)) and
        row['frame'][38:42] == bytes((70, 79, 45, 0)))]
    changed_log = text.replace(f'IPV4_FRAGMENT_OUTPUT_PASS index={lane + 1} cases=45 option_cases=24',
                               f'IPV4_FRAGMENT_OUTPUT_PASS index={lane + 1} cases=44 option_cases=24')
    cases = [(name, changed, text) for name, changed in changes.items()]
    cases.append(('incomplete-application-summary', rows, changed_log))

    def received_change(sample, alter, repair_ip=False, repair_transport=False):
        pattern = (r'(^IPV4_FRAGMENT_INPUT_OPTIONS index=' + str(lane + 1) + ' test=' + str(sample) +
                   r' utc_before_ms=\d+ utc_after_ms=\d+ length=\d+ bytes=)([0-9a-f]+)$')
        match = re.search(pattern, text, re.M)
        require(match is not None, 'actual delivered packet for received-option control')
        data = bytearray.fromhex(match[2])
        alter(data)
        header = (data[0] & 15) * 4
        if repair_transport:
            data[header + 2:header + 4] = bytes(2)
            data[header + 2:header + 4] = checksum(data[header:]).to_bytes(2, 'big')
        if repair_ip:
            data[10:12] = bytes(2)
            data[10:12] = checksum(data[:header]).to_bytes(2, 'big')
        return text[:match.start(2)] + data.hex() + text[match.end(2):]

    cases.append(('raw-original-checksum-recomputed', rows, received_change(6, lambda data: None, repair_ip=True)))
    cases.append(('reassembled-received-checksum', rows, received_change(7, flip(10))))
    cases.append(('received-route-pointer-repaired', rows, received_change(7, flip(22), repair_ip=True)))
    cases.append(('received-timestamp-repaired', rows, received_change(9,
        lambda data: data.__setitem__(slice(24, 28), (86400000).to_bytes(4, 'big')), repair_ip=True)))
    cases.append(('received-payload-transport-repaired', rows, received_change(10, flip(-1), repair_transport=True)))
    pattern = r'^IPV4_FRAGMENT_INPUT_OPTIONS index=' + str(lane + 1) + r' test=6 [^\n]*\n'
    cases.append(('missing-delivered-option-case', rows, re.sub(pattern, '', text, flags=re.M)))
    copied = copy.deepcopy(rows)
    index = original['input_frame_indices'][10][0]
    frame = bytearray(copied[index]['frame'])
    frame[34] ^= 1
    frame[24:26] = bytes(2)
    frame[24:26] = checksum(frame[14:74]).to_bytes(2, 'big')
    copied[index]['frame'] = bytes(frame)
    cases.append(('injected-copied-option-repaired', copied, text))
    rejected_rows = []
    with zipfile.ZipFile(path, 'x', compression=zipfile.ZIP_DEFLATED) as archive:
        for name, changed, log in cases:
            require(changed != rows or log != text, 'control changes actual original evidence')
            encoded = encode_capture(changed)
            archive.writestr(name + '.pcap', encoded)
            archive.writestr(name + '.log', log)
        archive.writestr('cases.json', json.dumps([name for name, _, _ in cases]))
    with zipfile.ZipFile(path) as archive:
        require(archive.testzip() is None, 'all reopened damaged-evidence archive CRCs')
        for name, _, _ in cases:
            encoded = archive.read(name + '.pcap')
            with tempfile.TemporaryDirectory(prefix='axiom64-option-fragment-control-', dir=path.parent) as directory:
                temporary = Path(directory) / 'original-control.pcap'
                temporary.write_bytes(encoded)
                try:
                    audit(read_capture(temporary), lane, archive.read(name + '.log').decode())
                except ValueError as error:
                    rejected_rows.append(dict(name=name, reason=str(error), sha256=hashlib.sha256(encoded).hexdigest()))
                else:
                    raise ValueError('accepted damaged option-bearing Ethernet evidence: ' + name)
    require(len(rejected_rows) == 23, 'all twenty-three damaged actual packet and log controls reject')
    return dict(rejected=len(rejected_rows), archive_sha256=hashlib.sha256(path.read_bytes()).hexdigest(),
                controls=rejected_rows)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('capture', type=Path)
    parser.add_argument('--lane', type=int, choices=(0, 1), required=True)
    parser.add_argument('--log', type=Path, required=True)
    parser.add_argument('--native', action='store_true')
    parser.add_argument('--damage-archive', type=Path)
    args = parser.parse_args()
    print(json.dumps(verify_capture(args.capture, args.lane, args.log, native=args.native,
                                    damage_archive=args.damage_archive)))


if __name__ == '__main__':
    main()
