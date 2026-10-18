# SPDX-License-Identifier: GPL-3.0-or-later
"""Independently audit original Ethernet captures of fragment expiry and reuse."""
import argparse
import copy
import hashlib
import json
from pathlib import Path
import re
import struct
import zipfile


def require(condition, message):
    if not condition:
        raise ValueError(message)


def checksum(data):
    value = 0
    for offset in range(0, len(data), 2):
        value += data[offset] << 8
        if offset + 1 < len(data):
            value += data[offset + 1]
    while value > 65535:
        value = (value & 65535) + (value >> 16)
    return value ^ 65535


def read_capture(path):
    data = path.read_bytes()
    formats = {b'\xd4\xc3\xb2\xa1': ('<', 1000), b'\xa1\xb2\xc3\xd4': ('>', 1000),
               b'\x4d\x3c\xb2\xa1': ('<', 1), b'\xa1\xb2\x3c\x4d': ('>', 1)}
    require(len(data) >= 24 and data[:4] in formats, 'unsupported or missing PCAP header')
    order, scale = formats[data[:4]]
    require(struct.unpack_from(order + 'HH', data, 4) == (2, 4) and
            struct.unpack_from(order + 'I', data, 20)[0] == 1, 'not Ethernet PCAP v2.4')
    rows, at = [], 24
    while at < len(data):
        require(at + 16 <= len(data), 'truncated capture record')
        seconds, fraction, size, original = struct.unpack_from(order + 'IIII', data, at)
        at += 16
        require(size == original and 14 <= size <= 65553 and at + size <= len(data),
                'truncated or oversized captured Ethernet frame')
        rows.append(dict(ns=seconds * 1000000000 + fraction * scale, frame=data[at:at + size]))
        at += size
    return rows


def encode_capture(rows):
    data = bytearray(bytes.fromhex('d4c3b2a1') + struct.pack('<HHIIII', 2, 4, 0, 0, 65553, 1))
    for row in rows:
        seconds, nanos = divmod(row['ns'], 1000000000)
        frame = row['frame']
        data.extend(struct.pack('<IIII', seconds, nanos // 1000, len(frame), len(frame)))
        data.extend(frame)
    return bytes(data)


def bind_clocks(rows, path):
    clocks = [json.loads(line) for line in path.read_text().splitlines()]
    require(len(clocks) == len(rows), 'independent monotonic receipt count differs')
    previous = 0
    for index, (row, clock) in enumerate(zip(rows, clocks)):
        before, after = clock['receipt_monotonic_ns'], clock['receipt_monotonic_after_ns']
        require(clock['frame'] == index and hashlib.sha256(row['frame']).hexdigest() == clock['sha256'] and
                clock['kernel_realtime_ns'] // 1000 * 1000 == row['ns'] and
                previous <= before <= after, 'independent receipt frame, timestamp or hash differs')
        row['elapsed_ns'] = before
        previous = after


def elapsed_ns(row):
    return row.get('elapsed_ns', row['ns'])


def audit(rows, lane, log, native=False):
    guest = bytes([0x52, 0x54, 0, 0x12, 0x34, 0x10 + lane])
    peer = bytes([2, 0x41, 0x58, 0x49, 0x50, lane])
    local, remote = bytes([10, 23, lane + 1, 2]), bytes([10, 23, lane + 1, 1])
    identity = 0x7a10 + lane * 16
    controls, acknowledgements, fragments, errors = [], [], [], []
    for index, row in enumerate(rows):
        frame = row['frame']
        if len(frame) < 34 or frame[12:14] != b'\x08\0':
            continue
        packet = frame[14:]
        total = int.from_bytes(packet[2:4], 'big')
        fragment_identity = (identity <= int.from_bytes(packet[4:6], 'big') < identity + 4 and
                             packet[12:20] == remote + local)
        selected = (fragment_identity or
                    packet[24:26] == b'FE' or
                    (len(packet) >= 28 and packet[9] == 1 and packet[20] in (3, 4, 5, 11, 12)))
        if not selected:
            continue
        require(28 <= total <= len(packet) and packet[0] == 0x45 and not checksum(packet[:20]),
                'selected IPv4 header length/checksum differs')
        packet = packet[:total]
        item = dict(index=index, ns=elapsed_ns(row), frame=frame, packet=packet)
        if packet[24:26] == b'FE':
            incoming = packet[12:20] == remote + local
            require(packet[9] == 1 and len(packet) == 52 and packet[1] == 0 and
                    packet[8] == (51 if incoming else 64) and
                    packet[12:20] == (remote + local if incoming else local + remote) and
                    frame[:12] == (guest + peer if incoming else peer + guest) and
                    packet[6:8] == (b'\0\0' if incoming else b'\x40\0') and
                    packet[20:22] == (b'\0\0' if incoming else b'\x08\0') and
                    packet[26] == lane and not checksum(packet[20:]) and
                    packet[28:] == bytes((i * 17 + lane * 31) & 255 for i in range(8, 32)),
                    'expiry control tuple, body, checksum or policy differs')
            item['phase'] = packet[27]
            (acknowledgements if incoming else controls).append(item)
        elif fragment_identity:
            require(packet[12:20] == remote + local and frame[6:12] == peer and
                    packet[1] == 0 and packet[8:10] == b'\x33\x01', 'fragment ownership differs')
            fragments.append(item)
        elif packet[12:20] == local + remote:
            errors.append(item)
    require([x['phase'] for x in controls] == [0, 2, 3, 4] and
            [x['phase'] for x in acknowledgements] == [0, 1, 2], 'missing or repeated ordered barrier')
    groups = [[x for x in fragments if int.from_bytes(x['packet'][4:6], 'big') == identity + case]
              for case in range(4)]
    require([len(group) for group in groups] == [4, 1, 1, 1], 'missing, duplicate or extra fragment')
    initial, duplicate, tail, fresh = groups[0]
    first = initial['packet']
    require(len(first) == 44 and first[6:8] == b'\x20\0' and
            first == duplicate['packet'] == fresh['packet'] and
            all(x['frame'][:6] == guest for x in groups[0]), 'first-fragment duplicate/reuse differs')
    body = bytearray([0, 0, 0, 0, ord('F'), ord('R'), 0, lane])
    body.extend((i * 17 + lane * 31) & 255 for i in range(8, 64))
    struct.pack_into('!H', body, 2, checksum(bytes(body)))
    require(first[20:] == body[:24] and len(tail['packet']) == 60 and
            tail['packet'][6:8] == b'\0\x03' and tail['packet'][20:] == body[24:], 'fragment bytes differ')
    no_first, error_input, broadcast = [group[0] for group in groups[1:]]
    error_body = bytearray(body[:24])
    error_body[0], error_body[2:4] = 3, b'\0\0'
    struct.pack_into('!H', error_body, 2, checksum(bytes(error_body)))
    require(no_first['packet'][6:8] == b'\0\x03' and no_first['packet'][20:] == body[24:] and
            no_first['frame'][:6] == guest and error_input['packet'][6:8] == b'\x20\0' and
            error_input['packet'][20:] == error_body and error_input['frame'][:6] == guest and
            broadcast['packet'][6:8] == b'\x20\0' and broadcast['packet'][20:] == body[:24] and
            broadcast['frame'][:6] == b'\xff' * 6, 'suppression context bytes or Ethernet mode differ')
    contexts = [initial, no_first, error_input, broadcast]
    require(all(b['ns'] - a['ns'] >= (7980000000 if native else 1980000000)
                for a, b in zip(contexts, contexts[1:])),
            'simultaneous suppression deadlines can hide a missing filter')
    relevant_errors = [x for x in errors if controls[0]['index'] < x['index'] < controls[-1]['index']]
    require(len(relevant_errors) == 1, 'missing eligible ICMP error or forbidden suppression response')
    quote = relevant_errors[0]
    packet = quote['packet']
    require(quote['frame'][:12] == peer + guest and packet[1] == (0xc0 if native else 0) and
            packet[8:10] == b'\x40\x01' and packet[6:8] == (b'\0\0' if native else b'\x40\0') and
            packet[20:22] == b'\x0b\x01' and packet[24:28] == b'\0' * 4 and
            not checksum(packet[20:]) and 28 <= len(packet[28:]) <= len(first) and
            packet[28:] == first[:len(packet[28:])], 'ICMP quote/checksum or host policy differs')
    require(59980000000 <= quote['ns'] - initial['ns'] <= (66000000000 if native else 61000000000),
            'expiry does not match the original 60-second deadline')
    require(29980000000 <= duplicate['ns'] - initial['ns'] <= 35000000000,
            'duplicate was not sent halfway through the original deadline')
    require(acknowledgements[1]['ns'] - broadcast['ns'] >= (68980000000 if native else 62980000000),
            'quiet observation ends before the final suppression deadline')
    sequence = [controls[0], initial, acknowledgements[0], duplicate, quote,
                acknowledgements[1], controls[1], tail, acknowledgements[2], controls[2], fresh, controls[3]]
    require(all(a['index'] < b['index'] and a['ns'] <= b['ns'] for a, b in zip(sequence, sequence[1:])),
            'expiry/reuse packets crossed their ordered barrier')
    pattern = rf'^IPV4_FRAGMENT_EXPIRY_PASS index={lane + 1} elapsed=([0-9]+\.[0-9]+)\r?$'
    durations = re.findall(pattern, log, re.MULTILINE)
    require(len(durations) == 1 and 60 <= float(durations[0]) <= 100,
            'guest/client elapsed payload verification missing or repeated')
    return dict(lane=lane, capture_records=len(rows), expiry_seconds=(quote['ns']-initial['ns'])/1e9,
                duplicate_seconds=(duplicate['ns']-initial['ns'])/1e9,
                client_elapsed_seconds=float(durations[0]), staggered_contexts=4,
                negative_contexts=3, exact_quote_bytes=len(packet)-28,
                retained_identity_reused=True,
                elapsed_clock='independent monotonic receipts' if native else 'original QEMU PCAP clock',
                original_packet_times_not_rescaled=True, passed=True)


def damages(rows, lane, *, native=False):
    identity = 0x7a10 + lane * 16
    firsts = [i for i, r in enumerate(rows) if len(r['frame']) >= 58 and
              r['frame'][12:14] == b'\x08\0' and int.from_bytes(r['frame'][18:20], 'big') == identity and
              r['frame'][20:22] == b'\x20\0']
    quotes = [i for i, r in enumerate(rows) if len(r['frame']) >= 70 and
              r['frame'][34:36] == b'\x0b\x01' and int.from_bytes(r['frame'][46:48], 'big') == identity]
    require(len(firsts) == 3 and len(quotes) == 1, 'damage seed is not a complete capture')
    first, duplicate, fresh = firsts
    quote = quotes[0]

    def shift_clock(row, timestamp):
        if 'elapsed_ns' in row:
            row['elapsed_ns'] += timestamp - row['ns']
        row['ns'] = timestamp

    for name in ['early-expiry', 'late-expiry', 'late-duplicate', 'missing-quote', 'wrong-quote', 'extra-error',
                 'unicast-broadcast-case', 'simultaneous-suppression', 'missing-reuse', 'bad-outer-checksum']:
        changed = copy.deepcopy(rows)
        if name == 'early-expiry':
            shift_clock(changed[quote], changed[first]['ns'] + 59000000000)
        elif name == 'late-expiry':
            shift_clock(changed[quote], changed[first]['ns'] + (67 if native else 62) * 1000000000)
        elif name == 'late-duplicate':
            shift_clock(changed[duplicate], changed[first]['ns'] + 40000000000)
        elif name == 'missing-quote':
            del changed[quote]
        elif name in ('wrong-quote', 'bad-outer-checksum'):
            frame = bytearray(changed[quote]['frame'])
            if name == 'wrong-quote':
                frame[46] ^= 1
                frame[52:54] = b'\0\0'
                struct.pack_into('!H', frame, 52, checksum(bytes(frame[42:62])))
                frame[36:38] = b'\0\0'
                total = int.from_bytes(frame[16:18], 'big')
                struct.pack_into('!H', frame, 36, checksum(bytes(frame[34:14+total])))
            else:
                frame[24] ^= 1
            changed[quote]['frame'] = bytes(frame)
        elif name == 'extra-error':
            changed.insert(quote + 1, copy.deepcopy(changed[quote]))
        elif name in ('unicast-broadcast-case', 'simultaneous-suppression'):
            candidates = [i for i, r in enumerate(changed) if len(r['frame']) >= 34 and
                          r['frame'][12:14] == b'\x08\0' and
                          identity < int.from_bytes(r['frame'][18:20], 'big') < identity + 4]
            if name == 'unicast-broadcast-case':
                i = candidates[-1]
                changed[i]['frame'] = changed[first]['frame'][:6] + changed[i]['frame'][6:]
            else:
                for i in candidates:
                    shift_clock(changed[i], changed[first]['ns'])
        else:
            del changed[fresh]
        yield name, changed


def verify_capture(capture, lane, log, native=False, damage_archive=None):
    rows, text = read_capture(capture), log.read_text(errors='replace')
    if native:
        bind_clocks(rows, capture.with_suffix('.clocks.jsonl'))
    result = audit(rows, lane, text, native)
    if damage_archive:
        failures = []
        with zipfile.ZipFile(damage_archive, 'x', compression=zipfile.ZIP_DEFLATED, compresslevel=1) as archive:
            for name, changed in damages(rows, lane, native=native):
                archive.writestr(name + '.pcap', encode_capture(changed))
                if native:
                    archive.writestr(name + '.observations.json', json.dumps(dict(
                        synthetic_damage=True, original_receipts_unchanged=True,
                        rows=[dict(frame=i, ns=row['ns'], elapsed_ns=row.get('elapsed_ns'),
                                   sha256=hashlib.sha256(row['frame']).hexdigest())
                              for i, row in enumerate(changed)])) + '\n')
                try:
                    audit(changed, lane, text, native)
                except ValueError as error:
                    failures.append(dict(name=name, rejected=True, reason=str(error)))
                else:
                    raise ValueError('damaged capture was accepted: ' + name)
            archive.writestr('rejections.json', json.dumps(failures, indent=2) + '\n')
        result['damage_rejections'] = len(failures)
    return result


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('capture', type=Path)
    parser.add_argument('--lane', type=int, choices=[0, 1], required=True)
    parser.add_argument('--log', type=Path, required=True)
    parser.add_argument('--native', action='store_true')
    parser.add_argument('--damage-archive', type=Path)
    args = parser.parse_args()
    result = verify_capture(args.capture, args.lane, args.log, args.native, args.damage_archive)
    print(json.dumps(result))


if __name__ == '__main__':
    main()
