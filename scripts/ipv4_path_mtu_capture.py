# SPDX-License-Identifier: GPL-3.0-or-later
"""Audit original PMTU captures independently of the live peer implementation."""
import argparse
import copy
import hashlib
import json
from pathlib import Path
import re
import struct
import zipfile


def require(value, label):
    if not value:
        raise ValueError(label)


def checksum(data):
    total = sum((data[n] << 8) + (data[n + 1] if n + 1 < len(data) else 0)
                for n in range(0, len(data), 2))
    while total >> 16:
        total = (total & 65535) + (total >> 16)
    return (~total) & 65535


def read_capture(path):
    data = path.read_bytes()
    formats = {b'\xd4\xc3\xb2\xa1': ('<', 1000), b'\xa1\xb2\xc3\xd4': ('>', 1000),
               b'\x4d\x3c\xb2\xa1': ('<', 1), b'\xa1\xb2\x3c\x4d': ('>', 1)}
    require(len(data) >= 24 and data[:4] in formats, 'classic PCAP header')
    order, scale = formats[data[:4]]
    require(struct.unpack_from(order + 'I', data, 20)[0] == 1, 'Ethernet capture')
    at, rows = 24, []
    while at < len(data):
        require(at + 16 <= len(data), 'complete record header')
        seconds, fraction, captured, original = struct.unpack_from(order + 'IIII', data, at)
        at += 16
        require(captured == original and at + captured <= len(data), 'complete original frame')
        rows.append(dict(ns=seconds * 1000000000 + fraction * scale, frame=data[at:at + captured]))
        at += captured
    return rows


def encode(rows):
    data = bytearray(struct.pack('<IHHIIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1))
    for row in rows:
        frame, stamp = row['frame'], row['ns']
        data.extend(struct.pack('<IIII', stamp // 1000000000, stamp // 1000 % 1000000,
                                len(frame), len(frame)))
        data.extend(frame)
    return bytes(data)


def case_policy(case):
    return case % 6 if case < 12 else 1 if case < 16 else case - 12


def hint(case):
    return 900 if case < 12 or case >= 16 else (68, 551, 552, 0)[case - 12]


def learned(case):
    return 1500 if case_policy(case) >= 4 and case < 16 else max(552, hint(case))


def application(lane, case, length):
    data = bytearray((n * 29 + lane * 53 + case * 97) % 256 for n in range(length))
    if case < 6 or case >= 16:
        data[:8] = bytes([8, 0, 0, 0, 80, 68, case, lane])
        struct.pack_into('!H', data, 2, checksum(data))
    return bytes(data)


def inspect(rows, lane, log, query_model='release'):
    require(query_model in ('release', 'read-only'), 'known path query contract')
    releases = int(query_model == 'release')
    require(len(re.findall(r'^IPV4_PATH_MTU_QUERY_MODEL index=' + str(lane + 1) +
                          ' release=' + str(releases) + r'\r?$', log, re.M)) == 1,
            'client query contract matches independently selected kernel model')
    local, remote = bytes([10, 23, lane + 1, 2]), bytes([10, 23, lane + 1, 1])
    guest, host = bytes.fromhex('5254001234') + bytes([0x10 + lane]), bytes.fromhex('0241584950') + bytes([lane])
    requests, replies = {}, {}
    data, errors = {n: [] for n in range(18)}, {n: [] for n in range(18)}
    for index, row in enumerate(rows):
        frame = row['frame']
        if len(frame) < 34 or frame[12:14] != b'\x08\0':
            continue
        packet = frame[14:]
        source, destination = packet[12:16], packet[16:20]
        source_case = source[:3] == remote[:3] and 180 <= source[3] < 198
        target_case = destination[:3] == remote[:3] and 180 <= destination[3] < 198
        control = packet[24:26] == b'PM' and (source, destination) in [(local, remote), (remote, local)]
        if not (source_case or target_case or control):
            continue
        total = int.from_bytes(packet[2:4], 'big')
        require(packet[:2] == b'\x45\0' and 20 <= total <= len(packet) and
                not checksum(packet[:20]), 'valid original IP header and checksum')
        packet = packet[:total]
        outgoing = source == local
        require(frame[:12] == (host + guest if outgoing else guest + host), 'Ethernet direction')
        require(packet[8] == (64 if outgoing else 51), 'IP TTL')
        item = dict(index=index, packet=packet)
        if control:
            body = packet[20:]
            require(packet[9] == 1 and len(body) == 32 and not checksum(body) and
                    body[0:2] == (b'\x08\0' if outgoing else b'\0\0') and
                    packet[6:8] == (b'\x40\0' if outgoing else b'\0\0') and
                    body[9] == lane and body[10:] ==
                    bytes((n * 17 + lane * 31) % 256 for n in range(10, 32)), 'exact control bytes')
            key = tuple(body[6:9])
            table = requests if outgoing else replies
            require(key not in table, 'one original packet per control key')
            table[key] = item
        elif target_case:
            require(outgoing, 'data source belongs to this NIC')
            data[destination[3] - 180].append(item)
        else:
            require(destination == local and packet[9] == 1 and packet[6:8] == b'\0\0' and
                    len(packet) == 56 and packet[20:22] == b'\x03\x04', 'incoming fragmentation-needed shape')
            errors[source[3] - 180].append(item)
    order = []
    for case in range(18):
        policy = case_policy(case)
        order += [(case, 0, policy), (case, 1, policy), (case, 6, policy)]
        order += [(case, phase, policy) for policy in range(6) for phase in [2, 3]]
        order += [(case, 4, case_policy(case))]
    order += [(18, 5, 0)]
    require(set(requests) == set(replies) == set(order), 'complete exact control union')
    positions = [table[key]['index'] for key in order for table in [requests, replies]]
    require(all(a < b for a, b in zip(positions, positions[1:])), 'ordered request/acknowledgement ownership')
    datagrams = fragments = 0
    for case in range(18):
        raw = case < 6 or case >= 16
        policy = case_policy(case)
        windows = [(replies[case, 0, policy]['index'], replies[case, 1, policy]['index'], policy, True)]
        windows += [(replies[case, 2, p]['index'], replies[case, 3, p]['index'], p, False) for p in range(6)]
        assigned = set()
        first = None
        for begin, end, policy, initial in windows:
            packets = [r for r in data[case] if begin < r['index'] < end]
            assigned.update(r['index'] for r in packets)
            forbidden = not initial and policy == 2 and learned(case) < 1120
            require(bool(packets) == (not forbidden), 'DO silence or required real datagram')
            if forbidden:
                continue
            size = 300 if not initial and policy == 1 and learned(case) == 552 else 1100
            total = size + (20 if raw else 28)
            limit = 1500 if initial or policy >= 3 else learned(case)
            split = total > limit
            locked = not initial and learned(case) == 552 and hint(case) < 552
            df = policy in (2, 3) or (policy == 1 and not locked)
            payload = bytearray()
            identity = packets[0]['packet'][4:6]
            for part in packets:
                packet = part['packet']
                flags = int.from_bytes(packet[6:8], 'big')
                require(packet[9] == (1 if raw else 17) and packet[4:6] == identity and
                        len(packet) <= limit and not flags & 0x8000 and
                        (flags & 8191) * 8 == len(payload), 'fragment geometry and ownership')
                payload.extend(packet[20:])
                require(bool(flags & 0x4000) == (df and not split) and
                        bool(flags & 0x2000) == (len(payload) < total - 20) and
                        (not flags & 0x2000 or (len(packet) > 20 and (len(packet) - 20) % 8 == 0)),
                        'DF, MF and nonfinal alignment')
            require(len(payload) == total - 20 and (len(packets) > 1) == split, 'exact complete datagram coverage')
            if raw:
                require(payload == application(lane, case, size) and not checksum(payload), 'exact raw application bytes')
            else:
                require(struct.unpack('!HHH', payload[:6]) ==
                        (49200 + case * 2 + lane, 48000 + case, size + 8), 'UDP tuple and length')
                pseudo = local + bytes([10, 23, lane + 1, 180 + case]) + struct.pack('!BBH', 0, 17, len(payload))
                require(payload[6:8] != b'\0\0' and not checksum(pseudo + payload) and
                        payload[8:] == application(lane, case, size), 'UDP checksum and application bytes')
            if initial:
                first = packets[0]
            datagrams += 1
            fragments += len(packets)
        require(assigned == {r['index'] for r in data[case]}, 'no data outside an owned policy window')
        require(len(errors[case]) == 2, 'one bad and one valid original hint')
        bad, good = errors[case]
        for item in [bad, good]:
            body = item['packet'][20:]
            require(body[4:6] == b'\0\0' and int.from_bytes(body[6:8], 'big') == hint(case) and
                    body[8:] == first['packet'][:28], 'hint owns exact original header and payload quote')
        require(checksum(bad['packet'][20:]) != 0 and checksum(good['packet'][20:]) == 0 and
                first['index'] < bad['index'] < replies[case, 1, case_policy(case)]['index'] and
                requests[case, 6, case_policy(case)]['index'] < good['index'] < replies[case, 6, case_policy(case)]['index'],
                'damaged-hint silence precedes ordered valid learning')
    cases = re.findall(r'^IPV4_PATH_MTU_CASE index=' + str(lane + 1) + r' case=(\d+) mtu=(\d+)\r?$', log, re.M)
    require([(int(n), int(value)) for n, value in cases] == [(n, learned(n)) for n in range(18)], 'all actual client path queries')
    route_cases = re.findall(r'^IPV4_PATH_MTU_ROUTES index=' + str(lane + 1) +
                            r' case=(\d+) restored=(\d+)\r?$', log, re.M)
    require(route_cases == cases, 'all actual route ownership and restoration queries')
    held = re.findall(r'^IPV4_PATH_MTU_HELD index=' + str(lane + 1) +
                      r' case=(\d+) first=(\d+) shared=(\d+) current=(\d+)\r?$', log, re.M)
    require([(int(n), int(first), int(shared), int(current)) for n, first, shared, current in held] ==
            [(n, 1500, learned(n) if releases else 1500, learned(n)) for n in range(18)],
            'actual stale-first, duplicate and explicit release queries')
    held_routes = re.findall(r'^IPV4_PATH_MTU_HELD_ROUTES index=' + str(lane + 1) +
                             r' case=(\d+) restored=(\d+)\r?$', log, re.M)
    require(held_routes == cases, 'actual held descriptions follow route ownership changes')
    require(len(re.findall(r'^IPV4_PATH_MTU_LINK index=' + str(lane + 1) +
                          r' lower=600 restored=1500\r?$', log, re.M)) == 1,
            'actual link MTU change and device-bound recovery')
    require(len(re.findall(r'^IPV4_PATH_MTU_HELD_LINK index=' + str(lane + 1) +
                          r' first=600 restored=1500 preserved=900\r?$', log, re.M)) == 1,
            'actual retained queries across preserved and clipped link limits')
    require(len(re.findall(r'^IPV4_PATH_MTU_PASS index=' + str(lane + 1) +
                          r' cases=18 policies_each=6\r?$', log, re.M)) == 1, 'actual client final acknowledgement')
    result = dict(passed=True, lane=lane, cases=18, policy_checks=108, damaged_hints_rejected=18,
                  datagrams=datagrams, data_frames=fragments, route_query_cases=18,
                  retained_query_cases=18, link_mtu_recovery=True, original_times_not_rescaled=True)
    return result, (requests, replies, data, errors)


def seal_ip(frame):
    frame[24:26] = b'\0\0'
    struct.pack_into('!H', frame, 24, checksum(frame[14:34]))


def verify_capture(path, lane, log_path, damage_archive=None, native=False, query_model='release'):
    original = path.read_bytes()
    rows, log = read_capture(path), log_path.read_text(errors='replace')
    if native:
        clocks = [json.loads(line) for line in path.with_suffix('.clocks.jsonl').read_text().splitlines()]
        require(len(clocks) == len(rows), 'every original native frame has an observation')
        for number, (row, clock) in enumerate(zip(rows, clocks)):
            require(clock['frame'] == number and clock['sha256'] == hashlib.sha256(row['frame']).hexdigest() and
                    clock['kernel_realtime_ns'] // 1000 == row['ns'] // 1000, 'native frame and receipt binding')
    result, proof = inspect(rows, lane, log, query_model)
    result['query_model'] = query_model
    req, rep, data, errors = proof
    if damage_archive:
        failures = []
        with zipfile.ZipFile(damage_archive, 'x', compression=zipfile.ZIP_DEFLATED, compresslevel=1) as archive:
            archive.writestr('fixture-policy.json', json.dumps(dict(synthetic_damage=True,
                original_captures_and_native_receipts_unchanged=True,
                original_elapsed_time_requirements_unchanged=True)) + '\n')
            for name in ['missing-valid-hint', 'wrong-quote', 'wrong-DF', 'bad-UDP-checksum', 'missing-fragment',
                         'bad-IP-checksum', 'missing-final-ack', 'forbidden-DO-output', 'wrong-route', 'false-client-MTU',
                         'false-route-MTU', 'missing-route-check', 'false-link-MTU',
                         'false-held-MTU', 'missing-held-route', 'false-held-link']:
                changed, text = copy.deepcopy(rows), log
                target = errors[0][1]['index']
                if name == 'missing-valid-hint':
                    del changed[target]
                elif name == 'wrong-quote':
                    frame = bytearray(changed[target]['frame'])
                    frame[46] ^= 1
                    frame[52:54] = b'\0\0'
                    struct.pack_into('!H', frame, 52, checksum(frame[42:62]))
                    frame[36:38] = b'\0\0'
                    struct.pack_into('!H', frame, 36, checksum(frame[34:70]))
                    changed[target]['frame'] = bytes(frame)
                elif name == 'missing-fragment':
                    begin, end = rep[0, 2, 0]['index'], rep[0, 3, 0]['index']
                    target = next(r['index'] for r in data[0] if begin < r['index'] < end)
                    del changed[target]
                elif name == 'missing-final-ack':
                    del changed[rep[18, 5, 0]['index']]
                elif name == 'false-client-MTU':
                    text = text.replace(f'IPV4_PATH_MTU_CASE index={lane + 1} case=0 mtu=900',
                                        f'IPV4_PATH_MTU_CASE index={lane + 1} case=0 mtu=899')
                elif name == 'false-route-MTU':
                    text = text.replace(f'IPV4_PATH_MTU_ROUTES index={lane + 1} case=0 restored=900',
                                        f'IPV4_PATH_MTU_ROUTES index={lane + 1} case=0 restored=899')
                elif name == 'missing-route-check':
                    text = re.sub(r'^IPV4_PATH_MTU_ROUTES index=' + str(lane + 1) +
                                  r' case=0 restored=900\r?\n', '', text, count=1, flags=re.M)
                elif name == 'false-link-MTU':
                    text = text.replace(f'IPV4_PATH_MTU_LINK index={lane + 1} lower=600 restored=1500',
                                        f'IPV4_PATH_MTU_LINK index={lane + 1} lower=600 restored=1400')
                elif name == 'false-held-MTU':
                    text = text.replace(f'IPV4_PATH_MTU_HELD index={lane + 1} case=0 first=1500 ',
                                        f'IPV4_PATH_MTU_HELD index={lane + 1} case=0 first=1400 ')
                elif name == 'missing-held-route':
                    text = re.sub(r'^IPV4_PATH_MTU_HELD_ROUTES index=' + str(lane + 1) +
                                  r' case=0 restored=900\r?\n', '', text, count=1, flags=re.M)
                elif name == 'false-held-link':
                    text = text.replace(f'IPV4_PATH_MTU_HELD_LINK index={lane + 1} first=600',
                                        f'IPV4_PATH_MTU_HELD_LINK index={lane + 1} first=500')
                elif name == 'forbidden-DO-output':
                    source = copy.deepcopy(changed[data[0][0]['index']])
                    frame = bytearray(source['frame'])
                    frame[20:22] = b'\x40\0'
                    seal_ip(frame)
                    source['frame'] = bytes(frame)
                    changed.insert(rep[0, 3, 2]['index'], source)
                else:
                    if name == 'bad-UDP-checksum':
                        target = data[6][0]['index']
                    else:
                        begin, end = rep[0, 2, 3]['index'], rep[0, 3, 3]['index']
                        target = next(r['index'] for r in data[0] if begin < r['index'] < end)
                    frame = bytearray(changed[target]['frame'])
                    if name == 'wrong-DF':
                        frame[20] ^= 0x40
                        seal_ip(frame)
                    elif name == 'bad-UDP-checksum':
                        frame[40] ^= 1
                    elif name == 'bad-IP-checksum':
                        frame[24] ^= 1
                    else:
                        frame[28] ^= 1
                        seal_ip(frame)
                    changed[target]['frame'] = bytes(frame)
                archive.writestr(name + '.pcap', encode(changed))
                archive.writestr(name + '.log', text)
                try:
                    inspect(changed, lane, text, query_model)
                except ValueError as error:
                    failures.append(dict(name=name, rejected=True, reason=str(error)))
                else:
                    raise ValueError('damaged PMTU evidence was accepted: ' + name)
            archive.writestr('rejections.json', json.dumps(failures, indent=2) + '\n')
        result['damage_rejections'] = len(failures)
    require(path.read_bytes() == original, 'original capture remained unchanged')
    result['capture_sha256'] = hashlib.sha256(original).hexdigest()
    return result


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('capture', type=Path)
    parser.add_argument('--lane', type=int, choices=[0, 1], required=True)
    parser.add_argument('--log', type=Path, required=True)
    parser.add_argument('--native', action='store_true')
    parser.add_argument('--query-model', choices=('release', 'read-only'), default='release')
    parser.add_argument('--damage-archive', type=Path)
    args = parser.parse_args()
    print(json.dumps(verify_capture(args.capture, args.lane, args.log, args.damage_archive,
                                    args.native, args.query_model)))
