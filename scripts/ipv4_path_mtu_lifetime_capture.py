# SPDX-License-Identifier: GPL-3.0-or-later
"""Independently prove ten-minute PMTU expiry from original packets and clocks."""
import copy
import hashlib
import json
from pathlib import Path
import re
import struct
import zipfile
from ipv4_expiry_capture import (bind_clocks, checksum, elapsed_ns, encode_capture,
                                 read_capture, require)


def inspect(rows, lane, log):
    local, remote = bytes([10, 23, lane + 1, 2]), bytes([10, 23, lane + 1, 1])
    target = bytes([10, 23, lane + 1, 210])
    guest = bytes.fromhex('5254001234') + bytes([0x10 + lane])
    host = bytes.fromhex('0241584950') + bytes([lane])
    requests, replies, data, hints = {}, {}, [], []
    for index, row in enumerate(rows):
        frame = row['frame']
        if len(frame) < 34 or frame[12:14] != b'\x08\0':
            continue
        packet = frame[14:]
        control = packet[9:10] == b'\x01' and packet[24:26] == b'PL'
        if not control and target not in (packet[12:16], packet[16:20]):
            continue
        total = int.from_bytes(packet[2:4], 'big')
        incoming = packet[16:20] == local
        require(28 <= total <= len(packet) and packet[:2] == b'\x45\0' and
                not checksum(packet[:20]) and not any(packet[total:]),
                'lifetime IPv4 bounds, checksum and padding')
        packet = packet[:total]
        require(frame[:12] == (guest + host if incoming else host + guest) and
                packet[8] == (51 if incoming else 64), 'lifetime Ethernet owner and TTL')
        item = dict(index=index, ns=elapsed_ns(row), packet=packet)
        if control:
            body = packet[20:]
            require(len(packet) == 52 and packet[12:20] ==
                    (remote + local if incoming else local + remote) and
                    packet[6:8] == (b'\0\0' if incoming else b'\x40\0') and
                    body[:2] == (b'\0\0' if incoming else b'\x08\0') and
                    not checksum(body) and body[8:10] == bytes([0, lane]) and body[10:] ==
                    bytes((n * 17 + lane * 31) & 255 for n in range(10, 32)),
                    'lifetime exact control checksum, route, flags and payload')
            key = body[6], body[7]
            collection = replies if incoming else requests
            require(key not in collection, 'lifetime control appears exactly once')
            collection[key] = item
        elif not incoming:
            require(len(packet) == 1128 and packet[6:10] == b'\x40\0\x40\x11' and
                    packet[12:20] == local + target, 'lifetime whole DO data ownership and flags')
            segment = packet[20:]
            source, destination, length, wire_sum = struct.unpack('!HHHH', segment[:8])
            pseudo = local + target + struct.pack('!BBH', 0, 17, len(segment))
            require(source in (49300 + lane, 49500 + lane) and destination == 48100 and
                    length == 1108 and wire_sum and not checksum(pseudo + segment) and
                    segment[8:] == bytes((n * 31 + lane * 47 + 81) % 256 for n in range(1100)),
                    'lifetime actual UDP tuple, checksum and exact application bytes')
            item['port'] = source
            data.append(item)
        else:
            require(len(packet) == 56 and packet[6:10] == b'\0\0\x33\x01' and
                    packet[12:20] == target + local and packet[20:22] == b'\x03\x04' and
                    packet[24:28] == b'\0\0\x03\x84', 'lifetime exact quoted hint header')
            hints.append(item)
    keys = [(0, 0), (0, 1), (0, 2)] + [(n, 3) for n in range(22)] + [(22, 4)]
    require(set(requests) == set(replies) == set(keys), 'all lifetime requests and acknowledgements')
    sequence = sorted(requests, key=lambda key: requests[key]['index'])
    require(sequence == keys, 'lifetime request order')
    for position, key in enumerate(keys):
        request, reply = requests[key], replies[key]
        require(request['index'] < reply['index'] and request['ns'] <= reply['ns'] and
                request['packet'][24:] == reply['packet'][24:], 'lifetime exact acknowledged barrier')
        if position:
            previous = replies[keys[position - 1]]
            require(previous['index'] < request['index'] and previous['ns'] <= request['ns'],
                    'lifetime barriers preserve wire and clock order')
    require(len(data) == 3 and len(hints) == 2, 'one original and two post-expiry datagrams with two hints')
    initial, bad, valid = data[0], hints[0], hints[1]
    require(initial['port'] == 49300 + lane and
            replies[0, 0]['index'] < initial['index'] < bad['index'] < replies[0, 1]['index'] and
            requests[0, 2]['index'] < valid['index'] < replies[0, 2]['index'],
            'lifetime hint provenance and bad-then-valid ordering')
    for hint in hints:
        require(hint['packet'][28:] == initial['packet'][:28], 'lifetime exact original quoted bytes')
    require(checksum(bad['packet'][20:]) != 0 and checksum(valid['packet'][20:]) == 0 and
            bad['packet'][20:22] + bad['packet'][24:] ==
            valid['packet'][20:22] + valid['packet'][24:], 'only valid outer checksum can learn')
    require({item['port'] for item in data[1:]} == {49300 + lane, 49500 + lane},
            'both retained and newly connected descriptions recover')
    expiry = []
    for item in data[1:]:
        seconds = (item['ns'] - valid['ns']) / 1000000000
        require(600 <= seconds <= 610 and replies[20, 3]['index'] < item['index'] <
                replies[21, 3]['index'], 'actual whole datagrams follow unchanged ten-minute expiry')
        expiry.append(seconds)
    query_lines = re.findall(r'^IPV4_PATH_MTU_LIFETIME_QUERY index=' + str(lane + 1) +
                            r' sample=(\d+) mtu=(\d+) fresh=(\d+) elapsed_ms=(\d+)\r?$', log, re.M)
    require(len(query_lines) == 22, 'all actual socket MTU queries are retained')
    link = list(re.finditer(r'^IPV4_PATH_MTU_LIFETIME_LINK index=' + str(lane + 1) +
                            r' sample=10 preserved=900\r?$', log, re.M))
    require(len(link) == 1 and
            log.find(f'IPV4_PATH_MTU_LIFETIME_QUERY index={lane + 1} sample=9 ') < link[0].start() <
            log.find(f'IPV4_PATH_MTU_LIFETIME_QUERY index={lane + 1} sample=10 '),
            'actual mid-lifetime link transition precedes the unchanged deadline checks')
    for sample, values in enumerate(query_lines):
        number, owned, fresh, client_ms = map(int, values)
        expected = 1500 if sample == 21 else 900
        require(number == sample and owned == fresh == expected, 'actual owned and fresh query values')
        seconds = (requests[sample, 3]['ns'] - valid['ns']) / 1000000000
        scheduled = sample * 30 if sample < 20 else 590 if sample == 20 else 605
        require(scheduled - 1 <= seconds <= scheduled + 5 and
                abs(seconds * 1000 - client_ms) <= 2000,
                'actual original capture intervals agree with the client elapsed clock')
        if sample < 21:
            require(seconds < 600, 'no early query or renewal of the ten-minute path')
    final = re.findall(r'^IPV4_PATH_MTU_LIFETIME_PASS index=' + str(lane + 1) +
                       r' elapsed_ms=(\d+) samples=22 lookups_no_refresh=1\r?$', log, re.M)
    require(len(final) == 1 and 600000 <= int(final[0]) <= 610000,
            'complete actual client lifetime and final marker')
    require(replies[21, 3]['index'] < requests[22, 4]['index'], 'final client acknowledgement follows recovery')
    return (dict(passed=True, lane=lane, samples=22, original_datagrams=3,
                 recovered_descriptions=2, expiry_seconds=expiry, lifetime_seconds=600,
                 link_mtu_preserves_deadline=True, original_packet_times_not_rescaled=True),
            dict(requests=requests, replies=replies, data=data, hints=hints))


def verify_capture(path, lane, log_path, *, native=False, damage_archive=None):
    path, log_path = Path(path), Path(log_path)
    original, original_log = path.read_bytes(), log_path.read_bytes()
    rows = read_capture(path)
    if native:
        bind_clocks(rows, path.with_suffix('.clocks.jsonl'))
    log = original_log.decode(errors='replace')
    result, proof = inspect(rows, lane, log)
    if damage_archive:
        rejected = []
        with zipfile.ZipFile(damage_archive, 'x', compression=zipfile.ZIP_DEFLATED,
                             compresslevel=1) as archive:
            archive.writestr('fixture-policy.json', json.dumps(dict(synthetic_damage=True,
                original_capture_log_and_native_clocks_unchanged=True,
                required_production_lifetime_seconds=600)) + '\n')
            names = ['missing-valid-hint', 'wrong-quote', 'early-expiry', 'late-expiry',
                     'missing-second-description', 'bad-UDP-checksum', 'wrong-DF',
                     'missing-lookup', 'missing-final-ack', 'false-client-MTU',
                     'false-client-duration', 'duplicate-final-data', 'wrong-route', 'early-lookup',
                     'missing-link-transition', 'false-link-limit']
            for name in names:
                changed, text = copy.deepcopy(rows), log
                valid = proof['hints'][1]['index']
                final_data = proof['data'][1]['index']
                if name == 'missing-valid-hint':
                    del changed[valid]
                elif name == 'wrong-quote':
                    frame = bytearray(changed[valid]['frame'])
                    frame[61] ^= 1
                    frame[36:38] = b'\0\0'
                    struct.pack_into('!H', frame, 36, checksum(frame[34:70]))
                    changed[valid]['frame'] = bytes(frame)
                elif name in ('early-expiry', 'late-expiry'):
                    delta = (-14 if name == 'early-expiry' else 10) * 1000000000
                    boundary = min(proof['data'][1]['index'], proof['data'][2]['index'],
                                   proof['requests'][21, 3]['index'])
                    for row in changed[boundary:]:
                        row['ns'] += delta
                        if 'elapsed_ns' in row:
                            row['elapsed_ns'] += delta
                elif name == 'missing-second-description':
                    del changed[proof['data'][2]['index']]
                elif name == 'missing-lookup':
                    del changed[proof['requests'][10, 3]['index']]
                elif name == 'missing-final-ack':
                    del changed[proof['replies'][22, 4]['index']]
                elif name == 'false-client-MTU':
                    pattern = r'(IPV4_PATH_MTU_LIFETIME_QUERY index=' + str(lane + 1) + r' sample=20 mtu=)900'
                    text, count = re.subn(pattern, r'\g<1>1500', text)
                    require(count == 1, 'one original lookup query was damaged')
                elif name == 'false-client-duration':
                    pattern = r'(IPV4_PATH_MTU_LIFETIME_PASS index=' + str(lane + 1) + r' elapsed_ms=)\d+'
                    text, count = re.subn(pattern, r'\g<1>1000', text)
                    require(count == 1, 'one original elapsed observation was damaged')
                elif name == 'missing-link-transition':
                    text = re.sub(r'^IPV4_PATH_MTU_LIFETIME_LINK index=' + str(lane + 1) +
                                  r' sample=10 preserved=900\r?\n', '', text, count=1, flags=re.M)
                elif name == 'false-link-limit':
                    text = text.replace(f'IPV4_PATH_MTU_LIFETIME_LINK index={lane + 1} sample=10 preserved=900',
                                        f'IPV4_PATH_MTU_LIFETIME_LINK index={lane + 1} sample=10 preserved=899')
                elif name == 'duplicate-final-data':
                    changed.insert(final_data, copy.deepcopy(changed[final_data]))
                elif name == 'early-lookup':
                    row = changed[proof['requests'][10, 3]['index']]
                    row['ns'] -= 100000000000
                    if 'elapsed_ns' in row:
                        row['elapsed_ns'] -= 100000000000
                else:
                    frame = bytearray(changed[final_data]['frame'])
                    if name == 'bad-UDP-checksum':
                        frame[40] ^= 1
                    elif name == 'wrong-DF':
                        frame[20:22] = b'\0\0'
                    elif name == 'wrong-route':
                        frame[33] ^= 1
                    if name != 'bad-UDP-checksum':
                        frame[24:26] = b'\0\0'
                        struct.pack_into('!H', frame, 24, checksum(frame[14:34]))
                    changed[final_data]['frame'] = bytes(frame)
                archive.writestr(name + '.pcap', encode_capture(changed))
                archive.writestr(name + '.log', text)
                archive.writestr(name + '.observations.json', json.dumps([
                    dict(index=n, ns=row['ns'], elapsed_ns=elapsed_ns(row),
                         frame_sha256=hashlib.sha256(row['frame']).hexdigest())
                    for n, row in enumerate(changed)]) + '\n')
                try:
                    inspect(changed, lane, text)
                except ValueError as error:
                    rejected.append(dict(name=name, rejected=True, reason=str(error)))
                else:
                    raise ValueError('damaged lifetime evidence accepted: ' + name)
            archive.writestr('rejections.json', json.dumps(rejected, indent=2) + '\n')
        result['damage_rejections'] = len(rejected)
    require(path.read_bytes() == original and log_path.read_bytes() == original_log,
            'original lifetime capture and client log remained unchanged')
    result['capture_sha256'] = hashlib.sha256(original).hexdigest()
    return result
