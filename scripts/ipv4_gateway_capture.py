# SPDX-License-Identifier: GPL-3.0-or-later
"""Independently verify gateway next hops, exact datagrams and shared descriptions."""
import copy
import hashlib
import json
from pathlib import Path
import re
import struct
import zipfile
from ipv4_expiry_capture import bind_clocks, checksum, encode_capture, read_capture


def require(value, reason):
    if not value:
        raise ValueError(reason)


def inspect(rows, lane, log, query_model='release'):
    require(query_model in ('release', 'read-only'), 'known gateway query contract')
    require(len(re.findall(r'^IPV4_GATEWAY_QUERY_MODEL index=' + str(lane + 1) +
                          ' release=' + str(int(query_model == 'release')) + r'\r?$', log, re.M)) == 1,
            'gateway client query contract matches the selected kernel model')
    guest = bytes([0x52, 0x54, 0, 0x12, 0x34, 0x10 + lane])
    control_mac = bytes([2, 0x41, 0x58, 0x49, 0x50, lane])
    primary, alias, remote = [bytes([10, 23, lane + 1, last]) for last in (2, 3, 1)]
    targets = [bytes([192, 0, lane + 2, 10 + kind]) for kind in range(2)]
    gateways = [primary[:3] + bytes([250 + n]) for n in range(2)]
    macs = {remote: control_mac, gateways[0]: bytes([2, 0x47, 0x57, 0x41, lane, 1]),
            gateways[1]: bytes([2, 0x47, 0x57, 0x42, lane, 1]),
            **{target: bytes([2, 0x47, 0x57, 0x44, lane, 1]) for target in targets}}
    pending, neighbours = {}, {}
    requests, replies, datagrams, hints = {}, {}, {}, {}
    arp_pairs = []
    for index, row in enumerate(rows):
        frame = row['frame']
        if len(frame) < 34:
            require(frame[6:12] != guest or frame[12:14] != b'\x08\0',
                    'complete original owned IPv4 header')
            continue
        if frame[12:14] == b'\x08\x06' and len(frame) >= 42:
            operation = frame[20:22]
            target = frame[38:42] if operation == b'\0\1' else frame[28:32]
            if target not in macs:
                continue
            local = primary if target == remote else alias
            require(frame[14:20] == b'\0\1\x08\0\x06\x04' and not any(frame[42:]),
                    'gateway ARP format and padding')
            if operation == b'\0\1':
                require(frame[:14] == b'\xff' * 6 + guest + b'\x08\x06' and
                        frame[22:38] == guest + local + b'\0' * 6,
                        'gateway ARP request source and ownership')
                pending.setdefault(target, []).append(index)
            else:
                require(operation == b'\0\2' and frame[:14] == guest + macs[target] + b'\x08\x06' and
                        frame[22:42] == macs[target] + target + guest + local and
                        pending.get(target), 'gateway ARP reply matches an owned request')
                arp_pairs.append(dict(target=target.hex(), request=pending[target].pop(0), reply=index))
                neighbours[target] = index
            continue
        if frame[12:14] != b'\x08\0':
            continue
        total = int.from_bytes(frame[16:18], 'big')
        ip = frame[14:14 + total]
        require(frame[6:12] != guest or len(ip) >= 28,
                'complete original owned IPv4 transport header')
        if len(ip) < 28:
            continue
        outgoing_control = ip[9] == 1 and ip[12:20] == primary + remote and ip[24:26] == b'GW'
        incoming_control = ip[9] == 1 and ip[12:20] == remote + primary and ip[24:26] == b'GW'
        hint = ip[9] == 1 and ip[16:20] == alias and ip[20:22] == b'\3\4'
        data = frame[6:12] == guest and (ip[12:16] == alias or ip[16:20] in targets)
        if not (outgoing_control or incoming_control or hint or data):
            continue
        require(ip[:2] == b'\x45\0' and 28 <= total == len(ip) <= len(frame) - 14 and
                not checksum(ip[:20]) and not any(frame[14 + total:]),
                'gateway original IPv4 header, bounds and checksum')
        if outgoing_control or incoming_control:
            body = ip[20:]
            kind, phase = body[6:8]
            require(kind < 2 and phase < 8 and len(ip) == 52 and
                    ip[6:10] == (b'\x40\0\x40\1' if outgoing_control else b'\0\0\x33\1') and
                    frame[:12] == (control_mac + guest if outgoing_control else guest + control_mac),
                    'gateway control IP policy, Ethernet ownership and tuple')
            expected = bytearray([8 if outgoing_control else 0, 0, 0, 0, 0x47, 0x57, kind, phase, lane])
            expected.extend((n * 17 + lane * 31) & 255 for n in range(9, 32))
            struct.pack_into('!H', expected, 2, checksum(expected))
            require(body == bytes(expected), 'gateway exact control body and checksum')
            records = requests if outgoing_control else replies
            require((kind, phase) not in records, 'one ordered gateway control per phase')
            records[kind, phase] = index
            continue
        if hint:
            require(len(ip) == 56 and ip[12:20] == gateways[0] + alias and
                    frame[:12] == guest + macs[gateways[0]] and ip[6:10] == b'\0\0\x33\1' and
                    ip[24:28] == b'\0\0\3\x84' and not checksum(ip[20:]),
                    'gateway hint ownership, announced limit and checksum')
            quoted = ip[28:]
            require(len(quoted) == 28 and quoted[9] in (1, 17), 'gateway complete original quoted header')
            kind = 1 if quoted[9] == 1 else 0
            require(kind not in hints, 'one original eligible gateway hint per protocol')
            hints[kind] = dict(index=index, quote=quoted)
            continue
        require(ip[9] in (1, 17), 'gateway application protocol')
        kind = 1 if ip[9] == 1 else 0
        body = ip[20:]
        if not kind:
            require(len(body) >= 16 and struct.unpack('!HHH', body[:6]) ==
                    (49100 + lane * 4, 48009, len(body)) and
                    not checksum(ip[12:20] + struct.pack('!BBH', 0, 17, len(body)) + body),
                    'gateway UDP checksum, ports and length')
            body = body[8:]
        else:
            require(not checksum(body), 'gateway raw ICMP checksum')
        phase = body[7] if kind else body[4]
        require(phase in (0, 1, 2, 3, 4, 6) and ip[12:20] == alias + targets[kind] and
                ip[6:10] == b'\x40\0\x40' + bytes([1 if kind else 17]),
                'gateway data phase, explicit source and unchanged IP destination')
        next_hop = gateways[1] if phase == 1 else targets[kind] if phase == 3 else gateways[0]
        require(frame[:12] == macs[next_hop] + guest and neighbours.get(next_hop, index) < index,
                'gateway data selects its independently resolved next-hop MAC')
        length = 1100 if phase == 0 else 32
        expected = bytearray((n * 31 + phase * 17 + lane * 13) & 255 for n in range(length))
        if kind:
            expected[:8] = bytes([8, 0, 0, 0, 0x47, 0x57, kind, phase])
            struct.pack_into('!H', expected, 2, checksum(expected))
        else:
            expected[:8] = bytes([0x47, 0x57, lane, kind, phase, 0, 0, 0])
        require(body == bytes(expected), 'gateway exact application bytes')
        require((kind, phase) not in datagrams, 'one original gateway datagram per phase')
        datagrams[kind, phase] = dict(index=index, ip=ip)
    expected_controls = {(kind, phase) for kind in range(2) for phase in range(8)}
    expected_data = {(kind, phase) for kind in range(2) for phase in (0, 1, 2, 3, 4, 6)}
    require(set(requests) == set(replies) == expected_controls and set(datagrams) == expected_data and
            set(hints) == {0, 1}, 'complete original gateway datagrams, controls and hints')
    require(all(any(pair['target'] == target.hex() for pair in arp_pairs)
                for target in gateways + targets) and not any(pending.values()),
            'complete gateway and direct-neighbour ARP exchanges')
    previous = -1
    for kind in range(2):
        for phase in range(8):
            request, reply = requests[kind, phase], replies[kind, phase]
            require(previous < request < reply, 'ordered original gateway barriers')
            if (kind, phase) in datagrams:
                require(previous < datagrams[kind, phase]['index'] < reply,
                        'gateway acknowledgement follows the actual datagram')
            if phase == 0:
                original = datagrams[kind, 0]
                require(original['index'] < hints[kind]['index'] < reply and
                        hints[kind]['quote'] == original['ip'][:28],
                        'gateway hint quotes its exact earlier owned datagram')
            previous = reply
    values = re.findall(r'^IPV4_GATEWAY_MTU index=' + str(lane + 1) +
                        r' kind=(\d+) phase=(\d+) first=(-?\d+) shared=(-?\d+)\r?$', log, re.M)
    require([(int(k), int(p)) for k, p, _, _ in values] ==
            [(kind, phase) for kind in range(2) for phase in range(8)],
            'all original shared-description MTU queries in execution order')
    for kind, phase, first, shared in values:
        kind, phase = int(kind), int(phase)
        expected = (900, 900) if phase in (0, 2) else (1500, 1500)
        if phase == 5:
            expected = (1500 if kind else -107,
                        1500 if kind and query_model == 'read-only' else -107)
        elif phase == 6 and kind and query_model == 'release':
            expected = (-107, -107)
        require((int(first), int(shared)) == expected, 'native-observed raw/UDP destination cache lifecycle')
    for kind in range(2):
        require(len(re.findall(r'^IPV4_GATEWAY_ERROR index=' + str(lane + 1) + ' kind=' + str(kind) +
                               r' fresh_unbound=101 removed_source=101\r?$', log, re.M)) == 1,
                'actual fresh-unbound and removed-source errors')
    require(len(re.findall(r'^IPV4_GATEWAY_PASS index=' + str(lane + 1) +
                           r' protocols=2 datagrams=12\r?$', log, re.M)) == 1,
            'actual gateway client completed both protocols')
    result = dict(passed=True, lane=lane, protocols=2, datagrams=12, controls=16, hints=2,
                  shared_queries=16, arp_exchanges=len(arp_pairs))
    return result, dict(data=datagrams, hints=hints, replies=replies, arp=arp_pairs)


def seal_ip(frame):
    frame[24:26] = b'\0\0'
    struct.pack_into('!H', frame, 24, checksum(frame[14:34]))


def seal_udp(frame):
    frame[40:42] = b'\0\0'
    total = int.from_bytes(frame[16:18], 'big')
    pseudo = frame[26:34] + struct.pack('!BBH', 0, 17, total - 20)
    struct.pack_into('!H', frame, 40, checksum(pseudo + frame[34:14 + total]) or 65535)


def verify_capture(path, lane, log_path, damage_archive=None, native=False, query_model='release'):
    path, log_path = Path(path), Path(log_path)
    original, original_log = path.read_bytes(), log_path.read_bytes()
    rows, text = read_capture(path), original_log.decode(errors='replace')
    if native:
        bind_clocks(rows, path.with_suffix('.clocks.jsonl'))
    result, proof = inspect(rows, lane, text, query_model)
    result['query_model'] = query_model
    if damage_archive:
        names = ['missing-data', 'wrong-next-hop', 'wrong-source', 'wrong-destination', 'payload',
                 'UDP-checksum', 'IP-checksum', 'missing-hint', 'false-hint-MTU', 'wrong-quote',
                 'missing-control', 'early-control', 'false-raw-error-MTU', 'missing-query',
                 'false-error', 'missing-success', 'ARP-target', 'ARP-source',
                 'forbidden-source-output', 'false-raw-restoration', 'reordered-queries', 'short-owned-output']
        rejected = []
        with zipfile.ZipFile(damage_archive, 'x', compression=zipfile.ZIP_DEFLATED, compresslevel=1) as archive:
            for name in names:
                changed, log = copy.deepcopy(rows), text
                target = proof['data'][0, 1]['index']
                if name == 'missing-data':
                    del changed[target]
                elif name == 'missing-hint':
                    del changed[proof['hints'][0]['index']]
                elif name == 'missing-control':
                    del changed[proof['replies'][0, 5]]
                elif name == 'early-control':
                    control = changed.pop(proof['replies'][0, 1])
                    changed.insert(target, control)
                elif name in ('false-raw-error-MTU', 'false-raw-restoration', 'missing-query'):
                    phase = 6 if name != 'false-raw-error-MTU' else 5
                    pattern = (r'^IPV4_GATEWAY_MTU index=' + str(lane + 1) + r' kind=1 phase=' +
                               str(phase) + r' first=-?\d+ shared=-?\d+\r?$')
                    value = '' if name == 'missing-query' else (
                        f'IPV4_GATEWAY_MTU index={lane + 1} kind=1 phase={phase} first=' +
                        ('-107 shared=-107' if phase == 5 or query_model == 'read-only' else
                         '1500 shared=1500'))
                    log, count = re.subn(pattern, value, log, count=1, flags=re.M)
                    require(count == 1, 'one original raw lifecycle observation was damaged')
                    require(log != text, 'raw lifecycle damage changes the original observation')
                elif name == 'short-owned-output':
                    frame = bytearray(changed[target]['frame'][:34])
                    frame[16:18] = (20).to_bytes(2, 'big')
                    seal_ip(frame)
                    frame.extend(bytes(60 - len(frame)))
                    position = proof['replies'][0, 5]
                    changed.insert(position, dict(changed[position], frame=bytes(frame)))
                elif name == 'reordered-queries':
                    pattern = r'^IPV4_GATEWAY_MTU index=' + str(lane + 1) + r' kind=0 phase=[05] .*\r?$'
                    observations = re.findall(pattern, log, re.M)
                    require(len(observations) == 2, 'two original query receipts to reorder')
                    log = re.sub(pattern, lambda match: observations.pop(), log, flags=re.M)
                elif name == 'false-error':
                    log = log.replace(f'IPV4_GATEWAY_ERROR index={lane + 1} kind=0 fresh_unbound=101',
                                      f'IPV4_GATEWAY_ERROR index={lane + 1} kind=0 fresh_unbound=0')
                elif name == 'missing-success':
                    log = log.replace(f'IPV4_GATEWAY_PASS index={lane + 1} protocols=2 datagrams=12', '')
                else:
                    if name in ('false-hint-MTU', 'wrong-quote'):
                        target = proof['hints'][0]['index']
                    elif name in ('ARP-target', 'ARP-source'):
                        target = next(pair['request'] for pair in proof['arp']
                                      if pair['target'].endswith('fa'))
                    frame = bytearray(changed[target]['frame'])
                    if name == 'wrong-next-hop':
                        frame[3] = 0x41
                    elif name == 'wrong-source':
                        frame[29] = 2
                        seal_ip(frame)
                        seal_udp(frame)
                    elif name == 'wrong-destination':
                        frame[33] = 99
                        seal_ip(frame)
                        seal_udp(frame)
                    elif name == 'payload':
                        frame[-1] ^= 1
                        seal_udp(frame)
                    elif name == 'UDP-checksum':
                        frame[40] ^= 1
                    elif name == 'IP-checksum':
                        frame[24] ^= 1
                    elif name == 'false-hint-MTU':
                        frame[41] ^= 1
                        frame[36:38] = b'\0\0'
                        struct.pack_into('!H', frame, 36, checksum(frame[34:]))
                    elif name == 'wrong-quote':
                        frame[61] ^= 1
                        frame[52:54] = b'\0\0'
                        struct.pack_into('!H', frame, 52, checksum(frame[42:62]))
                        frame[36:38] = b'\0\0'
                        struct.pack_into('!H', frame, 36, checksum(frame[34:]))
                    elif name == 'ARP-target':
                        frame[41] = 249
                    elif name == 'ARP-source':
                        frame[31] = 2
                    elif name == 'forbidden-source-output':
                        frame[46] = 5
                        seal_udp(frame)
                        changed.insert(proof['replies'][0, 5], dict(changed[target], frame=bytes(frame)))
                    if name != 'forbidden-source-output':
                        changed[target]['frame'] = bytes(frame)
                archive.writestr(name + '.pcap', encode_capture(changed))
                archive.writestr(name + '.log', log)
                try:
                    inspect(changed, lane, log, query_model)
                except ValueError as error:
                    rejected.append(dict(name=name, rejected=True, reason=str(error)))
                else:
                    raise ValueError('damaged gateway evidence was accepted: ' + name)
            archive.writestr('rejections.json', json.dumps(rejected, indent=2) + '\n')
        result['damaged_rejected'] = len(rejected)
        result['archive'] = str(damage_archive)
        result['archive_sha256'] = hashlib.sha256(Path(damage_archive).read_bytes()).hexdigest()
    require(path.read_bytes() == original and log_path.read_bytes() == original_log,
            'original gateway packet and client evidence remained unchanged')
    result['capture_sha256'] = hashlib.sha256(original).hexdigest()
    result['log_sha256'] = hashlib.sha256(original_log).hexdigest()
    return result
