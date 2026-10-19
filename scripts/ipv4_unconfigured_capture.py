# SPDX-License-Identifier: GPL-3.0-or-later
"""Independently check original unconfigured-device packets and source queries."""
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


def inspect(rows, lane, log):
    guest = bytes([0x52, 0x54, 0, 0x12, 0x34, 0x10 + lane])
    control = bytes([2, 0x55, 0x4e, 0x43, lane, 0])
    prefix = bytes([198, 18, lane + 1])
    own, other = bytes([10, 23, lane + 1, 2]), bytes([10, 23, 2 - lane, 2])
    expected = {(phase, kind) for phase in range(7) for kind in range(2)}
    source = lambda phase: b'\0' * 4 if phase == 0 else own if phase == 3 else other
    requests, replies, data, arp_requests, arp_replies = {}, {}, {}, {}, {}
    first, last = None, None
    for index, row in enumerate(rows):
        frame = row['frame']
        require(len(frame) >= 14, 'complete original Ethernet header')
        if frame[12:14] == b'\x88\xb5':
            require(len(frame) == 60 and frame[14:19] == b'UNC1' + bytes([lane]),
                    'unconfigured complete Ethernet barrier')
            phase, kind, reply = frame[19:22]
            key = phase, kind
            require(key in expected and reply in (0, 1), 'known unconfigured barrier phase')
            body = b'UNC1' + bytes([lane, phase, kind, reply]) + bytes(
                (n * 19 + phase * 7 + kind * 31 + lane) & 255 for n in range(22, 60))
            require(frame == (guest + control if reply else control + guest) + b'\x88\xb5' + body,
                    'unconfigured barrier bytes and hardware ownership')
            records = replies if reply else requests
            require(key not in records, 'one original unconfigured barrier per direction')
            records[key] = index
            if key == (6, 1) and reply:
                last = index
            first = index if first is None else min(first, index)
            continue
        arp = frame[12:14] == b'\x08\x06'
        ip = frame[12:14] == b'\x08\0'
        if arp:
            require(len(frame) >= 42, 'complete original ARP frame')
            operation = int.from_bytes(frame[20:22], 'big')
            target = frame[38:42] if operation == 1 else frame[28:32]
        elif ip:
            require(len(frame) >= 34, 'complete original IPv4 header')
            target = frame[30:34]
        else:
            continue
        if target[:3] != prefix:
            continue
        offset = target[3] - 10
        key = phase, kind = divmod(offset, 2)
        require(key in expected, 'owned unconfigured destination belongs to a required phase')
        mac = bytes([2, 0x55, 0x4e, 0x43, lane, 1 + offset])
        local = source(phase)
        first = index if first is None else min(first, index)
        if arp:
            require(operation in (1, 2) and frame[14:20] == b'\0\1\x08\0\x06\x04' and
                    not any(frame[42:]), 'unconfigured original ARP format')
            if operation == 1:
                require(frame[:14] == b'\xff' * 6 + guest + b'\x08\x06' and
                        frame[22:42] == guest + local + b'\0' * 6 + target,
                        'unconfigured ARP request retains selected source')
                arp_requests.setdefault(key, []).append(index)
            else:
                require(frame[:14] == guest + mac + b'\x08\x06' and
                        frame[22:42] == mac + target + guest + local and
                        len(arp_replies.get(key, [])) < len(arp_requests.get(key, [])),
                        'unconfigured ARP reply matches pending output and request')
                arp_replies.setdefault(key, []).append(index)
            continue
        total = int.from_bytes(frame[16:18], 'big')
        packet = frame[14:14 + total]
        require(total == (52 if kind else 60) and len(packet) == total and
                packet[:2] == b'\x45\0' and not checksum(packet[:20]) and
                packet[6:10] == b'\x40\0\x40' + bytes([1 if kind else 17]) and
                packet[12:20] == local + target and frame[:12] == mac + guest and
                not any(frame[14 + total:]), 'unconfigured original IP ownership and policy')
        body = packet[20:]
        if not kind:
            require(struct.unpack('!HHH', body[:6]) == (49200 + lane * 32 + phase, 48010, 40) and
                    not checksum(local + target + b'\0\x11\0\x28' + body),
                    'unconfigured original UDP ports, length and checksum')
            body = body[8:]
        required = bytearray((n * 23 + phase * 17 + kind * 11 + lane) & 255 for n in range(32))
        if kind:
            required[:8] = bytes([8, 0, 0, 0, 0x55, 0x43, lane, phase])
            struct.pack_into('!H', required, 2, checksum(required))
        else:
            required[:8] = bytes([0x55, 0x43, lane, phase, kind, 0, 0, 0])
        require(body == bytes(required) and key not in data,
                'one original exact unconfigured application datagram')
        data[key] = index
    require(set(requests) == set(replies) == set(data) == set(arp_requests) == set(arp_replies) == expected,
            'all fourteen original source, ARP, datagram and barrier cases')
    previous = -1
    for phase in range(7):
        for kind in range(2):
            key = phase, kind
            require(previous < requests[key] < replies[key] and previous < data[key] < replies[key] and
                    all(previous < request < reply < data[key]
                        for request, reply in zip(arp_requests[key], arp_replies[key])) and
                    len(arp_requests[key]) == len(arp_replies[key]),
                    'owned ARP resolves before actual data and acknowledgement in execution order')
            previous = replies[key]
    require(first is not None and last is not None, 'bounded original unconfigured workload')
    for row in rows[first:last + 1]:
        frame = row['frame']
        if frame[6:12] == guest and frame[12:14] == b'\x08\0':
            require(len(frame) >= 34 and frame[30:33] == prefix,
                    'no extra guest IPv4 output during unconfigured phases')
    values = re.findall(r'^IPV4_UNCONFIGURED_SOURCE index=' + str(lane + 1) +
                        r' phase=(\d+) kind=(\d+) source=([0-9a-f]{8}) explicit=(\d+) mtu=(\d+)\r?$',
                        log, re.M)
    require(values == [(str(phase), str(kind), source(phase).hex(),
                        str(int(phase in (2, 4, 6))), '1500')
                       for phase in range(7) for kind in range(2)],
            'all original connected source and MTU queries in execution order')
    require(len(re.findall(r'^IPV4_UNCONFIGURED_PASS index=' + str(lane + 1) +
                           r' protocols=2 datagrams=14\r?$', log, re.M)) == 1,
            'actual unconfigured client completed both protocols')
    return dict(passed=True, lane=lane, datagrams=14, source_queries=14, barriers=14,
                arp_exchanges=sum(map(len, arp_requests.values()))), dict(
                    data=data, requests=requests, replies=replies,
                    arp_requests=arp_requests, arp_replies=arp_replies)


def verify_capture(path, lane, log_path, damage_archive=None, native=False):
    path, log_path = Path(path), Path(log_path)
    original, original_log = path.read_bytes(), log_path.read_bytes()
    rows, text = read_capture(path), original_log.decode(errors='replace')
    if native:
        bind_clocks(rows, path.with_suffix('.clocks.jsonl'))
    result, proof = inspect(rows, lane, text)
    if damage_archive:
        names = ['missing-data', 'duplicate-data', 'wrong-source', 'wrong-destination',
                 'wrong-next-hop', 'payload', 'IP-checksum', 'UDP-checksum', 'missing-ARP-request',
                 'missing-ARP-reply', 'ARP-source', 'ARP-target', 'missing-barrier', 'early-barrier',
                 'barrier-bytes', 'false-source-query', 'reordered-source-queries', 'missing-success']
        rejected = []
        with zipfile.ZipFile(damage_archive, 'x', compression=zipfile.ZIP_DEFLATED, compresslevel=1) as archive:
            for name in names:
                changed, log = copy.deepcopy(rows), text
                target = proof['data'][0, 0]
                if name.startswith('missing-ARP'):
                    del changed[proof['arp_requests' if name.endswith('request') else 'arp_replies'][0, 0][0]]
                elif name == 'missing-data':
                    del changed[target]
                elif name == 'duplicate-data':
                    changed.insert(target, copy.deepcopy(changed[target]))
                elif name == 'missing-barrier':
                    del changed[proof['replies'][0, 0]]
                elif name == 'early-barrier':
                    frame = changed.pop(proof['replies'][0, 0])
                    changed.insert(target, frame)
                elif name == 'false-source-query':
                    log = log.replace(f'index={lane + 1} phase=0 kind=0 source=00000000',
                                      f'index={lane + 1} phase=0 kind=0 source=7f000001')
                elif name == 'reordered-source-queries':
                    pattern = r'^IPV4_UNCONFIGURED_SOURCE index=' + str(lane + 1) + r' phase=0 .*\r?$'
                    lines = re.findall(pattern, log, re.M)
                    require(len(lines) == 2, 'two original source query lines to damage')
                    log = re.sub(pattern, lambda match: lines.pop(), log, flags=re.M)
                elif name == 'missing-success':
                    log = log.replace(f'IPV4_UNCONFIGURED_PASS index={lane + 1} protocols=2 datagrams=14', '')
                else:
                    if name.startswith('ARP-'):
                        target = proof['arp_replies'][0, 0][0]
                    elif name == 'barrier-bytes':
                        target = proof['replies'][0, 0]
                    frame = bytearray(changed[target]['frame'])
                    offset = {'wrong-source': 29, 'wrong-destination': 33, 'wrong-next-hop': 5,
                              'payload': 60, 'IP-checksum': 24, 'UDP-checksum': 40,
                              'ARP-source': 31, 'ARP-target': 41, 'barrier-bytes': 59}[name]
                    frame[offset] ^= 1
                    if name in ('wrong-source', 'wrong-destination', 'payload'):
                        frame[24:26] = b'\0\0'
                        struct.pack_into('!H', frame, 24, checksum(frame[14:34]))
                        frame[40:42] = b'\0\0'
                        struct.pack_into('!H', frame, 40,
                                         checksum(frame[26:34] + b'\0\x11\0\x28' + frame[34:74]) or 65535)
                    changed[target]['frame'] = bytes(frame)
                require(changed != rows or log != text, 'damage changes original evidence')
                archive.writestr(name + '.pcap', encode_capture(changed))
                archive.writestr(name + '.log', log)
                try:
                    inspect(changed, lane, log)
                except ValueError as error:
                    rejected.append(dict(name=name, reason=str(error)))
                else:
                    raise ValueError('damaged unconfigured evidence accepted: ' + name)
            archive.writestr('rejections.json', json.dumps(rejected, indent=2) + '\n')
        result.update(damaged_rejected=len(rejected), archive=str(damage_archive),
                      archive_sha256=hashlib.sha256(Path(damage_archive).read_bytes()).hexdigest())
    require(path.read_bytes() == original and log_path.read_bytes() == original_log,
            'original unconfigured packet and client evidence remains unchanged')
    result.update(capture_sha256=hashlib.sha256(original).hexdigest(),
                  log_sha256=hashlib.sha256(original_log).hexdigest())
    return result
