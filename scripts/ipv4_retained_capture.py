# SPDX-License-Identifier: GPL-3.0-or-later
"""Check original retained-source packets independently of the live peer."""
import re
import struct
from ipv4_expiry_capture import checksum


def require(value, reason):
    if not value:
        raise ValueError(reason)


def inspect(rows, lane, log, query_model='release', native_cache=False):
    require(query_model in ('release', 'read-only'), 'known retained query model')
    guest = bytes([0x52, 0x54, 0, 0x12, 0x34, 0x10 + lane])
    control = bytes([2, 0x52, 0x53, 0x43, lane, 0])
    prefix = bytes([198, 18, 31 + lane])
    own, other = bytes([10, 23, lane + 1, 2]), bytes([10, 23, 2 - lane, 2])
    cases = []
    for phase in range(6):
        cases += [(phase, 2, 8), (phase, 2, 9)]
        cases += [(phase, kind, method) for kind in range(2) for method in range(8)]
    cases += [(6, 0, 0), (7, 0, 0), (7, 0, 7)]
    requests, replies, data = {}, {}, {}
    for index, row in enumerate(rows):
        frame = row['frame']
        if len(frame) < 14 or frame[12:14] != b'\x88\xb6':
            continue
        require(len(frame) == 60 and frame[14:19] == b'RSC1' + bytes([lane]),
                'retained complete original barrier')
        phase, kind, method, reply = frame[19:23]
        key = phase, kind, method
        require(key in cases and reply in (0, 1), 'retained required barrier case')
        expected = ((guest + control) if reply else (control + guest)) + b'\x88\xb6RSC1'
        expected += bytes([lane, phase, kind, method, reply]) + bytes(
            (n * 13 + phase * 7 + kind * 31 + method * 17 + lane) & 255
            for n in range(23, 60))
        require(frame == expected, 'retained original barrier bytes and hardware ownership')
        records = replies if reply else requests
        require(key not in records, 'one original retained barrier in each direction')
        records[key] = index
    require(set(requests) == set(replies) == set(cases), 'all 111 retained barriers')
    previous = -1
    native_zero, native_preferred = 0, 0
    resolved = {}
    arp_requests, arp_replies = 0, 0
    first = min(requests[cases[0]], replies[cases[0]])
    for key in cases:
        phase, kind, method = key
        require(previous < requests[key] < replies[key], 'retained barrier execution order')
        preferred = {0: b'\0' * 4, 1: other, 2: own, 3: other, 4: b'\0' * 4, 5: other}
        local = (other if phase == 7 else
                 b'\0' * 4 if phase == 6 or not kind and method in (0, 1, 2, 3, 7)
                 else preferred[phase])
        if kind == 2:
            local = preferred[phase] if method == 8 else b'\0' * 4
        variable_source = (phase < 6 and native_cache and kind != 1 and
                           (kind == 2 or method in (0, 1, 2, 3, 7)))
        announced = local if any(local) else preferred.get(phase, b'\0' * 4)
        target = prefix + bytes([12 if phase == 7 else 13 if kind == 2 else
                                (20 if method == 6 else 10) + kind])
        mac = control[:5] + target[3:]
        pending = []
        for index in range(previous + 1, replies[key]):
            frame = rows[index]['frame']
            require(len(frame) >= 14, 'complete retained Ethernet header')
            if frame[12:14] == b'\x08\x06' and len(frame) >= 42:
                operation = int.from_bytes(frame[20:22], 'big')
                remote = frame[38:42] if operation == 1 else frame[28:32]
                if remote[:3] != prefix:
                    continue
                require(phase != 6 and remote == target and
                        frame[14:20] == b'\0\1\x08\0\x06\x04' and not any(frame[42:]),
                        'retained owned ARP target and format')
                if operation == 1:
                    require(frame[:14] == b'\xff' * 6 + guest + b'\x08\x06' and
                            frame[22:42] == guest + announced + b'\0' * 6 + target,
                            'retained ARP source preserves an assigned IP source or selects an address')
                    pending.append(index)
                    arp_requests += 1
                else:
                    require(operation == 2 and pending and frame[:14] == guest + mac + b'\x08\x06' and
                            frame[22:42] == mac + target + guest + announced,
                            'retained ARP reply is owned by an original request')
                    pending.pop(0)
                    resolved[target] = index
                    arp_replies += 1
                first = min(first, index)
            if frame[12:14] != b'\x08\0' or frame[6:12] != guest:
                continue
            # The gateway and fresh-source workload ends before the first retained
            # case. Other packets may precede it in the complete original capture.
            if previous < 0 and (len(frame) < 34 or frame[30:33] != prefix):
                continue
            require(phase != 6 and len(frame) >= 34 and key not in data,
                    'removed source emits nothing; other cases emit exactly one original datagram')
            packet = frame[14:14 + int.from_bytes(frame[16:18], 'big')]
            raw = kind == 1
            if variable_source:
                require(packet[12:16] in (b'\0' * 4, preferred[phase]),
                        'retained native UDP cache source')
                local = packet[12:16]
                if any(preferred[phase]):
                    native_zero += not any(local)
                    native_preferred += any(local)
            require(len(packet) == (52 if raw else 60) and
                    int.from_bytes(packet[2:4], 'big') == len(packet) and
                    packet[:2] == b'\x45\0' and not checksum(packet[:20]) and
                    packet[6:10] == b'\x40\0\x40' + bytes([1 if raw else 17]) and
                    packet[12:20] == local + target and frame[:12] == mac + guest and
                    not any(frame[14 + len(packet):]) and target in resolved and
                    resolved[target] < index and not pending,
                    'retained original source, header, policy, next hop and resolved ownership')
            body = packet[20:]
            if not raw:
                require(struct.unpack('!HHH', body[:6]) ==
                        (49300 + lane * 32 + (2 if kind == 2 else phase == 7), 48010, 40) and
                        not checksum(local + target + b'\0\x11\0\x28' + body),
                        'retained UDP pseudoheader, ports and lengths')
                body = body[8:]
            expected = bytearray((n * 23 + phase * 17 + kind * 11 + method * 7 + lane) & 255
                                 for n in range(32))
            if raw:
                expected[:8] = bytes([8, 0, 0, 0, 0x52, 0x53, phase, method])
                struct.pack_into('!H', expected, 2, checksum(expected))
            else:
                expected[:8] = bytes([0x52, 0x53, lane, phase, kind, method, 0, 0])
            require(body == bytes(expected), 'retained original application payload')
            data[key] = index
            first = min(first, index)
        require(not pending and (key in data) == (phase != 6),
                'retained original data and complete ARP pairs precede acknowledgement')
        previous = replies[key]
    if native_cache:
        require(native_zero and native_preferred, 'native unnamed output observes both cache source outcomes')
    accepted = set(data.values())
    for index, row in enumerate(rows):
        frame = row['frame']
        if len(frame) >= 14 and frame[12:14] == b'\x08\0' and frame[6:12] == guest:
            if first <= index <= previous or len(frame) >= 34 and frame[30:33] == prefix:
                require(index in accepted, 'no extra original IP output during retained-source cases')
    values = re.findall(r'^IPV4_RETAINED_SOURCE index=' + str(lane + 1) +
                        r' phase=(\d+) kind=(\d+) method=(\d+) local=([0-9a-f]{8})\r?$', log, re.M)
    require(values == [(str(p), str(k), str(m), other.hex() if p == 7 else '00000000')
                       for p, k, m in cases if p != 6], 'retained actual socket names in order')
    limits = re.findall(r'^IPV4_RETAINED_REMOVED index=' + str(lane + 1) +
                        r' sendto=101 sendmsg=101 cache=(\d+),107\r?$', log, re.M)
    require(len(limits) == 1 and int(limits[0]) in
            ((1500,) if query_model == 'release' else (1500, 68)),
            'retained source errors and actual retired destination limit')
    for marker in [f'IPV4_RETAINED_QUERY_MODEL index={lane + 1} model={query_model}',
                   f'IPV4_RETAINED_PASS index={lane + 1} protocols=2 phases=6 methods=8 datagrams=110']:
        require(len(re.findall('^' + re.escape(marker) + r'\r?$', log, re.M)) == 1,
                'retained actual errors, shared cache and client completion')
    return dict(passed=True, lane=lane, datagrams=110, barriers=111,
                arp_requests=arp_requests, arp_replies=arp_replies,
                methods=8, phases=6, shared_description=True, query_model=query_model,
                retired_MTU=int(limits[0]), native_cache_sources=dict(zero=native_zero, preferred=native_preferred)), dict(
                    data=data, requests=requests, replies=replies)
