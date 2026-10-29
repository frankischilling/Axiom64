# SPDX-License-Identifier: GPL-3.0-or-later
"""Independently audit original IPv4 alias frames and damaged evidence."""
import argparse
from pathlib import Path
import copy
import hashlib
import json
import re
import struct
import zipfile

from ipv4_path_mtu_capture import read_capture, encode, checksum, require


def inspect(rows, lane, log, query_model='release'):
    require(query_model in ('release', 'read-only'), 'known alias query contract')
    require(len(re.findall(r'^IPV4_ALIAS_QUERY_MODEL index=' + str(lane + 1) +
                          ' release=' + str(int(query_model == 'release')) + r'\r?$', log, re.M)) == 1,
            'alias client query contract matches the selected kernel model')
    require(len(re.findall(r'^IPV4_ALIAS_RETIRED_DEVICE index=' + str(lane + 1) +
                          r' mtu=1500\r?$', log, re.M)) == 1, 'retired queries preserve live device MTU')
    retired = re.findall(r'^IPV4_ALIAS_RETIRED index=' + str(lane + 1) +
                         r' query=(\d+) mtu=(-?\d+)\r?$', log, re.M)
    require([int(n) for n, _ in retired] == list(range(34)), 'every retired query in execution order')
    expected = ([1500, -107, -107, -107, 1500, -107] + [-107] * 4 + [1500, -107] * 3 + [-107]
                if query_model == 'release' else
                [1500] * 6 + [1500, 1500, -107, 1500] + [1500] * 6 + [-107]) * 2
    require(all(int(value) == target or (query_model == 'read-only' and target == 1500 and int(value) == 68)
                for (_, value), target in zip(retired, expected)), 'exact retired destination MTUs')
    for n in range(1, len(retired)):
        if n % 17 in (1, 2, 5, 11, 13, 15):
            require((int(retired[n - 1][1]), int(retired[n][1])) != (68, 1500),
                    'retired shared destination cannot recover without a route refresh')
    guest = bytes.fromhex('5254001234') + bytes([16 + lane])
    host = bytes.fromhex('02414c4941') + bytes([lane])
    primary = bytes([10, 23, lane + 1, 2])
    alias = primary[:3] + b'\x03'
    other = bytes([10, 33, lane + 1, 2])
    remotes = [primary[:3] + b'\x09', other[:3] + b'\x09']
    sources = [alias, other, other, primary]
    requests, replies, host_echo, kernel_echo = {}, {}, [], []
    arp_out, arp_in, arp_host, arp_guest = [], [], [], []
    for position, row in enumerate(rows):
        frame = row['frame']
        owned = host in (frame[:6], frame[6:12])
        outgoing_arp = frame[6:12] == guest and frame[12:14] == b'\x08\x06'
        if owned or outgoing_arp:
            require(len(frame) >= 42, 'complete alias Ethernet protocol header')
        if owned:
            require(frame[12:14] in (b'\x08\x06', b'\x08\0'), 'owned alias Ethernet protocol')
        if len(frame) < 42:
            continue
        if frame[12:14] == b'\x08\x06':
            sender, target = frame[28:32], frame[38:42]
            if not owned and sender not in remotes and target not in remotes:
                continue
            require(frame[14:20] == b'\0\x01\x08\0\x06\x04' and not any(frame[42:]),
                    'alias ARP format and padding')
            operation = int.from_bytes(frame[20:22], 'big')
            require(operation in (1, 2), 'alias ARP operation')
            outgoing = frame[6:12] == guest
            origin, destination = (guest, host) if outgoing else (host, guest)
            require(frame[6:12] == origin and frame[22:28] == origin, 'ARP sender hardware ownership')
            if operation == 1:
                require(frame[:6] == b'\xff' * 6 and frame[32:38] == b'\0' * 6,
                        'ARP request target hardware')
            else:
                require(frame[:6] == destination and frame[32:38] == destination,
                        'ARP reply target hardware')
            item = dict(index=position, sender=sender, target=target)
            if outgoing and operation == 1:
                require((sender in (alias, primary) and target == remotes[0]) or
                        (sender == other and target == remotes[1]), 'ARP selected local source')
                arp_out.append(item)
            elif not outgoing and operation == 2:
                require(sender in remotes and target in sources, 'peer ARP reply tuple')
                arp_in.append(item)
            else:
                require((sender, target) == ((alias, remotes[0]) if outgoing else (remotes[0], alias)),
                        'guest-owned alias ARP tuple')
                (arp_guest if outgoing else arp_host).append(item)
            continue
        if frame[12:14] != b'\x08\0':
            continue
        packet = frame[14:]
        if not (host in (frame[:6], frame[6:12]) or
                (packet[24:26] in (b'AL', b'AH') and
                 (packet[12:16] in remotes or packet[16:20] in remotes))):
            continue
        total = int.from_bytes(packet[2:4], 'big')
        require(total == 84 and len(packet) >= total and packet[:2] == b'\x45\0' and
                not checksum(packet[:20]) and packet[9] == 1 and
                packet[6:8] in (b'\0\0', b'\x40\0') and not any(packet[total:]),
                'complete original alias IPv4 packet')
        packet = packet[:total]
        body = packet[20:]
        require(not checksum(body) and body[1] == 0 and body[7] == lane, 'alias ICMP checksum and lane')
        require(body[:1] in (b'\0', b'\x08'), 'alias ICMP echo type')
        if body[4:6] == b'AL':
            case = body[6]
            require(case < 4, 'alias case range')
            outgoing = body[0] == 8
            local = sources[case]
            remote = local[:3] + b'\x09'
            expected = bytearray([8 if outgoing else 0, 0, 0, 0, 65, 76, case, lane])
            expected.extend((n * 17 + lane * 31 + case) & 255 for n in range(8, 64))
            struct.pack_into('!H', expected, 2, checksum(expected))
            table = requests if outgoing else replies
            require(case not in table and body == bytes(expected), 'one exact alias echo payload')
            table[case] = position
        else:
            require(body[4:6] == b'AH' and body[6] == 1 and body[8:] == bytes(range(8, 64)),
                    'exact unsolicited alias echo payload')
            outgoing = body[0] == 0
            local, remote = other, remotes[1]
            (kernel_echo if outgoing else host_echo).append(position)
        require(packet[12:20] == (local + remote if outgoing else remote + local), 'alias IP route tuple')
        require(frame[:12] == (host + guest if outgoing else guest + host), 'alias Ethernet direction')
        require(packet[8] == (64 if outgoing else 51), 'alias IP TTL')
    require(set(requests) == set(replies) == set(range(4)), 'all four alias request/reply pairs')
    order = [requests[n] for n in range(4)]
    require(order == sorted(order), 'alias transition order')
    for n in range(4):
        require(requests[n] < replies[n] and (n == 3 or replies[n] < requests[n + 1]),
                'guest acknowledged each alias transition')
        source, remote = sources[n], sources[n][:3] + b'\x09'
        record = (f'IPV4_ALIAS_WIRE index={lane + 1} case={n} source={source.hex()} '
                  f'destination={remote.hex()}')
        require(log.splitlines().count(record) == 1, 'exact client alias route observation')
    require(len(arp_out) >= 2 and len(arp_out) == len(arp_in), 'complete alias ARP resolutions')
    unmatched = list(arp_in)
    for request in arp_out:
        uses = [requests[n] for n in range(4) if request['sender'] == sources[n] and
                request['target'] == sources[n][:3] + b'\x09' and
                request['index'] < requests[n]]
        require(uses, 'each alias resolution has a later original data use')
        first_use = min(uses)
        matches = [r for r in unmatched if r['sender'] == request['target'] and
                   r['target'] == request['sender'] and
                   request['index'] < r['index'] < first_use]
        require(len(matches) == 1, 'one owned ARP reply precedes its original data use')
        unmatched.remove(matches[0])
    require(not unmatched, 'no orphan alias ARP replies')
    for case in (0, 1):
        require(any(r['sender'] == sources[case] and r['target'] == sources[case][:3] + b'\x09' and
                    r['index'] < requests[case] for r in arp_out), 'ARP uses each original alias source')
    require(len(arp_host) == len(arp_guest) == len(host_echo) == len(kernel_echo) == 1,
            'one guest-owned ARP and kernel echo reply')
    require(arp_host[0]['index'] < arp_guest[0]['index'] < replies[3] and
            host_echo[0] < kernel_echo[0] < replies[3], 'final barrier waits for guest-owned replies')
    marker = f'IPV4_ALIAS_PASS index={lane + 1} wire_cases=4 local_udp=3'
    require(log.splitlines().count(marker) == 1 and log.index(marker) > log.index(
        f'IPV4_ALIAS_WIRE index={lane + 1} case=3 '), 'complete alias client result')
    return dict(passed=True, lane=lane, wire_cases=4, arp_requests=len(arp_out), arp_replies=1,
                kernel_echo_replies=1, requests=requests, replies=replies,
                guest_arp_index=arp_guest[0]['index'], kernel_echo_index=kernel_echo[0])


def arp_damage(rows, lane, request_index, kind):
    changed = copy.deepcopy(rows)
    alias = bytes([10, 23, lane + 1, 3])
    remote = alias[:3] + b'\x09'
    requests = [n for n, row in enumerate(rows) if len(row['frame']) >= 42 and
                row['frame'][12:14] == b'\x08\x06' and row['frame'][20:22] == b'\0\x01' and
                row['frame'][28:32] == alias and row['frame'][38:42] == remote]
    replies = [n for n, row in enumerate(rows) if len(row['frame']) >= 42 and
               row['frame'][12:14] == b'\x08\x06' and row['frame'][20:22] == b'\0\x02' and
               row['frame'][28:32] == remote and row['frame'][38:42] == alias]
    require(len(requests) == len(replies) == 1, 'one original alias ARP damage seed')
    request, reply = requests[0], replies[0]
    require(request < reply < request_index, 'original ARP reply precedes its data use')
    if kind == 'late-arp-reply':
        changed[reply]['frame'], changed[request_index]['frame'] = (changed[request_index]['frame'],
                                                                changed[reply]['frame'])
    else:
        changed.insert(request + 1, copy.deepcopy(rows[request]))
        orphan = bytearray(rows[reply]['frame'])
        orphan[28:32] = bytes([10, 33, lane + 1, 9])
        orphan[38:42] = bytes([10, 23, lane + 1, 2])
        changed.append(dict(ns=rows[-1]['ns'], frame=bytes(orphan)))
    return changed


def fix_ip(frame):
    frame[24:26] = b'\0\0'
    struct.pack_into('!H', frame, 24, checksum(frame[14:34]))


def verify_capture(path, lane, log_path, damage_archive, query_model='release'):
    archive = damage_archive
    rows, log = read_capture(path), log_path.read_text()
    positive = inspect(rows, lane, log, query_model)
    positive['query_model'] = query_model
    original = {str(p): hashlib.sha256(p.read_bytes()).hexdigest() for p in (path, log_path)}
    classes = ['missing-request', 'missing-reply', 'wrong-source', 'cross-lane-mac',
               'bad-icmp-checksum', 'padding', 'oversized-total', 'wrong-payload',
               'transition-order', 'missing-arp-reply', 'wrong-arp-sender',
               'missing-kernel-reply', 'false-client-source', 'late-arp-reply', 'reused-arp-reply',
               'short-alias-ipv4', 'short-alias-arp', 'short-broadcast-arp',
               'foreign-arp-owned-mac', 'unknown-owned-type', 'false-retired-query', 'revived-retired-query']
    with zipfile.ZipFile(archive, 'x', compression=zipfile.ZIP_DEFLATED, compresslevel=6) as saved:
        for name in classes:
            changed, text = copy.deepcopy(rows), log
            selected = positive['requests'][1]
            if name == 'revived-retired-query':
                for query, value in enumerate((68, 1500, 68)):
                    pattern = (r'^IPV4_ALIAS_RETIRED index=' + str(lane + 1) + ' query=' +
                               str(query) + r' mtu=-?\d+\r?$')
                    text, count = re.subn(pattern,
                        f'IPV4_ALIAS_RETIRED index={lane + 1} query={query} mtu={value}',
                        text, count=1, flags=re.M)
                    require(count == 1, 'one original shared-destination query was damaged')
            elif name == 'false-retired-query':
                pattern = r'^IPV4_ALIAS_RETIRED index=' + str(lane + 1) + r' query=0 mtu=\d+\r?$'
                text, count = re.subn(pattern, f'IPV4_ALIAS_RETIRED index={lane + 1} query=0 mtu=1400',
                                      text, count=1, flags=re.M)
                require(count == 1, 'one original retired query was damaged')
            elif name in ('short-broadcast-arp', 'foreign-arp-owned-mac', 'unknown-owned-type'):
                if name == 'short-broadcast-arp':
                    frame = next(r['frame'][:41] for r in rows if len(r['frame']) >= 42 and
                                 r['frame'][12:14] == b'\x08\x06' and
                                 r['frame'][20:22] == b'\0\x01' and
                                 r['frame'][28:32] == bytes([10, 23, lane + 1, 3]))
                elif name == 'foreign-arp-owned-mac':
                    frame = bytearray(rows[positive['guest_arp_index']]['frame'])
                    frame[28:32] = bytes([10, 88, lane + 1, 3])
                    frame[38:42] = bytes([10, 88, lane + 1, 9])
                    frame[14:16] = b'\0\x02'
                else:
                    frame = bytearray(rows[positive['requests'][0]]['frame'])
                    frame[12:14] = b'\x08\x07'
                changed.append(dict(ns=rows[-1]['ns'], frame=bytes(frame)))
            elif name in ('short-alias-ipv4', 'short-alias-arp'):
                index = positive['requests'][0] if name == 'short-alias-ipv4' else positive['guest_arp_index']
                size = 34 if name == 'short-alias-ipv4' else 41
                changed.append(dict(ns=rows[-1]['ns'], frame=rows[index]['frame'][:size]))
            elif name in ('late-arp-reply', 'reused-arp-reply'):
                changed = arp_damage(rows, lane, positive['requests'][0], name)
            elif name in ('missing-request', 'missing-reply', 'missing-arp-reply', 'missing-kernel-reply'):
                index = (positive['requests'][0] if name == 'missing-request' else
                         positive['replies'][3] if name == 'missing-reply' else
                         positive['guest_arp_index'] if name == 'missing-arp-reply' else
                         positive['kernel_echo_index'])
                del changed[index]
            elif name == 'transition-order':
                a, b = positive['requests'][0], positive['requests'][1]
                changed[a]['frame'], changed[b]['frame'] = changed[b]['frame'], changed[a]['frame']
            elif name == 'false-client-source':
                text = text.replace(f'case=2 source={bytes([10,33,lane+1,2]).hex()}', 'case=2 source=00000000')
            else:
                if name == 'wrong-arp-sender':
                    selected = positive['guest_arp_index']
                frame = bytearray(changed[selected]['frame'])
                if name == 'wrong-source':
                    frame[29] ^= 1
                    fix_ip(frame)
                elif name == 'cross-lane-mac':
                    frame[11] ^= 1
                elif name == 'bad-icmp-checksum':
                    frame[36] ^= 1
                elif name == 'padding':
                    frame += b'\x01'
                elif name == 'oversized-total':
                    struct.pack_into('!H', frame, 16, 100)
                    fix_ip(frame)
                elif name == 'wrong-payload':
                    frame[50] ^= 1
                    frame[36:38] = b'\0\0'
                    struct.pack_into('!H', frame, 36, checksum(frame[34:98]))
                elif name == 'wrong-arp-sender':
                    frame[31] ^= 1
                changed[selected]['frame'] = bytes(frame)
            try:
                inspect(changed, lane, text, query_model)
            except ValueError as error:
                saved.writestr(name + '.pcap', encode(changed))
                saved.writestr(name + '.log', text)
                saved.writestr(name + '.rejection.txt', str(error) + '\n')
            else:
                raise AssertionError('damaged alias evidence accepted: ' + name)
    with zipfile.ZipFile(archive) as saved:
        require(saved.testzip() is None and len(saved.namelist()) == len(classes) * 3,
                'complete readable alias negative archive')
    require(all(hashlib.sha256(Path(n).read_bytes()).hexdigest() == v for n, v in original.items()),
            'original alias evidence unchanged')
    return dict(passed=True, lane=lane, wire_cases=4, damaged_rejected=len(classes),
                original_sha256=original, archive=str(archive),
                archive_sha256=hashlib.sha256(archive.read_bytes()).hexdigest())


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('capture', type=Path)
    parser.add_argument('--lane', type=int, choices=(0, 1), required=True)
    parser.add_argument('--log', type=Path, required=True)
    parser.add_argument('--query-model', choices=('release', 'read-only'), default='release')
    parser.add_argument('--damage-archive', type=Path, required=True)
    args = parser.parse_args()
    result = verify_capture(args.capture, args.lane, args.log, args.damage_archive, args.query_model)
    print(json.dumps(result))


if __name__ == '__main__':
    main()
