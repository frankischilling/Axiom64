# SPDX-License-Identifier: GPL-3.0-or-later
"""Audit real ten-minute PMTU expiry from original frames and socket results."""
import copy
import hashlib
import ipaddress
import json
from pathlib import Path
import re
import struct
import zipfile
from ipv4_expiry_capture import checksum, encode_capture, read_capture
from tcp_capture_clock import bind_native_clock


def require(value, reason):
    if not value:
        raise ValueError(reason)


def stamp(row):
    return row.get('monotonic_ns', row['ns'])


def destination_contract(log):
    require(log.count('IPV6_EXPIRY_DESTINATION_PASS queries=20 transports=2 aliases=2') == 1,
            'complete owned destination contract')
    queries = re.findall(r'^IPV6_EXPIRY_DESTINATION kind=(\d+) case=(\d+) value=(-?\d+) errno=(\d+)$', log, re.MULTILINE)
    require(len(queries) == 20, 'all cached destination query observations')
    for number, encoded in enumerate(queries):
        kind, case, value, error = map(int, encoded)
        expected_error = 107 if number % 10 in (0, 3, 6, 9) or number == 14 else 0
        require(kind == number // 10 + 2 and case == number and error == expected_error and
                value == (-1 if error else 65536), 'exact native cached destination lifetime')


def application(log):
    destination_contract(log)
    require(log.count('IPV6_EXPIRY_PASS adapters=2 paths=32 stages=7 lifetime_seconds=600 lower_delay_seconds=20') == 1
            and 'IPV6_EXPIRY_FAIL' not in log, 'complete actual expiry client')
    samples = re.findall(r'^IPV6_EXPIRY_SAMPLE lane=(\d+) case=(\d+) stage=(\d+) before=(-?\d+) after=(\d+) result=(-?\d+) errno=(\d+) async=(\d+) pending=(\d+)$', log, re.MULTILINE)
    require(len(samples) == 224, 'all 224 actual expiry socket observations')
    seen = set()
    for encoded in samples:
        lane, number, stage, before, after, result, error, asynchronous, pending = map(int, encoded)
        role = number % 4
        mtu = (1500 if role == 3 or stage in (0, 6) or stage == 5 and role != 2 else
               1280 if role in (1, 2) and stage >= 3 else 1400 if role < 2 else 1500)
        emitted = stage == 2 or mtu == 1500
        queried = (1400 if role == 0 else 1280) if number >= 8 and stage >= 5 and role != 3 else mtu
        wanted = (mtu if stage < 5 else -1, queried, 1440 if emitted else -1,
                  0 if emitted else 90, 90 if stage == 1 and role < 2 or stage == 3 and role < 3 else 0, 0)
        require(lane in (0, 1) and number in range(16) and stage in range(7) and
                (lane, number, stage) not in seen and
                (before, after, result, error, asynchronous, pending) == wanted,
                'exact MTU, actual send, asynchronous error and error consumption')
        seen.add((lane, number, stage))
    counts = re.findall(r'^IPV6_EXPIRY_LOOKUPS lane=(\d+) case=(\d+) reads=(\d+) sends=(\d+)$', log, re.MULTILINE)
    require(len(counts) == 32, 'all periodic lookup and ordinary send counts')
    inventory = {}
    for encoded in counts:
        lane, number, reads, sends = map(int, encoded)
        require(lane in (0, 1) and number in range(16) and (lane, number) not in inventory and
                115 <= reads <= 130 and sends == (reads if number % 4 else 0),
                'retained paths queried throughout the unchanged ten-minute lifetime')
        inventory[lane, number] = sends
    return inventory


def inspect_neighbor(frame, lane, pending):
    guest = bytes([0x52, 0x54, 0, 0x12, 0x34, 0x10 + lane])
    peer = bytes([2, 0x49, 0x50, 0x36, lane, 1])
    global_local = ipaddress.IPv6Address(f'2001:db8:{lane + 1}::2').packed
    link_local = ipaddress.IPv6Address('fe80::2').packed
    require(len(frame) == 86 and frame[12:14] == b'\x86\xdd' and
            frame[14:18] == b'\x60\0\0\0' and frame[18:22] == b'\0\x20\x3a\xff',
            'expiry ND bounds and lifetime')
    source, destination, body = frame[22:38], frame[38:54], frame[54:]
    require(body[0] in (135, 136) and body[1] == 0 and
            not checksum(source + destination + struct.pack('!I3xB', 32, 58) + body),
            'complete original neighbor checksum and code')
    target = body[8:24]
    number = target[-1] - 32
    local = link_local if number % 8 >= 4 else global_local
    remote = local[:-1] + bytes([32 + number]) if number in range(16) else None
    require(target == remote, 'expiry neighbor belongs to an exercised destination')
    if body[0] == 135:
        multicast = b'\xff\x02' + bytes(9) + b'\1\xff' + target[-3:]
        require(frame[6:12] == guest and source in (global_local, link_local) and
                (destination, frame[:6]) in ((target, peer), (multicast, b'\x33\x33\xff' + target[-3:])) and
                body[4:8] == bytes(4) and body[24:] == b'\1\1' + guest,
                'original multicast or unicast neighbor solicitation')
        pending.setdefault(target, []).append(source)
    else:
        requests = pending.get(target, [])
        require(requests and frame[:12] == guest + peer and source == target and
                destination == requests[0] and body[4:8] == b'\x60\0\0\0' and
                body[24:] == b'\2\1' + peer, 'original owned neighbor advertisement')
        requests.pop(0)
        if not requests:
            pending.pop(target)


def inspect(rows, lane, log, native=False):
    counts = application(log.replace('\r\n', '\n'))
    guest = bytes([0x52, 0x54, 0, 0x12, 0x34, 0x10 + lane])
    control = bytes([2, 0x49, 0x50, 0x36, lane, 0])
    peer = control[:-1] + b'\1'
    global_local = ipaddress.IPv6Address(f'2001:db8:{lane + 1}::2').packed
    link_local = ipaddress.IPv6Address('fe80::2').packed
    phase, waiting, ready = -1, None, False
    barriers, data, hints = {}, {}, {}
    heartbeats = {number: [] for number in range(16)}
    firmware, mld, nd = 0, 0, 0
    previous = None
    neighbor_requests = {}
    for index, row in enumerate(rows):
        frame = row['frame']
        require(len(frame) >= 14, 'complete expiry Ethernet envelope')
        if not (native and frame[12:14] == b'\x86\xdd' and len(frame) > 20 and frame[20] == 0):
            require(previous is None or stamp(row) >= previous, 'original ordered expiry packet clocks')
            previous = stamp(row)
        if frame[12:14] == b'\x88\xbc':
            require(len(frame) == 60 and frame[14:19] == b'IP6X' + bytes([lane]) and
                    not any(frame[21:]), 'exact expiry barrier bytes')
            number, reply = frame[19:21]
            if not reply:
                require(frame[:12] == control + guest and waiting is None and
                        number == phase + 1 and number <= 6, 'ordered owned expiry requests')
                phase, waiting = number, number
                barriers[number, 0] = index
            else:
                require(frame[:12] == guest + control and reply == 1 and waiting == number,
                        'one exact expiry acknowledgement')
                barriers[number, 1] = index
                waiting = None
                ready = True
            continue
        if not ready and not native:
            require(firmware < 256 and frame[6:12] == guest, 'bounded guest firmware prelude')
            firmware += 1
            continue
        require(frame[12:14] == b'\x86\xdd' and len(frame) >= 54 and
                frame[14:18] == b'\x60\0\0\0', 'original expiry IPv6 header')
        size, protocol, hop = struct.unpack_from('!HBB', frame, 18)
        require(len(frame) >= 54 + size, 'complete expiry IPv6 payload')
        source, destination, body = frame[22:38], frame[38:54], frame[54:54 + size]
        if native and protocol == 0:
            require(frame[:12] == b'\x33\x33\0\0\0\x16' + guest and hop == 1 and
                    body[:8] == b'\x3a\0\5\2\0\0\1\0' and body[8:10] == b'\x8f\0' and
                    source in (bytes(16), link_local) and
                    destination == ipaddress.IPv6Address('ff02::16').packed and
                    not checksum(source + destination + struct.pack('!I3xB', len(body) - 8, 58) + body[8:]),
                    'separately counted original native multicast reports')
            mld += 1
            continue
        require(ready and protocol in (17, 58) and
                not checksum(source + destination + struct.pack('!I3xB', size, protocol) + body),
                'complete original expiry transport checksum')
        if protocol == 58 and body[:1] in (b'\x87', b'\x88'):
            inspect_neighbor(frame, lane, neighbor_requests)
            nd += 1
            continue
        require(hop == 64, 'original expiry hop limit')
        if frame[6:12] == peer:
            require(protocol == 58 and frame[:6] == guest and body[:2] == b'\2\0' and
                    len(body) == 56 and waiting in (2, 3), 'bounded live Packet Too Big quote')
            number = body[47] - 32
            original_stage = 0 if waiting == 2 else 2
            require(number in range(16) and (number, original_stage) in data,
                    'quote identifies an actual earlier datagram')
            original = rows[data[number, original_stage]]['frame']
            require(source == original[38:53] + b'\xfa' and destination == original[22:38] and
                    body[8:] == original[14:62], 'exact original IPv6 and transport quote bytes')
            key = number, waiting
            ordinal = len(hints.get(key, []))
            role = number % 4
            expected = (((1400,) if role < 2 else ()) if waiting == 2 else
                        (1400, 1450, 1279) if role == 0 else (1280,) if role < 3 else ())
            require(ordinal < len(expected) and int.from_bytes(body[4:8], 'big') == expected[ordinal],
                    'exact lower, equal, increasing and subminimum PTB inventory')
            hints.setdefault(key, []).append(index)
            continue
        require(frame[:12] == peer + guest, 'expiry data source and destination MAC ownership')
        payload = body[8:] if protocol == 17 else body
        offset = 0 if protocol == 17 else 4
        require(len(payload) >= 16 and payload[offset:offset + 4] == b'P6EX', 'tagged original expiry application bytes')
        number, stage, link, reserved = payload[offset + 4:offset + 8]
        require(number in range(16) and link == lane and not reserved and
                protocol == (17 if number < 8 else 58), 'expiry socket and protocol ownership')
        local = link_local if number % 8 >= 4 else global_local
        require(source == local and destination == local[:-1] + bytes([32 + number]),
                'expiry address and scope ownership')
        expected = bytearray((n * 29 + number * 7 + stage * 11 + lane) & 255 for n in range(len(payload)))
        expected[offset:offset + 8] = b'P6EX' + bytes([number, stage, lane, 0])
        if protocol == 17:
            require(struct.unpack_from('!HHH', body) == (49000 + number, 50000 + number, len(body)) and
                    body[6:8] != bytes(2) and payload == expected, 'all original UDP ports and application bytes')
        else:
            require(payload[:2] == b'\x81\0' and payload[4:] == expected[4:], 'all original raw ICMPv6 application bytes')
        if stage == 250:
            require(number % 4 != 0 and len(payload) == 16 and waiting is None and phase in (2, 3, 4, 5),
                    'ordinary traffic on a retained path during observation')
            heartbeats[number].append(index)
        else:
            role = number % 4
            allowed = stage in (0, 2, 6) or role == 3 or stage == 1 and role == 2 or stage == 5 and role < 2
            late_neighbor = (stage, phase, waiting) in ((0, 2, 2), (2, 3, 3))
            require(stage in range(7) and allowed and len(payload) == 1440 and
                    (late_neighbor or waiting is None and phase == (1, 2, 2, 3, 3, 4, 5)[stage]) and
                    (number, stage) not in data,
                    'only the actual successful stage sends appear on the wire')
            data[number, stage] = index
    expected_data = {(n, s) for n in range(16) for s in range(7)
                     if s in (0, 2, 6) or n % 4 == 3 or s == 1 and n % 4 == 2 or s == 5 and n % 4 < 2}
    require(ready and phase == 6 and waiting is None and set(data) == expected_data and
            len(barriers) == 14 and sum(map(len, hints.values())) == 28, 'complete original expiry wire inventory')
    intervals = []
    for number in range(16):
        beats = heartbeats[number]
        require(len(beats) == counts[lane, number], 'ordinary actual wire sends match the client count')
        if number % 4:
            require(stamp(rows[beats[-1]]) - stamp(rows[beats[0]]) >= 580000000000,
                    'ordinary traffic spans the unchanged ten-minute observation')
        role = number % 4
        if role == 3:
            continue
        second = hints[number, 3][0]
        first = hints[number, 2][0] if role < 2 else second
        initial_anchor = hints[number - role, 2][0]
        require(stamp(rows[second]) - stamp(rows[initial_anchor]) >= 20000000000,
                'fresh quoted feedback follows a real twenty-second delay')
        require((role == 2 or stamp(rows[barriers[2, 1]]) - stamp(rows[first]) >= 50000000) and
                stamp(rows[barriers[3, 1]]) - stamp(rows[hints[number, 3][-1]]) >= 50000000,
                'actual hint delivery precedes socket checks')
        # Existing exceptions retain their first expiry even after a lower hint.
        # A separate path first learned at stage three owns a later deadline.
        if role < 2:
            require(597000000000 <= stamp(rows[barriers[4, 0]]) - stamp(rows[first]) < 600000000000,
                    'initial learned PMTU still blocks before its real deadline')
            expired = data[number, 5]
            require(600000000000 <= stamp(rows[expired]) - stamp(rows[first]) < 610000000000 and
                    stamp(rows[expired]) - stamp(rows[second]) < 600000000000,
                    'lower, equal, increasing and subminimum hints cannot extend an existing expiry')
            intervals.append((first, expired))
        else:
            require(580000000000 <= stamp(rows[barriers[5, 0]]) - stamp(rows[second]) < 600000000000,
                    'the independently learned path remains blocked beyond other paths expiry')
            expired = data[number, 6]
            require(600000000000 <= stamp(rows[expired]) - stamp(rows[second]) < 610000000000,
                    'independently learned PMTU retains its own complete ten-minute lifetime')
            intervals.append((second, expired))
    return dict(passed=True, lane=lane, paths=16, samples=112, datagrams=len(data),
                hints=28, real_expiry_intervals=len(intervals), firmware_frames=firmware,
                native_MLD_reports=mld, neighbor_frames=nd), dict(data=list(data.values()),
                hints=[i for values in hints.values() for i in values], intervals=intervals)


def verify_capture(path, lane, log_path, archive, native=False, statistics=None, interface_index=None):
    path, log_path = Path(path), Path(log_path)
    original, original_log = path.read_bytes(), log_path.read_bytes()
    rows, log = read_capture(path), original_log.decode(errors='replace')
    clock = None
    if native:
        selected = []
        for row in rows:
            if row['frame'][12:14] == b'\x86\xdd' and len(row['frame']) > 20 and row['frame'][20] == 0:
                continue
            row['stamp'] = row['ns'] // 1000
            selected.append(row)
        clock = bind_native_clock(path, selected, statistics)
    result, proof = inspect(rows, lane, log, native)
    rejected = []
    names = ('missing-data', 'duplicate-data', 'missing-hint', 'wrong-quote', 'wrong-port',
             'wrong-checksum', 'early-expiry', 'late-expiry', 'wrong-MTU', 'wrong-errno',
             'missing-sample', 'missing-heartbeat', 'missing-lookup', 'wrong-cached-getter',
             'foreign-neighbor-source', 'wrong-neighbor-recipient')
    with zipfile.ZipFile(archive, 'w', zipfile.ZIP_DEFLATED) as saved:
        for name in names:
            changed, changed_log = copy.deepcopy(rows), log
            index = proof['data'][0]
            if name == 'missing-data':
                del changed[index]
            elif name == 'duplicate-data':
                changed.insert(index, copy.deepcopy(changed[index]))
            elif name == 'missing-hint':
                del changed[proof['hints'][0]]
            elif name in ('wrong-quote', 'wrong-port', 'wrong-checksum'):
                index = proof['hints'][0] if name == 'wrong-quote' else index
                frame = bytearray(changed[index]['frame'])
                frame[-1 if name == 'wrong-quote' else 55 if name == 'wrong-port' else 60] ^= 1
                changed[index]['frame'] = bytes(frame)
            elif name in ('early-expiry', 'late-expiry'):
                start, index = proof['intervals'][0]
                duration = 599000000000 if name == 'early-expiry' else 611000000000
                changed[index]['ns'] = changed[start]['ns'] + duration
                changed[index]['monotonic_ns'] = stamp(changed[start]) + duration
            elif name in ('wrong-MTU', 'wrong-errno', 'missing-sample'):
                wanted = f'IPV6_EXPIRY_SAMPLE lane={lane} case=0 stage=1 before=1400 after=1400 result=-1 errno=90 async=90 pending=0'
                replacement = (wanted.replace('after=1400', 'after=1500') if name == 'wrong-MTU' else
                               wanted.replace('errno=90', 'errno=0') if name == 'wrong-errno' else '')
                require(wanted in changed_log, 'damage targets an actual original sample')
                changed_log = changed_log.replace(wanted, replacement, 1)
            elif name == 'wrong-cached-getter':
                wanted = f'IPV6_EXPIRY_SAMPLE lane={lane} case=8 stage=5 before=-1 after=1400 result=1440 errno=0 async=0 pending=0'
                require(wanted in changed_log, 'damage targets the actual expired raw cached getter')
                changed_log = changed_log.replace(wanted, wanted.replace('after=1400', 'after=1500'), 1)
            elif name == 'missing-heartbeat':
                index = next(i for i, row in enumerate(changed) if b'P6EX\x01\xfa' in row['frame'])
                del changed[index]
            elif name in ('foreign-neighbor-source', 'wrong-neighbor-recipient'):
                wanted = 135 if name == 'foreign-neighbor-source' else 136
                index = next(i for i, row in enumerate(changed) if len(row['frame']) == 86 and
                             row['frame'][20] == 58 and row['frame'][54] == wanted)
                frame = bytearray(changed[index]['frame'])
                if wanted == 135:
                    frame[22:38] = ipaddress.IPv6Address('2001:db8:ffff::2').packed
                else:
                    other = (ipaddress.IPv6Address(f'2001:db8:{lane + 1}::2').packed
                             if frame[38:40] == b'\xfe\x80' else
                             ipaddress.IPv6Address('fe80::2').packed)
                    frame[38:54] = other
                frame[56:58] = bytes(2)
                value = checksum(bytes(frame[22:54]) + struct.pack('!I3xB', 32, 58) + bytes(frame[54:]))
                frame[56:58] = value.to_bytes(2, 'big')
                changed[index]['frame'] = bytes(frame)
            else:
                changed_log = re.sub(rf'^IPV6_EXPIRY_LOOKUPS lane={lane} case=0 .*$', '', changed_log, count=1, flags=re.MULTILINE)
            saved.writestr(name + '.pcap', encode_capture(changed))
            saved.writestr(name + '.log', changed_log)
            try:
                inspect(changed, lane, changed_log, native)
            except ValueError as failure:
                rejected.append(dict(name=name, reason=str(failure)))
            else:
                raise ValueError('accepted damaged IPv6 expiry evidence: ' + name)
        saved.writestr('rejections.json', json.dumps(rejected, indent=2))
    require(path.read_bytes() == original and log_path.read_bytes() == original_log,
            'original expiry packets and client output remain unchanged')
    result.update(damaged_rejected=len(rejected), native_clock=clock,
                  original_sha256=hashlib.sha256(original).hexdigest(),
                  archive_sha256=hashlib.sha256(Path(archive).read_bytes()).hexdigest())
    return result
