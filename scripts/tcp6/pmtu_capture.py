# SPDX-License-Identifier: GPL-3.0-or-later
"""Independently reconstruct TCP6 quoted errors, byte streams and route metrics."""
import hashlib
import ipaddress
import struct
import copy
import json
from pathlib import Path
import tempfile
import zipfile
from functools import lru_cache
from ipv4_expiry_capture import read_capture, encode_capture, checksum
from tcp6.capture import require

SIZE, CASES, MASK = 4096, 22, 0xffffffff


@lru_cache(maxsize=88)
def expected(lane, scenario, direction):
    return bytes(((n * 29) ^ (n >> 7) ^ (lane * 53) ^ (scenario * 97) ^ (direction * 41)) & 255
                 for n in range(SIZE))


def inspect(rows, lane, log, native=False):
    require(log.splitlines().count('TCP6_PMTU_PASS lanes=2 cases_each=22 bytes_each=4096') == 1,
            'one actual complete PMTU client')
    guest = bytes([0x52, 0x54, 0, 0x12, 0x34, 0x10 + lane])
    peer = bytes([2, 0x41, 0x58, 0x54, 0x43, lane])
    control = bytes([2, ord('I'), ord('P'), ord('6'), lane, 0])
    local = ipaddress.IPv6Address(f'2001:db8:{lane + 1}::2').packed
    requests, replies, flows = {}, {}, {}
    notices = {n: [] for n in range(CASES)}
    for index, row in enumerate(rows):
        frame = row['frame']
        if frame[12:14] == b'\x88\xc2':
            require(len(frame) == 60 and frame[14:19] == b'IP6M' + bytes([lane]) and
                    frame[19] <= CASES * 3 and frame[20] in (0, 1) and not any(frame[21:]),
                    'complete original phase envelope')
            reply = frame[20]
            require(frame[:12] == (guest + control if reply else control + guest), 'phase interface owner')
            book = replies if reply else requests
            require(frame[19] not in book, 'unique PMTU phase')
            book[frame[19]] = index
            continue
        if 0 not in requests and not native:
            require(index < 256 and frame[6:12] == guest, 'bounded original firmware prelude')
            continue
        require(frame[12:14] == b'\x86\xdd' and len(frame) >= 54, 'complete IPv6 workload')
        ip = frame[14:]
        length = int.from_bytes(ip[4:6], 'big')
        require(ip[0] >> 4 == 6 and 40 + length <= len(ip), 'IPv6 declared payload bounds')
        source, target, body = ip[8:24], ip[24:40], ip[40:40 + length]
        if ip[6] != 6:
            skip = 8 if ip[6] == 0 else 0
            require(ip[6] == 58 or (native and ip[6] == 0 and body[:8] == bytes.fromhex('3a00050200000100')),
                    'bounded ICMPv6 and listener maintenance')
            body = body[skip:]
            require(len(body) >= 8, 'complete ICMPv6 header')
            valid = not checksum(source + target + struct.pack('!I3xB', len(body), 58) + body)
            if body[0] != 2:
                require(valid and body[0] in (133, 135, 136, 143), 'valid IPv6 maintenance')
                continue
            require(body[1] == 0 and len(body) in (55, 56) and frame[:12] == guest + peer and target == local,
                    'original PTB bounds and interface')
            quoted = body[8:]
            scenario = quoted[39] - 10
            router = ipaddress.IPv6Address(f'2001:db8:{lane + 1}::fa').packed
            require(scenario in notices and quoted[0] >> 4 == 6 and source == router,
                    'owned router and destination cohort')
            notices[scenario].append(dict(index=index, valid_checksum=valid, quoted=quoted,
                mtu=int.from_bytes(body[4:8], 'big'), lower=row.get('arrival_lower_ns', row['ns']),
                upper=row.get('arrival_upper_ns', row['ns'])))
            continue
        require(length >= 20 and not checksum(source + target + struct.pack('!I3xB', length, 6) + body),
                'independent TCP6 pseudo-header checksum')
        sport, dport, sequence, acknowledgment, bits, window, _, urgent = struct.unpack_from('!HHIIHHHH', body)
        outgoing = source == local
        scenario, remainder = divmod((dport if outgoing else sport) - 44000 - lane, 20)
        require(scenario in notices and remainder == 0, 'owned TCP ports')
        remote = ipaddress.IPv6Address(f'2001:db8:{lane + 1}::{10 + scenario:x}').packed
        require(source + target == (local + remote if outgoing else remote + local) and
                frame[:12] == (peer + guest if outgoing else guest + peer), 'full TCP6 and Ethernet tuple')
        header, flags = (bits >> 12) * 4, bits & 511
        require(20 <= header <= length and not bits & 0x0e00 and not urgent and not flags & 4,
                'TCP header bounds, reserved flags and no reset')
        mss, at = None, 20
        while at < header:
            kind = body[at]
            if not kind:
                break
            if kind == 1:
                at += 1
                continue
            require(at + 2 <= header and body[at + 1] >= 2 and at + body[at + 1] <= header,
                    'complete captured TCP option')
            if kind == 2:
                require(flags & 2 and body[at + 1] == 4 and mss is None, 'one SYN MSS')
                mss = int.from_bytes(body[at + 2:at + 4], 'big')
            at += body[at + 1]
        flow = flows.setdefault(scenario, [dict(events=[], seen=bytearray(SIZE), data=bytearray(SIZE)),
                                           dict(events=[], seen=bytearray(SIZE), data=bytearray(SIZE))])
        direction = 0 if outgoing else 1
        item, opposite = flow[direction], flow[1 - direction]
        if flags & 2:
            require(mss and bool(flags & 16) == (scenario in (1, 3, 5) if outgoing else scenario not in (1, 3, 5)),
                    'active/passive PMTU role')
            require('initial' not in item or item['initial'] == sequence, 'stable PMTU ISN')
            item.update(initial=sequence, mss=mss)
        require('initial' in item, 'SYN precedes PMTU data')
        data = body[header:]
        start = (sequence - item['initial'] - (0 if flags & 2 else 1)) & MASK
        if data:
            require(not flags & 2 and start + len(data) <= SIZE and len(data) <= opposite.get('mss', 0) and
                    data == expected(lane, scenario, direction)[start:start + len(data)],
                    'exact PMTU bytes, sequence and advertised MSS')
            item['seen'][start:start + len(data)] = b'\1' * len(data)
            item['data'][start:start + len(data)] = data
        if flags & 1:
            require(start + len(data) == SIZE, 'FIN follows complete stream')
        if flags & 3 or data:
            item['sent_max'] = max(item.get('sent_max', 0), start + len(data) + bool(flags & 1))
        if flags & 16:
            require('initial' in opposite and ((acknowledgment - opposite['initial'] - 1) & MASK) <= opposite.get('sent_max', 0),
                    'ACK covers only already transmitted bytes')
        item['events'].append(dict(index=index, frame=frame, flags=flags, seq=sequence,
                                   ack=acknowledgment, data=data, start=start))
    require(set(requests) == set(replies) == set(range(CASES * 3 + 1)) and
            all(requests[n] < replies[n] < requests[n + 1] for n in range(CASES * 3)) and
            requests[CASES * 3] < replies[CASES * 3] and set(flows) == set(range(CASES)),
            'all original complete PMTU phases and independent flows')
    result = []
    for scenario in range(CASES):
        first, second = flows[scenario]
        offered = {4: 536, 5: 536, 6: 1200, 7: 1220, 8: 1280}.get(scenario, 1440)
        require(second['mss'] == offered and second['initial'] == 0xfffffff0,
                'actual controlled peer MSS and wrapped origin')
        ignored = scenario in (2, 3, 4, 5, 6, 7, 20)
        for stage in ('connected', 'recovered'):
            mss = offered if stage == 'connected' or ignored else 1220
            mtu = 1500 if stage == 'connected' or ignored else 1280
            require(log.splitlines().count(f'TCP6_PMTU_METRIC lane={lane} case={scenario} stage={stage} mss={mss} mtu={mtu}') == 1,
                    'native-compared actual TCP MSS and shared route MTU')
        require(log.splitlines().count(f'TCP6_PMTU_FLOW_PASS lane={lane} case={scenario} bytes_each=4096') == 1,
                'one actual completed application case')
        for direction, item in enumerate((first, second)):
            require(all(item['seen']) and bytes(item['data']) == expected(lane, scenario, direction),
                    'complete reconstructed bidirectional streams')
            require(any(event['flags'] & 1 for event in item['events']) and any(
                event['flags'] & 16 and event['ack'] == (item['initial'] + SIZE + 2) & MASK
                for event in (second if direction == 0 else first)['events']), 'acknowledged half-closes')
        hints = notices[scenario]
        require(len(hints) == (3 if scenario == 9 else 2 if 10 <= scenario <= 19 else 1),
                'complete original PTB cohort')
        require(all(replies[scenario * 3 + 1] < hint['index'] < requests[scenario * 3 + 3] for hint in hints),
                'PTB belongs to its own live stream phase')
        damaged = 10 <= scenario <= 19
        valid_hints = hints[1:] if damaged else hints
        for hint in valid_hints:
            require(hint['valid_checksum'] and hint['mtu'] in (1280, 1400, 1500) and any(
                event['index'] < hint['index'] and event['frame'][14:62] == hint['quoted']
                for event in first['events']), 'valid PTB quotes an exact previously transmitted packet')
        if damaged:
            initial_data = next(event for event in first['events'] if event['data'])
            quote = bytearray(initial_data['frame'][14:62])
            mtu = 1280
            if scenario == 11:
                quote[44:48] = first['initial'].to_bytes(4, 'big')
            elif scenario == 12:
                quote[44:48] = ((first['initial'] + SIZE + 2) & MASK).to_bytes(4, 'big')
            elif scenario in (13, 14, 15, 16):
                quote[{13: 9, 14: 25, 15: 40, 16: 42}[scenario]] ^= 64 if scenario in (13, 14) else 1
            elif scenario == 17:
                mtu = 1279
            elif scenario == 18:
                quote = quote[:47]
            elif scenario == 19:
                quote[6] = 17
            require(hints[0]['quoted'] == bytes(quote) and hints[0]['mtu'] == mtu and
                    hints[0]['valid_checksum'] == (scenario != 10), 'exact intentionally damaged notification')
            require(valid_hints[0]['lower'] - hints[0]['upper'] >= 50000000,
                    'full fifty-ms invalid-hint observation before valid PTB')
            require(not any(hints[0]['index'] < event['index'] < valid_hints[0]['index'] and
                event['data'] and event['start'] == 0 and len(event['data']) <= 1220 for event in first['events']),
                'invalid quote cannot resize the first outstanding segment')
        if scenario not in (2, 3, 4, 5, 6, 7, 20, 21):
            lowered = next(hint for hint in valid_hints if hint['mtu'] == 1280)
            require(any(event['index'] > lowered['index'] and event['start'] == 0 and
                        len(event['data']) == 1220 for event in first['events']), 'exact-prefix 1220-byte actual retry')
        if scenario in (20, 21):
            hint = hints[0]
            require(any(event['index'] < hint['index'] and event['ack'] == (first['initial'] + SIZE + 1) & MASK
                        for event in second['events']), 'idle quote follows complete acknowledgment')
            require(not any(event['index'] > hint['index'] and event['data'] for event in first['events']),
                    'idle quote creates no phantom retransmission')
        result.append(dict(case=scenario, received=SIZE, sent=SIZE, notices=len(hints),
            outgoing_sha256=hashlib.sha256(first['data']).hexdigest(),
            incoming_sha256=hashlib.sha256(second['data']).hexdigest()))
    return dict(passed=True, lane=lane, cases=result, frames=len(rows))


def verify(path, lane, log, native=False, statistics=None):
    rows = read_capture(path)
    clock = None
    if native:
        from tcp6.observation import bind
        clock = bind(path, rows, statistics)
    result = inspect(rows, lane, log, native)
    result.update(sha256=hashlib.sha256(path.read_bytes()).hexdigest(), clock=clock)
    return result


def damaged(path, lane, log, native, output, statistics=None):
    rows = read_capture(path)
    if native:
        from tcp6.observation import bind
        bind(path, rows, statistics)
    inspect(rows, lane, log, native)
    guest = bytes([0x52, 0x54, 0, 0x12, 0x34, 0x10 + lane])
    data = next(n for n, row in enumerate(rows) if row['frame'][12:14] == b'\x86\xdd' and
        row['frame'][20] == 6 and row['frame'][6:12] == guest and
        len(row['frame']) > 54 + (row['frame'][66] >> 4) * 4)
    hints = [n for n, row in enumerate(rows) if row['frame'][12:14] == b'\x86\xdd' and
             row['frame'][20] == 58 and row['frame'][54] == 2]
    invalid = next(n for n in hints if rows[n]['frame'][101] == 20)
    valid = next(n for n in hints if n > invalid and rows[n]['frame'][101] == 20)
    variants = {}
    def change(name, at, mutate, protocol=6, repair=True):
        changed = copy.deepcopy(rows)
        frame = bytearray(changed[at]['frame'])
        mutate(frame)
        if repair:
            field = 70 if protocol == 6 else 56
            frame[field:field + 2] = bytes(2)
            length = int.from_bytes(frame[18:20], 'big')
            frame[field:field + 2] = struct.pack('!H', checksum(frame[22:54] +
                struct.pack('!I3xB', length, protocol) + frame[54:54 + length]))
        changed[at]['frame'] = bytes(frame)
        variants[name] = changed, log
    change('checksum', data, lambda frame: frame.__setitem__(70, frame[70] ^ 1), repair=False)
    change('full-address', data, lambda frame: frame.__setitem__(23, frame[23] ^ 64))
    change('peer-port', data, lambda frame: frame.__setitem__(56, frame[56] ^ 1))
    change('payload', data, lambda frame: frame.__setitem__(54 + (frame[66] >> 4) * 4,
        frame[54 + (frame[66] >> 4) * 4] ^ 1))
    change('quoted-source', valid, lambda frame: frame.__setitem__(71, frame[71] ^ 64), protocol=58)
    change('valid-MTU', valid, lambda frame: frame.__setitem__(slice(58, 62), (1279).to_bytes(4, 'big')), protocol=58)
    changed = copy.deepcopy(rows)
    if native:
        changed[valid]['arrival_lower_ns'] = changed[invalid]['arrival_upper_ns'] + 1000000
        changed[valid]['arrival_upper_ns'] = changed[valid]['arrival_lower_ns']
    else:
        changed[valid]['ns'] = changed[invalid]['ns'] + 1000000
    variants['short-observation'] = changed, log
    variants['missing-valid-PTB'] = [row for n, row in enumerate(rows) if n != valid], log
    variants['false-shared-metric'] = rows, log.replace(
        f'TCP6_PMTU_METRIC lane={lane} case=4 stage=recovered mss=536 mtu=1500',
        f'TCP6_PMTU_METRIC lane={lane} case=4 stage=recovered mss=536 mtu=1280')
    variants['missing-completion'] = rows, log.replace('TCP6_PMTU_PASS lanes=2 cases_each=22 bytes_each=4096', '')
    archive_path = output / (path.stem + '-damaged.zip')
    with zipfile.ZipFile(archive_path, 'x', zipfile.ZIP_DEFLATED) as archive:
        for name, (changed, text) in variants.items():
            archive.writestr(name + '.pcap', encode_capture(changed))
            archive.writestr(name + '.log', text)
            archive.writestr(name + '.bounds.json', json.dumps([
                [row.get('arrival_lower_ns'), row.get('arrival_upper_ns')] for row in changed]))
    rejected = []
    with zipfile.ZipFile(archive_path) as archive, tempfile.TemporaryDirectory(prefix='axiom64-tcp6-pmtu-') as temporary:
        for name in variants:
            file = Path(temporary) / (name + '.pcap')
            file.write_bytes(archive.read(name + '.pcap'))
            changed = read_capture(file)
            bounds = json.loads(archive.read(name + '.bounds.json'))
            require(len(changed) == len(bounds), 'serialized PMTU control observation count')
            for row, (lower, upper) in zip(changed, bounds):
                if lower is not None:
                    row.update(arrival_lower_ns=lower, arrival_upper_ns=upper)
            try:
                inspect(changed, lane, archive.read(name + '.log').decode(), native)
            except ValueError as failure:
                rejected.append(dict(name=name, reason=str(failure)))
            else:
                raise ValueError('reader accepted reopened damaged PMTU evidence: ' + name)
    return dict(passed=True, rejected=rejected, archive_sha256=hashlib.sha256(archive_path.read_bytes()).hexdigest())
