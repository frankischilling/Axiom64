# SPDX-License-Identifier: GPL-3.0-or-later
"""Reconstruct ordinary TCP6 errors from original packets and application results."""
import copy
import hashlib
import ipaddress
import json
from pathlib import Path
import struct
import tempfile
import zipfile
from ipv4_expiry_capture import read_capture, encode_capture, checksum
from tcp6.capture import require

CASES, MASK = 62, 0xffffffff
ERRORS = (101, 13, 113, 113, 111, 13, 13, 71, 113, 113, 71, 71, 71)
HARD = (False, True, False, False, True, True, True, True, False, False, True, True, True)
KINDS = ((1, 0), (1, 1), (1, 2), (1, 3), (1, 4), (1, 5), (1, 6), (1, 99),
         (3, 0), (3, 1), (4, 0), (4, 1), (4, 2))
MARKER = 'TCP6_ERRORS_PASS lanes=2 cases_each=62'


def inspect(rows, lane, log, native=False):
    require(log.splitlines().count(MARKER) == 1, 'one complete ordinary error client')
    guest = bytes([0x52, 0x54, 0, 0x12, 0x34, 0x10 + lane])
    peer = bytes([2, 0x41, 0x58, 0x54, 0x43, lane])
    control = bytes([2, ord('I'), ord('P'), ord('6'), lane, 0])
    local = ipaddress.IPv6Address(f'2001:db8:{lane + 1}::2').packed
    router = ipaddress.IPv6Address(f'2001:db8:{lane + 1}::fa').packed
    requests, replies = {}, {}
    flows = {n: dict(events=[], hints=[]) for n in range(CASES)}
    for index, row in enumerate(rows):
        frame = row['frame']
        require(len(frame) >= 14, 'complete error Ethernet frame')
        event = dict(index=index, frame=frame, lower=row.get('arrival_lower_ns', row['ns']),
                     upper=row.get('arrival_upper_ns', row['ns']))
        if frame[12:14] == b'\x88\xc3':
            require(len(frame) == 60 and frame[14:19] == b'IP6E' + bytes([lane]) and
                    frame[19] <= CASES * 3 and frame[20] in (0, 1) and not any(frame[21:]),
                    'complete ordinary error phase')
            reply = frame[20]
            require(frame[:12] == (guest + control if reply else control + guest), 'error phase owner')
            book = replies if reply else requests
            require(frame[19] not in book, 'unique error phase')
            book[frame[19]] = event
            continue
        if 0 not in requests and not native:
            require(index < 256 and frame[6:12] == guest, 'bounded original firmware prelude')
            continue
        require(frame[12:14] == b'\x86\xdd' and len(frame) >= 54, 'complete error IPv6 packet')
        ip = frame[14:]
        size = int.from_bytes(ip[4:6], 'big')
        require(ip[0] >> 4 == 6 and 40 + size <= len(ip), 'declared error IPv6 bounds')
        source, target, body = ip[8:24], ip[24:40], ip[40:40 + size]
        if ip[6] != 6:
            skip = 8 if ip[6] == 0 else 0
            require(ip[6] == 58 or native and ip[6] == 0 and
                    body[:8] == bytes.fromhex('3a00050200000100'), 'bounded error maintenance protocol')
            body = body[skip:]
            require(len(body) >= 8, 'complete error ICMPv6 header')
            valid = not checksum(source + target + struct.pack('!I3xB', len(body), 58) + body)
            if body[0] not in (1, 3, 4):
                require(valid and body[0] in (133, 135, 136, 143), 'valid error fixture maintenance')
                continue
            require(len(body) in (55, 56) and body[4:8] == bytes(4) and source == router and
                    target == local and frame[:12] == guest + peer, 'ordinary error outer ownership')
            quoted = body[8:]
            scenario = quoted[39] - 10
            require(scenario in flows, 'ordinary error belongs to complete case cohort')
            event.update(quoted=quoted, type=body[0], code=body[1], valid=valid)
            flows[scenario]['hints'].append(event)
            continue
        require(size >= 20 and not checksum(source + target + struct.pack('!I3xB', size, 6) + body),
                'independent ordinary error TCP checksum')
        sport, dport, sequence, acknowledgment, bits, window, _, urgent = struct.unpack_from('!HHIIHHHH', body)
        outgoing = source == local
        port = dport if outgoing else sport
        scenario, remainder = divmod(port - 44000 - lane, 20)
        require(scenario in flows and remainder in (0, 2), 'ordinary error TCP peer port cohort')
        mode, kind = divmod(scenario, 13)
        generation = int(remainder == 2)
        require(not generation or mode == 1 and HARD[kind], 'only hard passive errors replace requests')
        remote = ipaddress.IPv6Address(f'2001:db8:{lane + 1}::{10 + scenario:x}').packed
        require(source + target == (local + remote if outgoing else remote + local) and
                frame[:12] == (peer + guest if outgoing else guest + peer) and
                (sport if outgoing else dport) == 45000 + scenario * 20 + lane,
                'full ordinary error stream identity')
        header, flags = (bits >> 12) * 4, bits & 511
        require(20 <= header <= size and not bits & 0x0e00 and not urgent,
                'ordinary error TCP header bounds')
        at, mss = 20, None
        while at < header:
            option = body[at]
            if option == 0:
                break
            if option == 1:
                at += 1
                continue
            require(at + 2 <= header and body[at + 1] >= 2 and at + body[at + 1] <= header,
                    'ordinary error TCP option bounds')
            if option == 2:
                require(flags & 2 and body[at + 1] == 4 and mss is None, 'one error SYN MSS')
                mss = int.from_bytes(body[at + 2:at + 4], 'big')
            at += body[at + 1]
        event.update(outgoing=outgoing, generation=generation, flags=flags, seq=sequence,
                     ack=acknowledgment, data=body[header:], mss=mss)
        flows[scenario]['events'].append(event)
    phases = set(range(CASES * 3 + 1))
    require(set(requests) == set(replies) == phases and all(
        requests[n]['index'] < replies[n]['index'] and (n == CASES * 3 or
        replies[n]['index'] < requests[n + 1]['index']) for n in phases),
        'all complete ordered error phases')
    results = []
    for scenario, flow in flows.items():
        mode, kind = divmod(scenario, 13)
        events, hints = flow['events'], flow['hints']
        require(events and len(hints) == 1, 'one actual ordinary error for each case')
        hint = hints[0]
        begin, observed, end = (replies[scenario * 3 + n] for n in (1, 2, 3))
        require(begin['index'] < hint['index'] < observed['index'] < end['index'] and
                observed['lower'] - hint['upper'] >= 50000000,
                'full actual fifty-ms quoted-error observation')
        quoted_event = next((item for item in events if item['outgoing'] and
            (item['flags'] & 2 if mode in (0, 1, 4) else item['data'])), None)
        require(quoted_event is not None and quoted_event['index'] < hint['index'],
                'error follows actual quoted transmission')
        quote = bytearray(quoted_event['frame'][14:62])
        if mode == 4:
            if kind in (1, 2):
                value = int.from_bytes(quote[44:48], 'big')
                quote[44:48] = ((value + (-1 if kind == 1 else 2)) & MASK).to_bytes(4, 'big')
            elif kind in (3, 4, 5, 6):
                quote[{3: 9, 4: 25, 5: 40, 6: 42}[kind]] ^= 64 if kind in (3, 4) else 1
            elif kind == 7:
                quote = quote[:47]
            elif kind == 8:
                quote[6] = 17
            elif kind == 9:
                quote[0] = 0x50
        require(hint['quoted'] == bytes(quote) and (hint['type'], hint['code']) ==
                ((1, 4) if mode == 4 else KINDS[kind]) and
                hint['valid'] == (mode != 4 or kind != 0), 'exact actual error class and quote mutation')
        aborted = mode == 0 or native and scenario == 61
        expected_error = ERRORS[kind] if mode in (0, 2) else 111 if aborted else 0
        replacement = int(mode == 1 and HARD[kind])
        require(log.splitlines().count(f'TCP6_ERRORS_FLOW_PASS lane={lane} case={scenario} mode={mode} '
                f'error={expected_error} replacement={replacement}') == 1,
                'actual native-compared error consumption and request generation')
        require(all(begin['index'] < item['index'] < end['index'] for item in events),
                'stream belongs to its original case lifetime')
        for generation in range(replacement + 1):
            group = [item for item in events if item['generation'] == generation]
            discarded = replacement and generation == 0
            origins = []
            for outgoing in (True, False):
                syns = [item for item in group if item['outgoing'] == outgoing and item['flags'] & 2]
                needed = outgoing or not aborted
                require(bool(syns) == needed and (not syns or all(
                    item['seq'] == syns[0]['seq'] and item['mss'] and not item['data'] and
                    bool(item['flags'] & 16) == (mode == 1 if outgoing else mode != 1)
                    for item in syns)), 'actual active/passive SYN role and stable generation')
                initial = syns[0]['seq'] if syns else None
                if not outgoing and initial is not None:
                    require(initial == (0xffffffe0 if generation else 0xfffffff0) and
                            syns[0]['mss'] == 1440, 'controlled wrapped peer identity')
                origins.append(initial)
            syn_seen = [False, False]
            for item in group:
                direction = 0 if item['outgoing'] else 1
                if item['flags'] & 4:
                    require(discarded, 'reset belongs only to a retired passive request')
                    continue
                if item['flags'] & 2:
                    syn_seen[direction] = True
                else:
                    require(syn_seen[direction], 'actual SYN precedes error stream progress')
                if item['flags'] & 16:
                    require(syn_seen[1 - direction], 'error ACK follows actual opposite SYN')
            if aborted:
                require(not any(item['data'] or item['flags'] & (1 | 4) for item in group),
                        'aborted active error has no established stream')
                continue
            if discarded:
                require(not any(item['data'] or item['flags'] & 1 for item in group),
                        'hard passive error retires initial request')
                require(any(not item['outgoing'] and item['flags'] == 16 and
                    item['index'] > hint['index'] and item['ack'] == (origins[0] + 1) & MASK
                    for item in group), 'discarded request receives original-generation ACK')
                continue
            require(not any(item['flags'] & 4 for item in group), 'surviving stream has no reset')
            expected = (b'onetwo' if mode in (2, 3) else b'one', b'K')
            sent_max = [0, 0]
            data, seen, fin, ack_fin = [bytearray(len(value)) for value in expected], [
                bytearray(len(value)) for value in expected], [False, False], [False, False]
            for item in group:
                direction = 0 if item['outgoing'] else 1
                other = 1 - direction
                if item['flags'] & 4:
                    continue
                if item['flags'] & 2:
                    require(not item['flags'] & 1, 'SYN excludes FIN')
                else:
                    start = (item['seq'] - origins[direction] - 1) & MASK
                    if item['data']:
                        require(start + len(item['data']) <= len(expected[direction]) and
                                item['data'] == expected[direction][start:start + len(item['data'])],
                                'exact surviving error stream sequence and bytes')
                        data[direction][start:start + len(item['data'])] = item['data']
                        seen[direction][start:start + len(item['data'])] = b'\1' * len(item['data'])
                    if item['flags'] & 1:
                        require(start + len(item['data']) == len(expected[direction]), 'error FIN follows exact bytes')
                        fin[direction] = True
                    if item['data'] or item['flags'] & 1:
                        sent_max[direction] = max(sent_max[direction], start + len(item['data']) + bool(item['flags'] & 1))
                if item['flags'] & 16:
                    acknowledged = (item['ack'] - origins[other] - 1) & MASK
                    require(acknowledged <= sent_max[other], 'error ACK covers only transmitted bytes')
                    if acknowledged == len(expected[other]) + 1:
                        ack_fin[other] = True
            require(all(all(value) for value in seen) and all(bytes(value) == wanted for value, wanted in zip(data, expected)) and
                    all(fin) and all(ack_fin), 'complete surviving byte streams and acknowledged half-closes')
            if mode in (2, 3):
                require(any(not item['outgoing'] and item['flags'] & 16 and
                    item['ack'] == (origins[0] + 7) & MASK and item['index'] > observed['index'] for item in group),
                    'post-error acknowledged progress clears diagnostic')
            if mode == 4:
                synack = next(item for item in group if not item['outgoing'] and item['flags'] & 2)
                require(synack['lower'] - observed['upper'] >= 100000000,
                        'ignored quote retains pending open before real handshake')
        results.append(dict(case=scenario, mode=mode, error=expected_error, replacement=replacement))
    return dict(passed=True, lane=lane, cases=results, frames=len(rows))


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
    hints = [n for n, row in enumerate(rows) if len(row['frame']) >= 109 and
             row['frame'][12:14] == b'\x86\xdd' and row['frame'][20] == 58 and row['frame'][54] in (1, 3, 4)]
    data = next(n for n, row in enumerate(rows) if row['frame'][12:14] == b'\x86\xdd' and
                row['frame'][20] == 6 and len(row['frame']) > 54 + (row['frame'][66] >> 4) * 4)
    variants = {}
    def change(name, index, mutate, protocol=6, repair=True):
        changed = copy.deepcopy(rows)
        frame = bytearray(changed[index]['frame'])
        mutate(frame)
        if repair:
            field = 70 if protocol == 6 else 56
            frame[field:field + 2] = bytes(2)
            size = int.from_bytes(frame[18:20], 'big')
            frame[field:field + 2] = struct.pack('!H', checksum(frame[22:54] +
                struct.pack('!I3xB', size, protocol) + frame[54:54 + size]))
        changed[index]['frame'] = bytes(frame)
        variants[name] = changed, log
    change('tcp-checksum', data, lambda frame: frame.__setitem__(70, frame[70] ^ 1), repair=False)
    change('payload', data, lambda frame: frame.__setitem__(54 + (frame[66] >> 4) * 4, 0))
    change('full-address', data, lambda frame: frame.__setitem__(23, frame[23] ^ 64))
    change('ethernet-owner', data, lambda frame: frame.__setitem__(0, frame[0] ^ 2))
    change('error-class', hints[0], lambda frame: frame.__setitem__(55, 4), protocol=58)
    change('quoted-sequence', hints[0], lambda frame: frame.__setitem__(109, frame[109] ^ 1), protocol=58)
    change('outer-checksum', hints[0], lambda frame: frame.__setitem__(56, frame[56] ^ 1), protocol=58, repair=False)
    variants['missing-error'] = [row for n, row in enumerate(rows) if n != hints[0]], log
    variants['missing-completion'] = rows, log.replace(MARKER, '')
    variants['false-error'] = rows, log.replace(f'lane={lane} case=0 mode=0 error=101',
                                               f'lane={lane} case=0 mode=0 error=111')
    variants['false-passive-generation'] = rows, log.replace(f'lane={lane} case=14 mode=1 error=0 replacement=1',
                                                            f'lane={lane} case=14 mode=1 error=0 replacement=0')
    changed = copy.deepcopy(rows)
    phase = next(n for n, row in enumerate(changed) if row['frame'][12:14] == b'\x88\xc3' and
                 row['frame'][19:21] == b'\2\1')
    if native:
        changed[phase]['arrival_lower_ns'] = changed[hints[0]]['arrival_upper_ns'] + 1000000
        changed[phase]['arrival_upper_ns'] = changed[phase]['arrival_lower_ns']
    else:
        changed[phase]['ns'] = changed[hints[0]]['ns'] + 1000000
    variants['short-real-observation'] = changed, log
    archive_path = output / (path.stem + '-damaged.zip')
    with zipfile.ZipFile(archive_path, 'x', zipfile.ZIP_DEFLATED) as archive:
        for name, (changed, text) in variants.items():
            archive.writestr(name + '.pcap', encode_capture(changed))
            archive.writestr(name + '.log', text)
            archive.writestr(name + '.bounds.json', json.dumps([
                [row.get('arrival_lower_ns'), row.get('arrival_upper_ns')] for row in changed]))
    rejected = []
    with zipfile.ZipFile(archive_path) as archive, tempfile.TemporaryDirectory(prefix='axiom64-tcp6-errors-') as temporary:
        for name in variants:
            reopened = Path(temporary) / (name + '.pcap')
            reopened.write_bytes(archive.read(name + '.pcap'))
            changed = read_capture(reopened)
            bounds = json.loads(archive.read(name + '.bounds.json'))
            require(len(bounds) == len(changed), 'serialized ordinary error observation count')
            for row, (lower, upper) in zip(changed, bounds):
                if lower is not None:
                    row.update(arrival_lower_ns=lower, arrival_upper_ns=upper)
            try:
                inspect(changed, lane, archive.read(name + '.log').decode(), native)
            except ValueError as failure:
                rejected.append(dict(name=name, reason=str(failure)))
            else:
                raise ValueError('reader accepted reopened damaged ordinary error evidence: ' + name)
    return dict(passed=True, rejected=rejected, archive_sha256=hashlib.sha256(archive_path.read_bytes()).hexdigest())
