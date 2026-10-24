# SPDX-License-Identifier: GPL-3.0-or-later
"""Read original fragment captures independently of the injecting peer."""
import copy
import hashlib
import ipaddress
import json
from pathlib import Path
import re
import struct
import zipfile
from ipv4_expiry_capture import checksum, elapsed_ns, encode_capture, read_capture
from tcp_capture_clock import bind_native_clock


def require(value, reason):
    if not value:
        raise ValueError(reason)


def inspect(rows, lane, log, native=False, interface_index=None):
    log = log.replace('\r\n', '\n')
    if native:
        require(type(interface_index) is int and interface_index > 0,
                'actual independently queried native interface index')
    else:
        indexes = re.findall(rf'^NET_DEVICE index=([0-9]+) name=eth{lane} mtu=1500 carrier=1 '
                             rf'mac=52:54:0:12:34:{0x10 + lane:x}$', log, re.MULTILINE)
        require(len(indexes) == 1 and int(indexes[0]) > 0, 'actual kernel interface index and MAC')
        interface_index = int(indexes[0])
    require('IPV6_FRAGMENTS_FAIL' not in log and log.count(
        'IPV6_FRAGMENTS_PASS nics=2 cases_each=7 maximum=65527 expiry_seconds=60') == 1,
        'actual complete fragment client result')
    require(log.count('IPV6_FRAGMENTS_CASE_PASS ') == 14 and
            log.count('IPV6_FRAGMENTS_PHASE_PASS ') == 16, 'complete original client case and phase inventory')
    for number, size in [(1, 19), (2, 57), (3, 65527), (4, 41), (5, 9), (6, 41), (9, 41)]:
        scope = str(interface_index) if number == 4 else '0'
        require(len(re.findall(rf'^IPV6_FRAGMENTS_CASE_PASS lane={lane} case={number} bytes={size} scope={scope}$',
                               log, re.MULTILINE)) == 1, 'every actual datagram size, source and payload check')
    duration = re.findall(r'^IPV6_FRAGMENTS_EXPIRY_PASS elapsed_ns=([0-9]+)$', log, re.MULTILINE)
    require(len(duration) == 1 and 70000000000 <= int(duration[0]) < 100000000000,
            'complete client expiry and suppression observation')
    for phase in range(8):
        require(log.count(f'IPV6_FRAGMENTS_PHASE_PASS lane={lane} phase={phase}') == 1,
                'actual ordered fragment client barriers')
    guest = bytes([0x52, 0x54, 0, 0x12, 0x34, 0x10 + lane])
    peer = bytes([2, 0x49, 0x50, 0x36, lane, 1])
    control = peer[:5] + bytes(1)
    local = ipaddress.IPv6Address(f'2001:db8:{lane + 1}::2').packed
    remote = ipaddress.IPv6Address(f'2001:db8:{lane + 1}::1').packed
    link, remote_link = ipaddress.IPv6Address('fe80::2').packed, ipaddress.IPv6Address('fe80::1').packed
    requests, acknowledgements, fragments, outputs, plain, firmware = {}, {}, [], [], [], []
    ready = False
    for index, row in enumerate(rows):
        frame = row['frame']
        require(len(frame) >= 14, 'complete Ethernet envelope')
        if frame[12:14] == b'\x88\xb7':
            require(len(frame) == 60 and frame[14:19] == b'IP6F' + bytes([lane]) and
                    frame[19] in range(8) and not any(frame[21:]), 'complete fragment control envelope')
            phase, ack = frame[19:21]
            require(ack in (0, 1) and frame[:12] == (guest + control if ack else control + guest),
                    'original fragment control MAC and direction')
            target = acknowledgements if ack else requests
            require(phase not in target, 'one control packet per phase and direction')
            target[phase] = index
            ready = True
            continue
        if not ready and not native:
            require(frame[6:12] == guest and len(firmware) < 256, 'bounded original firmware frames')
            firmware.append(hashlib.sha256(frame).hexdigest())
            continue
        if frame[12:14] != b'\x86\xdd':
            raise ValueError('unexpected post-readiness Ethernet traffic')
        require(len(frame) >= 54 and frame[14:18] == b'\x60\0\0\0', 'original fixed IPv6 header')
        length, protocol, hop = struct.unpack('!HBB', frame[18:22])
        require(54 + length <= len(frame), 'complete original IPv6 payload')
        frame = frame[:54 + length]
        incoming = frame[6:12] == peer
        require(incoming or frame[6:12] == guest, 'original workload source MAC')
        item = dict(index=index, frame=frame, ns=elapsed_ns(row), protocol=protocol,
                    source=frame[22:38], destination=frame[38:54], hop=hop, body=frame[54:])
        if incoming and protocol in (44, 60):
            prefix = 0 if protocol == 44 else (frame[55] + 1) * 8
            require(prefix in (0, 8, 16) and len(frame) >= 62 + prefix and
                    (not prefix or frame[54:56] == bytes([44, prefix // 8 - 1])), 'legal saved extension prefix')
            if prefix:
                wanted = bytes(6) if prefix == 8 else b'\x1e\x0a' + bytes(12)
                require(frame[56:54 + prefix] == wanted, 'exact legal option bytes')
            next_header, reserved, field, identity = struct.unpack_from('!BBHI', frame, 54 + prefix)
            require(not reserved and not field & 6 and hop in (64, 255) and len(frame) <= 1514,
                    'exact original fragment header and interface MTU')
            item.update(identity=identity, offset=field & 0xfff8, more=bool(field & 1),
                        prefix=prefix, transport=next_header, data=frame[62 + prefix:])
            fragments.append(item)
        elif not incoming:
            if native and protocol == 0:
                require(frame[:6] == b'\x33\x33\0\0\0\x16' and hop == 1 and
                        item['source'] in (bytes(16), link) and item['destination'] ==
                        ipaddress.IPv6Address('ff02::16').packed and
                        frame[54:62] == b'\x3a\0\5\2\0\0\1\0' and
                        frame[62:64] == b'\x8f\0' and not checksum(frame[22:54] +
                        struct.pack('!I3xB', len(frame) - 62, 58) + frame[62:]), 'original native MLD report')
                continue
            require(protocol in (17, 58) and not checksum(frame[22:54] +
                    struct.pack('!I3xB', length, protocol) + frame[54:]), 'actual output transport checksum')
            outputs.append(item)
        else:
            require(protocol == 58 and not checksum(frame[22:54] + struct.pack('!I3xB', length, 58) +
                    frame[54:]), 'original peer neighbor control checksum')
            plain.append(item)
    require(list(requests) == list(range(8)) and list(acknowledgements) == list(range(8)),
            'all original ordered requests and acknowledgements')
    require(all(requests[n] < acknowledgements[n] < requests[n + 1] for n in range(7)),
            'original causal phase ordering')

    def payload(case, size):
        return bytes((at * 17 + lane * 31 + (8 if case == 9 and at >= 8 else case) * 7) & 255
                     for at in range(size))

    def transport(case, size, scoped=False, raw=False):
        source, destination = (remote_link, link) if scoped else (remote, local)
        if raw:
            body = bytearray(b'\x81\0\0\0' + payload(case, size - 4)); at, protocol = 2, 58
        else:
            ports = (58011, 58010) if scoped else (57000 + lane, 56000 + lane)
            body = bytearray(struct.pack('!HHHH', *ports, size + 8, 0) + payload(case, size)); at, protocol = 6, 17
        value = checksum(source + destination + struct.pack('!I3xB', len(body), protocol) + body)
        struct.pack_into('!H', body, at, value or (65535 if protocol == 17 else 0))
        return bytes(body)

    base = 0x66000000 + lane * 256
    expiry_id = 0x66008000 + lane * 256
    groups = {}
    for item in fragments:
        groups.setdefault(item['identity'], []).append(item)
    maximum = [(at, min(1448, 65535 - at), at + 1448 < 65535, 0) for at in range(0, 65535, 1448)]
    specifications = {
        base + 1: (transport(1, 19, raw=True), [(8, 11, False, 0), (0, 8, True, 8)]),
        base + 2: (transport(2, 57), [(48, 17, False, 0), (0, 24, True, 8), (0, 24, True, 8), (24, 24, True, 16)]),
        base + 3: (transport(3, 65527), list(reversed(maximum))),
        0x66009900: (transport(4, 41, scoped=True), [(0, 24, True, 0), (24, 25, False, 0)]),
        base + 5: (transport(6, 41), [(0, 16, True, 0), (0, 17, False, 0), (16, 33, False, 0)]),
        base + 7: (transport(7, 41), [(0, 16, True, 0), (8, 16, True, 0), (24, 25, False, 0)]),
        base + 8: (transport(7, 49), [(0, 16, True, 0), (32, 17, False, 0), (40, 17, False, 0)]),
        base + 9: (transport(7, 41)[:-1] + bytes([transport(7, 41)[-1] ^ 1]), [(0, 16, True, 0), (16, 33, False, 0)]),
        base + 10: (b'', [(0, 24, True, 0), (24, 8, False, 0)]),
        base + 11: (b'', [(0, 32, False, 0)]),
        base + 12: (transport(7, 41), [(0, 16, True, 0), (0, 16, True, 0)]),
        base + 13: (transport(7, 41), [(0, 15, True, 0)]),
        base + 14: (b'', [(65528, 16, False, 0)]),
        base + 15: (bytes(16), [(0, 16, True, 0)]),
        expiry_id: (transport(8, 41), [(0, 16, True, 0), (0, 16, True, 0), (16, 33, False, 0), (0, 16, True, 0)]),
        expiry_id + 1: (transport(8, 41), [(16, 33, False, 0)]),
        expiry_id + 2: (b'\1\4' + bytes(14), [(0, 16, True, 0)]),
        expiry_id + 3: (transport(8, 41), [(0, 16, True, 0)]),
    }
    # Neighbor and ICMP error checksums are part of their original complete input.
    ns = bytearray(b'\x87\0\0\0' + bytes(4) + local + b'\1\1' + peer)
    struct.pack_into('!H', ns, 2, checksum(remote + local + struct.pack('!I3xB', 32, 58) + ns))
    error = bytearray(b'\1\4' + bytes(14))
    struct.pack_into('!H', error, 2, checksum(remote + local + struct.pack('!I3xB', 16, 58) + error))
    specifications[base + 10] = (bytes(ns), specifications[base + 10][1])
    specifications[base + 11] = (bytes(ns), specifications[base + 11][1])
    specifications[base + 14] = (transport(7, 41)[:16], specifications[base + 14][1])
    specifications[expiry_id + 2] = (bytes(error), specifications[expiry_id + 2][1])
    require(set(groups) == set(specifications), 'all positive, malformed and suppression fragment identities')
    for identity, (body, shapes) in specifications.items():
        actual = groups[identity]
        require([(x['offset'], len(x['data']), x['more'], x['prefix']) for x in actual] == shapes,
                'exact original fragment offsets, lengths, order and duplicate geometry')
        for ordinal, item in enumerate(actual):
            if identity == 0x66009900:
                phase = 1 if ordinal == 0 else 2
            elif identity == base + 5:
                phase = 2
            elif identity == expiry_id:
                phase = 4 if ordinal < 2 else ordinal + 3
            elif identity in (expiry_id + 1, expiry_id + 2, expiry_id + 3):
                phase = 4
            else:
                phase = 1
            require(requests[phase] < item['index'] < acknowledgements[phase],
                    'every original fragment belongs to its actual client phase')
            expected = body
            if identity == base + 5 and ordinal == 1:
                expected = transport(5, 9)
            if identity == expiry_id and ordinal == 3:
                expected = transport(9, 41)
            at = 0 if identity == base + 14 else item['offset']
            require(item['data'] == expected[at:at + len(item['data'])], 'every original input fragment byte')
            destination = link if identity == 0x66009900 else local
            if identity == base + 12:
                destination = ipaddress.IPv6Address(f'2001:db8:{lane + 1}::77' if ordinal == 0 else 'ff02::1234:5678').packed
            if identity == expiry_id + 3:
                destination = ipaddress.IPv6Address('ff02::1').packed
            source = remote_link if identity == 0x66009900 else remote
            wanted_mac = b'\x33\x33' + destination[-4:] if destination[0] == 255 else guest
            wanted_protocol = 58 if identity in (base + 1, base + 10, base + 11, expiry_id + 2) else 6 if identity == base + 15 else 17
            require((item['source'], item['destination'], item['frame'][:12], item['transport'], item['hop']) ==
                    (source, destination, wanted_mac + peer, wanted_protocol, 255 if identity in (base + 10, base + 11) else 64),
                    'original fragment addresses, MAC, transport and hop policy')
    require(groups[0x66009900][0]['index'] < acknowledgements[1] < requests[2] <
            groups[0x66009900][1]['index'], 'scoped first retained across the two-link client barrier')
    diagnostics, advertisements, warm, probes = [], [], [], []
    for item in outputs:
        body = item['body']
        require(len(body) >= 8 and item['source'] in ((local, link) if body[0] == 135 else (local,)),
                'complete output and original source address')
        if item['protocol'] == 17:
            require(item['destination'] == remote and item['hop'] == 64 and item['frame'][:12] == peer + guest and
                    body[:6] == struct.pack('!HHH', 56000 + lane, 57000 + lane, 8) and len(body) == 8,
                    'only the original zero-byte UDP warmup'); warm.append(item)
        elif body[0] == 135:
            require(item['destination'] in (remote, ipaddress.IPv6Address('ff02::1:ff00:1').packed) and
                    item['hop'] == 255 and body[:2] + bytes(2) + body[4:8] == b'\x87\0' + bytes(6) and
                    body[8:] == remote + b'\1\1' + guest and item['frame'][:6] ==
                    (peer if item['destination'] == remote else b'\x33\x33\xff\0\0\1'),
                    'original resolved-neighbor probe'); probes.append(item)
        elif body[0] == 136:
            require(item['destination'] == remote and item['hop'] == 255 and item['frame'][:12] == peer + guest and
                    body[:2] + bytes(2) + body[4:] ==
                    b'\x88\0' + bytes(2) + b'\x40\0\0\0' + local, 'one positive unfragmented advertisement'); advertisements.append(item)
        else:
            require(item['destination'] == remote and item['hop'] == 64 and item['frame'][:6] == peer,
                    'original diagnostic destination, hop and MAC'); diagnostics.append(item)
    require(len(warm) == 1 and len(advertisements) == 1 and probes and len(diagnostics) == 4,
            'exact diagnostics, positive ND and absence of forbidden replies')
    solicitations, replies = [], []
    for item in plain:
        body = item['body']
        require(item['frame'][:12] == guest + peer and item['source'] == remote and
                item['destination'] in (local, link) and item['hop'] == 255,
                'original peer neighbor envelope')
        if body[0] == 135:
            require(item['destination'] == local and body[:2] + bytes(2) + body[4:] ==
                    b'\x87\0' + bytes(6) + local, 'exact positive unfragmented neighbor input')
            solicitations.append(item)
        else:
            require(body[:2] + bytes(2) + body[4:] == b'\x88\0' + bytes(2) + b'\x60\0\0\0' +
                    remote + b'\2\1' + peer, 'exact peer neighbor resolution input')
            replies.append(item)
    require(len(solicitations) == 1 and len(replies) == len(probes), 'every original peer neighbor input')
    for probe, reply in zip(probes, replies):
        require(probe['index'] < reply['index'] and probe['source'] == reply['destination'],
                'peer resolves the actual original neighbor probe source')
    require(requests[1] < solicitations[0]['index'] < advertisements[0]['index'] < acknowledgements[1],
            'positive unfragmented solicitation precedes its advertisement in the original phase')
    require(acknowledgements[0] < probes[0]['index'] < replies[0]['index'] < warm[0]['index'] < acknowledgements[1],
            'original neighbor resolution precedes the zero-byte application warmup')
    wanted_errors = [(4, 0, 4, base + 13), (4, 0, 42, base + 14), (4, 3, 0, base + 15), (3, 1, 0, expiry_id)]
    for item, (kind, code, pointer, identity) in zip(diagnostics, wanted_errors):
        body = item['body']
        require(groups[identity][0]['index'] < item['index'], 'offending input precedes its diagnostic')
        require((body[0], body[1], int.from_bytes(body[4:8], 'big'), body[8:]) ==
                (kind, code, pointer, groups[identity][0]['frame'][14:]), 'exact original first-fragment or malformed quote')
    require(diagnostics[2]['index'] < acknowledgements[3] < requests[4],
            'all malformed diagnostics precede the expiry cohort')
    first, duplicate, tail, fresh = groups[expiry_id]
    age = diagnostics[-1]['ns'] - first['ns']
    require(59980000000 <= age <= (66000000000 if native else 61000000000), 'fixed real 60-second expiry')
    require(29980000000 <= duplicate['ns'] - first['ns'] <= 35000000000, 'real duplicate cannot renew first arrival')
    require(elapsed_ns(rows[acknowledgements[4]]) - first['ns'] >= 70000000000,
            'complete original quiet window after actual first-fragment arrival')
    require(diagnostics[-1]['index'] < acknowledgements[4], 'expiry diagnostic precedes completion barrier')
    require(tail['index'] > acknowledgements[4] and fresh['index'] > acknowledgements[5],
            'expired identity reuse retains no old first fragment')
    for n in range(1, 4):
        require((n - .02) * 1000000000 <= groups[expiry_id + n][0]['ns'] - first['ns'] <=
                (n + 1) * 1000000000, 'actual staggered suppression arrivals')
    return dict(passed=True, lane=lane, fragments=len(fragments), diagnostics=4,
                expiry_ns=age, interface_index=interface_index, firmware_sha256=firmware), dict(
                fragments=fragments, diagnostics=diagnostics, requests=requests,
                acknowledgements=acknowledgements, plain=plain, interface_index=interface_index,
                solicitations=solicitations, advertisements=advertisements, warm=warm)


def verify_capture(path, lane, log_path, archive, native=False, statistics=None, interface_index=None):
    path, log_path = Path(path), Path(log_path)
    original, log_bytes = path.read_bytes(), log_path.read_bytes()
    rows, log = read_capture(path), log_bytes.decode(errors='replace')
    binding = None
    if native:
        timed = [dict(stamp=row['ns'] // 1000, frame=row['frame']) for row in rows]
        binding = bind_native_clock(path, timed, statistics)
        for row, packet in zip(rows, timed):
            row['elapsed_ns'] = packet['monotonic_ns']
    result, proof = inspect(rows, lane, log, native, interface_index)
    cases = [*('missing-fragment-' + str(n) for n in range(len(proof['fragments']))),
             'missing-diagnostic', 'wrong-quote', 'early-expiry', 'renewed-expiry', 'short-quiet-window',
             'missing-barrier', 'wrong-application-size', 'wrong-application-scope', 'short-client-duration',
             'missing-case', 'wrong-fragment-byte', 'duplicate-diagnostic', 'missing-neighbor-input',
             'wrong-fragment-MAC', 'wrong-output-hop', 'late-raw-fragments', 'late-malformed-fragment',
             'wrong-positive-scope', 'diagnostic-before-input', 'wrong-independent-index',
             'late-positive-NS', 'early-positive-NA', 'late-UDP-warmup',
             'first-arrival-short-quiet', 'expiry-after-completion']
    rejections = []
    with zipfile.ZipFile(archive, 'x', compression=zipfile.ZIP_DEFLATED) as saved:
        for name in cases:
            changed, text, context_index = copy.deepcopy(rows), log, interface_index
            if name.startswith('missing-fragment-'):
                del changed[proof['fragments'][int(name.rsplit('-', 1)[1])]['index']]
            elif name == 'missing-diagnostic':
                del changed[proof['diagnostics'][-1]['index']]
            elif name == 'missing-barrier':
                del changed[proof['acknowledgements'][4]]
            elif name == 'missing-neighbor-input':
                del changed[proof['plain'][-1]['index']]
            elif name in ('late-positive-NS', 'late-UDP-warmup'):
                at = proof['solicitations'][0]['index'] if name == 'late-positive-NS' else proof['warm'][0]['index']
                moved = changed.pop(at)
                moved['ns'] = max(row['ns'] for row in changed) + 1000000000
                changed.append(moved)
            elif name == 'early-positive-NA':
                at = proof['advertisements'][0]['index']
                changed.insert(proof['solicitations'][0]['index'], changed.pop(at))
            elif name in ('late-raw-fragments', 'late-malformed-fragment'):
                identity = 0x66000000 + lane * 256 + (1 if name == 'late-raw-fragments' else 13)
                indexes = {x['index'] for x in proof['fragments'] if x['identity'] == identity}
                moved = [row for at, row in enumerate(changed) if at in indexes]
                changed = [row for at, row in enumerate(changed) if at not in indexes]
                last = max(row['ns'] for row in changed)
                for number, row in enumerate(moved, 1):
                    row['ns'] = last + number * 1000000000
                changed.extend(moved)
            elif name == 'diagnostic-before-input':
                at = proof['diagnostics'][0]['index']
                error = changed.pop(at)
                target = next(x['index'] for x in proof['fragments'] if x['identity'] == 0x6600000d + lane * 256)
                changed.insert(target, error)
            elif name == 'wrong-positive-scope':
                text = re.sub(rf'(IPV6_FRAGMENTS_CASE_PASS lane={lane} case=4 bytes=41 scope=)[0-9]+',
                              lambda match: match[1] + str(proof['interface_index'] + 1000), text)
            elif name == 'wrong-independent-index':
                if native:
                    context_index += 1000
                else:
                    text = re.sub(rf'(NET_DEVICE index=)[0-9]+( name=eth{lane} )',
                                  lambda match: match[1] + str(proof['interface_index'] + 1000) + match[2], text)
            elif name == 'wrong-quote':
                at = proof['diagnostics'][-1]['index']; frame = bytearray(changed[at]['frame']); frame[-1] ^= 1
                frame[56:58] = bytes(2)
                struct.pack_into('!H', frame, 56, checksum(frame[22:54] + struct.pack('!I3xB', len(frame) - 54, 58) + frame[54:]))
                changed[at]['frame'] = bytes(frame)
            elif name in ('early-expiry', 'renewed-expiry'):
                item = changed[proof['diagnostics'][-1]['index']]
                for clock in ('ns', 'elapsed_ns'):
                    if clock in item:
                        first = next(x for x in proof['fragments'] if x['identity'] == 0x66008000 + lane * 256)
                        item[clock] = (first['ns'] + 55000000000 if name == 'early-expiry' and clock == 'elapsed_ns'
                                       else item[clock] + (-15 if name == 'early-expiry' else 10) * 1000000000)
            elif name == 'short-quiet-window':
                item = changed[proof['acknowledgements'][4]]
                first = next(x for x in proof['fragments'] if x['identity'] == 0x66008000 + lane * 256)
                delta = elapsed_ns(item) - first['ns'] - 69000000000
                for clock in ('ns', 'elapsed_ns'):
                    if clock in item:
                        item[clock] -= delta
            elif name == 'first-arrival-short-quiet':
                identity = 0x66008000 + lane * 256
                first = next(x for x in proof['fragments'] if x['identity'] == identity)
                delta = elapsed_ns(rows[proof['acknowledgements'][4]]) - first['ns'] - 69000000000
                indexes = {x['index'] for x in proof['fragments'] if identity <= x['identity'] <= identity + 3 and
                           proof['requests'][4] < x['index'] < proof['acknowledgements'][4]}
                indexes.add(proof['diagnostics'][-1]['index'])
                for at in indexes:
                    for clock in ('ns', 'elapsed_ns'):
                        if clock in changed[at]:
                            changed[at][clock] += delta
            elif name == 'expiry-after-completion':
                moved = changed.pop(proof['diagnostics'][-1]['index'])
                ack = rows[proof['acknowledgements'][4]]['frame']
                at = next(index for index, item in enumerate(changed) if item['frame'] == ack)
                changed.insert(at + 1, moved)
            elif name == 'wrong-application-size':
                text = text.replace(f'case=3 bytes=65527', 'case=3 bytes=65526')
            elif name == 'wrong-application-scope':
                text = re.sub(r'case=4 bytes=41 scope=[0-9]+', 'case=4 bytes=41 scope=0', text)
            elif name == 'short-client-duration':
                text = re.sub(r'elapsed_ns=[0-9]+', 'elapsed_ns=60000000000', text)
            elif name == 'missing-case':
                text = text.replace(f'IPV6_FRAGMENTS_CASE_PASS lane={lane} case=9', 'MISSING')
            elif name == 'wrong-fragment-byte':
                at = proof['fragments'][0]['index']; frame = bytearray(changed[at]['frame']); frame[-1] ^= 1
                changed[at]['frame'] = bytes(frame)
            elif name in ('wrong-fragment-MAC', 'wrong-output-hop'):
                at = proof['fragments'][0]['index'] if name == 'wrong-fragment-MAC' else proof['diagnostics'][0]['index']
                frame = bytearray(changed[at]['frame']); frame[0 if name == 'wrong-fragment-MAC' else 21] ^= 1
                changed[at]['frame'] = bytes(frame)
            else:
                changed.insert(proof['diagnostics'][-1]['index'], copy.deepcopy(changed[proof['diagnostics'][-1]['index']]))
            saved.writestr(name + '.pcap', encode_capture(changed)); saved.writestr(name + '.log', text)
            saved.writestr(name + '.context.json', json.dumps(dict(native=native,
                interface_index=context_index), indent=2) + '\n')
            try:
                inspect(changed, lane, text, native, context_index)
            except ValueError as error:
                rejections.append(dict(name=name, reason=str(error)))
            else:
                raise ValueError('damaged fragment evidence accepted: ' + name)
        saved.writestr('rejections.json', json.dumps(rejections, indent=2) + '\n')
    require(path.read_bytes() == original and log_path.read_bytes() == log_bytes, 'original fragment evidence unchanged')
    result.update(damaged_rejected=len(rejections), original_sha256=hashlib.sha256(original).hexdigest(),
                  native_clock=binding, archive_sha256=hashlib.sha256(Path(archive).read_bytes()).hexdigest())
    return result
