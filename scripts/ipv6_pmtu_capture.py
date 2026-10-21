# SPDX-License-Identifier: GPL-3.0-or-later
"""Independently bind ICMP quotes, socket results and subsequent original packets."""
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


def expected(sequence):
    if sequence < 24:
        kind, scope, mode = sequence // 12 + 2, sequence % 12 // 6, sequence % 6
        return kind, scope, mode, 2, 0, 1280 if kind == 3 or mode < 4 else 1500, (
            90 if (kind == 3 and mode == 2) or (kind == 2 and mode in (1, 2, 3)) else 0)
    if sequence < 50:
        n = (sequence - 24) % 13
        return ((sequence - 24) // 13 + 2, 0, 1,
                ((1,) * 8 + (3, 3, 4, 4, 4))[n],
                (0, 1, 2, 3, 4, 5, 6, 7, 0, 1, 0, 1, 2)[n], 1500,
                (0, 13, 0, 0, 111, 13, 13, 71, 0, 0, 71, 71, 71)[n])
    return (sequence - 50) // 5 + 2, 0, 1, 1, 4, 1500, 0


def stamp(row):
    return row.get('monotonic_ns', row['ns'])


def inspect(rows, lane, log, native=False):
    log = log.replace('\r\n', '\n')
    require(log.count('IPV6_PMTU_PASS adapters=2 cases=120 policies=6 malformed_each=10') == 1 and
            'IPV6_PMTU_FAIL' not in log, 'actual PMTU application completion')
    records = re.findall(r'^IPV6_PMTU_ERROR lane=(\d+) case=(\d+) type=(\d+) scope=(\d+) mode=(\d+) icmp=(\d+) code=(\d+) mtu=(\d+) errno=(\d+)$', log, re.MULTILINE)
    require(len(records) == 120, 'complete quoted-error socket result inventory')
    seen = set()
    for encoded in records:
        link, sequence, *values = map(int, encoded)
        require(link in (0, 1) and sequence in range(60) and (link, sequence) not in seen and
                tuple(values) == expected(sequence), 'exact native quoted-error result')
        seen.add((link, sequence))
    sends = re.findall(r'^IPV6_PMTU_SEND lane=(\d+) case=(\d+) result=(-?\d+) errno=(\d+)$', log, re.MULTILINE)
    require(len(sends) == 48, 'every post-PMTU actual send result')
    seen = set()
    for encoded in sends:
        link, sequence, result, error = map(int, encoded)
        require(link in (0, 1) and sequence in range(24) and (link, sequence) not in seen and
                (result, error) == ((-1, 90) if sequence % 6 == 2 else (1300, 0)), 'exact PMTU send result')
        seen.add((link, sequence))
    guest = bytes([0x52, 0x54, 0, 0x12, 0x34, 0x10 + lane])
    control, peer = bytes([2, 0x49, 0x50, 0x36, lane, 0]), bytes([2, 0x49, 0x50, 0x36, lane, 1])
    global_local = ipaddress.IPv6Address(f'2001:db8:{lane + 1}::2').packed
    link_local = ipaddress.IPv6Address('fe80::2').packed
    ready, ready_reply = False, False
    phase, waiting, completed = 0, None, 0
    active = None
    firmware, mld = [], 0
    data_indices, quote_indices, fragment_indices, intervals = [], [], [], []
    for index, row in enumerate(rows):
        frame = row['frame']
        require(len(frame) >= 14, 'complete PMTU Ethernet header')
        if frame[12:14] == b'\x88\xba':
            require(len(frame) == 60 and frame[14:19] == b'IP6P' + bytes([lane]) and
                    not any(frame[21:]), 'exact retained PMTU phase bytes')
            number, reply = frame[19:21]
            if not reply:
                require(frame[:12] == control + guest and waiting is None, 'one owned phase request')
                if not ready:
                    require(number == 0, 'readiness precedes PMTU configuration')
                    ready = True
                else:
                    require(ready_reply and number == phase + 1, 'all PMTU phase requests in order')
                    phase = number
                    sequence = (phase - 1) // 3
                    require(sequence == completed, 'complete ordered PMTU cases')
                    if phase % 3 == 1:
                        require(active is None, 'one PMTU application case')
                        kind, scope, mode, typ, code, _, _ = expected(sequence)
                        local = link_local if scope else global_local
                        remote = local[:-1] + bytes([16 + sequence])
                        active = dict(sequence=sequence, kind=kind, scope=scope, mode=mode,
                                      typ=typ, code=code, local=local, remote=remote, data=bytearray(),
                                      identification=None, done=False)
                    elif phase % 3 == 2:
                        require('injected' not in active, 'one pending quoted-error observation')
                waiting = (number, index)
            else:
                require(reply == 1 and frame[:12] == guest + control and waiting is not None and
                        number == waiting[0], 'exact owned PMTU acknowledgement')
                if number == 0:
                    ready_reply = True
                elif number % 3 == 2:
                    require('injected' in active and stamp(row) - stamp(rows[active['injected']]) >= 50000000,
                            'full real error observation before checking socket state')
                    intervals.append((active['injected'], index))
                    active['observed'] = True
                elif number % 3 == 0:
                    if active['sequence'] < 24:
                        require(active['observed'] and (active['done'] if active['mode'] != 2 else
                                stamp(row) - stamp(rows[waiting[1]]) >= 50000000),
                                'successful wire delivery or full rejected-send observation')
                        if active['mode'] == 2:
                            intervals.append((waiting[1], index))
                    completed += 1
                    active = None
                waiting = None
            continue
        if not ready and not native:
            require(len(firmware) < 256 and frame[6:12] == guest, 'bounded owned PMTU firmware traffic')
            firmware.append(hashlib.sha256(frame).hexdigest())
            continue
        require(ready_reply and frame[12:14] == b'\x86\xdd' and len(frame) >= 54 and
                frame[14:18] == b'\x60\0\0\0', 'original PMTU IPv6 envelope')
        size, protocol, hop = struct.unpack_from('!HBB', frame, 18)
        require(len(frame) >= 54 + size, 'original IPv6 payload bounds')
        source, destination, body = frame[22:38], frame[38:54], frame[54:54 + size]
        if native and protocol == 0:
            require(frame[6:12] == guest and hop == 1 and frame[54:62] == b'\x3a\0\5\2\0\0\1\0' and
                    source in (bytes(16), link_local) and destination == ipaddress.IPv6Address('ff02::16').packed and
                    frame[:6] == b'\x33\x33\0\0\0\x16' and body[8:10] == b'\x8f\0' and
                    not checksum(source + destination + struct.pack('!I3xB', len(body) - 8, 58) + body[8:]),
                    'separately counted native multicast reports')
            mld += 1
            continue
        require(active is not None, 'PMTU packet belongs to a live case')
        if protocol == 58 and body[:1] in (b'\x87', b'\x88'):
            require(hop == 255 and len(body) == 32 and not checksum(source + destination +
                    struct.pack('!I3xB', len(body), 58) + body), 'complete ND checksum and lifetime')
            if body[0] == 135:
                require(frame[6:12] == guest and source == active['local'] and body[8:24] == active['remote'] and
                        destination == b'\xff\x02' + bytes(9) + b'\1\xff' + active['remote'][-3:] and
                        frame[:6] == b'\x33\x33\xff' + active['remote'][-3:] and
                        body[:2] == b'\x87\0' and body[4:8] == bytes(4) and body[24:] == b'\1\1' + guest,
                        'owned PMTU solicitation')
            else:
                require(frame[:12] == guest + peer and source == active['remote'] and destination == active['local'] and
                        body[:8] == b'\x88\0' + body[2:4] + b'\x60\0\0\0' and
                        body[8:24] == source and body[24:] == b'\2\1' + peer,
                        'owned PMTU advertisement')
            continue
        if frame[6:12] == peer:
            require(waiting is not None and waiting[0] % 3 == 2 and 'original' in active and
                    'injected' not in active, 'one router error for the actual quoted packet')
            original = bytearray(active['original'][14:62])
            sequence = active['sequence']
            if sequence >= 50:
                damage = (sequence - 50) % 5
                if damage == 1:
                    original[23] ^= 64
                elif damage == 2:
                    original[39] ^= 64
                elif damage == 3:
                    original = original[:-1]
                elif damage == 4:
                    original[6] = 44
                    original[4:6] = (int.from_bytes(original[4:6], 'big') + 8).to_bytes(2, 'big')
                    original[40:40] = bytes([17 if active['kind'] == 2 else 58, 0, 0, 8, 0, 0, 0, 1])
            wanted = bytearray(bytes([active['typ'], active['code'], 0, 0]) +
                               struct.pack('!I', 1280 if sequence < 24 else 0) + original)
            router = active['remote'][:-1] + b'\xfa'
            wanted[2:4] = checksum(router + active['local'] + struct.pack('!I3xB', len(wanted), 58) + wanted).to_bytes(2, 'big')
            if sequence >= 50 and (sequence - 50) % 5 == 0:
                wanted[3] ^= 1
            require(frame[:12] == guest + peer and source == router and destination == active['local'] and
                    hop == 64 and protocol == 58 and body == wanted, 'every original quote and deliberate malformed byte')
            active['injected'] = index
            quote_indices.append(index)
            continue
        require(frame[:12] == peer + guest and source == active['local'] and destination == active['remote'] and
                hop == 64, 'actual output route, interface and source ownership')
        second = 'original' in active
        if second:
            require(active['sequence'] < 24 and active.get('observed') and active['mode'] != 2 and
                    not active['done'], 'only permitted sends produce later data')
        limit = 1280 if second and active['mode'] < 3 else 1500
        require(size + 40 <= limit, 'actual data obeys the selected learned or interface limit')
        if protocol == 44:
            require(second and active['mode'] < 2 and len(body) >= 8, 'permitted original Fragment header')
            protocol, reserved, offset, identification = struct.unpack_from('!BBHI', body)
            require(not reserved and not offset & 6 and offset & 0xfff8 == len(active['data']) and identification,
                    'complete ordered original fragment bounds')
            require(protocol == (17 if active['kind'] == 2 else 58) and
                    len(active['data']) + len(body) - 8 <= 1308, 'bounded original fragment protocol and bytes')
            if active['identification'] is None:
                active['identification'] = identification
            require(active['identification'] == identification, 'one original fragment identity')
            active['data'].extend(body[8:])
            fragment_indices.append(index)
            if offset & 1:
                require((len(body) - 8) % 8 == 0, 'aligned original nonfinal fragment')
                continue
            body = bytes(active['data'])
        require(protocol == (17 if active['kind'] == 2 else 58) and not checksum(source + destination +
                struct.pack('!I3xB', len(body), protocol) + body), 'complete original upper-layer checksum')
        length = 1300 if active['sequence'] < 24 else 16
        payload = bytes((n * 19 + active['sequence'] * 3 + lane) & 255 for n in range(length))
        if active['kind'] == 2:
            require(len(body) == length + 8 and struct.unpack_from('!HHH', body) ==
                    (47000 + active['sequence'], 48000 + active['sequence'], length + 8) and
                    body[6:8] != bytes(2) and body[8:] == payload,
                    'every original PMTU UDP application byte')
        else:
            require(len(body) == length and body[:2] == b'\x81\0' and body[4:] == payload[4:],
                    'every original PMTU raw application byte')
        data_indices.append(index)
        if second:
            active['done'] = True
        else:
            active['original'] = frame
    require(ready_reply and completed == 60 and active is None and waiting is None and
            len(quote_indices) == 60 and len(intervals) == 64 and fragment_indices,
            'complete quotes, actual output and real observation inventory')
    return dict(passed=True, lane=lane, cases=completed, quotes=len(quote_indices),
                fragments=len(fragment_indices), observations=len(intervals),
                firmware_frames=len(firmware), native_MLD_reports=mld), dict(
                    data=data_indices, quotes=quote_indices, fragments=fragment_indices, intervals=intervals)


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
    names = ('missing-data', 'duplicate-data', 'missing-quote', 'wrong-quote', 'wrong-MTU-result',
             'wrong-error-result', 'wrong-send-result', 'short-observation', 'fragment-offset',
             'fragment-id', 'data-checksum', 'foreign-source')
    with zipfile.ZipFile(archive, 'w', zipfile.ZIP_DEFLATED) as saved:
        for name in names:
            changed, changed_log = copy.deepcopy(rows), log
            index = proof['data'][0]
            if name == 'missing-data':
                del changed[index]
            elif name == 'duplicate-data':
                changed.insert(index, copy.deepcopy(changed[index]))
            elif name == 'missing-quote':
                del changed[proof['quotes'][0]]
            elif name == 'wrong-quote':
                index = proof['quotes'][0]
                frame = bytearray(changed[index]['frame'])
                frame[-1] ^= 1
                changed[index]['frame'] = bytes(frame)
            elif name in ('wrong-MTU-result', 'wrong-error-result'):
                wanted = f'IPV6_PMTU_ERROR lane={lane} case=0 type=2 scope=0 mode=0 icmp=2 code=0 mtu=1280 errno=0'
                changed_log = changed_log.replace(wanted, wanted.replace('mtu=1280', 'mtu=1500') if name == 'wrong-MTU-result'
                                                 else wanted.replace('errno=0', 'errno=90'), 1)
            elif name == 'wrong-send-result':
                wanted = f'IPV6_PMTU_SEND lane={lane} case=0 result=1300 errno=0'
                changed_log = changed_log.replace(wanted, wanted.replace('result=1300', 'result=1299'), 1)
            elif name == 'short-observation':
                a, b = proof['intervals'][0]
                changed[b]['ns'] = changed[a]['ns'] + 49000000
                changed[b]['monotonic_ns'] = stamp(changed[a]) + 49000000
            else:
                index = proof['fragments'][0] if name.startswith('fragment') else index
                frame = bytearray(changed[index]['frame'])
                frame[57 if name == 'fragment-offset' else 58 if name == 'fragment-id' else
                      60 if name == 'data-checksum' else 37] ^= 8
                changed[index]['frame'] = bytes(frame)
            saved.writestr(name + '.pcap', encode_capture(changed))
            saved.writestr(name + '.log', changed_log)
            try:
                inspect(changed, lane, changed_log, native)
            except ValueError as failure:
                rejected.append(dict(name=name, reason=str(failure)))
            else:
                raise ValueError('accepted damaged IPv6 PMTU evidence: ' + name)
        saved.writestr('rejections.json', json.dumps(rejected, indent=2))
    require(path.read_bytes() == original and log_path.read_bytes() == original_log, 'original PMTU evidence unchanged')
    result.update(damaged_rejected=len(rejected), native_clock=clock,
                  original_sha256=hashlib.sha256(original).hexdigest(),
                  archive_sha256=hashlib.sha256(Path(archive).read_bytes()).hexdigest())
    return result
