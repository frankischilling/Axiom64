# SPDX-License-Identifier: GPL-3.0-or-later
"""Reconstruct source output and rejected sends from original Ethernet captures."""
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


def policy(sequence):
    require(0 <= sequence < 216, 'bounded original output case')
    kind, scope = sequence // 108 + 2, sequence % 108 // 54
    configuration, number = sequence % 54 // 6, sequence % 6
    lengths = (0, 1452, 1453, 1472, 65527, 65528) if kind == 2 else (4, 1460, 1461, 1472, 65535, 65536)
    length = lengths[number]
    mode = configuration - 1 if configuration in range(1, 7) else 1
    mtu = 1280 if configuration == 8 else 1500
    allowed = configuration != 7 and mode in (0, 1, 5)
    error = length > (65527 if kind == 2 else 65535) or (not allowed and length + (48 if kind == 2 else 40) > mtu)
    return kind, scope, configuration, length, mtu, allowed, error


def stamp(row):
    return row.get('monotonic_ns', row['ns'])


def inspect_original(rows, lane, log, native=False):
    log = log.replace('\r\n', '\n')
    require(log.count('IPV6_OUTPUT_PASS adapters=2 cases=432 policies=9 scopes=2 copied_vectors=1 close_reuse=1') == 1 and
            'IPV6_OUTPUT_FAIL' not in log, 'actual output client completed the full workload')
    options = re.findall(r'^IPV6_OUTPUT_OPTION_CASE type=(\d+) case=(\d+) result=(-?\d+) errno=(\d+)$', log, re.MULTILINE)
    require(len(options) == 42 and log.count('IPV6_OUTPUT_OPTIONS_PASS cases=42') == 1,
            'complete actual output option argument checks')
    seen_options = set()
    for encoded in options:
        kind, number, result, error = map(int, encoded)
        wanted_error = 14 if number in (5, 10, 14) else 22 if number in (4, 6, 7, 8, 9, 11, 12, 13) else 0
        require(kind in (2, 3) and number in range(21) and (kind, number) not in seen_options and
                (result, error) == ((-1, wanted_error) if wanted_error else (0, 0)), 'original output option result and fault ordering')
        seen_options.add((kind, number))
    records = re.findall(r'^IPV6_OUTPUT_CASE lane=(\d+) case=(\d+) type=(\d+) scope=(\d+) configuration=(\d+) bytes=(\d+) result=(-?\d+) errno=(\d+)$', log, re.MULTILINE)
    require(len(records) == 432, 'every original output application result')
    seen = set()
    for encoded in records:
        link, number, kind, scope, configuration, length, result, error = map(int, encoded)
        require(link in (0, 1) and (link, number) not in seen, 'unique output application result')
        wanted = policy(number)
        require((kind, scope, configuration, length) == wanted[:4] and
                (result, error) == ((-1, 90) if wanted[-1] else (length, 0)), 'native output result and error policy')
        seen.add((link, number))
    require(seen == {(link, number) for link in range(2) for number in range(216)}, 'complete output result cross product')
    require(log.count(f'IPV6_OUTPUT_WIRE_PASS lane={lane} cases=216 maximum_raw=65535 maximum_UDP=65527') == 1,
            'actual adapter output completion')
    guest = bytes.fromhex('525400123410')[:-1] + bytes([0x10 + lane])
    control, peer = bytes([2, 0x49, 0x50, 0x36, lane, 0]), bytes([2, 0x49, 0x50, 0x36, lane, 1])
    local = ipaddress.IPv6Address(f'2001:db8:{lane + 1}::2').packed
    remote = ipaddress.IPv6Address(f'2001:db8:{lane + 1}::1').packed
    link, remote_link = ipaddress.IPv6Address('fe80::2').packed, ipaddress.IPv6Address('fe80::1').packed
    ready = False
    ready_reply = False
    active = None
    completed = 0
    firmware, mld = [], 0
    data_indices, fragments, raw_indices, quiet_pairs = [], [], [], []
    ids = set()
    # AF_PACKET can deliver opposite-direction records out of kernel timestamp order.
    # Keep original indices and clocks; validate causal order using those clocks.
    ordered = sorted(enumerate(rows), key=lambda item: (stamp(item[1]), item[0])) if native else enumerate(rows)
    for index, row in ordered:
        frame = row['frame']
        if frame[12:14] == b'\x88\xb8':
            require(len(frame) == 60 and frame[14:20] == b'IP6O' + bytes([lane, 0]) and
                    not any(frame[21:]), 'exact output readiness record')
            if frame[20] == 0:
                require(not ready and frame[:12] == control + guest, 'one original output readiness request')
                ready = True
            else:
                require(frame[20] == 1 and ready and not ready_reply and frame[:12] == guest + control,
                        'one original readiness acknowledgement')
                ready_reply = True
            continue
        if not ready and not native:
            require(len(firmware) < 256 and len(frame) >= 14 and frame[6:12] == guest, 'bounded owned output firmware')
            firmware.append(hashlib.sha256(frame).hexdigest())
            continue
        if frame[12:14] == b'\x88\xb9':
            require(ready_reply and len(frame) == 60 and frame[14:19] == b'IP6O' + bytes([lane]) and
                    frame[31] == 0 and not any(frame[33:]), 'exact output boundary bytes')
            kind, reply = frame[19], frame[32]
            number, length = struct.unpack_from('!II', frame, 20)
            wanted = policy(number)
            require((frame[28], frame[29], frame[30], length) == wanted[:4] and kind in (2, 3) and
                    reply in (0, 1) and frame[:12] == (guest + control if reply else control + guest),
                    'output boundary direction and original parameters')
            if kind == 2 and not reply:
                require(active is None and number == completed, 'one ordered output begin')
                active = dict(number=number, policy=wanted, begin=index, start=None, end=None,
                              body=bytearray(), done=False, identification=None)
            elif kind == 2:
                require(active is not None and number == active['number'] and active['start'] is None,
                        'one output begin acknowledgement')
                active['start'] = index
            elif not reply:
                require(active is not None and number == active['number'] and active['start'] is not None and active['end'] is None,
                        'one original output end request')
                active['end'] = index
            else:
                require(active is not None and number == active['number'] and active['end'] is not None,
                        'one output end acknowledgement')
                require(stamp(row) >= stamp(rows[active['end']]), 'original end acknowledgement clock follows request')
                require('last_data' not in active or stamp(row) >= stamp(rows[active['last_data']]), 'original end acknowledgement clock follows all data')
                if wanted[-1]:
                    require(not active['body'] and not active['done'], 'rejected application call emitted no datagram')
                    require(stamp(row) - stamp(rows[active['end']]) >= 50000000, 'full original fifty-millisecond rejection observation')
                    quiet_pairs.append((active['end'], index))
                else:
                    require(active['done'], 'output acknowledgement follows the complete original datagram')
                completed += 1
                active = None
            continue
        require(ready_reply and frame[12:14] == b'\x86\xdd' and len(frame) >= 54 and
                frame[14:18] == b'\x60\0\0\0', 'complete original IPv6 output envelope')
        length, protocol, hop = struct.unpack_from('!HBB', frame, 18)
        require(54 + length <= len(frame), 'complete original IPv6 bytes')
        source, destination, body = frame[22:38], frame[38:54], frame[54:54 + length]
        if native and protocol == 0:
            require(frame[:12] == bytes.fromhex('333300000016') + guest and hop == 1 and source in (bytes(16), link) and
                    destination == ipaddress.IPv6Address('ff02::16').packed and body[:8] == b'\x3a\0\5\2\0\0\1\0',
                    'native output multicast envelope')
            report = body[8:]
            require(len(report) >= 8 and report[:2] == b'\x8f\0' and not checksum(source + destination +
                    struct.pack('!I3xB', len(report), 58) + report), 'native output multicast checksum')
            mld += 1
            continue
        if protocol == 58 and body[:1] in (b'\x87', b'\x88'):
            require(hop == 255 and len(body) == 32 and not checksum(source + destination +
                    struct.pack('!I3xB', len(body), 58) + body), 'original output neighbor message')
            if body[0] == 135:
                target = body[8:24]
                expected_local = link if target == remote_link else local
                group = b'\xff\x02' + bytes(9) + b'\1\xff' + target[-3:]
                require(target in (remote, remote_link) and source == expected_local and destination == group and
                        frame[:12] == b'\x33\x33' + group[-4:] + guest and body[:2] == b'\x87\0' and
                        body[4:8] == bytes(4) and body[24:] == b'\1\1' + guest, 'owned neighbor solicitation')
            else:
                require(frame[:12] == guest + peer and source in (remote, remote_link) and
                        destination == (link if source == remote_link else local) and body[:2] == b'\x88\0' and
                        body[4:8] == b'\x60\0\0\0' and body[8:24] == source and body[24:] == b'\2\1' + peer,
                        'owned neighbor advertisement')
            continue
        require(active is not None and active['start'] is not None and not active['policy'][-1] and not active['done'],
                'one original datagram belongs to its accepted application call')
        require(stamp(row) >= stamp(rows[active['start']]), 'original data clock follows begin acknowledgement')
        kind, scope, configuration, size, mtu, allowed, _ = active['policy']
        own, target = (link, remote_link) if scope else (local, remote)
        require(frame[:12] == peer + guest and source == own and destination == target and hop == 64 and
                length + 40 <= 1500, 'original data source, route and interface MTU')
        data_indices.append(index)
        active['last_data'] = index
        if protocol == 44:
            require(allowed and length + 40 <= mtu and len(body) > 8 and not body[1],
                    'permitted complete Fragment header and socket fragment size')
            protocol, _, offset, identity = struct.unpack_from('!BBHI', body)
            require(identity and not offset & 6 and offset & 0xfff8 == len(active['body']), 'original contiguous fragment offsets')
            if active['identification'] is None:
                require((source, destination, identity) not in ids, 'fresh original fragment identity')
                ids.add((source, destination, identity))
                active['identification'] = identity
            require(active['identification'] == identity, 'stable original fragment identity')
            require(len(active['body']) + len(body) - 8 <= size + (8 if kind == 2 else 0), 'bounded reassembled output')
            active['body'].extend(body[8:])
            fragments.append(index)
            if offset & 1:
                require((len(body) - 8) % 8 == 0, 'aligned original nonfinal fragment')
                continue
            body = bytes(active['body'])
        else:
            require(not active['body'], 'unfragmented output does not replace fragments')
        require(protocol == (17 if kind == 2 else 58) and not checksum(source + destination +
                struct.pack('!I3xB', len(body), protocol) + body), 'original complete transport checksum')
        expected = bytes((n * 17 + active['number'] * 7 + lane) & 255 for n in range(size))
        if kind == 2:
            require(len(body) == size + 8 and struct.unpack_from('!HHH', body) ==
                    (45000 + lane + scope * 10, 46000 + lane + scope * 10, len(body)) and
                    body[6:8] != bytes(2) and body[8:] == expected, 'complete original UDP fields and bytes')
        else:
            require(body[:2] + bytes(2) + body[4:] == b'\x81\0\0\0' + expected[4:], 'every original raw output byte')
            if frame[20] == 58:
                raw_indices.append(index)
        active['done'] = True
    require(ready_reply and completed == 216 and active is None and fragments and quiet_pairs,
            'complete original output, fragmentation and rejection inventory')
    return dict(passed=True, lane=lane, cases=completed, fragment_groups=len(ids), fragments=len(fragments),
                negative_cases=len(quiet_pairs), minimum_quiet_ms=min((stamp(rows[b]) - stamp(rows[a])) / 1000000
                for a, b in quiet_pairs), firmware_frames=len(firmware), native_MLD_reports=mld), dict(
                    data=data_indices, fragments=fragments, raw=raw_indices, quiet=quiet_pairs)


def inspect(rows, lane, log, native=False, interface_index=None, native_send_class=None):
    from ipv6_send_controls_capture import boundary, inspect as inspect_send
    result, proof = inspect_original(rows[:boundary(rows, lane)], lane, log, native)
    controls, _ = inspect_send(rows, lane, log, native, interface_index, native_send_class)
    result['send_controls'] = controls
    from ipv6_extension_capture import inspect as inspect_extensions
    result['extensions'], _ = inspect_extensions(rows, lane, log, native, interface_index)
    from ipv6_routing_capture import inspect as inspect_routing
    result['routing'], _ = inspect_routing(rows, lane, log, native, interface_index)
    from ipv6_sticky_capture import inspect as inspect_sticky
    result['sticky'], _ = inspect_sticky(rows, lane, log, native, interface_index)
    return result, proof


def verify_capture(path, lane, log_path, archive, native=False, statistics=None, interface_index=None, native_send_class=None):
    path, log_path = Path(path), Path(log_path)
    original, original_log = path.read_bytes(), log_path.read_bytes()
    rows, log = read_capture(path), original_log.decode(errors='replace')
    clock = None
    if native:
        selected = []
        for row in rows:
            frame = row['frame']
            if frame[12:14] == b'\x86\xdd' and len(frame) >= 54 and frame[20] == 0 and frame[38:54] == bytes.fromhex('ff020000000000000000000000000016'):
                continue
            row['stamp'] = row['ns'] // 1000
            selected.append(row)
        clock = bind_native_clock(path, selected, statistics)
    result, proof = inspect(rows, lane, log, native, interface_index, native_send_class)
    controls = ('missing-data', 'duplicate-data', 'fragment-id', 'fragment-offset', 'checksum',
                'wrong-source', 'wrong-MAC', 'missing-end-ACK', 'short-quiet', 'wrong-case-result',
                'wrong-case-configuration', 'valid-checksum-wrong-raw',
                'data-before-begin-ACK', 'end-ACK-before-data')
    rejected = []
    with zipfile.ZipFile(archive, 'w', zipfile.ZIP_DEFLATED) as saved:
        for name in controls:
            changed, changed_log = copy.deepcopy(rows), log
            index = proof['data'][0]
            if name in ('data-before-begin-ACK', 'end-ACK-before-data'):
                data = proof['data'][0]
                before = next(n for n in range(len(changed)) if changed[n]['frame'][12:14] == b'\x88\xb9' and
                              changed[n]['frame'][19] == 2 and changed[n]['frame'][32] == 1 and int.from_bytes(changed[n]['frame'][20:24], 'big') == 0)
                after = next(n for n in range(len(changed)) if changed[n]['frame'][12:14] == b'\x88\xb9' and
                             changed[n]['frame'][19] == 3 and changed[n]['frame'][32] == 1 and int.from_bytes(changed[n]['frame'][20:24], 'big') == 0)
                target, reference = (data, before) if name == 'data-before-begin-ACK' else (after, data)
                changed[target]['ns'] = changed[reference]['ns'] - 1000
                changed[target]['monotonic_ns'] = stamp(changed[reference]) - 1000
            elif name == 'missing-data':
                del changed[index]
            elif name == 'duplicate-data':
                changed.insert(index, copy.deepcopy(changed[index]))
            elif name in ('fragment-id', 'fragment-offset'):
                index = proof['fragments'][0]
                frame = bytearray(changed[index]['frame'])
                frame[58 if name == 'fragment-id' else 57] ^= 8
                changed[index]['frame'] = bytes(frame)
            elif name in ('checksum', 'wrong-source', 'wrong-MAC'):
                frame = bytearray(changed[index]['frame'])
                frame[60 if name == 'checksum' else 37 if name == 'wrong-source' else 11] ^= 1
                changed[index]['frame'] = bytes(frame)
            elif name == 'missing-end-ACK':
                del changed[proof['quiet'][0][1]]
            elif name == 'short-quiet':
                a, b = proof['quiet'][0]
                changed[b]['ns'] = changed[a]['ns'] + 49000000
                changed[b]['monotonic_ns'] = stamp(changed[a]) + 49000000
            elif name == 'wrong-case-result':
                changed_log = changed_log.replace(f'IPV6_OUTPUT_CASE lane={lane} case=0 type=2 scope=0 configuration=0 bytes=0 result=0',
                                                  f'IPV6_OUTPUT_CASE lane={lane} case=0 type=2 scope=0 configuration=0 bytes=0 result=1', 1)
            elif name == 'wrong-case-configuration':
                index = next(n for n, row in enumerate(changed) if row['frame'][12:14] == b'\x88\xb9')
                frame = bytearray(changed[index]['frame'])
                frame[30] ^= 1
                changed[index]['frame'] = bytes(frame)
            else:
                index = proof['raw'][0]
                frame = bytearray(changed[index]['frame'])
                frame[55] ^= 1
                frame[56:58] = bytes(2)
                body = bytes(frame[54:54 + int.from_bytes(frame[18:20], 'big')])
                frame[56:58] = checksum(bytes(frame[22:54]) + struct.pack('!I3xB', len(body), 58) + body).to_bytes(2, 'big')
                changed[index]['frame'] = bytes(frame)
            saved.writestr(name + '.pcap', encode_capture(changed))
            saved.writestr(name + '.log', changed_log)
            try:
                inspect(changed, lane, changed_log, native, interface_index, native_send_class)
            except ValueError as failure:
                rejected.append(dict(name=name, reason=str(failure)))
            else:
                raise ValueError('accepted damaged IPv6 output evidence: ' + name)
        saved.writestr('rejections.json', json.dumps(rejected, indent=2))
    require(path.read_bytes() == original and log_path.read_bytes() == original_log, 'original output evidence remains unchanged')
    from ipv6_send_controls_capture import verify_capture as verify_send
    controls = verify_send(path, lane, log_path,
                           Path(archive).with_name(Path(archive).stem + '-send-controls.zip'),
                           native, interface_index, native_send_class)
    controls['native_clock_qualified'] = bool(clock)
    from ipv6_extension_capture import verify_capture as verify_extensions
    extensions = verify_extensions(path, lane, log_path,
        Path(archive).with_name(Path(archive).stem + '-extensions.zip'), native, interface_index)
    extensions['native_clock_qualified'] = bool(clock)
    from ipv6_routing_capture import verify_capture as verify_routing
    routing = verify_routing(path, lane, log_path,
        Path(archive).with_name(Path(archive).stem + '-routing.zip'), native, interface_index)
    routing['native_clock_qualified'] = bool(clock)
    from ipv6_sticky_capture import verify_capture as verify_sticky
    sticky = verify_sticky(path, lane, log_path,
        Path(archive).with_name(Path(archive).stem + '-sticky.zip'), native, interface_index)
    sticky['native_clock_qualified'] = bool(clock)
    result.update(damaged_rejected=len(rejected), original_sha256=hashlib.sha256(original).hexdigest(),
                  archive_sha256=hashlib.sha256(Path(archive).read_bytes()).hexdigest(), native_clock=clock,
                  send_controls=controls, extensions=extensions, routing=routing, sticky=sticky)
    return result
