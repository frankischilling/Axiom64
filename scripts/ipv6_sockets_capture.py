# SPDX-License-Identifier: GPL-3.0-or-later
"""Independently reconstruct original IPv6 raw/UDP socket exchanges."""
import copy
import hashlib
import ipaddress
import json
from pathlib import Path
import struct
import zipfile
from ipv4_expiry_capture import checksum, encode_capture, read_capture


def require(value, reason):
    if not value:
        raise ValueError(reason)


def inspect(rows, lane, log, native=False):
    require(log.count('IPV6_SOCKETS_ABI_PASS cases=286') == 1,
            'actual IPv6 argument bounds, copy ownership and scoped connection checks')
    abi_cases = {'negative-option-length': (2, 22), 'invalid-bind-length': (4, 22),
                 'invalid-connect-length': (4, 22), 'invalid-send-address-length': (4, 22),
                 'full-bind-address-import': (2, 14), 'full-connect-address-import': (2, 14),
                 'full-send-address-import': (2, 14), 'disconnect-address-import': (2, 14),
                 'conflicting-connect-device': (2, 22), 'negative-filter-length': (1, 22),
                 'raw-named-protocol': (1, 22), 'negative-sendmsg-address-length': (1, 22),
                 'negative-recvmsg-capacity': (1, 22), 'negative-receive-capacity': (2, 22),
                 'unreadable-receive-capacity': (4, 14)}
    abi_cases = {name: (count, -1, error) for name, (count, error) in abi_cases.items()}
    abi_cases.update({'partial-scope-bind': (6, -1, 22), 'partial-scope-connect': (6, -1, 22),
                      'bound-partial-scope-bind': (6, 0, 0), 'bound-partial-scope-connect': (6, 0, 0),
                      'disconnect-device-cleared': (4, 0, 0), 'unspecified-named-output': (64, 8, 0),
                      'unspecified-unconnected-output': (54, -1, 89), 'error-output-fault': (2, -1, 14),
                      'short-raw-output': (46, -1, 22), 'short-unspecified-output': (4, -1, 22),
                      'short-other-family': (4, -1, 22), 'short-inet6-output': (4, -1, 22),
                      'raw-other-family': (2, -1, 97), 'UDP-other-family': (2, -1, 22),
                      'empty-address-input': (6, -1, 22), 'empty-message-destination': (2, -1, 89),
                      'one-byte-address-fault': (8, -1, 14), 'oversized-address-input': (6, -1, 22),
                      'clamped-address-fault': (2, -1, 14), 'negative-address-before-fault': (8, -1, 22),
                      'consumed-error': (3, 0, 0), 'preserved-error': (3, 111, 0),
                      'error-invalid-length': (1, -1, 22), 'error-length-fault': (2, -1, 14),
                      'error-empty-output': (1, 0, 0)})
    require(log.count('IPV6_SOCKETS_ABI_CASE ') == 286 and all(
        log.count(f'IPV6_SOCKETS_ABI_CASE name={name} result={value} errno={error} passed=1') == count
        for name, (count, value, error) in abi_cases.items()), 'complete original socket ABI case results')
    require(log.count('IPV6_SOCKETS_LOCAL_PASS shared=1 faults=2 deadline=1 refused=1') == 1,
            'actual local socket, copy-fault and deadline checks')
    require(log.count(f'IPV6_SOCKETS_WIRE_PASS lane={lane} raw=1 UDP=4 scoped=1 error=1') == 1,
            'actual scoped socket completion')
    require(log.count('IPV6_SOCKETS_PASS nics=2 raw=1 UDP=1 loopback=1 faults=2 permissions=1') == 1,
            'actual complete socket client')
    for phase in range(3):
        require(log.count(f'IPV6_SOCKETS_PHASE_PASS lane={lane} phase={phase}') == 1,
                'actual ordered socket barriers')
    guest = bytes([0x52, 0x54, 0, 0x12, 0x34, 0x10 + lane])
    peer = bytes([2, 0x49, 0x50, 0x36, lane, 1])
    control = bytes([2, 0x49, 0x50, 0x36, lane, 0])
    local = ipaddress.IPv6Address(f'2001:db8:{lane + 1}::2').packed
    remote = ipaddress.IPv6Address(f'2001:db8:{lane + 1}::1').packed
    link = ipaddress.IPv6Address('fe80::2').packed
    remote_link = ipaddress.IPv6Address('fe80::1').packed
    requests, acknowledgements, packets, firmware, mld = {}, {}, [], [], []
    ready = False
    for index, row in enumerate(rows):
        frame = row['frame']
        if frame[12:14] == b'\x88\xb7':
            require(len(frame) == 60 and frame[14:19] == b'IP6S' + bytes([lane]) and not any(frame[21:]),
                    'complete socket Ethernet barrier')
            phase = frame[19]
            require(phase in range(3), 'defined socket barrier phase')
            reply = frame[20]
            require(reply in (0, 1) and frame[:12] == (guest + control if reply else control + guest),
                    'original socket barrier direction')
            book = acknowledgements if reply else requests
            require(phase not in book, 'unique socket barrier')
            book[phase] = index
            if phase == 0 and not reply:
                ready = True
            continue
        if not ready and not native:
            require(len(frame) >= 14 and frame[6:12] == guest,
                    'socket firmware prelude belongs to this adapter')
            require(len(firmware) < 256, 'bounded original socket firmware prelude')
            firmware.append(hashlib.sha256(frame).hexdigest())
            continue
        if frame[12:14] != b'\x86\xdd':
            continue
        require(len(frame) >= 54 and frame[14:18] == b'\x60\0\0\0', 'socket IPv6 fixed fields')
        length, protocol, hop = struct.unpack('!HBB', frame[18:22])
        require(54 + length <= len(frame), 'complete original socket IPv6 bytes')
        source, destination, body = frame[22:38], frame[38:54], frame[54:54 + length]
        if native and protocol == 0:
            require(frame[:12] == bytes.fromhex('333300000016') + guest and hop == 1 and
                    source in (bytes(16), link) and destination == ipaddress.IPv6Address('ff02::16').packed and
                    body[:8] == b'\x3a\0\5\2\0\0\1\0', 'native multicast report envelope')
            report = body[8:]
            require(len(report) >= 8 and report[:2] == b'\x8f\0' and not checksum(source + destination +
                    struct.pack('!I3xB', len(report), 58) + report), 'native multicast report checksum')
            at = 8
            for _ in range(int.from_bytes(report[6:8], 'big')):
                require(at + 20 <= len(report), 'bounded native multicast record')
                size = 20 + int.from_bytes(report[at + 2:at + 4], 'big') * 16 + report[at + 1] * 4
                require(report[at] in range(1, 7) and report[at + 4] == 255 and at + size <= len(report),
                        'valid native multicast record')
                at += size
            require(at == len(report), 'exact native multicast length')
            mld.append(index)
            continue
        require(protocol in (17, 58) and frame[6:12] in (guest, peer), 'original socket frame direction')
        packets.append(dict(index=index, guest=frame[6:12] == guest, source=source,
                            destination=destination, protocol=protocol, hop=hop, body=body, frame=frame))
    require(set(requests) == set(acknowledgements) == set(range(3)), 'all original socket barriers')
    require(requests[0] < acknowledgements[0] < requests[1] < acknowledgements[1] < requests[2] < acknowledgements[2],
            'causal socket barrier ordering')
    outgoing = [p for p in packets if p['guest']]
    incoming = [p for p in packets if not p['guest']]
    require(len(outgoing) == 7 and len(incoming) == 11, 'complete original socket packet cross product')
    sequence = [outgoing[0], incoming[0], outgoing[1], incoming[1], incoming[2], outgoing[2],
                *incoming[3:7], outgoing[3], incoming[7], outgoing[4], incoming[8], outgoing[5],
                incoming[9], outgoing[6], incoming[10]]
    require(all(a['index'] < b['index'] for a, b in zip(sequence, sequence[1:])), 'exact socket causal chain')
    require(acknowledgements[1] < sequence[0]['index'] and sequence[-1]['index'] < requests[2],
            'all transport traffic lies inside its original barriers')

    def envelope(packet, source, destination, protocol, hop, valid=True):
        require((packet['source'], packet['destination'], packet['protocol'], packet['hop']) ==
                (source, destination, protocol, hop), 'exact socket addresses, protocol and hop limit')
        dest_mac = b'\x33\x33' + destination[-4:] if destination[0] == 255 else (peer if packet['guest'] else guest)
        require(packet['frame'][:6] == dest_mac, 'exact socket destination MAC')
        value = checksum(source + destination + struct.pack('!I3xB', len(packet['body']), protocol) + packet['body'])
        require((value == 0) == valid, 'original valid or deliberately damaged socket checksum')

    for out_at, in_at, own, target in [(0, 0, local, remote), (5, 9, link, remote_link)]:
        solicit = b'\xff\x02' + bytes(9) + b'\1\xff' + target[-3:]
        request, answer = outgoing[out_at], incoming[in_at]
        envelope(request, own, solicit, 58, 255)
        require(request['body'][:2] + bytes(2) + request['body'][4:] ==
                b'\x87\0' + bytes(6) + target + b'\1\1' + guest, 'owned original neighbor solicitation')
        envelope(answer, target, own, 58, 255)
        require(answer['body'][:2] + bytes(2) + answer['body'][4:] ==
                b'\x88\0' + bytes(2) + b'\x60\0\0\0' + target + b'\2\1' + peer,
                'exact original neighbor resolution reply')
    raw = outgoing[1]
    raw_bytes = bytes([128, 0, 0, 0, 0x6a, 0x10 + lane, 0x27, 1]) + bytes((n * 7 + lane) & 255 for n in range(8, 19))
    envelope(raw, local, remote, 58, 37)
    require(raw['body'][:2] + bytes(2) + raw['body'][4:] == raw_bytes, 'exact original application ICMPv6 bytes')
    for at in (1, 2):
        envelope(incoming[at], remote, local, 58, 61, at == 2)
        expected = bytearray(raw_bytes)
        expected[0] = 129
        if at == 1:
            expected[-1] ^= 0x80
        require(incoming[at]['body'][:2] + bytes(2) + incoming[at]['body'][4:] == expected,
                'original raw reply or checksum rejection input')

    def udp(packet, source, destination, sport, dport, payload, valid=True, declared=None, zero=False):
        envelope(packet, source, destination, 17, 64, valid)
        require(len(packet['body']) >= 8, 'complete UDP header')
        a, b, length, value = struct.unpack('!HHHH', packet['body'][:8])
        require((a, b, length, packet['body'][8:]) ==
                (sport, dport, len(payload) + 8 if declared is None else declared, payload),
                'exact original UDP tuple, length and bytes')
        require((value == 0) == zero, 'mandatory checksum or deliberate zero-checksum input')

    for number, data, sport, dport, own, target in [
        (2, b'', 41000 + lane, 42000 + lane, local, remote),
        (3, bytes((n * 13 + lane) & 255 for n in range(41)), 41000 + lane, 42000 + lane, local, remote),
        (4, bytes((n * 3 + lane) & 255 for n in range(13)), 41010 + lane, 43000 + lane, local, remote),
        (6, bytes((n * 9 + lane) & 255 for n in range(7)), 41020 + lane, 44000 + lane, link, remote_link)]:
        udp(outgoing[number], own, target, sport, dport, data)
    udp(incoming[3], remote, local, 42000 + lane, 41000 + lane, b'\xe1', False)
    udp(incoming[4], remote, local, 42000 + lane, 41000 + lane, b'\xe1', False, zero=True)
    udp(incoming[5], remote, local, 42000 + lane, 41000 + lane, b'\xe2', False, declared=11)
    udp(incoming[6], remote, local, 42000 + lane, 41000 + lane, b'')
    udp(incoming[7], remote, local, 42000 + lane, 41000 + lane,
        bytes(((n * 13 + lane) & 255) ^ 0x5a for n in range(41)))
    udp(incoming[10], remote_link, link, 44000 + lane, 41020 + lane,
        bytes((n * 9 + lane) & 255 for n in range(7)))
    error = incoming[8]
    envelope(error, remote, local, 58, 64)
    require(error['body'][:2] + bytes(2) + error['body'][4:8] == b'\1\4' + bytes(6) and
            error['body'][8:] == outgoing[4]['frame'][14:54 + len(outgoing[4]['body'])],
            'original ICMPv6 error quotes the exact emitted datagram')
    return dict(passed=True, lane=lane, kernel_packets=7, peer_inputs=11, malformed_inputs=4,
                firmware_frames=len(firmware), firmware_sha256=firmware, native_MLD_reports=len(mld)), dict(
                    outgoing=outgoing, incoming=incoming, requests=requests, acknowledgements=acknowledgements)


def verify_capture(path, lane, log_path, archive, native=False):
    path, log_path = Path(path), Path(log_path)
    raw, log_raw = path.read_bytes(), log_path.read_bytes()
    rows, log = read_capture(path), log_raw.decode(errors='replace')
    result, proof = inspect(rows, lane, log, native)
    cases = ['missing-kernel', 'duplicate-kernel', 'checksum', 'source', 'destination', 'MAC', 'hop', 'payload',
             'missing-request', 'missing-ACK', 'missing-ABI-result', 'missing-ABI-case', 'failed-ABI-case',
             'wrong-error-ownership', 'wrong-partial-scope', 'wrong-short-UDP', 'wrong-import-order',
             'missing-local-result', 'missing-wire-result', 'missing-phase-result',
             *('missing-input-' + str(n) for n in range(11)), 'wrong-quote']
    if not native:
        cases += ['firmware-flood', 'foreign-firmware', 'short-firmware']
    rejected = []
    with zipfile.ZipFile(archive, 'x', compression=zipfile.ZIP_DEFLATED) as saved:
        for name in cases:
            changed, text = copy.deepcopy(rows), log
            at = proof['outgoing'][-1]['index']
            if name == 'missing-kernel':
                del changed[at]
            elif name == 'duplicate-kernel':
                changed.insert(at, copy.deepcopy(changed[at]))
            elif name == 'missing-request':
                del changed[proof['requests'][1]]
            elif name == 'missing-ACK':
                del changed[proof['acknowledgements'][2]]
            elif name == 'missing-ABI-result':
                text = text.replace('IPV6_SOCKETS_ABI_PASS', 'MISSING')
            elif name == 'missing-ABI-case':
                text = text.replace('IPV6_SOCKETS_ABI_CASE name=raw-named-protocol', 'MISSING')
            elif name == 'failed-ABI-case':
                text = text.replace('name=raw-named-protocol result=-1 errno=22 passed=1',
                                    'name=raw-named-protocol result=8 errno=22 passed=0')
            elif name == 'wrong-error-ownership':
                text = text.replace('name=consumed-error result=0 errno=0 passed=1',
                                    'name=consumed-error result=111 errno=0 passed=1')
            elif name == 'wrong-partial-scope':
                text = text.replace('name=partial-scope-connect result=-1 errno=22 passed=1',
                                    'name=partial-scope-connect result=0 errno=0 passed=1')
            elif name == 'wrong-short-UDP':
                text = text.replace('name=unspecified-unconnected-output result=-1 errno=89 passed=1',
                                    'name=unspecified-unconnected-output result=-1 errno=22 passed=1')
            elif name == 'wrong-import-order':
                text = text.replace('name=one-byte-address-fault result=-1 errno=14 passed=1',
                                    'name=one-byte-address-fault result=-1 errno=22 passed=1')
            elif name == 'missing-local-result':
                text = text.replace('IPV6_SOCKETS_LOCAL_PASS', 'MISSING')
            elif name == 'missing-wire-result':
                text = text.replace(f'IPV6_SOCKETS_WIRE_PASS lane={lane}', 'MISSING')
            elif name == 'missing-phase-result':
                text = text.replace(f'IPV6_SOCKETS_PHASE_PASS lane={lane} phase=1', 'MISSING')
            elif name.startswith('missing-input-'):
                del changed[proof['incoming'][int(name.rsplit('-', 1)[1])]['index']]
            elif name == 'firmware-flood':
                changed[:0] = [copy.deepcopy(rows[at]) for _ in range(257)]
            elif name in ('foreign-firmware', 'short-firmware'):
                frame = bytearray(rows[at]['frame'])
                if name == 'foreign-firmware':
                    frame[6] ^= 1
                else:
                    frame = frame[:5]
                row = copy.deepcopy(rows[0])
                row['frame'] = bytes(frame)
                changed.insert(0, row)
            else:
                if name == 'wrong-quote':
                    at = proof['incoming'][8]['index']
                frame = bytearray(changed[at]['frame'])
                offset = {'checksum': 60, 'source': 37, 'destination': 53, 'MAC': 5, 'hop': 21,
                          'payload': len(frame) - 1, 'wrong-quote': 100}[name]
                frame[offset] ^= 1
                if name != 'checksum':
                    protocol = frame[20]
                    check_at = 60 if protocol == 17 else 56
                    frame[check_at:check_at + 2] = bytes(2)
                    body = frame[54:54 + int.from_bytes(frame[18:20], 'big')]
                    value = checksum(frame[22:54] + struct.pack('!I3xB', len(body), protocol) + body)
                    struct.pack_into('!H', frame, check_at, value or (65535 if protocol == 17 else 0))
                changed[at]['frame'] = bytes(frame)
            saved.writestr(name + '.pcap', encode_capture(changed))
            saved.writestr(name + '.log', text)
            try:
                inspect(changed, lane, text, native)
            except ValueError as error:
                rejected.append(dict(name=name, reason=str(error)))
            else:
                raise ValueError('damaged socket evidence accepted: ' + name)
        saved.writestr('rejections.json', json.dumps(rejected, indent=2) + '\n')
    require(path.read_bytes() == raw and log_path.read_bytes() == log_raw, 'original socket evidence unchanged')
    result.update(damaged_rejected=len(rejected), original_sha256=hashlib.sha256(raw).hexdigest(),
                  archive_sha256=hashlib.sha256(Path(archive).read_bytes()).hexdigest())
    return result
