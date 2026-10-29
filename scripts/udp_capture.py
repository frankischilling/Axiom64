# SPDX-License-Identifier: GPL-3.0-or-later
"""Independently validate every frame in the controlled UDP wire scenario."""
from collections import Counter
import hashlib
import struct

from ipv4_expiry_capture import checksum, require


def _capture_records(path):
    raw = path.read_bytes()
    formats = {b'\xd4\xc3\xb2\xa1': ('<', 1000, 1000000),
               b'\xa1\xb2\xc3\xd4': ('>', 1000, 1000000),
               b'\x4d\x3c\xb2\xa1': ('<', 1, 1000000000),
               b'\xa1\xb2\x3c\x4d': ('>', 1, 1000000000)}
    require(len(raw) >= 24 and raw[:4] in formats, 'complete original UDP PCAP header')
    order, scale, limit = formats[raw[:4]]
    version, minor, _, _, snapshot, link = struct.unpack_from(order + 'HHIIII', raw, 4)
    require((version, minor, link) == (2, 4, 1) and 1514 <= snapshot <= 65553,
            'UDP Ethernet PCAP format and snapshot bound')
    rows, at = [], 24
    while at < len(raw):
        require(at + 16 <= len(raw), 'complete original UDP PCAP record')
        seconds, fraction, size, original = struct.unpack_from(order + 'IIII', raw, at)
        require(fraction < limit, 'bounded original UDP PCAP clock fraction')
        at += 16
        require(14 <= size == original <= snapshot and at + size <= len(raw),
                'complete original UDP captured frame')
        rows.append(dict(ns=seconds * 1000000000 + fraction * scale, frame=raw[at:at + size]))
        at += size
    return rows


def _payload(size, lane, phase, sequence=0):
    head = b'UD' + phase.encode() + bytes([lane]) + sequence.to_bytes(2, 'big') + size.to_bytes(2, 'big')
    return head + bytes(((position * 17 + sequence * 13 + lane * 7) % 256 for position in range(8, size)))


def _segment(src, dst, sport, dport, data, zero=False):
    encoded = bytearray(struct.pack('!HHHH', sport, dport, len(data) + 8, 0) + data)
    if not zero:
        struct.pack_into('!H', encoded, 6, checksum(src + dst + bytes([0, 17]) + len(encoded).to_bytes(2, 'big') + encoded) or 65535)
    return bytes(encoded)


def _ip_packet(src, dst, body, identifier=0x6400, protocol=17):
    header = bytearray(bytes([0x45, 0]) + (len(body) + 20).to_bytes(2, 'big') + identifier.to_bytes(2, 'big') + bytes(2) + bytes([51, protocol, 0, 0]) + src + dst)
    struct.pack_into('!H', header, 10, checksum(header))
    return bytes(header) + body


def audit_capture(path, lane, fault=False, *, route_retirement=False):
    require(type(route_retirement) is bool, 'known UDP route-lifetime capture contract')
    records = _capture_records(path)
    require(records and all((a['ns'] <= b['ns'] for a, b in zip(records, records[1:]))), 'original UDP capture clocks are ordered')
    guest = bytes([82, 84, 0, 18, 52, 16 + lane])
    peer = bytes([2, 65, 88, 85, 68, lane])
    pressure_mac = peer[:5] + bytes([lane + 10])
    local = bytes([10, 23, lane + 1, 2])
    remote = local[:3] + b'\x01'
    pressure_ip = local[:3] + b'\x03'
    unresolved = local[:3] + b'c'
    broadcast = b'\xff' * 4
    outgoing = []
    incoming = []
    errors = []
    arp = []
    prelude = []
    started = False
    for number, row in enumerate(records):
        frame = row['frame']
        ether = frame[12:14]
        if ether == b'\x86\xdd' and (not started):
            ip = frame[14:]
            require(frame[6:12] == guest and len(ip) >= 40 and (ip[0] >> 4 == 6) and (len(ip) == 40 + int.from_bytes(ip[4:6], 'big')), 'complete UDP IPv6 bootstrap frame')
            destination = ip[24:40]
            require(ip[8:24] == bytes(16) and frame[:6] == b'33' + destination[-4:], 'UDP bootstrap source and multicast mapping')
            body = ip[40:]
            hop = ip[7]
            if ip[6] == 0:
                require(body[:8] == b':\x00\x05\x02\x00\x00\x01\x00' and hop == 1, 'UDP bootstrap multicast router alert')
                body = body[8:]
                require(len(body) == 24 and body[:2] == b'\x83\x00' and (body[4:8] == bytes(4)) and (body[8:] == destination), 'UDP bootstrap membership report')
            else:
                require(ip[6] == 58 and hop == 255 and (len(body) == 24) and (body[:2] == b'\x87\x00') and (body[4:8] == bytes(4)), 'UDP bootstrap neighbor solicitation')
                target = bytes.fromhex('fe80000000000000') + bytes([80, 84, 0, 255, 254, 18, 52, 16 + lane])
                require(body[8:] == target and destination == bytes.fromhex('ff0200000000000000000001ff') + target[-3:], 'UDP bootstrap target identity')
            require(checksum(ip[8:40] + len(body).to_bytes(4, 'big') + bytes([0, 0, 0, 58]) + body) == 0, 'UDP bootstrap checksum')
            prelude.append(number)
            continue
        started = True
        if ether == b'\x08\x06':
            require(len(frame) == 60 and frame[14:20] == b'\x00\x01\x08\x00\x06\x04' and (not any(frame[42:])), 'complete UDP ARP frame')
            op = int.from_bytes(frame[20:22], 'big')
            if op == 1:
                target = frame[38:42]
                require(frame[:12] == b'\xff' * 6 + guest and frame[22:32] == guest + local and (frame[32:38] == bytes(6)) and (target in (remote, pressure_ip, unresolved)), 'UDP ARP request ownership')
                arp.append(('request', target, number))
            else:
                require(op == 2 and frame[:6] == guest and (frame[32:42] == guest + local) and (frame[28:32] in (remote, pressure_ip)), 'UDP ARP reply ownership')
                target = frame[28:32]
                mac = peer if target == remote else pressure_mac
                require(frame[6:12] == mac and frame[22:28] == mac, 'UDP ARP reply hardware identity')
                arp.append(('reply', target, number))
            continue
        require(ether == b'\x08\x00' and len(frame) >= 34, 'only original UDP fixture IPv4 frames after bootstrap')
        ip = frame[14:]
        total = int.from_bytes(ip[2:4], 'big')
        require(ip[0] == 69 and ip[1] == 0 and (20 <= total <= len(ip)) and (not any(ip[total:])) and (checksum(ip[:20]) == 0), 'complete UDP IPv4 header, checksum and padding')
        ip = ip[:total]
        out = frame[6:12] == guest
        if out:
            require(ip[12:16] == local and ip[8] == 64 and (ip[16:20] in (remote, pressure_ip, broadcast)), 'UDP guest IPv4 source, destination and TTL')
            mac = peer if ip[16:20] == remote else pressure_mac if ip[16:20] == pressure_ip else b'\xff' * 6
            require(frame[:12] == mac + guest, 'UDP guest Ethernet route')
            if ip[9] == 1:
                require(len(ip) == 56 and ip[6:8] == b'@\x00' and (ip[20:22] == b'\x03\x03') and (ip[24:28] == bytes(4)) and (checksum(ip[20:]) == 0), 'UDP complete emitted port error')
                errors.append((ip[28:], number))
                continue
            require(ip[9] == 17 and len(ip) >= 28, 'UDP guest protocol and header')
            body = ip[20:]
            sport, dport, size, check = struct.unpack_from('!HHHH', body)
            require(size == len(body) and check and (checksum(ip[12:20] + bytes([0, 17]) + size.to_bytes(2, 'big') + body) == 0), 'UDP guest complete segment and pseudo-header checksum')
            outgoing.append(dict(signature=(sport, dport, ip[16:20], body[8:]), ip=ip, number=number, flags=ip[6:8], sum=check))
        else:
            require(frame[6:12] == peer and frame[:6] in (guest, b'\xff' * 6), 'UDP incoming Ethernet identity')
            incoming.append(dict(frame=frame, ip=ip, number=number))
    resolution_count = 2 if route_retirement and not fault else 1
    expected_arp = Counter({('request', remote): resolution_count, ('reply', remote): resolution_count})
    if not fault:
        expected_arp.update({('request', pressure_ip): 1, ('reply', pressure_ip): 1, ('request', unresolved): 3})
    require(Counter(((kind, target) for kind, target, _ in arp)) == expected_arp, 'exact UDP route, pressure and unreachable ARP exchanges')
    request = next((number for kind, target, number in arp if kind == 'request' and target == remote))
    reply = next((number for kind, target, number in arp if kind == 'reply' and target == remote))
    require(request < reply, 'UDP ARP reply follows original request')
    control = 41000 + lane
    specs = []

    def emit(sport, dport, data, target=remote, flags=b'@\x00', label=None):
        specs.append(dict(signature=(sport, dport, target, data), flags=flags, label=label))
    if fault:
        if lane == 1:
            emit(47001, 9000, _payload(31, lane, 'G'), label='fault')
    else:
        for phase, sequence, size in [('E', 0, 129), ('E', 1, 47), ('E', 2, 31), ('M', 0, 1472)]:
            emit(control, 9000, _payload(size, lane, phase, sequence), label=f'{phase}{sequence}')
        emit(control, 9000, b'', label='zero')
        empty = struct.pack('!HHHH', control, 9001, 10, 0)
        word = checksum(local + remote + bytes([0, 17, 0, 10]) + empty + bytes(2))
        emit(control, 9001, word.to_bytes(2, 'big'), label='computed-zero')
        for phase in 'VFS':
            emit(control, 9000, _payload(31, lane, phase), label=phase)
            if phase == 'S':
                emit(42000 + lane, 9002, _payload(73, lane, 'Q'), label='server')
        emit(control, 9000, _payload(31, lane, 'O'), label='O')
        for i, sequence in enumerate((2, 0, 2, 1)):
            emit(42000 + lane, 9004, _payload(31, lane, 'O', sequence), label=f'order{i}')
        for phase in 'CI':
            emit(control, 9000, _payload(31, lane, phase), label=phase)
        for sequence in range(3):
            emit(control, 9000, _payload(31, lane, 'B', sequence), broadcast, label=f'B{sequence}')
        for sequence in range(48):
            emit(44000 + lane, 9003, _payload(31, lane, 'K', sequence), flags=bytes(2), label=f'K{sequence}')
        for sequence in range(33):
            emit(45000 + lane, 9000, _payload(129, lane, 'P', sequence), pressure_ip, label=f'P{sequence}')
        for phase in 'LR':
            flags = b'\x40\0' if route_retirement and phase == 'R' else bytes(2)
            emit(control, 9000, _payload(31, lane, phase), flags=flags, label=phase)
    require([v['signature'] for v in outgoing] == [v['signature'] for v in specs], 'exact complete ordered UDP datagrams, retained bytes and tuples')
    require(all((v['flags'] == s['flags'] for v, s in zip(outgoing, specs))), 'UDP original discovery flags before and after quoted MTU')
    observed = {s['label']: v for v, s in zip(outgoing, specs)}
    require(not outgoing or reply < outgoing[0]['number'], 'UDP output follows physical address resolution')
    if route_retirement and not fault:
        resolutions = [(kind, number) for kind, target, number in arp if target == remote]
        require([kind for kind, _ in resolutions] == ['request', 'reply', 'request', 'reply'] and
                observed['L']['number'] < resolutions[2][1] < resolutions[3][1] < observed['R']['number'],
                'UDP restored route independently resolves its neighbor before fresh output')
    expected = []

    def incoming_packet(body, identifier=0x6400, protocol=17, src=remote, dst=local, mac=None, trigger=None):
        ip = _ip_packet(src, dst, body, identifier, protocol)
        frame = ((b'\xff' * 6 if dst == broadcast else guest) + peer + b'\x08\x00' + ip).ljust(60, b'\x00')
        expected.append(dict(frame=frame, trigger=trigger))
        return ip

    def receive(data, dport=control, sport=9000, identifier=0x6400, src=remote, dst=local, zero=False, surplus=b'', trigger=None):
        return incoming_packet(_segment(src, dst, sport, dport, data, zero) + surplus, identifier, src=src, dst=dst, trigger=trigger)
    if fault:
        if lane == 1:
            receive(_payload(31, lane, 'G'), 47001, trigger='fault')
    else:
        for phase, sequence, size in [('E', 0, 129), ('E', 1, 47), ('E', 2, 31), ('M', 0, 1472)]:
            receive(_payload(size, lane, phase, sequence), trigger=f'{phase}{sequence}')
        receive(b'', trigger='zero')
        receive(specs[5]['signature'][3], sport=9001, trigger='computed-zero')
        require(observed['computed-zero']['sum'] == 65535, 'UDP computed-zero checksum uses all ones')
        good = _segment(remote, local, 9000, control, _payload(31, lane, 'V'))
        forms = [good[:n] for n in range(8)]
        for length in (0, 7, 9):
            forms.append(struct.pack('!HHHH', 9000, control, length, 0))
        bad = bytearray(good)
        bad[7] ^= 1
        if not any(bad[6:8]):
            bad[7] = 1
        forms.extend([bytes(bad), _segment(remote[:3] + b'\t', local, 9000, control, _payload(31, lane, 'V'))])
        bad = bytearray(good)
        struct.pack_into('!H', bad, 4, len(bad) - 1)
        forms.append(bytes(bad))
        require(len(forms) == 14, 'all deliberate UDP malformed forms')
        for n, body in enumerate(forms):
            incoming_packet(body, 28672 + n, trigger='V')
        receive(_payload(31, lane, 'V'), identifier=28686, zero=True, surplus=b'ignored-UDP-surplus', trigger='V')
        filtered = receive(_payload(31, lane, 'F'), sport=9009, identifier=28928, trigger='F')
        receive(_payload(31, lane, 'F'), identifier=28929, src=remote[:3] + b'\t', trigger='F')
        receive(_payload(31, lane, 'F'), identifier=28930, trigger='F')
        receive(_payload(73, lane, 'Q'), 42000 + lane, 9002, trigger='S')
        receive(_payload(31, lane, 'S'), trigger='server')
        for n in (2, 0, 2, 1):
            receive(_payload(31, lane, 'O', n), 42000 + lane, 9004, trigger='O')
        receive(_payload(31, lane, 'O'), trigger='order3')
        receive(_payload(31, lane, 'C'), 49999, 9005, identifier=29439, dst=broadcast, trigger='C')
        bad = bytearray(_segment(remote, local, 9005, 49999, _payload(31, lane, 'C')))
        bad[7] ^= 64
        incoming_packet(bytes(bad), 29438, trigger='C')
        closed = receive(_payload(31, lane, 'C'), 49999, 9005, identifier=29440, trigger='C')
        receive(_payload(31, lane, 'C'), trigger='C')
        quote = observed['I']['ip'][:28]
        quotes = []
        for offset in (20, 22, 16, 12, 0, 10, 24):
            damaged = bytearray(quote)
            if offset == 24:
                struct.pack_into('!H', damaged, offset, 7)
            elif offset in (20, 22):
                damaged[offset + 1] ^= 1
            elif offset in (16, 12):
                damaged[offset + 3] ^= 1
                damaged[10:12] = bytes(2)
                struct.pack_into('!H', damaged, 10, checksum(damaged[:20]))
            else:
                damaged[offset] ^= 1
            quotes.append(bytes(damaged))
        for code, value in [(3, q) for q in quotes] + [(4, quote)]:
            body = bytearray(bytes([3, code]) + bytes(6) + value)
            struct.pack_into('!H', body, 2, checksum(body))
            incoming_packet(bytes(body), protocol=1, trigger='I')
        receive(_payload(31, lane, 'B'), 44000 + lane, dst=broadcast, trigger='B0')
        for n in (1, 2):
            receive(_payload(1400, lane, 'B', n), 44000 + lane, dst=broadcast, trigger='B1')
        for n in range(48):
            receive(_payload(31, lane, 'K', n), 44000 + lane, dst=broadcast, trigger='B2' if not n else f'K{n - 1}')
        receive(_payload(31, lane, 'P', 33), trigger='P32')
        for phase in 'LR':
            receive(_payload(31, lane, phase), trigger=phase)
        require([value for value, _ in errors] == [filtered[:28], closed[:28]], 'only exact connected-filter and closed-port ICMP quotes; suppressed inputs stay silent')
        filter_sources = [v['number'] for v in incoming if v['ip'] == filtered]
        closed_sources = [v['number'] for v in incoming if v['ip'] == closed]
        require(len(filter_sources) == len(closed_sources) == 1, 'exact original filtered and closed-port inputs exist')
        require(errors[0][1] > filter_sources[0] and errors[1][1] > closed_sources[0], 'UDP ICMP errors follow their exact original ingress')
    require(Counter((v['frame'] for v in incoming)) == Counter((v['frame'] for v in expected)), 'every complete incoming UDP/ICMP fixture frame and malformed variant')
    byframe = {}
    for value in incoming:
        byframe.setdefault(value['frame'], []).append(value['number'])
    for value in expected:
        at = byframe[value['frame']].pop(0)
        require(observed[value['trigger']]['number'] < at, 'UDP incoming response follows its actual original request')
    if fault:
        require(not errors, 'failed UDP device emits no unowned ICMP')
    else:
        for n in range(48):
            frame = next((v['frame'] for v in expected if v['frame'][42:] == _payload(31, lane, 'K', n)))
            arrival = next((v['number'] for v in incoming if v['frame'] == frame))
            require(arrival < observed[f'K{n}']['number'], 'active broadcast acknowledgment follows exact ingress')
        pressure_reply = next((number for kind, target, number in arp if kind == 'reply' and target == pressure_ip))
        require(all((v['number'] > pressure_reply for key, v in observed.items() if key.startswith('P') and key[1:].isdigit())), 'all retained pending outputs follow resolved pressure neighbor')
    return dict(passed=True, records=len(records), bootstrap_frames=len(prelude), ARP_frames=len(arp), outgoing_datagrams=len(outgoing), incoming_frames=len(incoming), emitted_ICMP_errors=len(errors), sha256=hashlib.sha256(path.read_bytes()).hexdigest())


def audit_case(directory, row, *, version=1):
    """Check one original client result against its physical captures and command."""
    import json
    import re
    from pathlib import Path

    require(type(row.get('fault')) is bool and row.get('firmware') in ('bios', 'uefi') and
            row.get('transport') in ('modern', 'legacy'), 'known UDP firmware, transport and mode')
    require(type(version) is int and version in (1, 2), 'known UDP route-lifetime source contract')
    route_retirement = version == 2
    fault = row['fault']
    phase = Path(directory) / ('fault' if fault else 'normal')
    case = phase / (row['firmware'] + '-' + row['transport'])
    require(row.get('passed') is True and row.get('returncode') == 1 and
            row.get('timed_out') is False and row.get('error') is None and row.get('missing') == [] and
            row.get('injected') is True and type(row.get('seconds')) in (int, float) and
            0 < row['seconds'] <= 90,
            'actual complete UDP client status and unchanged deadline')
    delay = 5 if fault and row['firmware'] == 'uefi' and row['transport'] == 'modern' else 0
    require(row.get('debugger_delay') == delay, 'original delayed UEFI UDP fault setup')
    name = 'udp-' + row['firmware'] + '-' + row['transport'] + ('-fault' if fault else '') + '.log'
    require(row.get('log') == name and json.loads((case / 'result.json').read_text()) == row,
            'original persisted UDP profile result and log identity')
    text = (case / name).read_text()
    required = ['UDP_BINDINGS_PASS', 'UDP_ZERO_PEER_PASS', 'UDP_LOOPBACK_PASS', 'UDP_REUSE_PASS',
                'UDP_SHUTDOWN_PASS', 'UDP_ERRORS_PASS', 'UDP_RECEIVE_LIFETIME_PASS',
                'UDP_CAPTURED_RECEIVE_PASS', 'UDP_CONFIG_PASS', 'UDP_INTERRUPT_PASS',
                'UDP_RESTART_PASS', 'UDP_FORK_PASS', 'UDP_RESOURCE_CYCLES_PASS count=128',
                'UDP_PAYLOAD_LIMIT_PASS bytes=65507', 'UDP_BUFFER_LIMIT_PASS bytes=2048 payload=2020',
                'UDP_TESTS_PASS', 'AXIOM64_TESTS_PASS', 'AXIOM64_EXIT status=0']
    if fault:
        required += ['UDP_DEVICE_FAULT_PASS', 'UDP_OTHER_NIC_PASS']
        require('PACKET_FAULT_INJECTED model=virtio kind=id' in
                (case / (name[:-4] + '-gdb.log')).read_text(), 'actual retained UDP device fault injection')
    else:
        for lane in range(2):
            index = lane + 1
            required += [f'UDP_WIRE_PASS index={index}', f'UDP_ZERO_CHECKSUM_PASS index={index}',
                         f'UDP_MALFORMED_PASS index={index} frames=15',
                         f'UDP_CONNECTED_FILTER_PASS index={index}', f'UDP_SERVER_PASS index={index}',
                         f'UDP_WIRE_ERRORS_PASS index={index}',
                         f'UDP_BROADCAST_QUEUE_PASS index={index} ingress=48 retained=32',
                         f'UDP_LINK_DOWN index={index}', f'UDP_LINK_UP index={index}',
                         f'UDP_LINK_PASS index={index}', f'UDP_PRESSURE_PASS index={index} packets=33',
                         f'UDP_UNREACHABLE_PASS index={index}']
    lines = text.splitlines()
    require(all(lines.count(marker) == 1 for marker in required) and
            not any(marker in text for marker in ('UDP_FAIL ', 'PANIC:', 'FAULT pid=')),
            'every exact original UDP assertion and unique completion record')
    flags = re.findall(r'^UDP_ADMIN_DOWN index=(\d+) flags=([0-9a-f]+)\r?$', text, re.M)
    require(flags == ([] if fault else [('1', '1002'), ('2', '1002')]),
            'exact original UDP administrative-down query flags')
    if route_retirement:
        metrics = re.findall(r'^UDP_ADMIN_ROUTE index=(\d+) before=(\d+) after=(\d+)\r?$', text, re.M)
        require(metrics == ([] if fault else [('1', '552', '1500'), ('2', '552', '1500')]),
                'exact UDP path metrics before and after administrative route retirement')
    command = json.loads((case / 'command.json').read_text())
    require(isinstance(command, list) and command and all(isinstance(v, str) for v in command) and command[0] == 'qemu-system-x86_64' and
            '-rtc' not in command and '-icount' not in command and
            command[command.index('-machine') + 1] == 'pc' and
            command[command.index('-cpu') + 1] == 'max' and
            command[command.index('-m') + 1] == '2G' and
            Path(command[command.index('-cdrom') + 1]).parts[-2:] == (phase.name, 'image.iso'),
            'original UDP emulator and actual immutable image command')
    original_image = Path(command[command.index('-cdrom') + 1])
    devices = [command[i + 1] for i, value in enumerate(command) if value == '-device']
    for lane, model in enumerate(('virtio-net-pci', 'e1000')):
        expected = (f'{model},netdev=peer{lane},id=nic{lane},addr={lane + 4:x},'
                    f'mac=52:54:00:12:34:{lane + 16:02x}')
        if lane == 0:
            expected += ',disable-legacy=on' if row['transport'] == 'modern' else ',disable-modern=on'
        require(devices.count(expected) == 1, 'actual selected UDP physical adapter and transport')
    drives = [command[i + 1] for i, value in enumerate(command) if value == '-drive']
    require((len(drives) == 2 and 'if=pflash,format=raw,readonly=on,file=/usr/share/OVMF/OVMF_CODE_4M.fd' in drives)
            if row['firmware'] == 'uefi' else not drives, 'actual selected UDP firmware')
    dumps = [command[i + 1] for i, value in enumerate(command) if value == '-object']
    require(len(dumps) == 2 and all(
        value.startswith(f'filter-dump,id=retained{lane},netdev=peer{lane},file=') and
        Path(value.partition('file=')[2]) == original_image.parent / case.name / f'lane{lane}.pcap'
        for lane, value in enumerate(dumps)), 'both original passive UDP physical captures')
    captures = [audit_capture(case / f'lane{lane}.pcap', lane, fault,
                              route_retirement=route_retirement) for lane in range(2)]
    require(row.get('firmware_frames') == [value['bootstrap_frames'] for value in captures],
            'original UDP bootstrap counters match independent frames')
    expected = dict(arp=[2, 2] if route_retirement and not fault else [1, 1],
                    wire_datagrams=[0, 1] if fault else [4, 4])
    if not fault:
        expected.update(zero_payloads=[1, 1], zero_checksums=[1, 1], malformed=[14, 14],
                        filter_inputs=[3, 3], server_replies=[1, 1], filtered_tuple_errors=[1, 1],
                        reordered=[4, 4], port_errors=[1, 1], invalid_quotes=[7, 7],
                        broadcast_requests=[3, 3], broadcast_ingress=[48, 48],
                        broadcast_acknowledged=[48, 48], pending_sends=[33, 33],
                        pressure_arp=[1, 1], unanswered_arp=[3, 3], link_events=4)
    require(all(row.get(name) == value for name, value in expected.items()),
            'original complete UDP producer counters agree with the physical scenario')
    return dict(passed=True, fault=fault, firmware=row['firmware'], transport=row['transport'],
                captures=captures, log_sha256=hashlib.sha256((case / name).read_bytes()).hexdigest())


def audit(directory, input_root=None):
    import json
    from pathlib import Path
    from fetch import ROOT
    from udp_inputs import audit as audit_inputs

    directory = Path(directory)
    rows = json.loads((directory / 'results.json').read_text())
    expected = {(fault, firmware, transport) for fault in (False, True)
                for firmware in ('bios', 'uefi') for transport in ('modern', 'legacy')}
    require(len(rows) == 8 and {(v['fault'], v['firmware'], v['transport']) for v in rows} == expected,
            'all eight original UDP firmware, transport and fault profiles')
    phases = [audit_inputs(directory / ('fault' if fault else 'normal'), input_root or ROOT)
              for fault in (False, True)]
    require([v['fault'] for v in phases] == [False, True], 'actual normal and fault UDP inputs')
    checked = [audit_case(directory, row, version=phases[int(row['fault'])]['version']) for row in rows]
    return dict(passed=True, profiles=8, actual_images_opened=2, captures=16,
                physical_frames=sum(v['records'] for row in checked for v in row['captures']),
                phases=phases, rows=checked)


def main():
    import argparse
    import json
    from pathlib import Path
    from fetch import ROOT

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('directory', nargs='?', type=Path, default=ROOT / 'build/udp-wire')
    parser.add_argument('--input-root', type=Path, default=ROOT)
    parser.add_argument('--output', type=Path)
    args = parser.parse_args()
    result = audit(args.directory, args.input_root)
    if args.output:
        args.output.write_text(json.dumps(result, indent=2) + '\n')
    print(json.dumps({key: result[key] for key in ('passed', 'profiles', 'actual_images_opened',
                                                 'captures', 'physical_frames')}))


if __name__ == '__main__':
    main()
