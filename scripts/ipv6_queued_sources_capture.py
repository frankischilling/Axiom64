# SPDX-License-Identifier: GPL-3.0-or-later
"""Reconstruct copied-source retention from original Ethernet and client evidence."""
import copy
import hashlib
import ipaddress
import json
from pathlib import Path
import re
import struct
import tempfile
import zipfile
from ipv4_expiry_capture import checksum, encode_capture, read_capture
from tcp_capture_clock import bind_native_clock


def require(value, reason):
    if not value:
        raise ValueError(reason)


def records(text):
    text = text.replace('\r\n', '\n')
    pattern = (r'^IPV6_QUEUED_SOURCE_ROW lane=(\d+) case=(\d+) raw=(\d+) expires=(\d+) reused=(\d+) '
               r'removed=1 copied=1 delivered=1 fresh=1 error=0 elapsed_ns=(\d+)$')
    rows = [tuple(map(int, found)) for found in re.findall(pattern, text, re.M)]
    require(len(rows) == 16 and len([line for line in text.splitlines() if line.startswith('IPV6_QUEUED_SOURCE_ROW ')]) == 16,
            'complete exact queued-source observation inventory')
    require([row[:5] for row in rows] == [(lane, number, number // 4, number // 2 % 2, number % 2)
            for lane in range(2) for number in range(8)], 'exact queued-source adapters, transports, expiry and reuse cases')
    for _, _, _, expires, _, elapsed in rows:
        require(not expires or 1000000000 <= elapsed <= 2500000000, 'actual bounded original valid lifetime')
    require(text.splitlines().count('IPV6_QUEUED_SOURCE_DONE adapters=2 cases=16 UDP=8 raw=8 expiry=8 close_reuse=8') == 1,
            'complete original queued-source cohort')
    return rows


def inspect(rows, lane, text):
    observations = records(text)
    guest = bytes([0x52, 0x54, 0, 0x12, 0x34, 0x10 + lane])
    peer = bytes([2, 0x49, 0x50, 0x36, lane, 1])
    control = bytes([2, ord('Q'), ord('S'), ord('R'), lane, 0])
    address = lambda host: ipaddress.IPv6Address(f'2001:db8:{0x460 + lane:x}::{host:x}').packed
    remotes = {address(0x83 + number * 16): number for number in range(8)}
    gates, answers, original, fresh, fragments = {}, {}, {}, {}, {}
    probes = {number: [] for number in range(8)}
    excluded = set()

    def transport(frame, body, positions, number, protocol, fragmented):
        source, destination = frame[22:38], frame[38:54]
        require(not checksum(source + destination + struct.pack('!I3xB', len(body), protocol) + body),
                'original queued-source complete transport checksum')
        if protocol == 17:
            require(number < 4 and len(body) == 24 and not fragmented and
                    body[:6] == struct.pack('!HHH', 59400 + lane * 10 + number, 55124, 24),
                    'exact original UDP ports and extent')
            payload = body[8:]
            is_original = payload[:4] == b'QSRC'
            require(payload[:4] in (b'QSRC', b'QSRA') and payload[4:8] == bytes([
                lane, number, 0x5a, 0x71 if is_original else 0x72]), 'original UDP copied and companion identity')
        else:
            require(number >= 4 and len(body) >= 8 and body[:2] == b'\x80\0', 'original raw envelope')
            payload = body
            is_original = body[4:6] == b'QR'
            require(body[4:6] in (b'QR', b'QA') and body[6:8] == bytes([lane, number]) and
                    len(body) == (4000 if is_original else 16) and fragmented == is_original,
                    'every original raw fragment or fresh control')
        require(payload[8:] == bytes((at * 13 + lane + number) & 255 for at in range(8, len(payload))) and
                source == address(0x82 + number * 16 if is_original else 1),
                'every copied byte and retained versus companion source')
        target = original if is_original else fresh
        require(number not in target, 'one original datagram per admitted copy and companion')
        target[number] = positions

    for at, row in enumerate(rows):
        frame = row['frame']
        if frame[12:14] == b'\x88\xb7':
            require(len(frame) == 60 and frame[14:19] == b'QSRC' + bytes([lane]) and not any(frame[23:]),
                    'complete exact original source gate')
            number, stage, ack, delivered = frame[19:23]
            require(number in (*range(8), 255) and stage in range(5) and ack in (0, 1) and delivered in (0, 1) and
                    frame[:12] == (guest + control if ack else control + guest) and (number != 255 or stage == 0),
                    'source gate ownership and bounded case')
            key = number, stage, ack
            require(key not in gates and (ack or not delivered), 'unique original gate and request value')
            gates[key] = at, delivered
            excluded.add(at)
            continue
        if len(frame) < 54 or frame[12:14] != b'\x86\xdd':
            continue
        prefix = address(1)[:6]
        if frame[22:28] != prefix and frame[38:44] != prefix:
            continue
        excluded.add(at)
        size, protocol, hop = struct.unpack('!HBB', frame[18:22])
        source, destination, body = frame[22:38], frame[38:54], frame[54:54 + size]
        require(frame[14:18] == b'\x60\0\0\0' and len(body) == size, 'complete original queued IPv6 header')
        if protocol == 58 and body[:1] in (b'\x87', b'\x88'):
            number = remotes.get(body[8:24])
            require(number is not None and size == 32 and hop == 255 and body[1] == 0 and
                    not checksum(source + destination + struct.pack('!I3xB', size, 58) + body), 'complete original neighbor checksum')
            if body[0] == 135:
                multicast = b'\xff\x02' + bytes(9) + b'\1\xff' + body[21:24]
                require(source in (address(0x82 + number * 16), address(1)) and destination == multicast and
                        frame[:12] == b'\x33\x33' + multicast[-4:] + guest and body[4:8] == bytes(4) and
                        body[24:] == b'\1\1' + guest, 'actual selected-source or companion probe')
                probes[number].append((at, source))
                require(len(probes[number]) <= 4, 'original bounded neighbor attempts')
            else:
                all_nodes = ipaddress.IPv6Address('ff02::1').packed
                require(number not in answers and source == body[8:24] and destination == all_nodes and
                        frame[:12] == b'\x33\x33' + all_nodes[-4:] + peer and body[4:8] == b'\x20\0\0\0' and
                        body[24:] == b'\2\1' + peer, 'exact held neighbor answer after withdrawal')
                answers[number] = at
            continue
        number = remotes.get(destination)
        require(number is not None and frame[:12] == peer + guest and hop == 64, 'original queued wire ownership')
        if protocol == 44:
            require(number >= 4 and len(frame) <= 1514 and 8 < size <= 1460 and body[:2] == b'\x3a\0',
                    'complete original raw fragment header')
            field, identity = struct.unpack('!HI', body[2:8])
            offset, more = field & 0xfff8, bool(field & 1)
            require(identity and not field & 6 and (not more or (size - 8) % 8 == 0), 'raw fragment bounds')
            parts = fragments.setdefault((source, destination, identity, number), {})
            require(offset not in parts and len(parts) < 3, 'unique bounded original fragments')
            parts[offset] = body[8:], more, at, frame
        else:
            require(protocol == (58 if number >= 4 else 17), 'original queued transport')
            transport(frame, body, [at], number, protocol, False)
    for (_, _, _, number), parts in fragments.items():
        body, positions = bytearray(), []
        for position, (offset, (data, more, at, frame)) in enumerate(sorted(parts.items())):
            require(offset == len(body) and more == (position < len(parts) - 1), 'complete contiguous raw pieces')
            body.extend(data)
            positions.append(at)
        require(len(parts) == 3, 'all raw pieces at original MTU')
        transport(frame, bytes(body), positions, number, 58, True)
    expected = {(255, 0, ack) for ack in (0, 1)} | {
        (number, stage, ack) for number in range(8) for stage in range(5) for ack in (0, 1)}
    require(set(gates) == expected and set(answers) == set(original) == set(fresh) == set(range(8)),
            'complete queued-source gates, held answers, originals and companions')
    details = []
    for number in range(8):
        order = [gates[number, stage, ack][0] for stage in range(5) for ack in (0, 1)]
        initial = [at for at, source in probes[number] if source == address(0x82 + number * 16)]
        require(order == sorted(order) and initial and gates[number, 0, 1][0] < min(initial) <
                gates[number, 1, 1][0] < gates[number, 2, 0][0] < answers[number] < gates[number, 2, 1][0],
                'creation and actual selected-source admission precede removal and held resolution')
        require(answers[number] < min(original[number]) <= max(original[number]) < gates[number, 3, 1][0] <
                min(fresh[number]) <= max(fresh[number]) < gates[number, 4, 1][0] and
                gates[number, 3, 1][1] == gates[number, 4, 1][1] == 1,
                'actual copied output precedes its acknowledgment and fresh companion validation')
        require(all(gates[number, stage, 1][1] == 0 for stage in range(2)), 'no delivery before source withdrawal')
        if number // 2 % 2:
            require(rows[gates[number, 2, 0][0]]['ns'] - rows[gates[number, 0, 1][0]]['ns'] >= 1000000000,
                    'original valid interval remains visible on the actual wire')
        if number:
            require(gates[number - 1, 4, 1][0] < gates[number, 0, 0][0], 'previous owner completes before next creation')
        details.append(dict(number=number, initial=initial, removal=gates[number, 2, 0][0], answer=answers[number],
            output=original[number], fresh=fresh[number], ack3=gates[number, 3, 1][0], start=gates[number, 0, 1][0]))
    require(gates[255, 0, 0][0] < gates[255, 0, 1][0] < gates[0, 0, 0][0], 'original readiness precedes every admitted case')
    return dict(passed=True, lane=lane, cases=8, UDP=4, raw=4, expiry=4, close_reuse=4,
                observations=len(observations), details=details, packet_clock_qualified_here=False), excluded


def verify_capture(path, lane, log_path, archive, native=False, statistics=None):
    path, log_path = Path(path), Path(log_path)
    original, original_log = path.read_bytes(), log_path.read_bytes()
    rows, text = read_capture(path), original_log.decode()
    proof, selected = inspect(rows, lane, text)
    if native:
        timed = [dict(stamp=row['ns'] // 1000, frame=row['frame']) for at, row in enumerate(rows) if at in selected]
        proof['native_clock'] = bind_native_clock(path, timed, statistics)
        proof['packet_clock_qualified_here'] = True
    udp, raw, expiry = (proof['details'][number] for number in (0, 4, 2))
    labels = ['missing-output', 'missing-raw-fragment', 'missing-companion', 'missing-removal', 'missing-answer',
              'missing-selection', 'duplicate-output', 'bad-checksum', 'output-before-answer', 'false-removal',
              'false-delivery', 'short-expiry-time', 'short-wire-expiry', 'missing-done', 'neighbor-probe-flood']
    with zipfile.ZipFile(archive, 'x', zipfile.ZIP_DEFLATED) as saved:
        for label in labels:
            changed, log = copy.deepcopy(rows), text
            remove = {'missing-output': udp['output'], 'missing-raw-fragment': [raw['output'][0]],
                      'missing-companion': udp['fresh'], 'missing-removal': [udp['removal']],
                      'missing-answer': [udp['answer']], 'missing-selection': udp['initial']}.get(label)
            if remove is not None:
                changed = [row for at, row in enumerate(changed) if at not in remove]
            elif label == 'neighbor-probe-flood':
                at = udp['initial'][0]
                changed[at:at] = [copy.deepcopy(changed[at]) for _ in range(5)]
            elif label == 'duplicate-output':
                changed.insert(udp['output'][0], copy.deepcopy(changed[udp['output'][0]]))
            elif label == 'bad-checksum':
                frame = bytearray(changed[udp['output'][0]]['frame'])
                frame[60] ^= 1
                changed[udp['output'][0]]['frame'] = bytes(frame)
            elif label == 'output-before-answer':
                row = changed.pop(udp['output'][0])
                row['ns'] = changed[udp['answer']]['ns']
                changed.insert(udp['answer'], row)
            elif label == 'short-wire-expiry':
                interval = rows[expiry['removal']]['ns'] - rows[expiry['start']]['ns'] - 500000000
                for at in range(expiry['removal'], len(changed)):
                    changed[at]['ns'] -= interval
            elif label == 'missing-done':
                log = log.replace('IPV6_QUEUED_SOURCE_DONE', 'MISSING')
            else:
                number = 2 if label == 'short-expiry-time' else 0
                lines = log.splitlines()
                at = next(at for at, line in enumerate(lines) if line.startswith(f'IPV6_QUEUED_SOURCE_ROW lane={lane} case={number} '))
                lines[at] = (re.sub(r'elapsed_ns=\d+', 'elapsed_ns=1', lines[at]) if label == 'short-expiry-time' else
                    lines[at].replace('removed=1', 'removed=0') if label == 'false-removal' else
                    lines[at].replace('delivered=1', 'delivered=0'))
                log = '\n'.join(lines) + '\n'
            saved.writestr(label + '.pcap', encode_capture(changed))
            saved.writestr(label + '.log', log)
    rejected = []
    with zipfile.ZipFile(archive) as saved:
        for label in labels:
            with tempfile.TemporaryDirectory(prefix='ipv6-queued-source-negative-') as temporary:
                damaged = Path(temporary) / 'changed.pcap'
                damaged.write_bytes(saved.read(label + '.pcap'))
                try:
                    inspect(read_capture(damaged), lane, saved.read(label + '.log').decode())
                except ValueError as error:
                    rejected.append(dict(name=label, reason=str(error)))
                else:
                    raise ValueError('changed queued-source evidence accepted: ' + label)
    require(path.read_bytes() == original and log_path.read_bytes() == original_log, 'original queued-source evidence unchanged')
    proof.update(serialized_controls_reopened_rejected=len(rejected), rejections=rejected,
                 original_sha256=hashlib.sha256(original).hexdigest(),
                 archive_sha256=hashlib.sha256(Path(archive).read_bytes()).hexdigest())
    return proof
