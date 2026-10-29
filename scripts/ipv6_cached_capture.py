# SPDX-License-Identifier: GPL-3.0-or-later
"""Reconstruct cached-route sends independently from original packets and client inputs."""
import copy
import hashlib
import ipaddress
from pathlib import Path
import re
import struct
import zipfile
from ipv4_expiry_capture import read_capture, encode_capture, checksum
from ipv6_controls_capture import multicast_report
from tcp_capture_clock import bind_native_clock


def require(value, reason):
    if not value:
        raise ValueError(reason)


def addr(lane, host, scope):
    return ipaddress.IPv6Address(f'fe80::{host:x}' if scope else f'2001:db8:{lane + 1}::{host:x}').packed


def specification(number, lane):
    require(0 <= number < 64 and lane in (0, 1), 'original cached route bounds')
    scope, kind, variant = number // 32, 3 if number % 32 >= 16 else 2, number % 8
    mode = (3 if scope and kind == 2 else 2 if kind == 3 else 1) if number % 16 >= 8 else 0
    first = {0: 176, 6: 160, 7: 192}.get(variant, 128)
    final = addr(lane, 71, scope) if scope else ipaddress.IPv6Address(f'2001:db8:{145 + lane:x}::47').packed
    return dict(scope=scope, kind=kind, variant=variant, mode=mode, source=addr(lane, 2, scope),
                first=addr(lane, first, scope), final=final,
                effective=addr(lane, first, scope) if kind == 2 and variant in {1, 4, 5, 6} else final,
                mtu=-107 if variant in {2, 3} else 1500 if variant in {0, 6} else 1400,
                hops=55 if variant == 5 else 64)


def header(mode, lane, scope, first):
    size, left = (24, 24, 40, 64)[mode], (1, 0, 1, 2)[mode]
    data = bytearray(64)
    data[:8] = bytes((250, size // 8 - 1, 4 if mode else 2, left, left if mode else 0, 0, 0, 0))
    for n in range((left if mode else 0) + 1):
        data[8 + n * 16:24 + n * 16] = addr(lane, 77 + n, scope)
    at = 8 + (left * 16 if mode else 0)
    data[at:at + 16] = addr(lane, first, scope)
    if mode == 3:
        data[56:] = bytes((30, 6)) + b'\x99' * 6
    return bytes(data), size


def application(text):
    text = text.replace('\r\n', '\n')
    require('IPV6_CACHED_FAIL' not in text and text.splitlines().count(
        'IPV6_CACHED_PASS adapters=2 cases=128 variants=8 scopes=2 transports=2') == 1,
        'one complete actual cached route client')
    matches = re.findall(r'^IPV6_CACHED_CASE lane=(\d+) case=(\d+) type=(\d+) scope=(\d+) mode=(\d+) variant=(\d+) '
                         r'result=(-?\d+) errno=(\d+) before=(-?\d+) after=(-?\d+) routing=([0-9a-f]{128}) control=([0-9a-f]{192})$',
                         text, re.MULTILINE)
    require(len(matches) == 128, 'complete original cached application inventory')
    require(len([line for line in text.splitlines() if line.startswith('IPV6_CACHED_CASE ')]) == 128,
            'no malformed extra cached results')
    for position, row in enumerate(matches):
        lane, number, kind, scope, mode, variant, result, error, before, after = map(int, row[:10])
        require((lane, number) == (position // 64, position % 64), 'ordered unique original application calls')
        wanted = specification(number, lane)
        require((kind, scope, mode, variant, result, error, before, after) ==
                (wanted['kind'], wanted['scope'], wanted['mode'], wanted['variant'], 32, 0,
                 wanted['mtu'], wanted['mtu']), 'original peer, send and cached metric results')
        original, size = header(mode, lane, scope, 176 if variant == 0 else 160 if variant == 6 else 128)
        require(bytes.fromhex(row[10]) == original, 'all original stored Routing bytes')
        control = bytearray(b'\xa5' * 96)
        if variant in (5, 7):
            payload = struct.pack('<i', 55) if variant == 5 else header(0, lane, scope, 192)[0][:24]
            control[:16] = struct.pack('<Qii', 16 + len(payload), 41, 52 if variant == 5 else 57)
            control[16:16 + len(payload)] = payload
        require(bytes.fromhex(row[11]) == control, 'every original ancillary byte and padding')
    errors = re.findall(r'^IPV6_CACHED_ERROR lane=(\d+) case=(\d+) flags=(\d+) length=(\d+) '
                        r'name=([0-9a-f]{56}) control=([0-9a-f]{192})$', text, re.MULTILINE)
    require(len(errors) == 128 and len([line for line in text.splitlines() if line.startswith('IPV6_CACHED_ERROR ')]) == 128,
            'all original Routing local error dequeues')
    for position, row in enumerate(errors):
        lane, number, flags, length = map(int, row[:4])
        require((lane, number, flags, length) == (position // 64, position % 64, 8192, 64),
                'ordered complete local error result fields')
        wanted = specification(number, lane)
        mode = 0 if wanted['variant'] == 7 else wanted['mode']
        information = (1500 if wanted['variant'] in {0, 6, 7} else 1400) - (24, 24, 40, 64)[mode]
        name = struct.pack('<H', 10) + struct.pack('!H', 57000 if wanted['kind'] == 2 else 0) + bytes(4)
        name += wanted['effective'] + bytes(4)
        controls = struct.pack('<QiiIBBBBII', 60, 41, 25, 90, 1, 0, 0, 0, information, 0)
        controls += bytes(28) + b'\xa5' * 36
        require(bytes.fromhex(row[4]) == name and bytes.fromhex(row[5]) == controls,
                'effective local error destination, extension-adjusted MTU and every control byte')
    return text


def inspect(rows, lane, text, native=False):
    text = application(text)
    guest = bytes.fromhex('5254001234') + bytes((0x10 + lane,))
    remote = bytes((2, 0x49, 0x50, 0x36, lane, 1))
    control = bytes((2, 73, 80, 54, lane, 0))
    starts = [n for n, row in enumerate(rows) if row['frame'][6:12] == guest and
              row['frame'][12:21] == b'\x88\xc6IP6K' + bytes((lane, 0, 0))]
    require(len(starts) == 1 and (native or starts[0] <= 256), 'one bounded original cached readiness')
    requests, replies, neighbors, packets, hints, selected = {}, {}, {}, [], [], []
    firmware = []
    workload = [(None, scope) if number is None else (number, scope)
                for scope in range(2) for number in [None, *range(scope * 32, scope * 32 + 32)]]
    for at, row in enumerate(rows):
        frame = row['frame']
        if not native and at < starts[0]:
            firmware.append(hashlib.sha256(frame).hexdigest())
            continue
        require(len(frame) >= 14, 'complete captured Ethernet envelope')
        if frame[12:14] == b'\x88\xc6':
            require(len(frame) == 60 and frame[14:19] == b'IP6K' + bytes((lane,)) and
                    frame[20] in (0, 1) and not any(frame[21:]), 'exact original transaction bytes')
            phase, reply = frame[19:21]
            require(frame[:12] == (guest + control if reply else control + guest), 'original transaction MACs')
            book = replies if reply else requests
            require(phase not in book, 'unique original transaction edge')
            book[phase] = at
            selected.append(row)
            continue
        require(len(frame) >= 54 and frame[12:14] == b'\x86\xdd', 'defined captured cached protocol')
        size, protocol, hops = struct.unpack_from('!HBB', frame, 18)
        source, target = frame[22:38], frame[38:54]
        require(frame[14] >> 4 == 6 and len(frame) >= 54 + size, 'complete original captured IPv6 data')
        body = frame[54:54 + size]
        if native and protocol == 0 and target == ipaddress.IPv6Address('ff02::16').packed:
            multicast_report(frame, guest, addr(lane, 2, 1))
            continue
        selected.append(row)
        if protocol == 58 and body[:1] in (b'\x87', b'\x88'):
            require(size == 32 and hops == 255 and not checksum(source + target + struct.pack('!I3xB', size, 58) + body),
                    'original complete neighbor checksum and lifetime')
            destination = body[8:24]
            scope = destination[:2] == b'\xfe\x80'
            require(destination in [addr(lane, n, scope) for n in (128, 160, 176, 192)], 'owned queried first hop')
            if body[0] == 135:
                multicast = bytes.fromhex('ff0200000000000000000001ff') + destination[-3:]
                require(frame[:12] == b'\x33\x33\xff' + destination[-3:] + guest and source == addr(lane, 2, scope) and
                        target == multicast and body[4:8] == bytes(4) and body[24:] == b'\1\1' + guest,
                        'original owned neighbor query')
                neighbors[destination] = (at, source)
            else:
                require(destination in neighbors and frame[:12] == guest + remote and source == destination and
                        target == neighbors[destination][1] and body[4:8] == b'\x60\0\0\0' and body[24:] == b'\2\1' + remote,
                        'original causal neighbor reply')
                require(rows[neighbors[destination][0]]['ns'] <= row['ns'], 'neighbor timestamp order')
                del neighbors[destination]
            continue
        if frame[6:12] == guest:
            require(len(packets) < len(workload), 'bounded actual original sends')
            number, scope = workload[len(packets)]
            require(frame[:6] == remote and source == addr(lane, 2, scope),
                    'original packet envelope and bound source')
            if number is None:
                require(frame[14:18] == b'\x60\0\0\0' and protocol == 17 and size == 40 and hops == 64 and target == addr(lane, 128, scope) and
                        struct.unpack_from('!HHH', body) == (55000 + scope, 57000, 40) and
                        body[8:] == bytes((n * 19 + lane) & 255 for n in range(32)) and
                        not checksum(source + target + struct.pack('!I3xB', 40, 17) + body), 'original seed bytes')
            else:
                wanted = specification(number, lane)
                route, length = header(0 if wanted['variant'] == 7 else wanted['mode'], lane, scope, target[-1])
                route = bytearray(route[:length])
                transport = 17 if wanted['kind'] == 2 else 58
                route[0] = transport
                route[8:24] = wanted['effective']
                traffic_class = 0x25 if wanted['variant'] == 3 and wanted['mode'] else 0
                require(frame[14:18] == struct.pack('!I', 0x60000000 | traffic_class << 20) and
                        protocol == 43 and target == wanted['first'] and hops == wanted['hops'] and
                        body[:length] == route, 'exact original cached route and every emitted extension byte')
                body = body[length:]
                payload = bytes((n * 19 + number * 7 + lane) & 255 for n in range(32))
                if transport == 17:
                    require(len(body) == 40 and struct.unpack_from('!HHH', body) == (56000 + number, 57000, 40) and
                            body[8:] == payload, 'all original routed UDP fields and payload')
                else:
                    require(len(body) == 32 and body[:2] == b'\x81\0' and body[4:] == payload[4:],
                            'all original routed raw bytes')
                require(not checksum(source + wanted['effective'] + struct.pack('!I3xB', len(body), transport) + body),
                        'actual effective-destination transport checksum')
                require(size == length + len(body), 'complete original extension and transport lengths')
            packets.append(dict(at=at, frame=frame[:54 + size], number=number, scope=scope))
        else:
            require(frame[:12] == guest + remote and protocol == 58 and hops == 64 and size == 88 and
                    source in [addr(lane, 250, scope) for scope in range(2)] and
                    target == addr(lane, 2, source[:2] == b'\xfe\x80') and body[:2] == b'\x02\0' and
                    body[4:8] == struct.pack('!I', 1400) and
                    not checksum(source + target + struct.pack('!I3xB', size, 58) + body), 'original actual seed PTB')
            hints.append(dict(at=at, quote=body[8:]))
    require(set(requests) == set(replies) == set(range(133)) and len(packets) == 66 and len(hints) == 2 and not neighbors,
            'complete original route transactions, hints and neighbors')
    for phase in range(133):
        require(requests[phase] < replies[phase] and rows[requests[phase]]['ns'] <= rows[replies[phase]]['ns'] and
                (not phase or replies[phase - 1] < requests[phase]), 'causal original phase order')
        require(text.splitlines().count(f'IPV6_CACHED_PHASE_PASS lane={lane} phase={phase}') == 1,
                'actual client completed every original Ethernet phase')
    for position, packet in enumerate(packets):
        begin = 1 + position * 2
        require(requests[begin] < packet['at'] < replies[begin + 1], 'actual datagram inside its own transaction')
    for scope, hint in enumerate(hints):
        seed = packets[scope * 33]
        end = 2 + scope * 66
        require(hint['quote'] == seed['frame'][14:] and seed['at'] < hint['at'] and
                requests[end] < hint['at'] < replies[end] and
                rows[replies[end]]['ns'] - rows[hint['at']]['ns'] >= 50_000_000,
                'exact original seed quotation and full fifty-millisecond observation')
    return dict(passed=True, cases=64, seeds=2, original_fifty_ms_preserved=True,
                firmware_sha256=firmware), selected, packets


def verify_capture(path, lane, log_path, archive, native=False, statistics=None, interface_index=None):
    path, log_path, archive = Path(path), Path(log_path), Path(archive)
    original, log = path.read_bytes(), log_path.read_bytes()
    rows = read_capture(path)
    result, selected, packets = inspect(rows, lane, log.decode(), native)
    if native:
        require(statistics is not None and interface_index is not None, 'independent native capture context')
        for row in selected:
            row['stamp'] = row['ns'] // 1000
        result['native_clock'] = bind_native_clock(path, selected, statistics)
    controls = []
    # Serialized changes exercise both sides of the cache decision and real ownership.
    for label, number, offset in [('cached-segment', 1, 62), ('fresh-segment', 0, 62),
                                   ('replacement-segment', 3, 62), ('raw-segment', 17, 62),
                                   ('host-route-segment', 6, 62), ('named-segment', 4, 62),
                                   ('override-segment', 7, 62), ('transport-checksum', 1, 84),
                                   ('source-owner', 1, 37), ('first-hop', 1, 53),
                                   ('actual-payload', 1, -1), ('hop-limit', 5, 21)]:
        item = next(packet for packet in packets if packet['number'] == number)
        damaged = copy.deepcopy(rows)
        data = bytearray(damaged[item['at']]['frame'])
        data[offset] ^= 1
        damaged[item['at']]['frame'] = bytes(data)
        controls.append((label, encode_capture(damaged), log))
    controls += [('missing-case', original, log.replace(b'IPV6_CACHED_CASE lane=0 case=1 ', b'BROKEN_CASE lane=0 case=1 ', 1)),
                 ('changed-input', original, log.replace(b'routing=fa', b'routing=fb', 1))]
    error_lines = [line for line in log.splitlines() if line.startswith(b'IPV6_CACHED_ERROR ')]
    for number, field, offset in ((1, 'name', 8), (1, 'control', 24), (0, 'control', 24),
                                 (17, 'name', 8), (7, 'control', 24)):
        prefix = f'IPV6_CACHED_ERROR lane={lane} case={number} '.encode()
        line = next(value for value in error_lines if value.startswith(prefix))
        value = re.search(rb'\b' + field.encode() + rb'=([0-9a-f]+)', line).group(1)
        damaged = bytearray.fromhex(value.decode())
        damaged[offset] ^= 1
        changed = line.replace(field.encode() + b'=' + value, field.encode() + b'=' + damaged.hex().encode(), 1)
        controls.append((f'local-error-{field}-{number}', original, log.replace(line, changed, 1)))
    for number in (1, 3, 17, 6, 4, 7):
        item = next(packet for packet in packets if packet['number'] == number)
        wanted = specification(number, lane)
        wrong = wanted['final'] if wanted['effective'] == wanted['first'] else wanted['first']
        damaged = copy.deepcopy(rows)
        data = bytearray(damaged[item['at']]['frame'])
        data[62:78] = wrong
        mode = 0 if wanted['variant'] == 7 else wanted['mode']
        size = (24, 24, 40, 64)[mode]
        transport = 17 if wanted['kind'] == 2 else 58
        at = 54 + size
        body = bytearray(data[at:])
        offset = 6 if transport == 17 else 2
        body[offset:offset + 2] = bytes(2)
        value = checksum(wanted['source'] + wrong + struct.pack('!I3xB', len(body), transport) + body)
        body[offset:offset + 2] = struct.pack('!H', value or (65535 if transport == 17 else 0))
        data[at:] = body
        damaged[item['at']]['frame'] = bytes(data)
        controls.append((f'consistent-wrong-cache-{number}', encode_capture(damaged), log))
    shortened = copy.deepcopy(rows)
    end = next(row for row in shortened if row['frame'][12:21] == b'\x88\xc6IP6K' + bytes((lane, 2, 1)))
    hint = next(row for row in shortened if row['frame'][12:14] == b'\x86\xdd' and
                row['frame'][20] == 58 and row['frame'][54:56] == b'\x02\0')
    end['ns'] = hint['ns'] + 49_000_000
    end['stamp'] = end['ns'] // 1000
    controls.append(('shortened-observation', encode_capture(shortened), log))
    require(not archive.exists(), 'fresh serialized cached damage archive')
    with zipfile.ZipFile(archive, 'x', zipfile.ZIP_DEFLATED) as stream:
        for label, data, application_log in controls:
            stream.writestr(label + '.pcap', data)
            stream.writestr(label + '.log', application_log)
    # Reopen the exact serialized bytes; rejections cannot rely on a producer verdict.
    with zipfile.ZipFile(archive) as stream:
        import tempfile
        with tempfile.TemporaryDirectory(prefix='ipv6-cached-replay-') as temporary:
            capture = Path(temporary)/'control.pcap'
            for label, _, _ in controls:
                capture.write_bytes(stream.read(label + '.pcap'))
                try:
                    inspect(read_capture(capture), lane, stream.read(label + '.log').decode(), native)
                except ValueError:
                    continue
                raise ValueError('cached damaged control accepted: ' + label)
    require(path.read_bytes() == original and log_path.read_bytes() == log, 'original evidence remains unchanged')
    result.update(original_sha256=hashlib.sha256(original).hexdigest(),
                  original_log_sha256=hashlib.sha256(log).hexdigest(),
                  negative_controls=len(controls), negative_archive_sha256=hashlib.sha256(archive.read_bytes()).hexdigest())
    return result
