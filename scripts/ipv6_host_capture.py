# SPDX-License-Identifier: GPL-3.0-or-later
"""Independently reconstruct IPv6 host evidence from original packet captures."""
import copy
import hashlib
import ipaddress
import json
from pathlib import Path
import re
import struct
import zipfile
from ipv4_expiry_capture import checksum, encode_capture, read_capture
from ipv6_lifetime_contract import verify_log
from ipv6_lifetime_capture import inspect as inspect_lifetimes, verify_capture as verify_lifetimes
from ipv6_queued_sources_capture import inspect as inspect_queued_sources, verify_capture as verify_queued_sources


def require(value, reason):
    if not value:
        raise ValueError(reason)


def inspect(rows, lane, log, native=False):
    lifetimes = verify_log(log)
    lifetime_wire, excluded = inspect_lifetimes(rows, lane, log)
    queued_sources, queued_indices = inspect_queued_sources(rows, lane, log)
    excluded = set(excluded) | queued_indices
    require(log.count('IPV6_HOST_ROUTES_PASS adapters=2 filtered=1') == 1,
            'actual client completed route control and filtered inventory')
    require(log.count(f'IPV6_HOST_DIRECT_ND_PASS lane={lane} prefix=128') == 1,
            'actual client verified direct ND with a host prefix')
    require(log.count('IPV6_HOST_PREFIX_PASS adapters=2 tentative=1 failed=1 retained=1') == 1,
            'actual client completed prefix ownership and retained cleanup')
    require(log.count(f'IPV6_HOST_PREFIX_ORDER_PASS lane={lane} scenarios=3') == 1,
            'actual client checked manual and connected route ordering')
    guest = bytes([0x52, 0x54, 0, 0x12, 0x34, 0x10 + lane])
    peer = bytes([2, 0x49, 0x50, 0x36, lane, 1])
    control = bytes([2, 0x49, 0x50, 0x36, lane, 0])
    local = ipaddress.IPv6Address(f'2001:db8:{lane + 1}::2').packed
    remote = ipaddress.IPv6Address(f'2001:db8:{lane + 1}::1').packed
    unknown = ipaddress.IPv6Address(f'2001:db8:{lane + 1}::77').packed
    unresolved = ipaddress.IPv6Address(f'2001:db8:{lane + 1}::88').packed
    duplicate = ipaddress.IPv6Address(f'2001:db8:{lane + 1}::3').packed
    link = ipaddress.IPv6Address('fe80::2').packed
    all_nodes = ipaddress.IPv6Address('ff02::1').packed
    solicit = lambda target: b'\xff\x02' + bytes(9) + b'\1\xff' + target[-3:]
    requests, acknowledgements, emitted, incoming = {}, {}, [], []
    ready = [index for index, row in enumerate(rows) if
             row['frame'][12:14] == b'\x88\xb6' and row['frame'][14:21] == b'IP6H' + bytes([lane, 0, 0])]
    require(len(ready) == 1, 'one original client readiness request')
    mld_reports, firmware = 0, []
    for index, row in enumerate(rows):
        frame = row['frame']
        if not native and index < ready[0]:
            require(len(frame) >= 14 and frame[6:12] == guest, 'firmware prelude belongs to this adapter')
            require(len(firmware) < 256, 'bounded firmware network prelude')
            firmware.append(hashlib.sha256(frame).hexdigest())
            continue
        if frame[12:14] == b'\x88\xb6':
            require(len(frame) == 60 and frame[14:19] == b'IP6H' + bytes([lane]) and
                    not any(frame[21:]), 'exact phase payload and padding')
            phase = frame[19]
            require(phase in range(6), 'known phase')
            target = requests if frame[20] == 0 else acknowledgements
            require(phase not in target and frame[20] in (0, 1), 'one request and acknowledgement')
            require(frame[:12] == (control + guest if not frame[20] else guest + control),
                    'phase MAC ownership')
            target[phase] = index
        elif index in excluded:
            continue
        elif frame[12:14] == b'\x86\xdd':
            require(len(frame) >= 54, 'complete IPv6 fixed header')
            length = int.from_bytes(frame[18:20], 'big')
            require(length + 54 <= len(frame), 'declared IPv6 payload bounds')
            source, destination = frame[22:38], frame[38:54]
            payload = frame[54:54 + length]
            if frame[6:12] == guest:
                if native and frame[20] == 0:
                    require(frame[21] == 1 and destination == ipaddress.IPv6Address('ff02::16').packed and
                            source in (bytes(16), link) and frame[14:18] == b'\x60\0\0\0' and
                            frame[:6] == b'\x33\x33\0\0\0\x16' and
                            payload[:8] == b'\x3a\0\5\2\0\0\1\0', 'native MLD hop/options/group')
                    report = payload[8:]
                    require(len(report) >= 8 and report[:2] == b'\x8f\0' and
                            not checksum(source + destination + struct.pack('!I3xB', len(report), 58) + report),
                            'native MLD original checksum')
                    at = 8
                    for _ in range(int.from_bytes(report[6:8], 'big')):
                        require(len(report) - at >= 20 and report[at] in range(1, 7), 'native MLD record')
                        size = 20 + int.from_bytes(report[at + 2:at + 4], 'big') * 16 + report[at + 1] * 4
                        require(size <= len(report) - at, 'native MLD source and auxiliary bounds')
                        at += size
                    require(at == len(report), 'complete native MLD records')
                    mld_reports += 1
                    continue
                require(frame[14:18] == b'\x60\0\0\0' and frame[20] == 58 and length >= 8,
                        'kernel fixed header and upper-layer protocol')
                require(not checksum(source + destination + struct.pack('!I3xB', length, 58) + payload),
                        'original kernel pseudo-header checksum')
                require(payload[1] == 0, 'kernel ICMPv6 code')
                emitted.append((index, frame, source, destination, payload))
            else:
                require(frame[6:12] == peer, 'controlled peer source')
                incoming.append((index, frame, source, destination, payload))
    require(set(requests) == set(acknowledgements) == set(range(6)), 'readiness and all five ordered barriers')
    require(all(index > acknowledgements[5] for index in excluded),
            'lifetime packets follow every original host phase')
    previous = -1
    for phase in range(6):
        require(previous < requests[phase] < acknowledgements[phase], 'ordered request/completion')
        previous = acknowledgements[phase]
        require(len(re.findall(fr'^IPV6_HOST_PHASE_PASS lane={lane} phase={phase}\r?$', log, re.M)) == 1,
                'actual client completed phase')
    elapsed = re.findall(r'^IPV6_HOST_DAD_PASS elapsed_ns=(\d+)\r?$', log, re.M)
    require(len(elapsed) == 1 and int(elapsed[0]) >= 1000000000, 'actual client observed full DAD interval')
    maintenance, maintenance_responses, original_emitted = [], set(), []
    for index, frame, source, destination, payload in emitted:
        if native and payload[0] == 135 and destination == payload[8:24]:
            learned = {target for phase, target in ((1, remote), (2, unknown), (5, unresolved))
                       if acknowledgements[phase] < index}
            require(frame[21] == 255 and len(payload) == 32 and frame[:6] == peer and
                    source in (local, link) and destination == payload[8:24] and
                    destination in learned and payload[4:8] == bytes(4) and
                    payload[24:] == b'\1\1' + guest, 'complete owned native unicast maintenance NS')
            candidates = []
            for response, answer, sender, receiver, body in incoming:
                if (response > index and response not in maintenance_responses and sender == destination and
                        receiver == source and body[:1] == b'\x88'):
                    require(answer[:6] == guest and answer[14:18] == b'\x60\0\0\0' and
                            answer[20:22] == b'\x3a\xff' and len(body) == 32 and body[1] == 0 and
                            body[4:8] == b'\x60\0\0\0' and body[8:24] == destination and
                            body[24:] == b'\2\1' + peer and not checksum(sender + receiver +
                            struct.pack('!I3xB', len(body), 58) + body), 'exact native maintenance response')
                    candidates.append(response)
            require(candidates, 'native maintenance request has its captured peer response')
            response = min(candidates)
            maintenance_responses.add(response)
            maintenance.append(dict(request=index, response=response, source=source.hex(), target=destination.hex()))
        else:
            original_emitted.append((index, frame, source, destination, payload))
    require(len(maintenance) <= 9, 'bounded native maintenance exchanges')
    emitted = original_emitted
    incoming = [row for row in incoming if row[0] not in maintenance_responses]
    require(len(emitted) == 11, 'exact eleven original kernel packets')
    dad, resolution, advertisements, echoes = [], [], [], []
    advertisement_positions, echo_positions, resolution_positions = {}, {}, {}
    for index, frame, source, destination, payload in emitted:
        kind = payload[0]
        if kind == 135:
            target = payload[8:24]
            require(frame[21] == 255 and destination == solicit(target) and
                    frame[:6] == b'\x33\x33' + destination[-4:], 'NS destination, hop and multicast MAC')
            if source == bytes(16):
                require(len(payload) == 24 and payload[4:8] == bytes(4), 'DAD has no source option')
                dad.append((target, index))
            else:
                phase = next((p for p in (2, 5) if requests[p] < index < acknowledgements[p]), None)
                require(phase is not None and source == local and
                        target == (unknown if phase == 2 else unresolved) and
                        payload[4:8] == bytes(4) and payload[24:] == b'\1\1' + guest,
                        'owned pending neighbor solicitation')
                resolution.append(index)
                require(phase not in resolution_positions, 'one resolution per unresolved neighbor')
                resolution_positions[phase] = index
        elif kind == 136:
            phase = next((p for p in (1, 3, 4, 5) if requests[p] < index < acknowledgements[p]), None)
            require(phase is not None and source == local and
                    destination == (unresolved if phase == 5 else remote) and
                    frame[:6] == peer and frame[21] == 255 and
                    payload[4:8] == (b'\x40\0\0\0' if phase == 5 else b'\x60\0\0\0') and
                    payload[8:24] == local and payload[24:] == (b'' if phase == 5 else b'\2\1' + guest),
                    'exact unicast advertisement')
            require(phase not in advertisement_positions, 'one NA per valid solicitation phase')
            advertisements.append(phase)
            advertisement_positions[phase] = index
        elif kind == 129:
            phase = next((p for p in (1, 2) if requests[p] < index < acknowledgements[p]), None)
            require(phase is not None and source == local and
                    destination == (remote if phase == 1 else unknown) and frame[:6] == peer and
                    frame[21] == 64 and len(payload) == 101, 'original echo reply route and bounds')
            expected = bytes((n * 17 + lane + phase) & 255 for n in range(101))
            require(payload[4:] == expected[4:], 'exact original echo bytes')
            echoes.append(phase)
            require(phase not in echo_positions, 'one echo per request phase')
            echo_positions[phase] = index
        else:
            raise ValueError('unexpected kernel IPv6 packet')
    require(sorted(target for target, _ in dad) == sorted([local, link, duplicate]), 'three original DAD targets')
    require(all(acknowledgements[0] < index < requests[1] for target, index in dad if target != duplicate),
            'explicit readiness precedes assigned-address DAD')
    require(all(acknowledgements[3] < index < requests[4] for target, index in dad if target == duplicate),
            'duplicate candidate has its own actual DAD exchange')
    require(advertisements == [1, 3, 4, 5] and echoes == [1, 2] and len(resolution) == 2,
            'every response and rejection remains independently accounted')
    controls, used_inputs, control_positions = [], set(), []
    for index, frame, source, destination, payload in incoming:
        if requests[3] < index < acknowledgements[3] and source[-1] in range(40, 45):
            kind = source[-1] - 40
            controls.append(kind)
            used_inputs.add(index)
            control_positions.append(index)
            require(source == remote[:-1] + bytes([40 + kind]) and
                    frame[:6] == b'\x33\x33' + destination[-4:] and
                    frame[14:18] == b'\x60\0\0\0', 'original malformed-control ownership')
            require(destination == solicit(local), 'invalid controls reach the joined group')
            if kind == 4:
                require(frame[20] == 44 and payload[:8] == b'\x3a\0\0\0\0\0\0\1', 'actual atomic fragment control')
                body = payload[8:]
            else:
                require(frame[20] == 58, 'ordinary ND control protocol')
                body = payload
            valid_checksum = not checksum(source + destination + struct.pack('!I3xB', len(body), 58) + body)
            require(valid_checksum == (kind != 1), 'controls isolate checksum errors')
            require(frame[21] == (254 if kind == 0 else 255) and body[0] == 135 and
                    body[1] == (1 if kind == 2 else 0) and body[8:24] == local and
                    body[25] == (0 if kind == 3 else 1), 'exact original invalid ND condition')
    require(sorted(controls) == list(range(5)), 'all five real malformed ND controls')

    def valid_peer(lower, upper, kind, source, destination, target=None, option=True, phase=0):
        matches = [row for row in incoming if lower < row[0] < upper and row[2] == source and
                   row[3] == destination and row[4][:2] == bytes([kind, 0])]
        require(len(matches) == 1, 'one original valid peer input for each required exchange')
        index, frame, _, _, payload = matches[0]
        require(index not in used_inputs, 'independent ownership of each peer input')
        used_inputs.add(index)
        require(frame[14:18] == b'\x60\0\0\0' and frame[20] == 58 and
                frame[21] == (64 if kind == 128 else 255) and
                frame[:6] == (b'\x33\x33' + destination[-4:] if destination[0] == 255 else guest) and
                not checksum(source + destination + struct.pack('!I3xB', len(payload), 58) + payload),
                'valid original peer envelope and checksum')
        if kind == 128:
            expected = bytes((n * 17 + lane + phase) & 255 for n in range(101))
            require(len(payload) == 101 and payload[4:] == expected[4:], 'original echo request bytes')
        else:
            flags = bytes(4) if kind == 135 else (b'\x20\0\0\0' if destination[0] == 255 else b'\x60\0\0\0')
            require(payload[4:8] == flags and payload[8:24] == target and
                    payload[24:] == (bytes([1 if kind == 135 else 2, 1]) + peer if option else b''),
                    'complete original valid ND request or advertisement')
        return index

    def request(phase, kind, source, destination, target=None, option=True):
        return valid_peer(requests[phase], acknowledgements[phase], kind, source,
                          destination, target, option, phase)

    ns1 = request(1, 135, remote, solicit(local), local)
    echo1 = request(1, 128, remote, local)
    echo2 = request(2, 128, unknown, local)
    na2 = request(2, 136, unknown, local, unknown)
    ns3 = request(3, 135, remote, solicit(local), local)
    failed_ns = request(4, 135, remote, solicit(duplicate), duplicate)
    ns4 = request(4, 135, remote, solicit(local), local)
    bare_ns = request(5, 135, unresolved, local, local, False)
    na5 = request(5, 136, unresolved, local, unresolved)
    duplicate_probe = next(index for target, index in dad if target == duplicate)
    conflict = valid_peer(duplicate_probe, requests[4], 136, duplicate, all_nodes, duplicate)
    chains = [
        [requests[1], ns1, advertisement_positions[1], echo1, echo_positions[1], acknowledgements[1]],
        [requests[2], echo2, resolution_positions[2], na2, echo_positions[2], acknowledgements[2]],
        [requests[3], *control_positions, ns3, advertisement_positions[3], acknowledgements[3]],
        [requests[4], failed_ns, ns4, advertisement_positions[4], acknowledgements[4]],
        [requests[5], bare_ns, resolution_positions[5], na5, advertisement_positions[5], acknowledgements[5]],
    ]
    require(all(all(a < b for a, b in zip(chain, chain[1:])) for chain in chains),
            'original requests, resolution, responses and completion have causal order')
    require(len(incoming) == 15 and used_inputs == {row[0] for row in incoming},
            'every valid and malformed peer input remains independently accounted')
    return dict(passed=True, lane=lane, kernel_packets=11, phases=5, malformed_controls=5, lifetimes=lifetimes,
                queued_sources=queued_sources,
                peer_inputs=15, lifetime_wire=lifetime_wire, firmware_frames=len(firmware), firmware_sha256=firmware,
                actual_DAD_elapsed_ns=int(elapsed[0]), native_MLD_reports=mld_reports,
                native_maintenance=maintenance), dict(
                emitted=emitted, requests=requests, acknowledgements=acknowledgements,
                maintenance=maintenance,
                resolution=resolution, conflicts=[conflict], valid_inputs=dict(
                    NS=ns1, echo=echo1, NA=na2, bare_NS=bare_ns, bare_NA=na5))


def verify_capture(path, lane, log_path, archive, native=False, statistics=None):
    path, log_path = Path(path), Path(log_path)
    raw, raw_log = path.read_bytes(), log_path.read_bytes()
    rows, log = read_capture(path), raw_log.decode(errors='replace')
    wire = verify_lifetimes(path, lane, log_path, Path(archive).with_suffix('.lifetime.zip'),
                            native=native, statistics=statistics)
    result, proof = inspect(rows, lane, log, native)
    result['lifetime_wire'] = wire
    result['queued_sources'] = verify_queued_sources(path, lane, log_path,
        Path(archive).with_suffix('.queued-sources.zip'), native=native, statistics=statistics)
    rejected = []
    with zipfile.ZipFile(archive, 'x', compression=zipfile.ZIP_DEFLATED) as saved:
        cases = ['missing-kernel', 'duplicate-kernel', 'checksum', 'source', 'destination', 'MAC',
                 'hop-limit', 'payload', 'missing-phase', 'missing-ACK', 'missing-malformed',
                 'missing-conflict', 'false-DAD-time', 'missing-client-phase', 'missing-route-result',
                 'missing-valid-NS', 'missing-valid-echo', 'missing-valid-NA', 'missing-ready',
                 'missing-bare-NS', 'missing-bare-NA', 'missing-direct-ND-result', 'missing-prefix-result',
                 'missing-prefix-order-result']
        if not native:
            cases.append('firmware-flood')
        if proof['maintenance']:
            cases += ['missing-maintenance-NS', 'missing-maintenance-NA', 'maintenance-checksum']
        for name in cases:
            changed, text = copy.deepcopy(rows), log
            at = proof['emitted'][-1][0]
            if name == 'missing-kernel':
                del changed[at]
            elif name.startswith('missing-maintenance-'):
                del changed[proof['maintenance'][0]['request' if name.endswith('NS') else 'response']]
            elif name == 'maintenance-checksum':
                at = proof['maintenance'][0]['request']
                frame = bytearray(changed[at]['frame'])
                frame[56] ^= 1
                changed[at]['frame'] = bytes(frame)
            elif name == 'firmware-flood':
                frame = copy.deepcopy(rows[0])
                frame['frame'] = rows[proof['emitted'][0][0]]['frame']
                changed[:0] = [copy.deepcopy(frame) for _ in range(257)]
            elif name == 'duplicate-kernel':
                changed.insert(at, copy.deepcopy(changed[at]))
            elif name == 'missing-phase':
                del changed[proof['requests'][2]]
            elif name == 'missing-ACK':
                del changed[proof['acknowledgements'][3]]
            elif name == 'missing-malformed':
                at = next(i for i, row in enumerate(changed) if row['frame'][12:14] == b'\x86\xdd' and
                          len(row['frame']) >= 54 and row['frame'][37] == 42)
                del changed[at]
            elif name == 'missing-conflict':
                del changed[proof['conflicts'][0]]
            elif name == 'missing-ready':
                del changed[proof['requests'][0]]
            elif name.startswith('missing-valid-'):
                del changed[proof['valid_inputs'][name.removeprefix('missing-valid-')]]
            elif name.startswith('missing-bare-'):
                del changed[proof['valid_inputs']['bare_' + name.removeprefix('missing-bare-')]]
            elif name == 'false-DAD-time':
                text = re.sub(r'IPV6_HOST_DAD_PASS elapsed_ns=\d+', 'IPV6_HOST_DAD_PASS elapsed_ns=1', text)
            elif name == 'missing-client-phase':
                text = text.replace(f'IPV6_HOST_PHASE_PASS lane={lane} phase=3', 'MISSING')
            elif name == 'missing-route-result':
                text = text.replace('IPV6_HOST_ROUTES_PASS adapters=2 filtered=1', 'MISSING')
            elif name == 'missing-direct-ND-result':
                text = text.replace(f'IPV6_HOST_DIRECT_ND_PASS lane={lane} prefix=128', 'MISSING')
            elif name == 'missing-prefix-result':
                text = text.replace('IPV6_HOST_PREFIX_PASS adapters=2 tentative=1 failed=1 retained=1', 'MISSING')
            elif name == 'missing-prefix-order-result':
                text = text.replace(f'IPV6_HOST_PREFIX_ORDER_PASS lane={lane} scenarios=3', 'MISSING')
            else:
                frame = bytearray(changed[at]['frame'])
                offset = {'checksum': 56, 'source': 37, 'destination': 53, 'MAC': 5,
                          'hop-limit': 21, 'payload': len(frame) - 1}[name]
                frame[offset] ^= 1
                if name != 'checksum':
                    frame[56:58] = b'\0\0'
                    body = bytes(frame[54:54 + int.from_bytes(frame[18:20], 'big')])
                    struct.pack_into('!H', frame, 56, checksum(frame[22:54] + struct.pack('!I3xB', len(body), 58) + body))
                changed[at]['frame'] = bytes(frame)
            saved.writestr(name + '.pcap', encode_capture(changed))
            saved.writestr(name + '.log', text)
            try:
                inspect(changed, lane, text, native)
            except ValueError as error:
                rejected.append(dict(name=name, reason=str(error)))
            else:
                raise ValueError('damaged IPv6 host evidence accepted: ' + name)
        saved.writestr('rejections.json', json.dumps(rejected, indent=2) + '\n')
    require(path.read_bytes() == raw and log_path.read_bytes() == raw_log, 'original evidence stays unchanged')
    result.update(damaged_rejected=len(rejected), original_sha256=hashlib.sha256(raw).hexdigest(),
                  archive_sha256=hashlib.sha256(Path(archive).read_bytes()).hexdigest())
    return result
