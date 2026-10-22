# SPDX-License-Identifier: GPL-3.0-or-later
"""Reconstruct finite-address UDP evidence independently of the live peer."""
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
    require(text.splitlines().count('IPV6_LIFETIME_WIRE_DONE observations=18') == 1,
            'one complete lifetime wire inventory')
    rows, barriers = [], []
    fields = {'lane', 'stage', 'kind', 'elapsed_ns', 'sent', 'errno', 'polled', 'events',
              'received', 'receive_errno', 'exact', 'source'}
    for line in text.splitlines():
        if line.startswith('IPV6_LIFETIME_BARRIER '):
            match = re.fullmatch(r'IPV6_LIFETIME_BARRIER lane=([01]) stage=2 kind=([01]) passed=1', line)
            require(match is not None and len(barriers) < 4, 'exact successful permanent-source barrier')
            lane, kind = map(int, match.groups())
            require((lane, kind) == (len(barriers) // 2, len(barriers) % 2) and
                    len(rows) == lane * 9 + 6 + kind, 'barrier acknowledgment precedes expired socket observation')
            barriers.append((lane, kind))
        if not line.startswith('IPV6_LIFETIME_WIRE '):
            continue
        pairs = [part.split('=', 1) for part in line.removeprefix('IPV6_LIFETIME_WIRE ').split()]
        require(all(len(pair) == 2 for pair in pairs), 'complete lifetime wire fields')
        row = dict(pairs)
        require(len(pairs) == len(row) and set(row) == fields and
                all(re.fullmatch('-?[0-9]+', row[key]) for key in fields - {'source'}),
                'exact lifetime wire integer field inventory')
        at = len(rows)
        row = {key: value if key == 'source' else int(value) for key, value in row.items()}
        lane, stage, kind = at // 9, at // 3 % 3, at % 3
        require(at < 18 and (row['lane'], row['stage'], row['kind']) == (lane, stage, kind),
                'eighteen ordered lifetime observations')
        require((0, 4200000000, 9200000000)[stage] <= row['elapsed_ns'] <
                (2000000000 if stage == 0 else 16000000000), 'bounded original elapsed wire observations')
        expired = stage == 2 and kind < 2
        expected = dict(sent=16, errno=0, polled=0 if expired else 1, events=0 if expired else 1,
                        received=-1 if expired else 16, receive_errno=11 if expired else 0,
                        exact=0 if expired else 1)
        require(all(row[key] == value for key, value in expected.items()),
                'retained output and expired input exclusion match the executed Linux behavior')
        selected = ipaddress.IPv6Address(
            f'2001:db8:{0x420 + lane:x}::{0x81 if stage and kind == 2 else 0x82:x}').packed
        require(row['source'] == selected.hex(), 'complete retained or fresh source address')
        rows.append(row)
    require(len(rows) == 18 and len(barriers) == 4, 'all lifetime send, receive and barrier observations')
    return rows


def inspect(rows, lane, text):
    observed = records(text)
    guest = bytes([0x52, 0x54, 0, 0x12, 0x34, 0x10 + lane])
    peer = bytes([2, 0x49, 0x50, 0x36, lane, 1])
    remote = ipaddress.IPv6Address(f'2001:db8:{0x420 + lane:x}::100').packed
    sources = {bytes.fromhex(row['source']) for row in observed if row['lane'] == lane}
    multicast = b'\xff\x02' + bytes(9) + b'\1\xff' + remote[-3:]
    requests, replies, probes, answers, closed, excluded = {}, {}, [], [], [], set()
    barriers, barrier_acks = {}, {}
    for at, row in enumerate(rows):
        frame = row['frame']
        if len(frame) < 54 or frame[12:14] != b'\x86\xdd':
            continue
        if remote not in (frame[22:38], frame[38:54]) and not (
                frame[20] == 58 and frame[54:56] == b'\x87\0' and frame[62:78] == remote):
            continue
        excluded.add(at)
        size, protocol, hop = struct.unpack('!HBB', frame[18:22])
        source, destination, body = frame[22:38], frame[38:54], frame[54:54 + size]
        require(frame[14:18] == b'\x60\0\0\0' and len(body) == size and protocol in (17, 58) and
                not checksum(source + destination + struct.pack('!I3xB', size, protocol) + body),
                'original complete lifetime frame and pseudo-header checksum')
        if protocol == 17:
            require(size == 24 and hop == 64 and body[8:12] in (b'LIF6', b'LIFB') and body[12] == lane and
                    body[13] in range(3) and body[14] in range(3) and body[15] == 0x5a,
                    'lifetime UDP length and complete ownership tag')
            stage, kind = body[13:15]
            require(body[16:] == bytes((n * 17 + lane + stage + kind) & 255 for n in range(8, 16)),
                    'every original UDP payload byte')
            barrier = body[8:12] == b'LIFB'
            require(not barrier or stage == 2 and kind < 2, 'only expired observations use permanent barriers')
            selected = (ipaddress.IPv6Address(f'2001:db8:{0x420 + lane:x}::81').packed if barrier else
                        bytes.fromhex(observed[lane * 9 + stage * 3 + kind]['source']))
            port = 59300 + lane if barrier else 59000 + kind * 100 + lane
            output = frame[6:12] == guest
            require(frame[:12] == (peer + guest if output else guest + peer) and
                    source == (selected if output else remote) and
                    destination == (remote if output else selected) and
                    body[:6] == struct.pack('!HHH', *( (port, 55123, 24)
                    if output else (55123, port, 24))),
                    'original lifetime addresses, MACs, ports and UDP length')
            target = (barriers if output else barrier_acks) if barrier else (requests if output else replies)
            require((stage, kind) not in target, 'one exact original datagram per observation')
            target[stage, kind] = at
        elif body[:2] == b'\x87\0':
            require(frame[6:12] == guest and source in sources and hop == 255 and size == 32 and
                    body[4:8] == bytes(4) and body[8:24] == remote and body[24:] == b'\1\1' + guest and
                    destination in (remote, multicast) and
                    frame[:6] == (peer if destination == remote else b'\x33\x33' + multicast[-4:]),
                    'complete original lifetime neighbor solicitation')
            probes.append(at)
        elif body[:2] == b'\x88\0':
            require(frame[:12] == guest + peer and source == remote and destination in sources and
                    hop == 255 and size == 32 and body[4:8] == b'\x60\0\0\0' and
                    body[8:24] == remote and body[24:] == b'\2\1' + peer,
                    'complete original lifetime neighbor advertisement')
            answers.append(at)
        else:
            require(size == 72 and hop == 64 and frame[:12] == peer + guest and source in sources and
                    destination == remote and body[:2] == b'\1\4' and body[4:8] == bytes(4),
                    'closed fresh lifetime socket ICMPv6 error')
            quote, udp = body[8:48], body[48:]
            require(quote[:8] == b'\x60\0\0\0\0\x18\x11\x40' and quote[8:24] == remote and
                    quote[24:] == source and udp[:6] == struct.pack('!HHH', 55123, 59200 + lane, 24) and
                    not checksum(quote[8:] + struct.pack('!I3xB', 24, 17) + udp), 'complete closed socket quote')
            require(udp[8:13] == b'LIF6' + bytes([lane]) and udp[13] in range(3) and udp[14:16] == b'\2\x5a',
                    'closed fresh socket quoted payload ownership')
            stage = udp[13]
            require(udp[16:] == bytes((n * 17 + lane + stage + 2) & 255 for n in range(8, 16)) and
                    source == bytes.fromhex(observed[lane * 9 + stage * 3 + 2]['source']) and
                    (stage, 2) in replies and replies[stage, 2] < at and stage not in closed,
                    'one causal error quoting an actual fresh reply')
            closed.append(stage)
    wanted = {(stage, kind) for stage in range(3) for kind in range(3)}
    require(set(requests) == set(replies) == wanted, 'all nine original sends and controlled replies')
    require(all(requests[key] < replies[key] for key in wanted), 'every reply follows its actual datagram')
    require(set(barriers) == set(barrier_acks) == {(2, 0), (2, 1)}, 'both complete permanent-source wire barriers')
    for kind in range(2):
        key = (2, kind)
        require(requests[key] < replies[key] < barrier_acks[key] < requests[2, kind + 1] and
                requests[key] < barriers[key] < barrier_acks[key],
                'expired reply is injected before an acknowledged permanent-source barrier and next send')
    require([requests[key] for key in sorted(wanted)] == sorted(requests.values()), 'ordered wire observations')
    require(0 < len(probes) == len(answers) <= 12 and all(a < b for a, b in zip(probes, answers)),
            'all lifetime neighbor resolution responses accounted')
    require(all(rows[answer]['frame'][38:54] == rows[probe]['frame'][22:38]
                for probe, answer in zip(probes, answers)), 'each neighbor answer returns to its actual requester')
    for kind in range(3):
        origin = rows[requests[0, kind]]['ns']
        require(rows[requests[1, kind]]['ns'] - origin >= 2000000000 and
                rows[requests[2, kind]]['ns'] - origin >= 8000000000,
                'original packet clocks retain real preferred and valid lifetime intervals')
    return dict(passed=True, lane=lane, datagrams=9, replies=9, expired_source_sends=2,
                excluded_expired_replies=2, acknowledged_barriers=2, neighbor_probes=len(probes), closed_fresh_errors=closed,
                requests={f'{stage}-{kind}': at for (stage, kind), at in requests.items()},
                replies_positions={f'{stage}-{kind}': at for (stage, kind), at in replies.items()},
                barrier_positions={f'{stage}-{kind}': at for (stage, kind), at in barriers.items()},
                barrier_ack_positions={f'{stage}-{kind}': at for (stage, kind), at in barrier_acks.items()}), excluded


def verify_capture(path, lane, log_path, archive, native=False, statistics=None):
    path, log_path, archive = Path(path), Path(log_path), Path(archive)
    original, original_log = path.read_bytes(), log_path.read_bytes()
    rows, text = read_capture(path), original_log.decode(errors='replace')
    result, positions = inspect(rows, lane, text)
    if native:
        timed = [dict(stamp=row['ns'] // 1000, frame=row['frame']) for at, row in enumerate(rows) if at in positions]
        result['native_clock'] = bind_native_clock(path, timed, statistics)
    request = result['requests']['2-0']
    reply = result['replies_positions']['2-0']
    names = ['missing-expired-send', 'missing-expired-reply', 'duplicate-send', 'checksum', 'source',
             'destination', 'MAC', 'port', 'payload', 'hop', 'short-wire-lifetime', 'missing-observation',
              'duplicate-observation', 'wrong-selected-source', 'false-receive', 'short-client-time', 'missing-done',
             'missing-barrier', 'missing-barrier-ack', 'missing-barrier-result', 'late-expired-reply']
    with zipfile.ZipFile(archive, 'x', zipfile.ZIP_DEFLATED) as saved:
        for name in names:
            changed, log = copy.deepcopy(rows), text
            if name.startswith('missing-expired-'):
                del changed[request if name.endswith('send') else reply]
            elif name in ('missing-barrier', 'missing-barrier-ack'):
                positions = result['barrier_positions' if name == 'missing-barrier' else 'barrier_ack_positions']
                del changed[positions['2-0']]
            elif name == 'missing-barrier-result':
                log = log.replace(f'IPV6_LIFETIME_BARRIER lane={lane} stage=2 kind=0 passed=1', 'MISSING')
            elif name == 'late-expired-reply':
                delayed = changed.pop(reply)
                # Keep packet bytes intact; place this control after the barrier acknowledgment.
                after = result['barrier_ack_positions']['2-0']
                delayed['ns'] = changed[after - 1]['ns']
                changed.insert(after, delayed)
            elif name == 'duplicate-send':
                changed.insert(request, copy.deepcopy(changed[request]))
            elif name == 'short-wire-lifetime':
                origin = rows[result['requests']['0-0']]['ns']
                for at in range(request, len(changed)):
                    changed[at]['ns'] -= rows[request]['ns'] - origin - 1000000000
            elif name.endswith('observation') or name in ('wrong-selected-source', 'false-receive', 'short-client-time'):
                lines = log.splitlines()
                at = next(at for at, line in enumerate(lines) if line.startswith(f'IPV6_LIFETIME_WIRE lane={lane} stage=2 kind=0 '))
                if name == 'missing-observation': del lines[at]
                elif name == 'duplicate-observation': lines.insert(at, lines[at])
                elif name == 'wrong-selected-source': lines[at] = re.sub(r'source=[0-9a-f]+', 'source=' + '00' * 16, lines[at])
                elif name == 'false-receive': lines[at] = lines[at].replace('received=-1', 'received=16')
                else: lines[at] = re.sub(r'elapsed_ns=\d+', 'elapsed_ns=1', lines[at])
                log = '\n'.join(lines) + '\n'
            elif name == 'missing-done':
                log = log.replace('IPV6_LIFETIME_WIRE_DONE observations=18', 'MISSING')
            else:
                frame = bytearray(changed[request]['frame'])
                frame[{'checksum': 60, 'source': 37, 'destination': 53, 'MAC': 5, 'port': 55,
                       'payload': 69, 'hop': 21}[name]] ^= 1
                if name != 'checksum':
                    frame[60:62] = bytes(2)
                    struct.pack_into('!H', frame, 60, checksum(frame[22:54] + struct.pack('!I3xB', 24, 17) + frame[54:78]) or 65535)
                changed[request]['frame'] = bytes(frame)
            saved.writestr(name + '.pcap', encode_capture(changed))
            saved.writestr(name + '.log', log)
    rejected = []
    with zipfile.ZipFile(archive) as saved:
        for name in names:
            with tempfile.TemporaryDirectory(prefix='ipv6-lifetime-control-') as directory:
                damaged = Path(directory) / 'original.pcap'
                damaged.write_bytes(saved.read(name + '.pcap'))
                try:
                    inspect(read_capture(damaged), lane, saved.read(name + '.log').decode())
                except ValueError as error:
                    rejected.append(dict(name=name, reason=str(error)))
                else:
                    raise ValueError('damaged lifetime wire evidence accepted: ' + name)
    require(path.read_bytes() == original and log_path.read_bytes() == original_log, 'original lifetime evidence unchanged')
    result.update(serialized_controls_reopened_rejected=len(rejected), rejections=rejected,
                  original_sha256=hashlib.sha256(original).hexdigest(),
                  archive_sha256=hashlib.sha256(archive.read_bytes()).hexdigest())
    return result
