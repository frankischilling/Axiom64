# SPDX-License-Identifier: GPL-3.0-or-later
"""Reconstruct TCP6 streams and loss timers without using the transmitting peer."""
import hashlib
import ipaddress
import re
import struct
from functools import lru_cache
from ipv4_expiry_capture import read_capture, checksum

SIZE = 65536
MASK = 0xffffffff


def require(value, reason):
    if not value:
        raise ValueError(reason)


@lru_cache(maxsize=8)
def expected(lane, role, direction):
    return bytes(((n * 29) ^ (n >> 7) ^ (lane * 53) ^ (role * 97) ^ (direction * 41)) & 255
                 for n in range(SIZE))


def inspect(rows, lane, log, native=False, scoped=False):
    marker = ('TCP6_SCOPED_FAULT_PASS' if scoped else 'TCP6_FAULT_PASS') + ' flows=4 bytes_each=65536'
    require(log.splitlines().count(marker) == 1,
            'one completed actual IPv6 TCP workload')
    if scoped:
        names = [tuple(map(int, match)) for match in re.findall(
            r'^TCP6_SCOPED_NAME_PASS lane=(\d+) role=(\d+) index=(\d+) local_scope=(\d+) '
            r'peer_scope=(\d+) local_port=(\d+) peer_port=(\d+)\r?$', log, re.M)]
        require(len(names) == 4 and {(row[0], row[1]) for row in names} ==
                {(nic, role) for nic in range(2) for role in range(2)}, 'complete actual scoped socket names')
        zones = {}
        for nic, role, index, local_scope, peer_scope, local_port, peer_port in names:
            require(index > 0 and local_scope == peer_scope == index and
                    local_port == (44010 if role else 44020) and
                    peer_port == (45000 if role else 44000), 'actual local and peer scope and port')
            require(nic not in zones or zones[nic] == index, 'one actual interface index per zone')
            zones[nic] = index
        require(zones[0] != zones[1], 'identical link-local tuples retain independent interface zones')
        retained = re.findall(r'^TCP6_SCOPED_RETAINED_PASS first_index=(\d+) second_index=(\d+) '
                              r'port=44020 error=98\r?$', log, re.M)
        require(retained == [(str(zones[0]), str(zones[1]))],
                'same-zone retained port denies binding before the second zone opens')
    for role in range(2):
        require(log.count(f'TCP_FAULT_FLOW_PASS lane={lane} role={role} bytes_each=65536 ') == 1,
                'one actual active/passive stream result')
    guest = bytes([0x52, 0x54, 0, 0x12, 0x34, 0x10 + lane])
    peer = bytes([2, 0x41, 0x58, 0x54, 0x43, lane])
    control = bytes([2, ord('I'), ord('P'), ord('6'), lane, 0])
    local = ipaddress.IPv6Address('fe80::2' if scoped else f'2001:db8:{lane + 1}::2').packed
    remote = ipaddress.IPv6Address('fe80::1' if scoped else f'2001:db8:{lane + 1}::1').packed
    ready, reply, flows = None, None, {}
    for index, row in enumerate(rows):
        frame = row['frame']
        if frame[12:14] == b'\x88\xc1':
            require(len(frame) == 60 and frame[14:20] == b'IP6T' + bytes([lane, 0]) and
                    not any(frame[21:]), 'complete original TCP6 readiness frame')
            if frame[20] == 0:
                require(ready is None and frame[:12] == control + guest, 'unique readiness request')
                ready = index
            else:
                require(frame[20] == 1 and ready is not None and reply is None and
                        frame[:12] == guest + control, 'unique owned readiness reply')
                reply = index
            continue
        if ready is None and not native:
            require(index < 256 and frame[6:12] == guest, 'bounded guest firmware prelude')
            continue
        require(frame[12:14] == b'\x86\xdd' and len(frame) >= 54, 'IPv6-only TCP workload')
        ip = frame[14:]
        size = int.from_bytes(ip[4:6], 'big')
        require(ip[0] >> 4 == 6 and 40 + size <= len(ip), 'captured IPv6 declared bounds')
        if ip[6] != 6:
            # Validate maintenance packets even though they carry no stream bytes.
            skip = 8 if ip[6] == 0 else 0
            require((ip[6] == 58 or (native and ip[6] == 0 and
                    ip[40:48] == bytes.fromhex('3a00050200000100'))) and size >= skip + 8 and
                    not checksum(ip[8:40] + struct.pack('!I3xB', size - skip, 58) +
                                 ip[40 + skip:40 + size]), 'maintenance ICMPv6 checksum')
            require(ip[40 + skip] in (133, 135, 136, 143), 'bounded router/neighbor/listener maintenance types')
            continue
        require(reply is not None and index > reply, 'TCP follows actual readiness exchange')
        outgoing = ip[8:24] == local
        require(ip[8:40] == (local + remote if outgoing else remote + local) and
                frame[:12] == (peer + guest if outgoing else guest + peer),
                'all sixteen address bytes and both Ethernet owners')
        tcp = ip[40:40 + size]
        require(size >= 20 and not checksum(ip[8:40] + struct.pack('!I3xB', size, 6) + tcp),
                'independent IPv6 pseudo-header checksum')
        source, target, seq, ack, bits, window, _, urgent = struct.unpack_from('!HHIIHHHH', tcp)
        header, flags = (bits >> 12) * 4, bits & 511
        require(20 <= header <= size and not bits & 0x0e00 and not urgent and not flags & 4,
                'TCP header bounds, reserved bits and no reset')
        local_port, remote_port = (source, target) if outgoing else (target, source)
        port_offset = 0 if scoped else lane
        role = 0 if remote_port == 44000 + port_offset else 1 if (
            remote_port == 45000 + port_offset and local_port == 44010 + port_offset) else None
        require(role is not None, 'actual active/passive TCP6 ports')
        require(not scoped or local_port == (44010 if role else 44020), 'same bound ports across zones')
        key = role, local_port, remote_port
        flow = flows.setdefault(key, [dict(events=[], data=bytearray(SIZE), seen=bytearray(SIZE)),
                                      dict(events=[], data=bytearray(SIZE), seen=bytearray(SIZE))])
        direction = 0 if outgoing else 1
        item, opposite = flow[direction], flow[1 - direction]
        mss, at = None, 20
        while at < header:
            kind = tcp[at]
            if not kind:
                break
            if kind == 1:
                at += 1
                continue
            require(at + 2 <= header and tcp[at + 1] >= 2 and at + tcp[at + 1] <= header,
                    'captured TCP option bounds')
            if kind == 2:
                require(flags & 2 and tcp[at + 1] == 4 and mss is None, 'one SYN MSS option')
                mss = int.from_bytes(tcp[at + 2:at + 4], 'big')
            at += tcp[at + 1]
        if flags & 2:
            require(mss and not tcp[header:] and not flags & 1 and bool(flags & 16) ==
                    bool(role if outgoing else not role), 'active/passive SYN and advertised MSS')
            require('initial' not in item or (item['initial'], item['mss']) == (seq, mss),
                    'retransmitted SYN preserves sequence and MSS')
            item.update(initial=seq, mss=mss)
        require('initial' in item, 'SYN precedes stream sequence space')
        body = tcp[header:]
        start = (seq - item['initial'] - (0 if flags & 2 else 1)) & MASK
        if body:
            require(not flags & 2 and start + len(body) <= SIZE and len(body) <= opposite.get('mss', 0),
                    'payload within advertised MSS and complete stream bounds')
            require(body == expected(lane, role, direction)[start:start + len(body)],
                    'independent complete stream byte pattern')
            item['data'][start:start + len(body)] = body
            item['seen'][start:start + len(body)] = b'\1' * len(body)
        if flags & 1:
            require(start + len(body) == SIZE, 'FIN consumes sequence after every stream byte')
        if flags & 3 or body:
            item['sent_max'] = max(item.get('sent_max', 0), start + len(body) + bool(flags & 1))
        if flags & 16:
            require('initial' in opposite and ((ack - opposite['initial'] - 1) & MASK) <= opposite.get('sent_max', 0),
                    'ACK covers only bytes already present in the opposite capture')
        item['events'].append(dict(index=index, lower=row.get('arrival_lower_ns', row['ns']),
                                   upper=row.get('arrival_upper_ns', row['ns']), flags=flags,
                                   sequence=seq, ack=ack, body=body, window=window))
    require(ready is not None and reply is not None and len(flows) == 2 and
            {key[0] for key in flows} == {0, 1}, 'both IPv6 active/passive captured flows')
    results = []
    for (role, _, _), flow in sorted(flows.items()):
        require(flow[1]['initial'] == 0xfffffff0 and flow[1]['mss'] == 536,
                'controlled wrapped sequence origin and original peer MSS')
        for direction, item in enumerate(flow):
            require(all(item['seen']) and bytes(item['data']) == expected(lane, role, direction),
                    'all exact bytes captured in each direction')
            require(any(event['flags'] & 1 for event in item['events']) and any(
                event['flags'] & 16 and event['ack'] == (item['initial'] + SIZE + 2) & MASK
                for event in flow[1 - direction]['events']), 'each final FIN is actually acknowledged')
        events = flow[0]['events']
        syns = [event for event in events if event['flags'] & 2]
        data = [event for event in events if event['body']]
        fins = [event for event in events if event['flags'] & 1]
        require(len(syns) >= 2 and len(data) >= 2 and len(fins) >= 2,
                'capture proves all three actual retransmissions')
        require(data[0]['sequence'] == data[1]['sequence'] and data[0]['body'] == data[1]['body'],
                'lost first data is retransmitted byte for byte')
        for attempts in (syns, data, fins):
            first, retry = attempts[:2]
            end = (first['sequence'] + len(first['body']) + bool(first['flags'] & 3)) & MASK
            require(not any(first['index'] < event['index'] < retry['index'] and
                event['flags'] & 16 and ((event['ack'] - end) & MASK) < (1 << 31)
                for event in flow[1]['events']),
                'actually dropped sequence remains unacknowledged until its real retry')
        delays = [(syns[1]['lower'] - syns[0]['upper']) / 1000000,
                  (data[1]['lower'] - data[0]['upper']) / 1000000,
                  (fins[1]['lower'] - fins[0]['upper']) / 1000000]
        require(delays[0] >= 850 and delays[1] >= 2850 and delays[2] >= (180 if native else 850),
                'unchanged real handshake, data and FIN loss deadlines')
        results.append(dict(role=role, bytes_each=SIZE, handshake_retry_ms=delays[0],
            data_retry_ms=delays[1], fin_retry_ms=delays[2], sequence_wrap=True,
            outgoing_sha256=hashlib.sha256(flow[0]['data']).hexdigest(),
            incoming_sha256=hashlib.sha256(flow[1]['data']).hexdigest()))
    return dict(lane=lane, flows=results, captured_frames=len(rows), passed=True)


def verify(path, lane, log, native=False, statistics=None, scoped=False):
    rows = read_capture(path)
    clock = None
    if native:
        from tcp6.observation import bind
        clock = bind(path, rows, statistics)
    result = inspect(rows, lane, log, native, scoped)
    result.update(sha256=hashlib.sha256(path.read_bytes()).hexdigest(), clock=clock)
    return result
