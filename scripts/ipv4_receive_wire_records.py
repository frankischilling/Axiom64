# SPDX-License-Identifier: GPL-3.0-or-later
"""Decode original syscall and netlink records without using the packet producer."""
import json
import struct


def require(value, reason):
    if not value:
        raise ValueError(reason)


def unique(pairs):
    result = dict(pairs)
    require(len(result) == len(pairs), 'duplicate JSON field')
    return result


def addresses(lane):
    return (0x0a4d0102 + 256 * lane, 0xc6120102 + 256 * lane)


def expected(lane, case):
    scenario = case % 13
    transport, prepared = divmod(case // 13, 2)
    primary, prefix = addresses(lane)
    other = addresses(lane ^ 1)[0]
    source = prefix - 1 if scenario in (2, 5, 11) else primary - 1
    if scenario in (7, 12):
        source = 0xcb007100 + (31 if scenario == 7 else 61) + lane
    if scenario == 8:
        source = 0xc0000265 + lane
    destination = {1: primary + 40, 2: prefix, 3: 0xffffffff, 4: primary | 255,
                   5: prefix | 255, 9: other + 40, 10: primary + 40}.get(scenario, primary)
    if scenario in (6, 7, 8, 11, 12):
        destination = 0xef4d0101 + 256 * lane
    specific = (destination if scenario in (0, 1, 2, 9, 10) else
                other if scenario in (7, 12) else prefix if scenario in (5, 11) else primary)
    body = b'AXRXDATA' + bytes((lane, case, transport, scenario, prepared, 1, case ^ 0xa5, 0x5a + lane))
    return dict(scenario=scenario, transport=transport, prepared=prepared, source=source,
                destination=destination, specific=specific, ttl=17 + case * 11 % 200,
                tos=(0x6e + case * 13) & 255, body=body)


def controls(value, index):
    packet = struct.pack('<I', index if value['prepared'] else 0)
    packet += struct.pack('!II', value['specific'] if value['prepared'] else 0, value['destination'])
    result = b''
    for kind, payload in ((8, packet), (2, struct.pack('<i', value['ttl'])), (1, bytes([value['tos']]))):
        length = 16 + len(payload)
        result += struct.pack('<Qii', length, 0, kind) + payload + b'\xa5' * (-length % 8)
    return result


def attributes(data):
    result, at = {}, 0
    while at < len(data):
        require(len(data) - at >= 4, 'complete netlink attribute header')
        size, kind = struct.unpack_from('<HH', data, at)
        require(4 <= size <= len(data) - at and kind not in result, 'bounded unique netlink attribute')
        result[kind] = data[at + 4:at + size]
        at += (size + 3) & ~3
    require(at == len(data), 'complete netlink attribute alignment')
    return result


def inventory(records, routes):
    decoded, identity, done = [], None, False
    for record in records:
        data, at = bytes.fromhex(record['hex']), 0
        while at < len(data):
            require(not done and len(data) - at >= 16, 'complete live multipart inventory')
            size, kind, flags, sequence, pid = struct.unpack_from('<IHHII', data, at)
            require(16 <= size <= len(data) - at and flags & 2 and not flags & 16,
                    'complete uninterrupted multipart inventory')
            if identity is None:
                identity = (sequence, pid)
            require(identity == (sequence, pid) and sequence > 0, 'consistent inventory request identity')
            body = data[at + 16:at + size]
            if kind == 3:
                require(body == bytes(4), 'successful final netlink dump status')
                done = True
            elif routes:
                require(kind == 24 and len(body) >= 12, 'original IPv4 route inventory')
                family, prefix, src_prefix, tos, table, protocol, scope, route_type, route_flags = struct.unpack_from('<8BI', body)
                require(family == 2 and prefix <= 32, 'IPv4 route prefix')
                attrs = attributes(body[12:])
                if 15 in attrs:
                    require(len(attrs[15]) == 4, 'route table attribute width')
                    table = int.from_bytes(attrs[15], 'little')
                for key in (1, 4, 5, 7):
                    require(key not in attrs or len(attrs[key]) == 4, 'IPv4 route attribute width')
                decoded.append(dict(prefix=prefix, table=table, protocol=protocol, scope=scope,
                    type=route_type, destination=int.from_bytes(attrs.get(1, bytes(4)), 'big'),
                    index=int.from_bytes(attrs.get(4, bytes(4)), 'little'), attrs=attrs))
            else:
                require(kind == 20 and len(body) >= 8, 'original IPv4 address inventory')
                family, prefix, flags, scope, index = struct.unpack_from('<BBBBI', body)
                require(family == 2 and prefix <= 32, 'IPv4 address prefix')
                attrs = attributes(body[8:])
                require(len(attrs.get(2, b'')) == 4, 'IPv4 local address width')
                decoded.append(dict(prefix=prefix, index=index,
                    address=int.from_bytes(attrs[2], 'big'), attrs=attrs))
            at += (size + 3) & ~3
        require(at == len(data), 'complete multipart netlink alignment')
    require(done, 'final netlink inventory terminator')
    return decoded


def state(record, messages, indices):
    lane, case, phase = record['lane'], record['case'], record['phase']
    value = expected(lane, case)
    scenario = value['scenario']
    require(scenario in (7, 8, 10, 11, 12) and phase in (0, 1, 2), 'selected mutation inventory')
    routes = scenario in (7, 8, 12)
    target = value['source'] if routes else addresses(lane)[0] + 40 if scenario == 10 else addresses(lane)[1]
    selected = (0 if scenario == 8 or (routes and phase == 2) or (not routes and phase == 1)
                else indices[lane] if not routes or (scenario == 12 and phase == 1) else indices[lane ^ 1])
    require(set(record) == {'kind', 'lane', 'case', 'phase', 'routes', 'target', 'found', 'index'} and
            record['routes'] == int(routes) and record['target'] == f'{target:08x}' and
            record['found'] == int(bool(selected)) and record['index'] == selected,
            'recorded address and route transition')
    require(all({key: item[key] for key in ('lane', 'case', 'phase', 'routes')} ==
                {key: record[key] for key in ('lane', 'case', 'phase', 'routes')} and
                set(item) == {'kind', 'lane', 'case', 'phase', 'routes', 'hex'} for item in messages),
            'inventory records belong to this transition')
    decoded = inventory(messages, routes)
    if routes:
        matching = [item for item in decoded if item['prefix'] == 32 and item['destination'] == target]
        require(len(matching) == bool(selected), 'independent host-route presence')
        if selected:
            item = matching[0]
            require((item['table'], item['protocol'], item['scope'], item['type'], item['index']) ==
                    (254, 4, 253, 1, selected) and 5 not in item['attrs'],
                    'independent reverse-route interface and source-selection scope')
        if scenario == 8:
            require(not any(item['table'] == 254 and (target >> (32 - item['prefix']) if item['prefix'] else 0) ==
                            (item['destination'] >> (32 - item['prefix']) if item['prefix'] else 0)
                            for item in decoded), 'actual absence of a reverse route for ingress fallback')
    else:
        actual = {(item['index'], item['address'], item['prefix']) for item in decoded if item['index'] in indices}
        wanted = {(indices[n], address, 24) for n in range(2)
                  for address in (addresses(n)[0], addresses(n)[0] + 40, addresses(n)[1])}
        if phase == 1:
            wanted.remove((indices[lane], target, 24))
        require(actual == wanted, 'independent complete address retirement and restoration inventory')


def read(text, native, firmware):
    lines = text.splitlines()
    require(lines.count('IPV4_RECEIVE_WIRE_DONE lanes=2 cases_each=78 observations=156') == 1 and
            not any(marker in text for marker in ('IPV4_RECEIVE_WIRE_FAIL', 'PANIC:', 'FAULT pid=')),
            'complete successful metadata application')
    if not native:
        require(lines.count('AXIOM64_TESTS_PASS') == lines.count('AXIOM64_EXIT status=0') == 1 and
                sum(lines.count('Firmware: ' + value) for value in ('BIOS', 'UEFI')) == 1 and
                lines.count('Firmware: ' + firmware.upper()) == 1, 'actual firmware and successful guest exit')
    rows = [json.loads(line, object_pairs_hook=unique) for line in lines if line.startswith('{')]
    identity = rows[0]
    require(set(identity) == {'kind', 'sysname', 'release'} and identity['kind'] == 'kernel' and
            identity['sysname'] == ('Linux' if native else 'Axiom64') and bool(identity['release']),
            'actual system identity')
    links = rows[1:3]
    require(all(set(item) == {'kind', 'lane', 'index', 'mac'} and item['kind'] == 'link' and
                item['lane'] == lane and type(item['index']) is int and item['index'] > 0 and
                item['mac'] == f'52540012341{lane}' for lane, item in enumerate(links)) and
            links[0]['index'] != links[1]['index'], 'two distinct actual ingress interfaces')
    indices = [item['index'] for item in links]
    at, observations = 3, []
    for lane in range(2):
        for case in range(78):
            value = expected(lane, case)
            for phase in range(3):
                if phase == 2:
                    row = rows[at]
                    require(set(row) == {'kind', 'lane', 'case', 'transport', 'scenario', 'prepared', 'index',
                            'result', 'flags', 'control_length', 'control_hex', 'payload'} and
                            row['kind'] == 'receive-wire' and row['lane'] == lane and row['case'] == case and
                            all(row[key] == value[key] for key in ('transport', 'scenario', 'prepared')) and
                            row['index'] == indices[lane] and row['result'] == (44 if value['transport'] else 16) and
                            row['flags'] == 0 and row['control_length'] == 80 and
                            bytes.fromhex(row['control_hex']) == controls(value, indices[lane]) and
                            bytes.fromhex(row['payload']) == value['body'],
                            f'original receive metadata lane={lane} case={case}')
                    observations.append(row)
                    at += 1
                if value['scenario'] in (7, 8, 10, 11, 12):
                    messages = []
                    while at < len(rows) and rows[at]['kind'] == 'inventory':
                        messages.append(rows[at])
                        at += 1
                    require(at < len(rows) and rows[at]['kind'] == 'state' and messages,
                            'original transition inventory followed by state')
                    require((rows[at]['lane'], rows[at]['case'], rows[at]['phase']) == (lane, case, phase),
                            'arrival, mutation and restoration order around receive')
                    state(rows[at], messages, indices)
                    at += 1
    require(at == len(rows), 'no extra metadata or transition observations')
    return dict(identity=identity, indices=indices, observations=observations, states=180)
