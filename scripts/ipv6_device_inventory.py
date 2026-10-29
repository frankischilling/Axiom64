# SPDX-License-Identifier: GPL-3.0-or-later
"""Read original netlink replies and compare device state with measured Linux."""
import json
import re
import struct

def require(condition, message):
    if not condition:
        raise ValueError(message)

def attributes(data):
    at = 0
    result = []
    while at < len(data):
        require(at + 4 <= len(data), 'complete attribute header')
        length, kind = struct.unpack_from('<HH', data, at)
        require(4 <= length <= len(data) - at, 'bounded attribute payload')
        result.append((kind & 16383, data[at + 4:at + length]))
        at += length + 3 & ~3
    require(at == len(data), 'complete aligned attributes')
    return result

def generation(data):
    values = [value for kind, value in attributes(data) if kind == 8]
    require(len(values) <= 1 and all((len(value) == 1 for value in values)), 'one complete generation-mode byte')
    return values[0][0] if values else -1

def link(data):
    require(len(data) >= 16, 'complete link header')
    family, padding, kind, index, flags, change = struct.unpack_from('<BBHiII', data)
    require(padding == change == 0, 'zero link padding and change mask')
    mtu = 0
    mode = -1
    for kind, value in attributes(data[16:]):
        if kind == 4:
            require(len(value) == 4, 'complete MTU value')
            mtu = struct.unpack('<I', value)[0]
        elif kind == 12 and family == 10:
            mode = generation(value)
        elif kind == 26:
            for af, values in attributes(value):
                if af == 10:
                    mode = generation(values)
    return dict(index=index, flags=flags, mtu=mtu, mode_found=int(mode >= 0), mode=mode, reply_family=family)

def fields(line):
    result = {}
    for pair in line.split()[1:]:
        key, value = pair.split('=', 1)
        require(key not in result, 'unique observation fields')
        result[key] = value if key == 'action' else int(value, 16 if key == 'flags' else 10)
    return result

def parse(text):
    raw = {}
    states = []
    queries = []
    for line in text.splitlines():
        if line.startswith('LINK_RAW '):
            matched = re.fullmatch('LINK_RAW kind=(request|reply) sequence=(\\d+) datagram=(\\d+) bytes=(\\d+) hex=([0-9a-f]+)', line)
            require(matched, 'complete original raw-record framing')
            kind, sequence, datagram, size, encoded = matched.groups()
            data = bytes.fromhex(encoded)
            require(len(data) == int(size) <= 16384, 'bounded original raw-record bytes')
            row = raw.setdefault(int(sequence), dict(request=[], reply=[]))
            row[kind].append((int(datagram), data))
        elif line.startswith('LINK_STATE '):
            states.append(fields(line))
        elif line.startswith('LINK_QUERY '):
            queries.append(fields(line))
    require(len(states) == 12 and len(queries) == 48 and (set(raw) == set(range(1, 49))), 'all twelve states and forty-eight raw transactions')
    require(text.splitlines().count('LINK_STATE_COMPLETE observations=12 queries=48') == 1, 'one complete device client')
    expected_keys = [(action, lane, stage) for action in ('administrative', 'mtu') for lane in range(2) for stage in range(3)]
    require([(row['action'], row['lane'], row['stage']) for row in states] == expected_keys, 'ordered action, adapter and stage observations')
    indices = {}
    canonical = []
    for number, row in enumerate(queries, 1):
        require(row['sequence'] == number, 'serialized query retains its actual request sequence')
        state = states[(number - 1) // 4]
        key = tuple((state[name] for name in ('action', 'lane', 'stage')))
        require(all((row[name] == state[name] for name in ('action', 'lane', 'stage'))), 'queries identify their observed action, adapter and stage')
        require((row['family'], row['dump']) == ((0, 0), (0, 1), (10, 0), (10, 1))[(number - 1) % 4], 'all four ordered query forms')
        packets = raw[number]
        require(len(packets['request']) == 1 and packets['request'][0][0] == 0, 'one original request per transaction')
        request = packets['request'][0][1]
        require(len(request) == 32, 'complete original request')
        length, kind, flags, sequence, port = struct.unpack_from('<IHHII', request)
        require((length, kind, flags, sequence, port) == (32, 18, 1 | (768 if row['dump'] else 0), number, 0), 'original GETLINK type, flags, sequence and kernel destination')
        family, padding, kind, index, flags, change = struct.unpack_from('<BBHiII', request, 16)
        require((family, padding, kind, flags, change) == (row['family'], 0, 0, 0, 0), 'queried family and zero request filters')
        if not row['dump']:
            require(index > 0 and (key not in indices or indices[key] == index), 'stable direct-query interface identity')
            indices[key] = index
        else:
            require(index == 0 and key in indices, 'unfiltered dump following its direct interface query')
        target = indices[key]
        links = []
        error = 0
        done = 0
        ports = set()
        require([index for index, _ in packets['reply']] == list(range(len(packets['reply']))), 'complete ordered reply datagrams')
        for _, data in packets['reply']:
            at = 0
            while at < len(data):
                require(at + 16 <= len(data), 'complete reply header')
                length, kind, flags, sequence, port = struct.unpack_from('<IHHII', data, at)
                require(16 <= length <= len(data) - at and sequence == number and (port > 0) and (not flags & 16), 'bounded complete reply with matching sequence and no interrupted dump')
                ports.add(port)
                body = data[at + 16:at + length]
                if kind == 2:
                    require(len(body) >= 20 and (not error), 'one complete netlink error')
                    error = struct.unpack_from('<i', body)[0]
                    require(error < 0, 'negative netlink error')
                    require(body[4:20] == request[:16], 'error quotes its original request')
                elif kind == 3:
                    require(row['dump'] and len(body) >= 4 and (struct.unpack_from('<i', body)[0] == 0), 'successful complete dump terminator')
                    done += 1
                else:
                    require(kind == 16, 'link response message')
                    value = link(body)
                    require(value['reply_family'] == (10 if row['family'] == 10 and row['dump'] else 0), 'reply uses the selected family layout')
                    if value['index'] == target:
                        links.append(value)
                at += length + 3 & ~3
            require(at == len(data), 'complete aligned reply messages')
        require(len(ports) == 1 and len(links) <= 1, 'one destination port and at most one selected link')
        value = links[0] if links else dict(flags=0, mtu=0, mode_found=0, mode=-1, reply_family=None)
        actual = dict(error=error, found=len(links), done=done, datagrams=len(packets['reply']), **{name: value[name] for name in ('flags', 'mtu', 'mode_found', 'mode')})
        require(all((row[name] == value for name, value in actual.items())), 'serialized query equals every original raw reply field')
        canonical.append({**{name: row[name] for name in ('action', 'lane', 'stage', 'family', 'dump')}, **{name: value for name, value in actual.items() if name != 'datagrams'}, 'reply_family': value['reply_family']})
    for state in states:
        low = state['action'] == 'mtu' and state['stage'] == 1
        require(state['flags'] == (4098 if state['action'] == 'administrative' and state['stage'] == 1 else 4163), 'exact settled administrative and operational flags')
        require(state['mtu'] == (1279 if low else 1500) and state['proc'] == int(not low), 'actual MTU and IPv6 scope presence')
        require(state['mode'] == (-1 if low else 1 if state['action'] == 'mtu' and state['stage'] == 2 else 2), 'retained or inherited generation mode')
    return dict(states=states, queries=canonical, raw_transactions=48)

def observations(text, reference):
    require(reference['schema'] == 1, 'known measured device-inventory reference')
    expected = reference['observations']
    try:
        value = parse(text)
        require('LINK_STATE_FATAL' not in text, 'no failed device-inventory operation')
        actual = [json.dumps(dict(kind=kind, **row), sort_keys=True, separators=(',', ':')) for kind, rows in [('state', value['states']), ('query', value['queries'])] for row in rows]
        return dict(passed=actual == expected, observations=actual, expected_count=len(expected), complete=True, raw_transactions=value['raw_transactions'])
    except (ValueError, KeyError, IndexError, struct.error) as error:
        return dict(passed=False, observations=[], expected_count=len(expected), complete=False, error=str(error), raw_transactions=0)
