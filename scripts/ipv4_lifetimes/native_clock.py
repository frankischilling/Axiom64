# SPDX-License-Identifier: GPL-3.0-or-later
"""Relate Linux's jiffies-based address stamps to unmodified monotonic observations."""
from pathlib import Path
import socket
import struct
import time

from ipv4_lifetimes.reader import CLOCK_BOUND_NS, INFINITE, attributes, decode, messages, require


def clocks():
    return dict(monotonic_ns=time.monotonic_ns(), realtime_ns=time.time_ns())


def capture(index, number):
    require(number in (0, 1), 'one independent stamp anchor before and after the client')
    address = 0xc00002f1 + number
    events = []
    with socket.socket(socket.AF_NETLINK, socket.SOCK_RAW, 0) as channel:
        channel.bind((0, 0))
        channel.settimeout(5)
        port = channel.getsockname()[0]

        def send(data):
            before = clocks()
            require(channel.sendto(data, (0, 0)) == len(data), 'complete independent stamp-anchor request')
            events.append(dict(direction='request', before=before, after=clocks(), bytes=data.hex()))

        def receive():
            before = clocks()
            data, sender = channel.recvfrom(16384)
            after = clocks()
            require(sender == (0, 0), 'independent stamp reply comes from the kernel')
            events.append(dict(direction='reply', before=before, after=after, bytes=data.hex()))
            return messages(data)

        fields = b''.join(struct.pack('<HH', 8, kind) + struct.pack('>I', address) for kind in (1, 2))
        send(struct.pack('<IHHII', 40, 20, 0x605, 1, 0) + struct.pack('<BBBBI', 2, 32, 0, 0, index) + fields)
        acknowledgement = receive()
        require(len(acknowledgement) == 1 and acknowledgement[0]['kind'] == 2 and
                struct.unpack_from('<i', acknowledgement[0]['body'])[0] == 0, 'independent permanent anchor inserted')
        send(struct.pack('<IHHII', 24, 22, 0x301, 2, 0) + b'\2' + bytes(7))
        done = False
        while not done:
            done = any(message['kind'] == 3 for message in receive())
    return dict(number=number, index=index, port=port, events=events)


def verify(path, client_log):
    anchors = decode(Path(path).read_text())
    require(type(anchors) is list and len(anchors) == 2, 'both original independent stamp anchors')
    ranges, offsets = [], []
    previous = 0
    for number, anchor in enumerate(anchors):
        require(set(anchor) == {'number', 'index', 'port', 'events'} and anchor['number'] == number and
                type(anchor['index']) is int and anchor['index'] > 0 and
                type(anchor['port']) is int and anchor['port'] > 0, 'actual independent stamp anchor identity')
        address = 0xc00002f1 + number
        events = anchor['events']
        require(len(events) >= 4 and [event['direction'] for event in events[:3]] == ['request', 'reply', 'request'] and
                all(event['direction'] == 'reply' for event in events[3:]), 'complete original anchor exchange order')
        for event in events:
            require(set(event) == {'direction', 'before', 'after', 'bytes'}, 'complete anchor clock and raw-byte record')
            for clock in ('monotonic_ns', 'realtime_ns'):
                before, after = event['before'][clock], event['after'][clock]
                require(type(before) is int and type(after) is int and 0 <= before <= after < 1 << 63 and
                        after - before <= CLOCK_BOUND_NS, 'bounded original anchor clock bracket')
            require(event['before']['monotonic_ns'] >= previous, 'ordered original anchor observations')
            previous = event['after']['monotonic_ns']
            offsets += [event[key]['realtime_ns'] - event[key]['monotonic_ns'] for key in ('before', 'after')]
        original = struct.pack('<IHHII', 40, 20, 0x605, 1, 0) + struct.pack('<BBBBI', 2, 32, 0, 0, anchor['index'])
        original += b''.join(struct.pack('<HH', 8, kind) + struct.pack('>I', address) for kind in (1, 2))
        require(bytes.fromhex(events[0]['bytes']) == original and
                bytes.fromhex(events[2]['bytes']) == struct.pack('<IHHII', 24, 22, 0x301, 2, 0) + b'\2' + bytes(7),
                'independent anchor requests never supply caller creation or update stamps')
        ack = messages(bytes.fromhex(events[1]['bytes']))
        require(len(ack) == 1 and ack[0]['kind'] == 2 and ack[0]['sequence'] == 1 and
                ack[0]['port'] == anchor['port'] and ack[0]['body'][:4] == bytes(4) and
                ack[0]['body'][4:20] == original[:16], 'complete matching anchor acknowledgement')
        replies = [message for event in events[3:] for message in messages(bytes.fromhex(event['bytes']))]
        cache = []
        for message in replies:
            require(message['sequence'] == 2 and message['port'] == anchor['port'] and
                    message['kind'] in (20, 3) and message['flags'] & 2 and not message['flags'] & 0x10,
                    'actual uninterrupted matching anchor inventory')
            if message['kind'] == 20:
                require(len(message['body']) >= 8, 'complete anchor inventory address header')
                fields = attributes(message['body'][8:])
                if fields.get(2) == struct.pack('>I', address):
                    require(struct.unpack_from('<BBBBI', message['body']) == (2, 32, 128, 0, anchor['index']) and
                            fields.get(1) == fields[2] and len(fields.get(6, b'')) == 16,
                            'actual independent permanent address and complete cache fields')
                    cache.append(struct.unpack('<IIII', fields[6]))
        require(replies[-1]['kind'] == 3 and replies[-1]['body'] == bytes(4) and
                sum(message['kind'] == 3 for message in replies) == 1 and len(cache) == 1 and
                cache[0][:2] == (INFINITE, INFINITE) and cache[0][2] == cache[0][3],
                'one kernel-owned permanent anchor stamp and successful dump completion')
        lower = events[0]['before']['monotonic_ns'] // 10_000_000
        upper = events[-1]['after']['monotonic_ns'] // 10_000_000
        signed = lambda value: ((cache[0][2] - value + (1 << 31)) & INFINITE) - (1 << 31)
        ranges.append((signed(upper), signed(lower)))
    require(anchors[0]['index'] == anchors[1]['index'], 'same independent anchor interface throughout the client')
    client = [decode(line.partition(' ')[2]) for line in Path(client_log).read_text().splitlines()
              if line.startswith('IPV4_LIFETIME_RECORD ')]
    require(client and anchors[0]['events'][-1]['after']['monotonic_ns'] <= client[0]['monotonic_before_ns'] and
            client[-1]['monotonic_after_ns'] <= anchors[1]['events'][0]['before']['monotonic_ns'],
            'actual independent anchors bracket the complete client observations')
    for value in client:
        offsets += [value['realtime' + suffix] - value['monotonic' + suffix]
                    for suffix in ('_before_ns', '_after_ns')]
    require(max(offsets) - min(offsets) <= CLOCK_BOUND_NS, 'unmodified native clocks remain stable across anchors and client')
    lower, upper = min(value[0] for value in ranges), max(value[1] for value in ranges)
    require(upper - lower <= 3, 'independent jiffies-to-monotonic stamp relation remains within three centiseconds')
    return lower, upper
