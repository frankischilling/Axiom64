# SPDX-License-Identifier: GPL-3.0-or-later
"""Verify original Ethernet captures and physical arrival/queue barriers."""
import hashlib
import json
import struct

from ipv4_receive_wire_records import expected, require, unique


def checksum(data):
    padded = data + bytes(len(data) % 2)
    total = sum(int.from_bytes(padded[at:at + 2], 'big') for at in range(0, len(padded), 2))
    while total >> 16:
        total = (total & 65535) + (total >> 16)
    return (~total) & 65535


def pcap(data):
    require(len(data) >= 24, 'complete original PCAP header')
    formats = {b'\xd4\xc3\xb2\xa1': ('<', 1000), b'\x4d\x3c\xb2\xa1': ('<', 1),
               b'\xa1\xb2\xc3\xd4': ('>', 1000), b'\xa1\xb2\x3c\x4d': ('>', 1)}
    require(data[:4] in formats, 'known original PCAP precision')
    endian, scale = formats[data[:4]]
    major, minor, zone, accuracy, snap, link = struct.unpack_from(endian + 'HHIIII', data, 4)
    require((major, minor, zone, accuracy, link) == (2, 4, 0, 0, 1) and snap >= 1500,
            'original Ethernet PCAP format')
    frames, at = [], 24
    while at < len(data):
        require(len(data) - at >= 16, 'complete original PCAP packet header')
        seconds, fraction, captured, original = struct.unpack_from(endian + 'IIII', data, at)
        at += 16
        require(fraction < 1000000000 // scale and 14 <= captured == original <= snap and
                captured <= len(data) - at, 'complete original captured Ethernet packet')
        frames.append((seconds * 1000000000 + fraction * scale, data[at:at + captured]))
        at += captured
    require(frames and all(a[0] <= b[0] for a, b in zip(frames, frames[1:])),
            'ordered original packet timestamps')
    return frames


def payload(frame, lane, case):
    value = expected(lane, case)
    guest, peer = bytes.fromhex(f'52540012341{lane}'), bytes.fromhex(f'02415852580{lane}')
    destination = value['destination']
    mac = (b'\xff' * 6 if value['scenario'] in (3, 4, 5) else
           b'\x01\0\x5e' + (destination & 0x7fffff).to_bytes(3, 'big') if destination >> 28 == 14 else guest)
    require(len(frame) == 60 and frame[:14] == mac + peer + b'\x08\0', 'actual data Ethernet destination and source')
    header, segment = frame[14:34], frame[34:58]
    version, tos, size, identity, fragment, ttl, protocol, check, source, actual = struct.unpack('!BBHHHBBHII', header)
    require((version, tos, size, identity, fragment, ttl, protocol, source, actual) ==
            (0x45, value['tos'], 44, 0x4d00 + case, 0, value['ttl'], 1 if value['transport'] == 1 else 17,
             value['source'], destination) and checksum(header) == 0 and frame[58:] == bytes(2),
            'original checksummed IPv4 fields and actual packet-specific TTL/TOS')
    require(segment[8:] == value['body'], 'physical packet nonce and body')
    if protocol == 1:
        require(struct.unpack('!BBHHH', segment[:8])[:2] == (0, 0) and
                struct.unpack('!HH', segment[4:8]) == (0x4158, case) and checksum(segment) == 0,
                'original ICMP echo reply checksum and identity')
    else:
        require(struct.unpack('!HHH', segment[:6]) == (42000 + case, 46000 + case, 24) and
                segment[6:8] != bytes(2) and
                checksum(header[12:20] + b'\0\x11\0\x18' + segment) == 0,
                'original UDP ports, length and pseudo-header checksum')


def relevant(frame):
    return frame[12:14] == b'\x88\xb9' or (frame[12:14] == b'\x08\0' and len(frame) >= 58 and
            frame[42:50] == b'AXRXDATA')


def verify(directory, lane, native, statistics):
    frames = pcap((directory / f'lane{lane}.pcap').read_bytes())
    physical = [data for _, data in frames if relevant(data)]
    peers = json.loads((directory / f'lane{lane}-frames.json').read_text(), object_pairs_hook=unique)
    require(all(set(item) == {'monotonic_ns', 'direction', 'data'} and item['direction'] in ('guest', 'peer') and
                type(item['monotonic_ns']) is int and item['monotonic_ns'] > 0 for item in peers),
            'actual finite peer transport observations')
    require(all(a['monotonic_ns'] <= b['monotonic_ns'] for a, b in zip(peers, peers[1:])),
            'original ordered peer receipts')
    observed = [item for item in peers if relevant(bytes.fromhex(item['data']))]
    require([bytes.fromhex(item['data']) for item in observed] == physical and len(physical) == 78 * 7,
            'independent PCAP equals all actual barrier and packet transport observations')
    guest, peer = bytes.fromhex(f'52540012341{lane}'), bytes.fromhex(f'02415852580{lane}')
    for case in range(78):
        selected = physical[case * 7:(case + 1) * 7]
        payload(selected[1], lane, case)
        wanted = []
        directions = []
        for phase in 'BQD':
            wanted.append((peer + guest + b'\x88\xb9AXR' + phase.encode() + bytes((lane, case))).ljust(60, b'\0'))
            directions.append('guest')
            if phase == 'B':
                wanted.append(selected[1])
                directions.append('peer')
            wanted.append((guest + peer + b'\x88\xb9AXRA' + bytes((lane, case)) + phase.encode()).ljust(60, b'\0'))
            directions.append('peer')
        require(selected == wanted and [item['direction'] for item in observed[case * 7:(case + 1) * 7]] == directions,
                'physical begin/data/ack/queued/ack/completed/ack order')
        require(observed[case * 7 + 6]['monotonic_ns'] - observed[case * 7]['monotonic_ns'] < 180000000000,
                'finite original metadata exchange')
    if native:
        require(statistics['dropped'] == 0 and statistics['packets'] == statistics['receipt_frames'] == len(frames) and
                statistics['original_packet_times_not_rescaled'] is True,
                'complete native capture without dropped packets')
        receipts = [json.loads(line, object_pairs_hook=unique) for line in
                    (directory / f'lane{lane}.clocks.jsonl').read_text().splitlines()]
        require(len(receipts) == len(frames), 'one actual native kernel timestamp per captured frame')
        for number, (receipt, (timestamp, frame)) in enumerate(zip(receipts, frames)):
            require(receipt['frame'] == number and receipt['sha256'] == hashlib.sha256(frame).hexdigest() and
                    # Capture writes classic microsecond PCAP and retains the
                    # original nanoseconds separately. Check that exact encoding.
                    receipt['kernel_realtime_ns'] // 1000 * 1000 == timestamp and
                    receipt['receipt_monotonic_ns'] <= receipt['receipt_monotonic_after_ns'],
                    'original kernel clock receipt and captured frame binding')
    return dict(data_packets=78, physical_barriers=468, captured_frames=len(frames))
