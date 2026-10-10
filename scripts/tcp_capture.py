# SPDX-License-Identifier: GPL-3.0-or-later
"""Independently validate captured TCP headers, sequence space and transfer bytes."""
import hashlib
import struct


BYTES = 262144


def payload(lane, phase):
    return bytes(((at * 37) ^ (at >> 8) ^ (phase * 73) ^ (lane * 11)) & 255 for at in range(BYTES))


def checksum(data):
    if len(data) & 1:
        data += b'\0'
    total = sum(struct.unpack(f'!{len(data) // 2}H', data))
    while total >> 16:
        total = (total & 65535) + (total >> 16)
    return (~total) & 65535


def verify(path, lane, host_port):
    data = path.read_bytes()
    if len(data) < 24 or data[:4] not in (b'\xd4\xc3\xb2\xa1', b'\xa1\xb2\xc3\xd4'):
        raise ValueError('invalid TCP capture header')
    endian = '<' if data[:4] == b'\xd4\xc3\xb2\xa1' else '>'
    major, minor, _, _, snap, link = struct.unpack_from(endian + 'HHIIII', data, 4)
    if (major, minor, link) != (2, 4, 1) or snap < 1514:
        raise ValueError('unsupported TCP capture format')
    guest, host = bytes([10, 23, lane + 1, 2]), bytes([10, 23, lane + 1, 1])
    flows, packets, offset = {}, 0, 24
    while offset < len(data):
        if offset + 16 > len(data):
            raise ValueError('truncated TCP capture record')
        _, _, size, original = struct.unpack_from(endian + 'IIII', data, offset)
        offset += 16
        if size != original or size > snap or size < 14 or offset + size > len(data):
            raise ValueError('truncated Ethernet capture')
        frame = data[offset:offset + size]
        offset += size
        if frame[12:14] != b'\x08\x00' or len(frame) < 34:
            continue
        ip = frame[14:]
        if ip[9] != 6:
            continue
        if {ip[12:16], ip[16:20]} != {guest, host}:
            raise ValueError('unexpected TCP IPv4 tuple')
        header, total = (ip[0] & 15) * 4, int.from_bytes(ip[2:4], 'big')
        if ip[0] >> 4 != 4 or header < 20 or total > len(ip) or total < header + 20 or checksum(ip[:header]):
            raise ValueError('invalid captured IPv4 header/checksum')
        if int.from_bytes(ip[6:8], 'big') & 0x3fff:
            raise ValueError('unexpected TCP fragmentation')
        tcp = ip[header:total]
        src, dst, sequence, acknowledgment, bits, window, _, urgent = struct.unpack_from('!HHIIHHHH', tcp)
        length, flags = (bits >> 12) * 4, bits & 0x1ff
        pseudo = ip[12:20] + struct.pack('!BBH', 0, 6, len(tcp))
        if length < 20 or length > len(tcp) or checksum(pseudo + tcp):
            raise ValueError('invalid captured TCP header/checksum')
        if bits & 0x0e00 or urgent:
            raise ValueError('unexpected reserved/urgent TCP fields')
        option, offered_mss = 20, None
        while option < length:
            kind = tcp[option]
            if not kind:
                break
            if kind == 1:
                option += 1
                continue
            if option + 2 > length or tcp[option + 1] < 2 or option + tcp[option + 1] > length:
                raise ValueError('invalid captured TCP option bounds')
            if kind == 2 and (tcp[option + 1] != 4 or not flags & 2):
                raise ValueError('invalid captured MSS option')
            if kind == 2:
                offered_mss = int.from_bytes(tcp[option + 2:option + 4], 'big')
            option += tcp[option + 1]
        outgoing = ip[12:16] == guest
        local_port, remote_port = (src, dst) if outgoing else (dst, src)
        role = 'client' if remote_port == host_port else 'server' if local_port == 41000 + lane else None
        if role is None:
            raise ValueError('unexpected captured TCP ports')
        flow = flows.setdefault((role, local_port, remote_port), [{}, {}])
        direction = flow[0 if outgoing else 1]
        if flags & 4:
            # The user-network bridge can answer later window-update ACKs after its
            # closed tuple has been removed. Accept only exact, incoming resets after
            # both FINs and their ACKs; a reset during transfer still fails acceptance.
            if outgoing or flags != 4 or tcp[length:] or window or any(
                    not item.get('finish') or 'initial' not in item or
                    (item['initial'] + BYTES + 2) & 0xffffffff not in flow[1 - at].get('acks', [])
                    for at, item in enumerate(flow)) or sequence != (direction['initial'] + BYTES + 2) & 0xffffffff:
                raise ValueError('unexpected captured TCP reset before complete acknowledged close')
            direction['post_close_resets'] = direction.get('post_close_resets', 0) + 1
            packets += 1
            continue
        if flags & 2:
            if not offered_mss:
                raise ValueError('wire acceptance requires an offered MSS')
            if 'initial' in direction and direction['initial'] != sequence:
                raise ValueError('TCP SYN retransmission changed its initial sequence')
            direction['initial'] = sequence
            direction['syn_ack'] = bool(flags & 16)
            direction['mss'] = offered_mss
            opposite = flow[1 if outgoing else 0]
            if flags & 16 and ('initial' not in opposite or acknowledgment != (opposite['initial'] + 1) & 0xffffffff):
                raise ValueError('TCP SYN-ACK acknowledged different sequence space')
        if 'initial' not in direction:
            raise ValueError('TCP data preceded a captured SYN')
        phase = (1 if outgoing else 2) if role == 'client' else (4 if outgoing else 3)
        direction.setdefault('phase', phase)
        direction.setdefault('bytes', bytearray(BYTES))
        direction.setdefault('seen', bytearray(BYTES))
        direction.setdefault('acks', []).append(acknowledgment if flags & 16 else None)
        body = tcp[length:]
        start = (sequence - direction['initial'] - (0 if flags & 2 else 1)) & 0xffffffff
        if body:
            if flags & 2 or start + len(body) > BYTES or len(body) > flow[1 if outgoing else 0].get('mss', 0):
                raise ValueError('TCP payload exceeded the expected sequence range')
            for at, byte in enumerate(body, start):
                if direction['seen'][at] and direction['bytes'][at] != byte:
                    raise ValueError('TCP retransmission changed payload bytes')
                direction['seen'][at] = 1
                direction['bytes'][at] = byte
        if flags & 1:
            if start + len(body) != BYTES:
                raise ValueError('TCP FIN preceded the complete transfer')
            direction['finish'] = True
        direction['last_window'] = window
        packets += 1
    if len(flows) != 2 or {key[0] for key in flows} != {'client', 'server'}:
        raise ValueError('capture lacks both native client/server transfers')
    evidence = []
    for (role, local, remote), directions in sorted(flows.items()):
        if directions[0]['syn_ack'] == directions[1]['syn_ack']:
            raise ValueError('capture lacks active/passive TCP handshake')
        for at, direction in enumerate(directions):
            opposite = directions[1 - at]
            if not all(direction['seen']) or bytes(direction['bytes']) != payload(lane, direction['phase']):
                raise ValueError('captured TCP sequence/payload differs from the independent expectation')
            if not direction.get('finish') or (direction['initial'] + BYTES + 2) & 0xffffffff not in opposite['acks']:
                raise ValueError('capture lacks acknowledged TCP half-close')
        evidence.append(dict(role=role, local_port=local, remote_port=remote,
                             outgoing_bytes=BYTES, incoming_bytes=BYTES,
                             post_close_resets=directions[1].get('post_close_resets', 0),
                             outgoing_sha256=hashlib.sha256(directions[0]['bytes']).hexdigest(),
                             incoming_sha256=hashlib.sha256(directions[1]['bytes']).hexdigest()))
    return dict(lane=lane, file=path.name, sha256=hashlib.sha256(data).hexdigest(),
                packets=packets, bytes=4 * BYTES, flows=evidence)
