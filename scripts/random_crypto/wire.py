# SPDX-License-Identifier: GPL-3.0-or-later
"""Check encrypted records and negotiated TLS versions in complete TCP captures."""
import hashlib
import struct

from random_crypto.peer import PAYLOAD
from tcp_fault_capture import packets, require


def stream(rows, outgoing):
    direction = [row for row in rows if row['outgoing'] == outgoing]
    origins = {row['seq'] for row in direction if row['flags'] & 2}
    require(len(origins) == 1, 'one captured TLS TCP SYN origin per direction')
    origin = (origins.pop()+1) & 0xffffffff
    values = {}
    for row in direction:
        offset = (row['seq']-origin) & 0xffffffff
        if not row['data']:
            continue
        require(offset + len(row['data']) <= 2*1024*1024, 'bounded captured TLS stream')
        for at, value in enumerate(row['data'], offset):
            require(at not in values or values[at] == value, 'identical TLS TCP retransmission')
            values[at] = value
    require(values and len(values) == max(values)+1, 'complete captured TLS TCP bytes')
    return bytes(values[at] for at in range(len(values)))


def records(data):
    values, offset = [], 0
    while offset < len(data):
        require(offset+5 <= len(data), 'complete TLS record header')
        kind, version, length = struct.unpack_from('!BHH', data, offset)
        offset += 5
        require(kind in (20, 21, 22, 23) and version in (0x301, 0x303) and
                0 < length <= 18432 and offset+length <= len(data), 'bounded TLS record')
        values.append((kind, data[offset:offset+length]))
        offset += length
    return values


def server_hello(values):
    handshakes = b''.join(body for kind, body in values if kind == 22)
    require(len(handshakes) >= 42 and handshakes[0] == 2, 'actual TLS ServerHello')
    length = int.from_bytes(handshakes[1:4], 'big')
    require(38 <= length <= len(handshakes)-4, 'complete TLS ServerHello length')
    body = handshakes[4:4+length]
    require(body[:2] == b'\x03\x03', 'TLS ServerHello legacy version')
    at = 35+body[34]
    require(at+5 <= len(body), 'bounded TLS session ID and cipher')
    cipher = int.from_bytes(body[at:at+2], 'big')
    require(body[at+2] == 0, 'TLS null compression')
    at += 3
    end = at+2+int.from_bytes(body[at:at+2], 'big')
    at += 2
    require(end == len(body), 'TLS ServerHello extension length')
    extensions = {}
    while at < end:
        require(at+4 <= end, 'TLS extension header')
        kind, size = struct.unpack_from('!HH', body, at)
        at += 4
        require(at+size <= end and kind not in extensions, 'TLS extension bounds and uniqueness')
        extensions[kind] = body[at:at+size]
        at += size
    return cipher, extensions.get(43)


def verify(capture, peers):
    rows = packets(capture, 0, tuple(peer['port'] for peer in peers))
    result = []
    for role, peer in enumerate(peers):
        selected = [row for row in rows if row['role'] == role]
        require(selected, 'captured TLS flow for every native peer')
        client, server = stream(selected, True), stream(selected, False)
        require(PAYLOAD not in client+server and
                ('AXIOM64_TLS_PEER_PASS ' + peer['name']).encode() not in client+server,
                'known application bytes are encrypted on the wire')
        sent, received = records(client), records(server)
        require(sent[0][0] == 22 and sent[0][1][0] == 1, 'actual TLS ClientHello')
        cipher, version = server_hello(received)
        if peer['name'] == 'tls12':
            require(version is None and cipher == 0xc030, 'TLS 1.2 negotiated wire cipher')
        else:
            require(version == b'\x03\x04' and cipher == 0x1302, 'TLS 1.3 negotiated wire version/cipher')
        if peer['expected_success']:
            require(any(kind == 23 for kind, _ in sent) and any(kind == 23 for kind, _ in received),
                    'encrypted application records in both directions')
        result.append(dict(name=peer['name'], packets=len(selected), cipher=cipher,
                           selected_version=version.hex() if version else '0303',
                           client_records=len(sent), server_records=len(received),
                           client_stream_sha256=hashlib.sha256(client).hexdigest(),
                           server_stream_sha256=hashlib.sha256(server).hexdigest(), passed=True))
    return result
