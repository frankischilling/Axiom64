# SPDX-License-Identifier: GPL-3.0-or-later
"""Reconstruct actual download bytes without using the endpoint implementation."""
from collections import Counter
import hashlib
import re
import struct

from random_crypto.wire import records, server_hello
from tcp_fault_capture import packets, require

# Independent contract values, rather than importing the fixture's generator.
PAYLOAD_BYTES = 1048593
PAYLOAD_SHA256 = 'ddc5d5de950305dda5a92c2d856751082987b22c05e539a3dad35a85b26c8982'
NAMES = ('http', 'tls12', 'tls13', 'hostname', 'untrusted', 'expired', 'future')
HTTP_PATHS = Counter({'/fixed': 2, '/chunked': 1, '/redirect': 1, '/truncated': 1,
                      '/range': 1, '/missing': 1, '/stall': 1, '/small': 1})


def stream(rows, outgoing):
    selected = [row for row in rows if row['outgoing'] == outgoing]
    origins = {(row['seq']+1) & 0xffffffff for row in selected if row['flags'] & 2}
    require(len(origins) == 1, 'one actual TCP handshake origin in each direction')
    origin = origins.pop()
    pieces = [((row['seq']-origin) & 0xffffffff, row['data']) for row in selected if row['data']]
    if not pieces:
        return b''
    length = max(offset+len(data) for offset, data in pieces)
    require(length <= 3*1024*1024, 'bounded captured download TCP stream')
    value, present = bytearray(length), bytearray(length)
    for offset, data in pieces:
        end = offset+len(data)
        if any(present[offset:end]):
            require(all(not present[at] or value[at] == byte
                        for at, byte in enumerate(data, offset)), 'identical overlapping TCP retransmissions')
        value[offset:end] = data
        present[offset:end] = b'\1'*len(data)
    require(all(present), 'actual capture includes every TCP data byte')
    return bytes(value)


def chunked(data):
    value = bytearray()
    while True:
        header, data = data.split(b'\r\n', 1)
        require(re.fullmatch(b'[0-9a-f]+', header), 'actual hexadecimal chunk length')
        length = int(header, 16)
        if not length:
            require(data == b'X-Axiom64-Trailer: complete\r\n\r\n', 'complete final chunk and actual trailer')
            return bytes(value)
        require(length == min(8191, PAYLOAD_BYTES-len(value)), 'actual fixture chunk boundaries')
        require(len(data) >= length+2 and data[length:length+2] == b'\r\n', 'complete framed HTTP chunk')
        value.extend(data[:length])
        data = data[length+2:]


def http(groups, peer):
    actual_requests, observations, targets = [], [], []
    partial, resumed = None, None
    for group in groups:
        request, reply = stream(group, True), stream(group, False)
        actual_requests.append(request.hex())
        first = request.split(b'\r\n', 1)[0]
        require(re.fullmatch(b'GET /[a-z]+ HTTP/1.1', first), 'actual HTTP method, path and version')
        require(request.endswith(b'\r\n\r\n'), 'complete captured HTTP request headers')
        target = first.split()[1].decode()
        targets.append(target)
        observers = [row for row in peer['requests'] if row['request'] == request.hex()]
        require(len(observers) == (2 if target == '/fixed' else 1), 'actual native request inventory')
        if target == '/stall':
            require(reply == b'', 'deadline peer sent no HTTP response')
            finishes = [row['ms'] for row in group if row['outgoing'] and row['flags'] & (1|4)]
            starts = [row['ms'] for row in group if row['outgoing'] and row['data']]
            require(finishes and starts and 1950 <= min(finishes)-min(starts) <= 5000,
                    'independent capture confirms the actual two-second client deadline')
            observations.append(dict(path=target, response_bytes=0, deadline_ms=min(finishes)-min(starts)))
            continue
        header, body = reply.split(b'\r\n\r\n', 1)
        lines = header.split(b'\r\n')
        require(re.fullmatch(b'HTTP/1.1 [0-9]{3} [A-Za-z ]+', lines[0]), 'actual response status line')
        status = int(lines[0].split()[1])
        fields = {}
        for line in lines[1:]:
            name, value = line.split(b':', 1)
            require(name.lower() not in fields, 'no repeated HTTP response field')
            fields[name.lower()] = value.strip()
        require(fields[b'connection'] == b'close', 'actual fixture connection close')
        require(status == {'/redirect': 302, '/missing': 404, '/range': 206}.get(target, 200),
                'actual captured response status')
        body_hash = hashlib.sha256(body).hexdigest()
        require(all(row['sent'] and row['response_header'] == (header+b'\r\n\r\n').hex() and
                    row['body_bytes'] == len(body) and row['body_sha256'] == body_hash for row in observers),
                'actual native response inventory matches captured header and every body byte')
        if target == '/chunked':
            require(fields.get(b'transfer-encoding') == b'chunked' and b'content-length' not in fields,
                    'actual chunked framing is unambiguous')
            decoded = chunked(body)
        else:
            require(b'transfer-encoding' not in fields, 'actual fixed-length framing is unambiguous')
            require(int(fields[b'content-length']) == (PAYLOAD_BYTES if target == '/truncated' else len(body)),
                    'actual declared fixed response length')
            decoded = body
        if target in ('/fixed', '/chunked'):
            require(len(decoded) == PAYLOAD_BYTES and hashlib.sha256(decoded).hexdigest() == PAYLOAD_SHA256,
                    'independent complete HTTP binary payload')
        elif target == '/redirect':
            require(decoded == b'' and fields.get(b'location') == b'/fixed', 'actual redirect target and empty body')
        elif target == '/truncated':
            require(len(body) == PAYLOAD_BYTES//2, 'actual incomplete transfer ends halfway')
            partial = body
        elif target == '/range':
            require(b'\r\nRange: bytes='+str(PAYLOAD_BYTES//2).encode()+b'-\r\n' in request,
                    'actual resumed request starts at the retained partial boundary')
            require(fields[b'content-range'] == f'bytes {PAYLOAD_BYTES//2}-{PAYLOAD_BYTES-1}/{PAYLOAD_BYTES}'.encode(),
                    'actual returned content range')
            resumed = body
        elif target == '/missing':
            require(body == b'fixture does not exist\n', 'actual HTTP failure body')
        elif target == '/small':
            require(body == b'Axiom64 output permission fixture\n', 'actual permission-control transfer bytes')
        else:
            raise ValueError('unexpected actual download path: '+target)
        observations.append(dict(path=target, status=status, response_bytes=len(body), body_sha256=body_hash))
    require(Counter(targets) == HTTP_PATHS, 'all nine required plain HTTP exchanges')
    require(Counter(actual_requests) == Counter(row['request'] for row in peer['requests']),
            'every actual HTTP request matches the independent native observer inventory')
    require(partial is not None and resumed is not None and len(partial+resumed) == PAYLOAD_BYTES and
            hashlib.sha256(partial+resumed).hexdigest() == PAYLOAD_SHA256,
            'actual captured partial and resumed bytes form the complete payload')
    return observations


def verify(capture, lane, peers):
    """Check a full adapter capture and its separately observed native exchanges."""
    require(set(peers) == set(NAMES), 'all seven required independent download peers')
    ports = tuple(peers[name]['port'] for name in NAMES)
    require(len(set(ports)) == len(ports) and all(type(port) is int and 0 < port < 65536 for port in ports),
            'unique actual endpoint ports')
    for name, peer in peers.items():
        require(peer['name'] == name and peer['closed'] and not peer['errors'] and
                peer['payload_bytes'] == PAYLOAD_BYTES and peer['payload_sha256'] == PAYLOAD_SHA256,
                'complete native peer with the fixed independent payload contract')
    rows = packets(capture, lane, ports)
    groups = {}
    for row in rows:
        frame = row['frame']
        at = 14+(frame[14] & 15)*4
        source, target = struct.unpack_from('!HH', frame, at)
        guest_port = source if row['outgoing'] else target
        groups.setdefault((NAMES[row['role']], guest_port), []).append(row)
    require(len(groups) == 15, 'nine plain HTTP and six independent TLS TCP connections')
    plain = [group for (name, _), group in groups.items() if name == 'http']
    plain_results = http(plain, peers['http'])
    tls = []
    for name in NAMES[1:]:
        selected = [group for (label, _), group in groups.items() if label == name]
        require(len(selected) == 1, 'one actual TLS TCP connection per certificate case')
        client, server = stream(selected[0], True), stream(selected[0], False)
        sent, received = records(client), records(server)
        require(sent and sent[0][0] == 22 and sent[0][1][0] == 1, 'actual captured TLS ClientHello')
        cipher, version = server_hello(received)
        require((version is None and cipher == 0xc030) if name == 'tls12' else
                (version == b'\x03\x04' and cipher in (0x1301, 0x1302, 0x1303)),
                'actual negotiated TLS version and permitted cipher')
        require(b'GET /fixed HTTP/1.1' not in client+server, 'HTTP request is encrypted on actual TLS wire')
        peer = peers[name]
        if name in ('tls12', 'tls13'):
            require(any(kind == 23 for kind, _ in sent) and any(kind == 23 for kind, _ in received),
                    'actual encrypted records in both directions')
            require(len(peer['requests']) == 1 and peer['requests'][0]['target'] == '/fixed' and
                    peer['requests'][0]['sent'] and peer['requests'][0]['body_bytes'] == PAYLOAD_BYTES and
                    peer['requests'][0]['body_sha256'] == PAYLOAD_SHA256 and
                    peer['requests'][0]['tls_version'] == ('TLSv1.2' if name == 'tls12' else 'TLSv1.3') and
                    not peer['rejected_handshakes'] and not peer['rejected_after_handshake'],
                    'actual TLS application exchange observed at the native endpoint')
        else:
            require(not peer['requests'] and len(peer['rejected_handshakes'])+len(peer['rejected_after_handshake']) == 1,
                    'rejected certificate received no application request')
            require(all(row['application_bytes'] == 0 for row in peer['rejected_after_handshake']),
                    'post-handshake rejection has no partial application request')
        tls.append(dict(name=name, cipher=cipher, selected_version=version.hex() if version else '0303',
            client_stream_sha256=hashlib.sha256(client).hexdigest(),
            server_stream_sha256=hashlib.sha256(server).hexdigest()))
    return dict(passed=True, lane=lane, capture_sha256=hashlib.sha256(capture.read_bytes()).hexdigest(),
                tcp_flows=len(groups), http=plain_results, tls=tls)
