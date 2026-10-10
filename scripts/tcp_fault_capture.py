# SPDX-License-Identifier: GPL-3.0-or-later
"""Check actual loss captures independently of the endpoint's packet/state code."""
from collections import Counter
import hashlib
import itertools
import json
from pathlib import Path
import struct
from tcp_capture import checksum

BYTES = 65536
MASK = (1 << 32) - 1


def require(value, reason):
    if not value:
        raise ValueError(reason)


def decode(frame, lane):
    if len(frame) < 34 or frame[12:14] != b'\x08\x00' or frame[23] != 6:
        return None
    ip = frame[14:]
    header, total = (ip[0] & 15) * 4, int.from_bytes(ip[2:4], 'big')
    require(ip[0] >> 4 == 4 and header >= 20 and header + 20 <= total <= len(ip) and
            not checksum(ip[:header]) and not int.from_bytes(ip[6:8], 'big') & 0x3fff,
            'invalid independent IPv4 checksum/length/fragmentation')
    guest, peer = bytes([10, 23, lane + 1, 2]), bytes([10, 23, lane + 1, 1])
    require({ip[12:16], ip[16:20]} == {guest, peer}, 'independent capture TCP address tuple')
    tcp = ip[header:total]
    source, target, seq, ack, bits, window, _, urgent = struct.unpack_from('!HHIIHHHH', tcp)
    length = (bits >> 12) * 4
    require(20 <= length <= len(tcp) and not bits & 0x0e00 and not urgent and
            not checksum(ip[12:20] + struct.pack('!BBH', 0, 6, len(tcp)) + tcp),
            'invalid independent TCP checksum/header')
    at = 20
    while at < length:
        kind = tcp[at]
        if kind == 0:
            break
        if kind == 1:
            at += 1
            continue
        require(at + 2 <= length and tcp[at + 1] >= 2 and at + tcp[at + 1] <= length,
                'invalid independent TCP options')
        at += tcp[at + 1]
    outgoing = ip[12:16] == guest
    remote = target if outgoing else source
    require(remote in (44000 + lane, 45000 + lane), 'independent TCP role port')
    return dict(outgoing=outgoing, role=int(remote == 45000 + lane), seq=seq, ack=ack,
                flags=bits & 0x1ff, window=window, data=tcp[length:], frame=frame)


def packets(path, lane):
    data = path.read_bytes()
    require(len(data) >= 24 and data[:4] in (bytes.fromhex('d4c3b2a1'), bytes.fromhex('a1b2c3d4')),
            'independent PCAP magic')
    endian = '<' if data[:4] == bytes.fromhex('d4c3b2a1') else '>'
    major, minor, _, _, snap, link = struct.unpack_from(endian + 'HHIIII', data, 4)
    require((major, minor, link) == (2, 4, 1) and snap >= 1514, 'independent PCAP format')
    offset, rows = 24, []
    while offset < len(data):
        require(offset + 16 <= len(data), 'independent PCAP record header')
        seconds, micros, size, original = struct.unpack_from(endian + 'IIII', data, offset)
        offset += 16
        require(micros < 1000000 and size == original and 14 <= size <= snap and offset + size <= len(data),
                'independent PCAP packet bounds')
        row = decode(data[offset:offset + size], lane)
        offset += size
        if row is not None:
            row['ms'] = seconds * 1000 + micros / 1000
            rows.append(row)
    require(rows, 'independent PCAP contains actual TCP')
    return rows


def stream(rows, origin, lane, role, direction):
    values, present = bytearray(BYTES), bytearray(BYTES)
    for row in rows:
        offset = (row['seq'] - origin) & MASK
        if not row['data']:
            continue
        require(offset + len(row['data']) <= BYTES, 'independent captured payload sequence bounds')
        for index, value in enumerate(row['data'], offset):
            expected = ((index * 29) ^ (index >> 7) ^ (lane * 53) ^ (role * 97) ^ (direction * 41)) & 255
            require(value == expected and (not present[index] or values[index] == value),
                    'independent captured payload bytes and duplicate consistency')
            values[index], present[index] = value, 1
    require(all(present), 'independent captured stream has every required byte')
    return hashlib.sha256(values).hexdigest()


def verify(path, lane, peer_rows, native=False):
    rows = packets(path, lane)
    require(peer_rows['lane'] == lane, 'independent peer lane identity')
    actual, reported, records = Counter(row['frame'] for row in rows), Counter(), []
    for record in peer_rows['frames']:
        row = decode(bytes.fromhex(record['frame']), lane)
        if row is not None:
            require(record['direction'] in ('send', 'receive') and
                    row['outgoing'] == (record['direction'] == 'receive'), 'independent peer direction')
            reported[row['frame']] += 1
            records.append((record, row))
    require(actual == reported, 'independent capture matches every actual peer/guest TCP frame')
    results = []
    for role in range(2):
        flow = [row for row in rows if row['role'] == role]
        guest, peer = ([row for row in flow if row['outgoing']], [row for row in flow if not row['outgoing']])
        require(guest and peer and not any(row['flags'] & 4 for row in flow), 'independent loss stream has no resets')
        syns = [row for row in guest if row['flags'] & 2]
        peer_syns = [row for row in peer if row['flags'] & 2]
        require(len(syns) >= 2 and len(peer_syns) >= 1 and
                all(row['seq'] == syns[0]['seq'] and bool(row['flags'] & 16) == bool(role) for row in syns),
                'independent actual handshake retransmission')
        guest_origin, peer_origin = (syns[0]['seq'] + 1) & MASK, (peer_syns[0]['seq'] + 1) & MASK
        require(peer_origin >= MASK - BYTES, 'independent peer sequence actually crosses wrap')
        guest_hash = stream(guest, guest_origin, lane, role, 0)
        peer_hash = stream(peer, peer_origin, lane, role, 1)
        drops = [(record, row) for record, row in records if row['role'] == role and 'drop' in record]
        require(len(drops) == 3 and {record['drop'] for record, _ in drops} == {'handshake', 'data', 'fin'},
                'independent recorded three actual loss injections')
        retries = {}
        for record, dropped in drops:
            same = [(entry, row) for entry, row in records if row['outgoing'] and row['role'] == role and
                    row['seq'] == dropped['seq'] and row['data'] == dropped['data'] and
                    (row['flags'] & 3) == (dropped['flags'] & 3)]
            require(len(same) >= 2 and same[0][0] is record, 'independent lost sequence/bytes were retransmitted')
            elapsed = same[1][0]['ms'] - record['ms']
            minimum = (180 if native else 850) if record['drop'] == 'fin' else (2850 if record['drop'] == 'data' else 850)
            require(elapsed >= minimum, 'independent retry elapsed clock')
            # PCAP and endpoint monotonic clocks must establish the same real wait.
            captured = [row for row in guest if row['seq'] == dropped['seq'] and
                        row['data'] == dropped['data'] and (row['flags'] & 3) == (dropped['flags'] & 3)]
            require(len(captured) >= 2 and captured[1]['ms'] - captured[0]['ms'] >= minimum - 5,
                    'independent capture confirms elapsed retry')
            occurrences = [index for index, row in enumerate(flow) if row is captured[0] or row is captured[1]]
            require(len(occurrences) == 2, 'independent loss/retry capture ordering')
            end = (dropped['seq'] + len(dropped['data']) + int(bool(dropped['flags'] & 3))) & MASK
            require(not any(not row['outgoing'] and row['flags'] & 16 and
                            ((row['ack'] - end) & MASK) < (1 << 31)
                            for row in flow[occurrences[0] + 1:occurrences[1]]),
                    'discarded guest sequence remains unacknowledged until its actual retry')
            retries[record['drop']] = round(elapsed, 3)
        for outgoing, origin, opposite in ((guest, guest_origin, peer), (peer, peer_origin, guest)):
            finishes = [row for row in outgoing if row['flags'] & 1]
            require(finishes and all((row['seq'] + len(row['data'])) & MASK == (origin + BYTES) & MASK
                                     for row in finishes), 'independent FIN follows complete stream')
            require(any(row['flags'] & 16 and row['ack'] == (origin + BYTES + 1) & MASK for row in opposite),
                    'independent final FIN acknowledgment')
        results.append(dict(role=role, bytes_each=BYTES, guest_sha256=guest_hash, peer_sha256=peer_hash,
                            sequence_wrap=True, retries_ms=retries, passed=True))
    return dict(file=path.name, lane=lane, sha256=hashlib.sha256(path.read_bytes()).hexdigest(),
                packets=len(rows), flows=results, passed=True)


def check_results(directory):
    count = 0
    for name in ('tcp-fault-native-results.json', 'tcp-fault-results.json'):
        path = directory / name
        require(path.exists(), 'both full native and VM controlled TCP result reports exist')
        rows = json.loads(path.read_text())
        if name == 'tcp-fault-native-results.json':
            require(len(rows) == 3 and {row['linkage'] for row in rows} == {'native', 'static', 'dynamic'},
                    'all three native controlled TCP profiles')
        else:
            expected = set(itertools.product(('static', 'dynamic'), ('bios', 'uefi'), ('modern', 'legacy')))
            require(len(rows) == 8 and {(row['linkage'], row['firmware'], row['transport']) for row in rows} == expected,
                    'all eight controlled TCP VM profiles')
        for row in rows:
            require(row['passed'] and not row['error'] and not row['missing'], 'successful controlled TCP result')
            require(Path(row['peer']).name == row['peer'], 'bounded peer evidence path')
            peers = json.loads((directory / row['peer']).read_text())
            require(len(peers) == len(row['captures']) == 2, 'both controlled TCP adapters captured')
            row['verified_captures'] = []
            for lane, capture in enumerate(row['captures']):
                require(Path(capture).name == capture, 'bounded independent PCAP path')
                row['verified_captures'].append(verify(directory / capture, lane, peers[lane],
                                                     native=name == 'tcp-fault-native-results.json'))
                count += 1
        path.write_text(json.dumps(rows, indent=2) + '\n')
    require(count == 22, 'all twenty-two controlled TCP captures exist')
    return count


if __name__ == '__main__':
    directory = Path(__file__).resolve().parents[1] / 'build'
    print(f'TCP_FAULT_CAPTURE_PASS captures={check_results(directory)}')
