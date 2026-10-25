# SPDX-License-Identifier: GPL-3.0-or-later
"""Independently prove DNS ownership, framing, clocks and close from raw PCAPs."""
import argparse
from collections import Counter
import hashlib
import json
from pathlib import Path
import re
import struct
from tcp_capture import checksum
from tcp_fault_capture import decode as decode_tcp, require, MASK
from dns_observer import link_receipts

FAILURES = ('wrong-id', 'wrong-name', 'wrong-type', 'wrong-class', 'query-bit',
            'opcode', 'short-prefix', 'short-body', 'short-frame', 'refused', 'connect-refused', 'compression-loop')
BASE = ('valid', 'large', 'split', 'wrong-id-valid', 'casefold', 'oversized-valid',
        'oversized-wrong-id-valid', 'questionless-negative', *FAILURES, 'silent')


def records(path):
    data = path.read_bytes()
    require(len(data) >= 24 and data[:4] in (bytes.fromhex('d4c3b2a1'), bytes.fromhex('a1b2c3d4')),
            'DNS capture magic')
    endian = '<' if data[:4] == bytes.fromhex('d4c3b2a1') else '>'
    major, minor, _, _, snap, link = struct.unpack_from(endian + 'HHIIII', data, 4)
    require((major, minor, link) == (2, 4, 1) and snap >= 1514, 'complete Ethernet PCAP format')
    rows, at = [], 24
    while at < len(data):
        require(at + 16 <= len(data), 'DNS capture record header')
        sec, usec, size, original = struct.unpack_from(endian + 'IIII', data, at)
        at += 16
        require(usec < 1000000 and size == original and 14 <= size <= snap and at + size <= len(data),
                'DNS capture record bounds')
        rows.append(dict(ms=sec * 1000 + usec / 1000, frame=data[at:at + size]))
        at += size
    require(rows and all(a['ms'] <= b['ms'] for a, b in zip(rows, rows[1:])), 'actual packet clock order')
    return rows


def decode(frame, lane):
    if frame[12:14] != b'\x08\x00':
        return None
    require(len(frame) >= 34, 'complete IPv4 header')
    ip = frame[14:]
    header, total = (ip[0] & 15) * 4, int.from_bytes(ip[2:4], 'big')
    require(ip[0] >> 4 == 4 and header >= 20 and header <= total <= len(ip) and
            checksum(ip[:header]) == 0 and not int.from_bytes(ip[6:8], 'big') & 0x3fff,
            'independent DNS IPv4 checksum, size and fragmentation')
    guest, peer = bytes([10, 23, lane + 1, 2]), bytes([10, 23, lane + 1, 1])
    require({ip[12:16], ip[16:20]} == {guest, peer}, 'configured selected nameserver address')
    outgoing = ip[12:16] == guest
    macs = (bytes([0x52, 0x54, 0, 0x12, 0x34, 0x10 + lane]), bytes([2, 0x41, 0x58, 0x44, 0x4e, lane]))
    require(frame[:12] == (macs[1] + macs[0] if outgoing else macs[0] + macs[1]),
            'selected adapter Ethernet address')
    if ip[9] == 6:
        row = decode_tcp(frame, lane, (53,))
        source, target = struct.unpack_from('!HH', ip, header)
        row.update(protocol='tcp', port=source if outgoing else target)
        return row
    require(ip[9] == 17 and header + 8 <= total, 'only complete UDP/TCP resolver packets')
    body = ip[header:total]
    source, target, length, value = struct.unpack_from('!HHHH', body)
    require(length == len(body) and value and
            checksum(ip[12:20] + struct.pack('!BBH', 0, 17, length) + body) == 0 and
            (target if outgoing else source) == 53 and (source if outgoing else target) != 0,
            'independent DNS UDP checksum, length and nameserver port')
    return dict(protocol='udp', outgoing=outgoing, port=source if outgoing else target,
                data=body[8:], frame=frame)


def question(query):
    require(len(query) >= 17 and query[2:12] == bytes.fromhex('01000001000000000000'),
            'one recursive query with no answer data')
    labels, at = [], 12
    while at < len(query) and query[at]:
        size = query[at]
        require(0 < size <= 63 and at + size + 1 < len(query), 'bounded independent query label')
        labels.append(query[at + 1:at + size + 1].decode('ascii'))
        at += size + 1
    require(query[at:] == b'\0\0\1\0\1' and labels, 'exact complete IN A question')
    name = '.'.join(labels)
    require(name.endswith('.tcp.fixture'), 'controlled absolute DNS name')
    return name.removesuffix('.tcp.fixture')


def expected_answer(query, case, lane):
    def body(kind):
        positive = kind in ('valid', 'large', 'split', 'selection', 'cycle-success', 'casefold', 'oversized-valid') or kind.startswith('parallel')
        base = 0x0a174001 + (lane << 8) if positive else 0x0a17ff01
        if kind.startswith('parallel'):
            base += int(kind[8:])
        if kind == 'cycle-success':
            base += 64
        count = 40 if kind in ('large', 'split', 'oversized-valid') else 1
        fields = bytearray(query[12:])
        ident = int.from_bytes(query[:2], 'big') ^ int(kind in ('wrong-id', 'wrong-id-valid', 'cycle-failure', 'oversized-wrong-id-valid'))
        flags = 0x8180
        if kind == 'wrong-name':
            fields[1] ^= 1
        if kind == 'wrong-type':
            fields[-3] = 28
        if kind == 'wrong-class':
            fields[-1] = 3
        if kind == 'query-bit':
            flags &= ~0x8000
        if kind == 'opcode':
            flags |= 0x0800
        if kind == 'refused':
            flags |= 5
        if kind == 'casefold':
            fields = fields.upper()
        if kind == 'compression-loop':
            fields = bytearray(b'\xc0\x0c\0\1\0\1')
        if kind == 'questionless-negative':
            return struct.pack('!6H', ident, 0x8183, 0, 0, 0, 0)
        result = struct.pack('!6H', ident, flags, 1, count, 0, 0) + fields + b''.join(
            b'\xc0\x0c' + struct.pack('!HHIH', 1, 1, 30, 4) + (base + i).to_bytes(4, 'big')
            for i in range(count))
        if kind.startswith('oversized'):
            result += bytes(4096 - len(result))
        return result
    answer = body(case)
    result = len(answer).to_bytes(2, 'big') + answer
    if case in ('wrong-id-valid', 'oversized-wrong-id-valid'):
        valid = body('valid')
        result += len(valid).to_bytes(2, 'big') + valid
    if case == 'short-prefix':
        result = result[:1]
    if case == 'short-body':
        result = result[:15]
    if case == 'short-frame':
        result = b'\0\x0c' + answer[:12]
    if case in ('silent', 'connect-refused'):
        result = b''
    return bytes(result)


def stream(rows, origin):
    values = {}
    for row in rows:
        offset = (row['seq'] - origin) & MASK
        if not row['data']:
            continue
        require(offset + len(row['data']) <= 65538, 'bounded independent framed stream sequence')
        for at, value in enumerate(row['data'], offset):
            require(at not in values or values[at] == value, 'consistent duplicate TCP bytes')
            values[at] = value
    require(not values or set(values) == set(range(max(values) + 1)), 'no missing captured TCP stream byte')
    return bytes(values[at] for at in range(len(values)))


def inventory(lane):
    result = Counter({case: 1 for case in (*BASE, 'selection')})
    if lane:
        result.update({f'parallel{i}': 1 for i in range(8)})
        result.update({'cycle-success': 64, 'cycle-failure': 64})
    return result


def verify(path, lane, evidence, text, linkage, native=False):
    raw = records(path)
    rows = []
    for row in raw:
        decoded = decode(row['frame'], lane)
        if decoded is not None:
            rows.append(dict(decoded, ms=row['ms']))
    reported = []
    for record in evidence['frames']:
        decoded = decode(bytes.fromhex(record['frame']), lane)
        if decoded is None:
            continue
        require(record['direction'] == ('query' if decoded['outgoing'] else 'reply'), 'peer frame direction')
        reported.append(dict(decoded, ms=record['ms']))
    require(evidence['lane'] == lane and Counter(row['frame'] for row in rows) ==
            Counter(row['frame'] for row in reported), 'all PCAP and peer IPv4 bytes match')
    for outgoing in (False, True):
        captured = [row for row in rows if row['outgoing'] == outgoing]
        observed = [row for row in reported if row['outgoing'] == outgoing]
        require([row['frame'] for row in captured] == [row['frame'] for row in observed],
                'complete per-direction PCAP/peer order')
        origin = captured[0]['ms'] - observed[0]['ms']
        require(all(abs(row['ms'] - record['ms'] - origin) < 100 for row, record in zip(captured, observed)),
                'independent packet and peer clocks agree within delivery allowance')
    if not native:
        receipts = re.findall(r'^DNS_FRAME linkage=' + linkage + r' index=' + str(lane + 1) +
                             r' length=(\d+) hash=([0-9a-f]{16}) packet_type=(\d+) monotonic_ms=(\d+)\r?$', text, re.M)
        expected = Counter()
        for row in rows:
            value = 0xcbf29ce484222325
            for byte in row['frame']:
                value = (value ^ byte) * 0x100000001b3 & 0xffffffffffffffff
            expected[(str(len(row['frame'])), f'{value:016x}', '4' if row['outgoing'] else '0')] += 1
        require(Counter(row[:3] for row in receipts) == expected and receipts, 'PCAP matches all actual driver receipts')
        clocks = [int(row[-1]) for row in receipts]
        require(clocks == sorted(clocks), 'actual driver receipt clocks are ordered')
        links = link_receipts(text, path, lane, linkage)
        require(f'DNS_CAPTURE_PASS linkage={linkage} index={lane + 1} packets={len(receipts) + links} dropped=0' in text,
                'zero-drop complete driver capture')
    owners, by_port, flows = [], {}, []
    for row in rows:
        if row['protocol'] == 'udp':
            if row['outgoing']:
                case = question(row['data'])
                previous = [owner for owner in owners if owner['port'] == row['port'] and owner['query'] == row['data']]
                if previous:
                    require(len(previous) == 1 and previous[0]['case'] == case, 'one UDP retransmission owner')
                else:
                    owners.append(dict(case=case, port=row['port'], query=row['data'], tc=[], claimed=False))
            else:
                require(len(row['data']) >= 17, 'complete truncated UDP response')
                candidates = [owner for owner in owners if owner['port'] == row['port'] and
                              owner['query'][:2] == row['data'][:2]]
                require(len(candidates) == 1, 'TC reply owns a preceding UDP query')
                owner = candidates[0]
                require(row['data'] == owner['query'][:2] + bytes.fromhex('83800001000000000000') +
                        owner['query'][12:], 'exact owned truncated UDP response')
                owner['tc'].append(row['ms'])
            continue
        flow = by_port.get(row['port'])
        if row['outgoing'] and row['flags'] & 2:
            if flow is None or flow['syn']['seq'] != row['seq']:
                flow = dict(port=row['port'], syn=row, rows=[])
                by_port[row['port']] = flow
                flows.append(flow)
        require(flow is not None, 'every DNS TCP segment has an actual active SYN')
        flow['rows'].append(row)
    require(Counter(owner['case'] for owner in owners) == inventory(lane), 'exact independent DNS transaction inventory')
    result, parallel = [], []
    for flow in flows:
        outgoing = [row for row in flow['rows'] if row['outgoing']]
        incoming = [row for row in flow['rows'] if not row['outgoing']]
        require(flow['syn']['flags'] == 2 and not flow['syn']['data'] and incoming, 'real DNS TCP active connection')
        origin = (flow['syn']['seq'] + 1) & MASK
        query = stream(outgoing, origin)
        if not query:
            candidates = [owner for owner in owners if owner['case'] == 'connect-refused' and not owner['claimed'] and
                          owner['tc'] and min(owner['tc']) <= flow['syn']['ms']]
            require(len(candidates) == 1 and len(incoming) == 1 and incoming[0]['flags'] == 20 and
                    incoming[0]['ack'] == origin and not incoming[0]['data'], 'actual refused DNS connection')
            owner = candidates[0]
            reply = b''
        else:
            require(len(query) >= 2 and int.from_bytes(query[:2], 'big') == len(query) - 2,
                    'complete framed TCP query without trailing bytes')
            case = question(query[2:])
            candidates = [owner for owner in owners if not owner['claimed'] and owner['query'] == query[2:] and
                          owner['tc'] and min(owner['tc']) <= flow['syn']['ms']]
            require(len(candidates) == 1, f'TCP query preserves its own preceding UDP transaction: lane={lane} case={case} candidates={len(candidates)} port={flow["port"]}')
            owner = candidates[0]
            peer_syn = [row for row in incoming if row['flags'] & 2]
            require(len(peer_syn) == 1 and peer_syn[0]['flags'] == 18 and peer_syn[0]['ack'] == origin and
                    not peer_syn[0]['data'], 'real successful SYN-ACK acknowledges owned SYN')
            remote = (peer_syn[0]['seq'] + 1) & MASK
            require(any(row['flags'] == 16 and row['ack'] == remote for row in outgoing), 'active handshake final ACK')
            progress, finished = {True: 0, False: 0}, {True: False, False: False}
            starts = {True: origin, False: remote}
            for row in flow['rows']:
                if row['flags'] & 2:
                    continue
                direction = row['outgoing']
                require(row['flags'] & 16 and not row['flags'] & 4 and
                        ((row['ack'] - starts[not direction]) & MASK) <=
                        progress[not direction] + int(finished[not direction]),
                        'ACK acknowledges only already captured owned bytes and no reset interrupts the fixture')
                offset = (row['seq'] - starts[direction]) & MASK
                if row['data']:
                    require(offset <= progress[direction], 'ordered delivered resolver bytes have no receive hole')
                    progress[direction] = max(progress[direction], offset + len(row['data']))
                if row['flags'] & 1:
                    require(offset + len(row['data']) == progress[direction], 'FIN uses the complete delivered sequence edge')
                    finished[direction] = True
            reply = stream(incoming, remote)
            require(reply == expected_answer(query[2:], case, lane), 'exact independently expected framed answer bytes')
            if case.startswith('parallel'):
                parallel.append((case, max(row['ms'] for row in outgoing if row['data']),
                                 min(row['ms'] for row in incoming if row['data'])))
            for side, start, size, opposite in ((outgoing, origin, len(query), incoming),
                                                (incoming, remote, len(reply), outgoing)):
                fins = [row for row in side if row['flags'] & 1]
                require(fins and all((row['seq'] + len(row['data'])) & MASK == (start + size) & MASK for row in fins) and
                        any(row['flags'] & 16 and row['ack'] == (start + size + 1) & MASK for row in opposite),
                        'complete acknowledged FIN follows exactly the owned stream')
            if case in ('large', 'split'):
                require(int.from_bytes(reply[:2], 'big') > 512 and len(reply) == int.from_bytes(reply[:2], 'big') + 2,
                        'complete answer exceeds UDP size')
            if case == 'split':
                chunks = [row for row in incoming if row['data']]
                require([len(row['data']) for row in chunks[:4]] == [1, 1, 17, 382] and len(chunks) == 5 and
                        chunks[-1]['ms'] - chunks[0]['ms'] >= 90,
                        'actual split length prefix and body with measured delivery clocks')
            if case == 'silent':
                closed = [row for row in outgoing if row['flags'] & 5]
                require(not reply and closed and 850 <= closed[0]['ms'] - flow['syn']['ms'] <= 1500,
                        'actual finite resolver wait while established peer sends no answer')
        require(owner['tc'] and min(owner['tc']) <= flow['syn']['ms'] and not owner['claimed'],
                'selected server TCP fallback follows the validated TC response')
        owner['claimed'] = True
        result.append(dict(case=owner['case'], port=flow['port'], query_bytes=len(query), reply_bytes=len(reply),
                           query_sha256=hashlib.sha256(query).hexdigest(), reply_sha256=hashlib.sha256(reply).hexdigest()))
    expected_flows = inventory(lane)
    if not lane:
        del expected_flows['selection']
    require(Counter(row['case'] for row in result) == expected_flows and
            all(owner['claimed'] or not lane and owner['case'] == 'selection' and not owner['tc'] for owner in owners),
            'all queries fall back exactly once except the deliberately unselected nameserver')
    if lane:
        require(len(parallel) == 8 and min(row[2] for row in parallel) > max(row[1] for row in parallel) and
                [row[0] for row in sorted(parallel, key=lambda row: row[2])] == [f'parallel{i}' for i in reversed(range(8))],
                'all independent queries remain open before reverse-order responses')
    return dict(lane=lane, file=path.name, sha256=hashlib.sha256(path.read_bytes()).hexdigest(),
                ipv4_frames=len(rows), transactions=len(owners), flows=result, passed=True)


def verify_report(root, name):
    results = json.loads((root / name).read_text())
    checked = []
    for result in results:
        require(result['passed'], 'actual application acceptance passed')
        inputs = json.loads((root / result['inputs']).read_text())
        for value in inputs['inputs'].values():
            path = root.parent / value['path']
            require(path.resolve().is_relative_to(root.resolve()) and path.is_file() and
                    hashlib.sha256(path.read_bytes()).hexdigest() == value['sha256'],
                    'exact retained client, provider, kernel and boot image inputs')
        peers = json.loads((root / result['peer']).read_text())
        text = (root / result['log']).read_text()
        require(len(peers) == len(result['captures']) == 2 and
                f"DNS_TCP_TESTS_PASS linkage={result['linkage']} cases=43 threads=8 cycles=128" in text,
                'complete application inventory and both Ethernet captures')
        native = result.get('native', False)
        for lane in range(2):
            checked.append(verify(root / result['captures'][lane], lane, peers[lane], text, result['linkage'], native))
    require(checked, 'actual DNS TCP reports present')
    return checked


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root', type=Path, default=Path(__file__).resolve().parents[1] / 'build')
    parser.add_argument('--report', default='dns-tcp-results.json')
    args = parser.parse_args()
    checked = verify_report(args.root, args.report)
    (args.root / 'dns-tcp-capture-results.json').write_text(json.dumps(checked, indent=2) + '\n')
    print(f"DNS_TCP_CAPTURE_PASS captures={len(checked)} flows={sum(len(row['flows']) for row in checked)}")


if __name__ == '__main__':
    main()
