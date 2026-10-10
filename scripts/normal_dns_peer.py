# SPDX-License-Identifier: GPL-3.0-or-later
"""Answer real application queries at only the nameservers accepted by normal DHCP."""
import struct
import time
from dns_peer import question, response
from udp_peer import checksum, ipv4, udp
from dhcp_peer import check


class NormalDns:
    def __init__(self, peer, mask):
        self.peer, self.mask = peer, mask
        self.queries, self.replies, self.arps = [], [], []
        self.transactions = {}

    def intercept(self, frame):
        peer = self.peer
        check(len(frame) >= 42 and frame[6:12] == peer.guest, 'normal application Ethernet source')
        if frame[12:14] == b'\x08\x06':
            body = frame[14:42]
            target = body[24:28]
            if target not in (peer.ip[:3] + b'\x35', peer.ip[:3] + b'\x36'):
                return False
            expected = peer.ip[:3] + bytes([54 if peer.approved else 53])
            check(peer.healthy and target == expected and body[:8] == bytes.fromhex('0001080006040001')
                  and body[8:14] == peer.guest and body[14:18] == peer.address
                  and body[18:24] == bytes(6) and frame[:6] == b'\xff' * 6,
                  'ARP targets only the accepted current ACK nameserver')
            answer = (peer.guest + peer.mac + b'\x08\x06' + bytes.fromhex('0001080006040002')
                      + peer.mac + target + peer.guest + peer.address).ljust(60, b'\0')
            self.arps.append({'query': frame.hex(), 'reply': answer.hex(), 'server': target.hex()})
            peer.send(answer)
            return True
        if frame[12:14] != b'\x08\x00' or frame[23] != 17 or frame[36:38] != b'\x00\x35':
            return False
        header = frame[14:34]
        total = int.from_bytes(header[2:4], 'big')
        server = peer.ip[:3] + bytes([54 if peer.approved else 53])
        check(peer.healthy and frame[:6] == peer.mac and header[0] == 0x45 and header[8]
              and checksum(header) == 0 and header[6:8] in (bytes(2), b'\x40\x00')
              and header[12:20] == peer.address + server and 28 <= total <= len(frame) - 14,
              'actual query uses the ACK nameserver and configured adapter route')
        segment = frame[34:14 + total]
        source, destination, length, value = struct.unpack('!4H', segment[:8])
        check(source and destination == 53 and length == len(segment) and value
              and checksum(peer.address + server + struct.pack('!BBH', 0, 17, length) + segment) == 0,
              'complete real DNS UDP query ports, length and checksum')
        query = segment[8:]
        name = question(query)
        phase = 'recovered' if peer.approved else 'initial'
        check(name in {f'normal-{phase}-{linkage}.linux-abi.fixture' for linkage in ('static', 'dynamic')},
              'phase and actual musl linkage identify the expected absolute question')
        key = (name, query[:2], source)
        transaction = self.transactions.setdefault(key, [])
        check(not transaction or bytes.fromhex(transaction[0]['frame'])[42:14 + total] == query,
              'identical cold-neighbor retransmission bytes')
        record = {'name': name, 'server': server.hex(), 'frame': frame.hex(),
                  'host_monotonic_ms': round(time.monotonic() * 1000), 'attempt': len(transaction) + 1}
        transaction.append(record)
        self.queries.append(record)
        check(len(transaction) <= 2, 'at most one retransmission while a cold nameserver ARP resolves')
        responding = min(lane for lane in range(2) if self.mask & (1 << lane))
        if peer.lane == responding:
            data = response(query, ((10, 23, 48, 71 if peer.approved else 70),))
            packet = ipv4(server, peer.address, udp(server, peer.address, 53, source, data))
            answer = (peer.guest + peer.mac + b'\x08\x00' + packet).ljust(60, b'\0')
            self.replies.append({'name': name, 'frame': answer.hex(),
                                 'host_monotonic_ms': round(time.monotonic() * 1000)})
            peer.send(answer)
        return True

    def evidence(self):
        return {'lane': self.peer.lane, 'healthy': bool(self.peer.healthy), 'queries': self.queries,
                'replies': self.replies, 'arps': self.arps}

    def validate(self):
        peer = self.peer
        if peer.healthy:
            expected = {f'normal-{phase}-{linkage}.linux-abi.fixture'
                        for phase in ('initial', 'recovered') for linkage in ('static', 'dynamic')}
            check({row['name'] for row in self.queries} == expected and len(self.transactions) == 4,
                  'all four real application transactions reach this accepted nameserver')
            check([row['name'] for row in self.queries if row['attempt'] == 1] ==
                  [f'normal-{phase}-{linkage}.linux-abi.fixture'
                   for phase in ('initial', 'recovered') for linkage in ('static', 'dynamic')],
                  'fresh resolver queries preserve phase and linkage order')
            check(len(self.arps) == 2 and {row['server'] for row in self.arps} ==
                  {peer.ip[:3].hex() + tail for tail in ('35', '36')},
                  'separate actual neighbor resolution for both generations of ACK nameserver')
        else:
            check(not self.queries and not self.replies and not self.arps,
                  'a missing DHCP peer never contributes a nameserver')
        return self.evidence()
