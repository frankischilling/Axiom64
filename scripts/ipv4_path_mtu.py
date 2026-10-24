# SPDX-License-Identifier: GPL-3.0-or-later
"""Validate real path-MTU datagrams and ordered client barriers on one NIC."""
import struct
from ipv4_path_mtu_lifetime import PathMtuLifetimePeer


def require(condition, message):
    if not condition:
        raise ValueError('path MTU: ' + message)


def checksum(data):
    data += b'\0' * (len(data) % 2)
    total = sum(struct.unpack('!' + 'H' * (len(data) // 2), data))
    while total >> 16:
        total = (total & 65535) + (total >> 16)
    return (~total) & 65535


class PathMtuPeer:
    def __init__(self, lane, *, native=False):
        self.lane = lane
        self.native = native
        self.local = bytes([10, 23, lane + 1, 2])
        self.remote = bytes([10, 23, lane + 1, 1])
        self.guest = bytes([0x52, 0x54, 0, 0x12, 0x34, 0x10 + lane])
        self.mac = bytes([2, 0x41, 0x58, 0x49, 0x50, lane])
        self.completed = self.next_policy = self.frames = self.datagrams = 0
        self.stage = 'idle'
        self.quote = None
        self.fragments = bytearray()
        self.identity = None
        self.observed = False
        self.pending_control = None
        self.passed = False
        self.lifetime = PathMtuLifetimePeer(lane, native=native)

    @property
    def target(self):
        return bytes([10, 23, self.lane + 1, 180 + self.completed])

    @property
    def original_policy(self):
        return self.completed % 6 if self.completed < 12 else 1 if self.completed < 16 else self.completed - 12

    @property
    def announced(self):
        return 900 if self.completed < 12 or self.completed >= 16 else [68, 551, 552, 0][self.completed - 12]

    @property
    def learned(self):
        return 1500 if self.original_policy >= 4 and self.completed < 16 else max(552, self.announced)

    def arp_reply(self, frame):
        lifetime = self.lifetime.arp_reply(frame)
        if lifetime is not None:
            return lifetime
        if len(frame) < 42 or frame[12:14] != b'\x08\x06' or not (
                frame[38:41] == self.remote[:3] and 180 <= frame[41] < 198):
            return None
        require(self.stage != 'idle' and frame[38:42] == self.target, 'ARP owns current case')
        expected = (b'\xff' * 6 + self.guest + b'\x08\x06' +
                    struct.pack('!HHBBH', 1, 0x800, 6, 4, 1) + self.guest +
                    self.local + b'\0' * 6 + self.target)
        require(frame[:42] == expected and len(frame) == (42 if self.native else 60) and
                not any(frame[42:]), 'exact ARP request bytes')
        return (self.guest + self.mac + b'\x08\x06' +
                struct.pack('!HHBBH', 1, 0x800, 6, 4, 2) + self.mac + self.target +
                self.guest + self.local).ljust(60, b'\0')

    def accepts(self, packet):
        return (self.lifetime.accepts(packet) or
                (len(packet) == 52 and packet[9] == 1 and packet[16:20] == self.remote and
                 packet[24:26] == b'PM') or
                (len(packet) >= 20 and packet[16:19] == self.remote[:3] and
                 180 <= packet[19] < 198))

    def packet(self, source, payload):
        header = bytearray(struct.pack('!BBHHHBBH4s4s', 0x45, 0, 20 + len(payload),
                                      0x706d, 0, 51, 1, 0, source, self.local))
        struct.pack_into('!H', header, 10, checksum(bytes(header)))
        return bytes(header) + payload

    def error(self, damaged=False):
        body = bytearray(struct.pack('!BBHHH', 3, 4, 0, 0, self.announced) + self.quote)
        struct.pack_into('!H', body, 2, checksum(bytes(body)))
        if damaged:
            body[2] ^= 1
        return self.packet(self.target, bytes(body))

    def expected_payload(self, length=1100):
        test = self.completed
        payload = bytearray((n * 29 + self.lane * 53 + test * 97) & 255 for n in range(1100))
        if test < 6 or test >= 16:
            payload[:8] = bytes([8, 0, 0, 0, ord('P'), ord('D'), test, self.lane])
            struct.pack_into('!H', payload, 2, checksum(bytes(payload)))
        return bytes(payload[:length])

    def data(self, packet):
        require(self.stage in ('initial', 'output'), 'data has a live ordered case')
        require(packet[16:20] == self.target, 'data destination owns exact case')
        raw = self.completed < 6 or self.completed >= 16
        require(packet[9] == (1 if raw else 17), 'data protocol')
        policy = self.original_policy if self.stage == 'initial' else self.next_policy
        limit = 1500 if self.stage == 'initial' or policy >= 3 else self.learned
        require(not (self.stage == 'output' and policy == 2 and self.learned < 1120),
                'DO must not emit an oversized datagram')
        require(len(packet) <= limit, 'wire packet obeys selected path/device limit')
        field = int.from_bytes(packet[6:8], 'big')
        offset, more = (field & 8191) * 8, bool(field & 8192)
        require(not self.observed and not field & 0x8000, 'no duplicate datagram or reserved flag')
        if self.identity is None:
            self.identity = packet[4:6]
        require(packet[4:6] == self.identity and offset == len(self.fragments),
                'one exact ordered fragment identity and cursor')
        application_length = 300 if self.stage == 'output' and policy == 1 and self.learned == 552 else 1100
        total = application_length + (20 if raw else 28)
        fragmented = total > limit
        locked = self.stage != 'initial' and self.learned == 552 and self.announced < 552
        df = policy in (2, 3) or (policy == 1 and not locked)
        require(bool(field & 0x4000) == (df and not fragmented), 'DF policy on actual wire')
        require(bool(field & 0x3fff) == fragmented,
                'fragment flags reflect the wire size')
        data = packet[20:]
        require(not more or (len(data) > 0 and len(data) % 8 == 0), 'nonfinal alignment')
        self.fragments.extend(data)
        self.frames += 1
        if more:
            return []
        require(len(self.fragments) == total - 20, 'complete exact fragment coverage')
        payload = bytes(self.fragments)
        if raw:
            require(payload == self.expected_payload(application_length) and not checksum(payload), 'raw payload')
        else:
            require(struct.unpack('!HHH', payload[:6]) ==
                    (49200 + self.completed * 2 + self.lane, 48000 + self.completed, application_length + 8),
                    'UDP ports and length')
            pseudo = self.local + self.target + struct.pack('!BBH', 0, 17, len(payload))
            require(payload[6:8] != b'\0\0' and not checksum(pseudo + payload) and
                    payload[8:] == self.expected_payload(application_length), 'UDP checksum and exact payload')
        self.observed = True
        self.datagrams += 1
        responses = []
        if self.stage == 'initial':
            require(not fragmented, 'initial quote is an emitted whole packet')
            self.quote = packet[:28]
            responses.append(self.error(damaged=True))
        if self.pending_control is not None:
            pending, self.pending_control = self.pending_control, None
            responses.extend(self.control(pending))
        return responses

    def control(self, packet):
        require(len(packet) == 52 and packet[16:20] == self.remote and
                packet[6:10] == b'\x40\0\x40\x01', 'control route, size and policy')
        body = packet[20:]
        test, phase, policy = body[6:9]
        require(body[:2] == b'\x08\0' and not checksum(body) and body[4:6] == b'PM' and
                body[9] == self.lane and body[10:] ==
                bytes((n * 17 + self.lane * 31) & 255 for n in range(10, 32)) and
                test == self.completed and not self.passed, 'control identity and bytes')
        responses = []
        # A send can remain queued behind ARP or driver backpressure while the
        # control route is already reachable. The acknowledgement still requires
        # the actual complete data, regardless of which frame reaches us first.
        needs_data = phase == 1 or (phase == 3 and (policy != 2 or self.learned >= 1120))
        if needs_data and not self.observed:
            require(self.pending_control is None and
                    ((phase == 1 and self.stage == 'initial' and policy == self.original_policy) or
                     (phase == 3 and self.stage == 'output' and policy == self.next_policy)),
                    'one deferred barrier owns the pending data')
            self.pending_control = bytes(packet)
            return []
        if phase == 0:
            require(self.stage == 'idle' and test < 18 and policy == self.original_policy,
                    'start one fresh path')
            self.stage = 'initial'
            self.next_policy = 0
            self.fragments = bytearray()
            self.identity = None
            self.observed = False
        elif phase == 1:
            require(self.stage == 'initial' and self.observed and policy == self.original_policy,
                    'bad-checksum observation follows actual quote')
            self.stage = 'bad-observed'
        elif phase == 6:
            require(self.stage == 'bad-observed' and policy == self.original_policy,
                    'valid quote follows guest rejection of damaged hint')
            responses.append(self.error())
            self.stage = 'learned'
        elif phase == 2:
            require(self.stage == 'learned' and policy == self.next_policy and policy < 6,
                    'start each output policy in order')
            self.stage = 'output'
            self.fragments = bytearray()
            self.identity = None
            self.observed = False
        elif phase == 3:
            require(self.stage == 'output' and policy == self.next_policy and
                    self.observed == (policy != 2 or self.learned >= 1120),
                    'policy barrier requires exact data or required silence')
            self.next_policy += 1
            self.stage = 'learned'
        elif phase == 4:
            require(self.stage == 'learned' and self.next_policy == 6 and
                    policy == self.original_policy, 'all policies completed before close')
            self.completed += 1
            self.stage = 'idle'
        elif phase == 5:
            require(self.stage == 'idle' and test == 18 and policy == 0,
                    'final client acknowledgement follows all cases')
            self.passed = True
        else:
            raise ValueError('path MTU: unknown control phase')
        reply = bytearray(body)
        reply[0] = 0
        reply[2:4] = b'\0\0'
        struct.pack_into('!H', reply, 2, checksum(bytes(reply)))
        responses.append(self.packet(self.remote, bytes(reply)))
        return responses

    def receive(self, packet):
        if self.lifetime.accepts(packet):
            return self.lifetime.receive(packet)
        require(len(packet) >= 20 and packet[:2] == b'\x45\0' and
                int.from_bytes(packet[2:4], 'big') == len(packet) and
                not checksum(packet[:20]) and packet[12:16] == self.local,
                'IP header, checksum and source')
        if packet[24:26] == b'PM':
            return self.control(packet)
        return self.data(packet)

    def report(self):
        return dict(passed=self.passed, cases=self.completed, frames=self.frames,
                    datagrams=self.datagrams, damaged_hints=self.completed,
                    policies_each=6, stage=self.stage)
