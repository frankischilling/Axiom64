# SPDX-License-Identifier: GPL-3.0-or-later
"""Inject metadata inputs after actual Ethernet requests; readers decide acceptance."""
import struct
import time
from ipv4_multicast_peer import checksum

SCENARIOS = 13
CASES = SCENARIOS * 6


def primary(lane):
    return 0x0a4d0102 + (lane << 8)


def prefix(lane):
    return 0xc6120102 + (lane << 8)


def specification(lane, sequence):
    scenario = sequence % SCENARIOS
    kind, prepared = divmod(sequence // SCENARIOS, 2)
    source, destination = primary(lane) - 1, primary(lane)
    if scenario in (1, 10):
        destination = primary(lane) + 40
    if scenario in (2, 5, 11):
        source = prefix(lane) - 1
    if scenario == 2:
        destination = prefix(lane)
    if scenario == 3:
        destination = 0xffffffff
    if scenario == 4:
        destination = primary(lane) | 255
    if scenario == 5:
        destination = prefix(lane) | 255
    if scenario in (6, 7, 8, 11, 12):
        destination = 0xef4d0101 + (lane << 8)
    if scenario in (7, 12):
        source = 0xcb007100 + (31 if scenario == 7 else 61) + lane
    if scenario == 8:
        source = 0xc0000265 + lane
    if scenario == 9:
        destination = primary(lane ^ 1) + 40
    return dict(lane=lane, case=sequence, scenario=scenario, transport=kind, prepared=prepared,
                source=source, destination=destination, ttl=17 + sequence * 11 % 200,
                tos=(0x6e + sequence * 13) & 255)


class ReceivePeer:
    def __init__(self, lane):
        self.lane = lane
        self.guest = bytes([0x52, 0x54, 0, 0x12, 0x34, 0x10 + lane])
        self.mac = bytes([2, 0x41, 0x58, 0x52, 0x58, lane])
        self.frames = []
        self.sequence = 0
        self.phase = None
        self.completed = []
        self.queued = []
        self.injected = 0

    def acknowledge(self, sequence, phase):
        return (self.guest + self.mac + b'\x88\xb9AXRA' +
                bytes([self.lane, sequence, ord(phase)])).ljust(60, b'\0')

    def packet(self, sequence):
        value = specification(self.lane, sequence)
        body = b'AXRXDATA' + bytes([self.lane, sequence, value['transport'], value['scenario'],
                                    value['prepared'], 1, sequence ^ 0xa5, 0x5a + self.lane])
        source, destination = struct.pack('!II', value['source'], value['destination'])[:4], struct.pack('!I', value['destination'])
        protocol = 1 if value['transport'] == 1 else 17
        if protocol == 1:
            payload = bytearray(struct.pack('!BBHHH', 0, 0, 0, 0x4158, sequence) + body)
            struct.pack_into('!H', payload, 2, checksum(bytes(payload)))
        else:
            payload = bytearray(struct.pack('!HHHH', 42000 + sequence, 46000 + sequence, 24, 0) + body)
            pseudo = source + destination + struct.pack('!BBH', 0, 17, len(payload))
            struct.pack_into('!H', payload, 6, checksum(pseudo + payload) or 65535)
        header = bytearray(struct.pack('!BBHHHBBH4s4s', 0x45, value['tos'], 20 + len(payload),
            0x4d00 + sequence, 0, value['ttl'], protocol, 0, source, destination))
        struct.pack_into('!H', header, 10, checksum(bytes(header)))
        if value['scenario'] in (3, 4, 5):
            mac = b'\xff' * 6
        elif value['destination'] >> 28 == 14:
            mac = b'\x01\0\x5e' + (value['destination'] & 0x7fffff).to_bytes(3, 'big')
        else:
            mac = self.guest
        return (mac + self.mac + b'\x08\0' + bytes(header) + bytes(payload)).ljust(60, b'\0')

    def receive(self, frame):
        self.frames.append(dict(monotonic_ns=time.monotonic_ns(), direction='guest', data=frame.hex()))
        if len(frame) < 14 or frame[6:12] != self.guest:
            raise ValueError('metadata Ethernet sender identity')
        if frame[12:14] != b'\x88\xb9':
            return []
        if (len(frame) != 60 or frame[:6] != self.mac or frame[14:17] != b'AXR' or
                frame[18] != self.lane or frame[19] != self.sequence or any(frame[20:])):
            raise ValueError('metadata physical barrier envelope and order')
        phase = chr(frame[17])
        if phase == 'B' and self.phase is None and self.sequence < CASES:
            self.phase = 'B'
            self.injected += 1
            return [self.packet(self.sequence), self.acknowledge(self.sequence, 'B')]
        if phase == 'Q' and self.phase == 'B':
            self.phase = 'Q'
            self.queued.append(self.sequence)
            return [self.acknowledge(self.sequence, 'Q')]
        if phase == 'D' and self.phase == 'Q':
            sequence = self.sequence
            self.completed.append(sequence)
            self.sequence += 1
            self.phase = None
            return [self.acknowledge(sequence, 'D')]
        raise ValueError('metadata begin/queued/completed barrier state')

    def result(self):
        return dict(lane=self.lane, passed=self.completed == self.queued == list(range(CASES)) and
                    self.phase is None and self.injected == CASES,
                    completed=self.completed, queued=self.queued, injected=self.injected,
                    packet_and_syscall_semantics_not_accepted_by_producer=True)
