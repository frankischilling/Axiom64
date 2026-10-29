# SPDX-License-Identifier: GPL-3.0-or-later
"""Own Ethernet release barriers; retain complete frames for independent readers."""
import struct
import time
from ipv4_multicast_peer import checksum
from ipv4_receive_wire_peer import primary

CASES = 68


def application(lane, sequence, phase, kind, number, size):
    data = bytearray((at * 19 + sequence * 7 + lane * 31 + phase * 11 + kind * 13) & 255
                     for at in range(size))
    data[:4] = b'SWIR'
    data[4:9] = bytes((lane, sequence, phase, kind, number))
    return bytes(data)


def owned_target(address):
    lane, sequence = ((address >> 8) & 255) - 1, (address & 255) - 1
    if address >> 16 == 0xc612 and lane in (0, 1) and 50 <= sequence < CASES:
        return lane, sequence
    offset = address - 0xcb007101
    lane, sequence = divmod(offset, 64)
    return (lane, sequence) if lane in (0, 1) and 0 <= sequence < 50 else None


class Coordinator:
    def __init__(self):
        self.links = []
        self.states = {}

    def acknowledge(self, state):
        frame = bytearray(state['barrier'])
        origin = state['lane']
        frame[:6] = self.links[origin].guest
        frame[6:12] = self.links[origin].mac
        frame[21] = 1
        return origin, bytes(frame)

    def ready(self, state):
        phase = state['phase']
        if phase in state['acknowledged']:
            return []
        sequence = state['sequence']
        if phase == 0:
            accepted = True
        elif phase == 1:
            if sequence >= 50:
                mode, mutation = divmod(sequence - 50, 3)
                accepted = bool(state['fills']) if mode < 4 and mutation else 3 in state['data']
            else:
                accepted = (0 in state['data'] if sequence < 36 else
                        bool(state['fills']) if sequence < 44 or sequence in (47, 49) else
                        (4 if sequence == 46 else 3) in state['data'])
        else:
            accepted = 1 in state['data']
        if not accepted:
            return []
        state['acknowledged'].add(phase)
        if phase == 2:
            self.links[state['lane']].completed.append(sequence)
        return [self.acknowledge(state)]

    def arp(self, lane, frame):
        if len(frame) < 42 or frame[14:22] != b'\0\x01\x08\0\x06\x04\0\x01':
            return []
        if frame[22:28] != self.links[lane].guest:
            raise ValueError('actual ARP sender hardware')
        identity = owned_target(int.from_bytes(frame[38:42], 'big'))
        if identity not in self.states:
            return []
        state = self.states[identity]
        reply = (self.links[lane].guest + self.links[lane].mac + b'\x08\x06' +
                 b'\0\x01\x08\0\x06\x04\0\x02' + self.links[lane].mac +
                 frame[38:42] + self.links[lane].guest + frame[28:32]).ljust(60, b'\0')
        if state['released']:
            return [(lane, reply)]
        state['arp'][lane] = reply
        return []

    def barrier(self, lane, frame):
        if len(frame) != 60 or frame[:6] != self.links[lane].mac or frame[14:18] != b'SCTL':
            raise ValueError('actual send ownership barrier envelope')
        origin, sequence, phase, reply = frame[18:22]
        if origin != lane or sequence >= CASES or phase not in (0, 1, 2) or reply:
            raise ValueError('send barrier fields')
        expected = bytes((at * 17 + sequence * 7 + lane * 31 + phase) & 255 for at in range(22, 60))
        if frame[22:] != expected:
            raise ValueError('complete original barrier bytes')
        identity = lane, sequence
        if phase == 0:
            if identity in self.states or sequence != len(self.links[lane].completed):
                raise ValueError('unique sequential send case')
            state = dict(lane=lane, sequence=sequence, phase=0, acknowledged=set(),
                         barrier=frame, released=False, arp={}, data={}, fills={})
            self.states[identity] = state
        else:
            state = self.states[identity]
            if phase != state['phase'] + 1 or state['phase'] not in state['acknowledged']:
                raise ValueError('send release/completion order')
            state.update(phase=phase, barrier=frame)
        frames = []
        if phase == 1:
            state['released'] = True
            frames = list(state['arp'].items())
            state['arp'].clear()
        return frames + self.ready(state)

    def packet(self, lane, frame):
        if len(frame) < 34 or frame[14] != 0x45:
            return []
        declared = int.from_bytes(frame[16:18], 'big')
        packet = frame[14:14 + declared]
        if len(packet) != declared or checksum(packet[:20]) or declared < 52:
            raise ValueError('actual complete IPv4 send header')
        identity = owned_target(int.from_bytes(packet[16:20], 'big'))
        if identity not in self.states:
            return []
        state = self.states[identity]
        body = packet[28:]
        if len(body) < 9 or body[:4] != b'SWIR':
            raise ValueError('original owned application bytes')
        origin, sequence, phase, kind, number = body[4:9]
        if (origin, sequence) != identity:
            raise ValueError('actual target/application ownership')
        expected_kind = sequence // 12 if sequence < 36 else sequence - 41 if sequence in (42, 43) else 0
        if kind != expected_kind or packet[9] != (1 if kind == 2 else 17):
            raise ValueError('actual raw/UDP protocol identity')
        if body != application(origin, sequence, phase, kind, number, 64 if sequence < 36 else 1100):
            raise ValueError('actual full payload retention/copy point')
        expected_lane, source, ttl, tos = origin, primary(origin), 63, 34
        if sequence < 36:
            scenario = sequence % 6
            if phase == 0 and scenario:
                ttl, tos = 37, 184
                expected_lane = origin ^ 1 if scenario in (2, 3, 5) else origin
                source = (primary(origin) + 40 if scenario in (1, 3) else
                          primary(origin ^ 1) + 40 if scenario == 4 else primary(expected_lane))
            if phase not in (0, 1):
                raise ValueError('ordinary selected/default send phase')
        elif sequence >= 50:
            mode, mutation = divmod(sequence - 50, 3)
            source = 0xc6120102 + origin * 256 if mode in (2,3) else primary(origin)
            if phase == 2:
                expected_lane, source = origin ^ 1, primary(origin ^ 1)
            elif phase == 3:
                ttl, tos = 37, 184
            elif phase == 1:
                ttl, tos = 11, 8
                if mutation == 0 and mode != 5:
                    expected_lane = origin ^ 1
                if mode & 1:
                    source = 0xc6120102 + origin * 256 if mode == 3 else primary(origin)
                elif expected_lane != origin:
                    source = primary(origin ^ 1)
                else:
                    source = primary(origin) if mode == 0 and mutation == 1 else 0xc6120102 + origin * 256
            else:
                raise ValueError('lifetime fill/selected/default send phase')
        elif sequence not in (42, 43):
            scenario = sequence - (36 if sequence < 42 else 44)
            if phase == 1:
                expected_lane, source, ttl, tos = origin ^ 1, primary(origin ^ 1), 11, 8
            elif phase in (3, 4):
                if scenario in (3, 5) or phase != (4 if scenario == 2 else 3):
                    raise ValueError('fault/interruption cannot emit owned datagram')
                source = primary(origin) + (40 if scenario == 1 else 0)
                ttl, tos = 37, 184
            elif phase != 2:
                raise ValueError('waiting fill/selected/default send phase')
        else:
            if phase == 1:
                ttl, tos = 11, 8
            elif phase != 2:
                raise ValueError('refused raw memory request emitted packet')
        if lane != expected_lane or int.from_bytes(packet[12:16], 'big') != source or packet[8] != ttl or packet[1] != tos:
            raise ValueError('actual held route/source/interface/TTL/TOS')
        if frame[:6] != self.links[lane].mac:
            raise ValueError('actual selected next-hop hardware')
        if kind != 2:
            sport, dport, length, _ = struct.unpack('!HHHH', packet[20:28])
            if dport != 49157 or length != declared - 20 or (kind == 1 and sport != 51000 + origin * 64 + sequence):
                raise ValueError('actual UDP header identity/length')
        elif packet[20:22] != b'\xfd\0' or checksum(packet[20:]):
            raise ValueError('actual complete raw ICMP checksum')
        collection, key = (state['fills'], number) if phase == 2 else (state['data'], phase)
        if key in collection:
            raise ValueError('duplicate actual owned datagram')
        collection[key] = frame
        return self.ready(state)


class SendPeer:
    def __init__(self, coordinator, lane):
        self.coordinator, self.lane = coordinator, lane
        self.guest = bytes([0x52, 0x54, 0, 0x12, 0x34, 0x10 + lane])
        self.mac = bytes([2, 0x41, 0x58, 0x52, 0x58, lane])
        self.frames, self.completed = [], []

    def receive(self, frame):
        self.frames.append(dict(monotonic_ns=time.monotonic_ns(), direction='guest', data=frame.hex()))
        if len(frame) < 14 or frame[6:12] != self.guest:
            raise ValueError('actual Ethernet send identity')
        if frame[12:14] == b'\x88\xb9':
            return self.coordinator.barrier(self.lane, frame)
        if frame[12:14] == b'\x08\x06':
            return self.coordinator.arp(self.lane, frame)
        if frame[12:14] == b'\x08\0':
            return self.coordinator.packet(self.lane, frame)
        return []

    def result(self):
        return dict(lane=self.lane, passed=self.completed == list(range(CASES)), completed=self.completed,
                    packet_semantics_and_independent_capture_readback_pending=True)


def peers():
    coordinator = Coordinator()
    coordinator.links = [SendPeer(coordinator, lane) for lane in range(2)]
    return coordinator.links
