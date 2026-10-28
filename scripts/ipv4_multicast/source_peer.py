# SPDX-License-Identifier: GPL-3.0-or-later
"""Physical stage barriers; packet acceptance belongs to the independent reader."""
import struct
import time
from ipv4_multicast_peer import packet, checksum


class SourcePeer:
    def __init__(self, lane, source_case='settled'):
        if source_case not in ('settled', 'queries', 'mtu', 'overlap'):
            raise ValueError('known physical source case')
        self.lane = lane
        self.scenario = source_case
        self.count = 7 if source_case == 'mtu' else 12 if source_case == 'queries' else 7
        self.guest = bytes([0x52, 0x54, 0, 0x12, 0x34, 0x10 + lane])
        self.mac = bytes([2, 0x41, 0x58, 0x4d, 0x43, lane])
        self.ip = bytes([10, 67, lane + 1, 1])
        self.frames = []
        self.started = []
        self.completed = []
        self.pending = None
        self.since = None
        self.observations = []
        self.query_count = 0
        self.first_reports = set()
        self.first_packet_stages = (1, 5) if source_case == 'overlap' else ()

    def acknowledge(self, stage, kind):
        return (self.guest + self.mac + b'\x88\xb9AXSA' +
                bytes([self.lane, stage, ord(kind)])).ljust(60, b'\0')

    def query(self, stage):
        if self.scenario == 'mtu':
            if stage not in (3, 5, 6):
                return []
        elif self.scenario != 'queries' or stage not in (3, 4, 5, 6, 8, 9, 10, 11):
            return []
        group = bytes.fromhex('ef7f2a01')
        general = self.scenario == 'queries' and stage in (6, 11)
        sources = {3: (0xc0000201, 0xc0000203), 4: (0xc0000203,),
                   8: (0xc0000201, 0xc0000203), 9: (0xc0000201,)}.get(stage, ()) if self.scenario == 'queries' else ()
        destination = bytes.fromhex('e0000001') if general else group
        body = bytearray(b'\x11\x0a\0\0' + (bytes(4) if general else group) +
                         b'\x02\x7d' + struct.pack('!H', len(sources)))
        body.extend(b''.join(struct.pack('!I', source) for source in sources))
        struct.pack_into('!H', body, 2, checksum(bytes(body)))
        mac = b'\x01\x00\x5e' + bytes([destination[1] & 127]) + destination[2:]
        frame = mac + self.mac + b'\x08\x00' + packet(self.ip, destination, bytes(body), 2,
                                                      options=b'\x94\x04\0\0')
        self.query_count += 1
        return [frame.ljust(60, b'\0')]

    def receive(self, frame):
        self.frames.append(dict(monotonic=time.monotonic(), direction='guest', data=frame.hex()))
        if len(frame) < 14 or frame[6:12] != self.guest:
            raise ValueError('source multicast guest Ethernet identity')
        if frame[12:14] != b'\x88\xb9':
            # Release a first-packet barrier only after actual IGMPv3 output.
            # Exact records and retransmission counts belong to the reader.
            if (self.started and self.started[-1] in self.first_packet_stages and
                    len(frame) >= 46 and frame[12:14] == b'\x08\x00' and
                    frame[14] == 0x46 and frame[23] == 2 and frame[38] == 0x22):
                self.first_reports.add(self.started[-1])
            return []
        if len(frame) != 60 or frame[:6] != self.mac or frame[18] != self.lane or any(frame[20:]):
            raise ValueError('source multicast control envelope')
        kind, stage = frame[14:18], frame[19]
        if kind == b'AXSB':
            if (self.pending is not None or stage != len(self.started) + 1 or
                    self.started != self.completed or stage > self.count):
                raise ValueError('ordered source multicast start barrier')
            self.started.append(stage)
            return [self.acknowledge(stage, 'B')]
        if kind != b'AXSD' or self.pending is not None or self.started != self.completed + [stage]:
            raise ValueError('ordered source multicast observation barrier')
        self.pending = stage
        self.since = time.monotonic_ns()
        return self.query(stage)

    def ready(self):
        if self.pending is None:
            return []
        now = time.monotonic_ns()
        first_packet = self.pending in self.first_packet_stages
        if first_packet:
            if self.pending not in self.first_reports:
                return []
        elif now - self.since < 3_000_000_000:
            return []
        stage = self.pending
        self.observations.append(dict(stage=stage, begin_ns=self.since, end_ns=now,
                                      first_packet_barrier=first_packet))
        self.completed.append(stage)
        self.pending = None
        return [self.acknowledge(stage, 'D')]

    def result(self):
        return dict(lane=self.lane,
                    passed=self.started == self.completed == list(range(1, self.count + 1)) and self.pending is None,
                    started=self.started, completed=self.completed, observations=self.observations,
                    queries_transmitted=self.query_count, packet_semantics_not_accepted_by_producer=True)
