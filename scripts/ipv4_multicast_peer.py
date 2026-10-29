# SPDX-License-Identifier: GPL-3.0-or-later
"""Physical Ethernet peer for the shared IPv4 multicast client."""
import struct
import time

GROUP = bytes.fromhex('ef6a4307')
GROUP_MAC = bytes.fromhex('01005e6a4307')


def checksum(data):
    if len(data) & 1:
        data += b'\0'
    total = sum(struct.unpack(f'!{len(data) // 2}H', data))
    while total >> 16:
        total = (total & 65535) + (total >> 16)
    return (~total) & 65535


def packet(source, destination, payload, protocol, *, options=b'', ttl=1):
    header = bytearray(struct.pack('!BBHHHBBH4s4s', 0x45 + len(options) // 4,
                                  0xc0 if protocol == 2 else 0, 20 + len(options) + len(payload),
                                  0x1067, 0, ttl, protocol, 0, source, destination) + options)
    struct.pack_into('!H', header, 10, checksum(bytes(header)))
    return bytes(header) + payload


class Peer:
    def __init__(self, lane):
        self.lane = lane
        self.guest = bytes([0x52, 0x54, 0, 0x12, 0x34, 0x10 + lane])
        self.mac = bytes([2, 0x41, 0x58, 0x4d, 0x43, lane])
        self.guest_ip = bytes([10, 67, lane + 1, 2])
        self.ip = bytes([10, 67, lane + 1, 1])
        self.phases = []
        self.reports = []
        self.output = []
        self.pending = None
        self.pending_since = None
        self.query_report = self.old_report = self.leave = False
        self.frames = []

    def ethernet(self, destination, ip):
        return (destination + self.mac + b'\x08\x00' + ip).ljust(60, b'\0')

    def acknowledge(self, phase):
        return (self.guest + self.mac + b'\x88\xb9AXMA' + bytes([self.lane, phase])).ljust(60, b'\0')

    def datagram(self, phase):
        payload = b'AXMCW' + bytes([self.lane, phase])
        udp = bytearray(struct.pack('!HHHH', 42000, 46067, 8 + len(payload), 0) + payload)
        pseudo = self.ip + GROUP + struct.pack('!BBH', 0, 17, len(udp))
        struct.pack_into('!H', udp, 6, checksum(pseudo + udp) or 65535)
        return self.ethernet(GROUP_MAC, packet(self.ip, GROUP, bytes(udp), 17, ttl=19))

    def query(self, old=False):
        body = bytearray(b'\x11\x0a\0\0' + bytes(4) + (b'' if old else b'\x02\x7d\0\0'))
        struct.pack_into('!H', body, 2, checksum(bytes(body)))
        return self.ethernet(bytes.fromhex('01005e000001'),
                              packet(self.ip, bytes.fromhex('e0000001'), bytes(body), 2,
                                     options=bytes.fromhex('94040000')))

    def receive(self, frame):
        self.frames.append(dict(monotonic=time.monotonic(), direction='guest', data=frame.hex()))
        if len(frame) < 14 or frame[6:12] != self.guest:
            raise ValueError('multicast guest Ethernet identity')
        if frame[12:14] == b'\x88\xb9':
            if len(frame) != 60 or frame[:6] != self.mac or frame[14:19] != b'AXMC' + bytes([self.lane]):
                raise ValueError('multicast control frame')
            phase = frame[19]
            if phase in self.phases or self.pending is not None:
                raise ValueError('duplicate or overlapping multicast phase')
            self.phases.append(phase)
            if 1 <= phase <= 9:
                return [self.datagram(phase), self.acknowledge(phase)]
            self.pending = phase
            self.pending_since = time.monotonic()
            if phase in (200, 201):
                return [self.query(old=phase == 201)]
            if phase not in (10, 11, 12, 202):
                raise ValueError('unknown multicast phase')
            return []
        if frame[12:14] != b'\x08\x00':
            return []
        ip = frame[14:]
        if len(ip) < 20:
            raise ValueError('short multicast IP')
        header = (ip[0] & 15) * 4
        total = int.from_bytes(ip[2:4], 'big')
        if ip[0] >> 4 != 4 or header < 20 or total < header or total > len(ip) or checksum(ip[:header]):
            raise ValueError('multicast IP header checksum or length')
        if ip[12:16] != self.guest_ip:
            raise ValueError('multicast IP source')
        body = ip[header:total]
        if ip[9] == 2:
            destination = ip[16:20]
            expected_mac = b'\x01\x00\x5e' + bytes([destination[1] & 127]) + destination[2:]
            if ip[8] != 1 or ip[1] != 0xc0 or ip[20:24] != b'\x94\x04\0\0' or header != 24 or checksum(body) or frame[:6] != expected_mac:
                raise ValueError('actual IGMP envelope or checksum')
            if len(body) < 8:
                raise ValueError('short IGMP report')
            if body[0] == 0x22:
                if destination != bytes.fromhex('e0000016') or body[1:2] != b'\0':
                    raise ValueError('actual IGMPv3 destination')
                offset = 8
                records = []
                for _ in range(int.from_bytes(body[6:8], 'big')):
                    if offset + 8 > len(body):
                        raise ValueError('truncated IGMP group record')
                    kind, auxiliary, sources = struct.unpack('!BBH', body[offset:offset + 4])
                    address = body[offset + 4:offset + 8]
                    end = offset + 8 + 4 * (sources + auxiliary)
                    if kind not in range(1, 7) or end > len(body):
                        raise ValueError('invalid IGMP group record')
                    records.append(dict(kind=kind, group=address.hex(), sources=sources))
                    if address == GROUP and kind == 2 and sources == 0 and self.pending == 200:
                        self.query_report = True
                    offset = end
                if offset != len(body):
                    raise ValueError('unconsumed IGMP report bytes')
                self.reports.append(dict(version=3, records=records))
            elif body[0] in (0x12, 0x16, 0x17):
                if len(body) != 8 or body[4:8] != GROUP:
                    raise ValueError('legacy IGMP group or length')
                self.reports.append(dict(version=1 if body[0] == 0x12 else 2, kind=body[0]))
                self.old_report |= body[0] == 0x16 and self.pending == 201
                self.leave |= body[0] == 0x17
            else:
                raise ValueError('unexpected IGMP message')
        elif ip[9] == 17:
            if len(body) < 8 or ip[16:20] != GROUP or frame[:6] != GROUP_MAC or ip[8] != 7:
                raise ValueError('actual UDP multicast destination or TTL')
            source, destination, length, check = struct.unpack('!HHHH', body[:8])
            if source != 46068 or destination != 46067 or length != len(body) or not check or checksum(self.guest_ip + GROUP + struct.pack('!BBH', 0, 17, length) + body):
                raise ValueError('actual multicast UDP ports, checksum or length')
            if body[8:] not in (b'AXMCO\x0a', b'AXMCO\x0b'):
                raise ValueError('unexpected multicast UDP payload')
            phase = body[-1]
            if phase in self.output:
                raise ValueError('duplicate multicast UDP output')
            self.output.append(phase)
        else:
            raise ValueError('unexpected IPv4 protocol during multicast test')
        return []

    def ready(self):
        phase = self.pending
        if phase is None:
            return []
        accepted = (phase in (10, 11) and phase in self.output) or (phase == 12 and time.monotonic() - self.pending_since >= .15) or (phase == 200 and self.query_report) or (phase == 201 and self.old_report) or (phase == 202 and self.leave)
        if not accepted:
            return []
        self.pending = None
        return [self.acknowledge(phase)]

    def result(self):
        expected = [1, 2, 3, 4, 5, 7, 8, 10, 11, 12, 200, 201, 202] if self.lane == 0 else [6, 9]
        return dict(lane=self.lane, passed=self.phases == expected and self.pending is None and
                    (self.lane == 1 or (self.output == [10, 11] and self.query_report and self.old_report and self.leave)),
                    phases=self.phases, reports=self.reports, output=self.output,
                    query_report=self.query_report, old_report=self.old_report, leave=self.leave)
