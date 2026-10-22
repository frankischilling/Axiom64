# SPDX-License-Identifier: GPL-3.0-or-later
"""Controlled peers for actual guest IPv6 DAD, ND and unicast echo."""
import hashlib
import ipaddress
import struct


def require(value, reason):
    if not value:
        raise ValueError(reason)


def checksum(data):
    if len(data) % 2:
        data += b'\0'
    total = sum(struct.unpack('!' + 'H' * (len(data) // 2), data))
    while total >> 16:
        total = (total & 65535) + (total >> 16)
    return (~total) & 65535


class Peer:
    def __init__(self, lane, native=False):
        self.lane = lane
        self.native = native
        self.mld_reports = 0
        self.maintenance_probes = 0
        self.guest = bytes([0x52, 0x54, 0, 0x12, 0x34, 0x10 + lane])
        self.mac = bytes([2, 0x49, 0x50, 0x36, lane, 1])
        self.control = bytes([2, ord('I'), ord('P'), ord('6'), lane, 0])
        self.local = ipaddress.IPv6Address(f'2001:db8:{lane + 1}::2').packed
        self.remote = ipaddress.IPv6Address(f'2001:db8:{lane + 1}::1').packed
        self.unknown = ipaddress.IPv6Address(f'2001:db8:{lane + 1}::77').packed
        self.unresolved = ipaddress.IPv6Address(f'2001:db8:{lane + 1}::88').packed
        self.duplicate = ipaddress.IPv6Address(f'2001:db8:{lane + 1}::3').packed
        self.link = ipaddress.IPv6Address('fe80::2').packed
        self.all_nodes = ipaddress.IPv6Address('ff02::1').packed
        self.outgoing, self.output, self.flows = [], bytearray(), []
        self.phase = 0
        self.ready = False
        self.firmware_frames = []
        self.complete = []
        self.dad = []
        self.duplicate_seen = False
        self.wait = None
        self.records = []
        from ipv6_lifetime_peer import LifetimePeer
        self.lifetimes = LifetimePeer(self)
        from ipv6_queued_sources_peer import QueuedSourcesPeer
        self.queued_sources = QueuedSourcesPeer(self)

    def multicast(self, target):
        return b'\xff\x02' + b'\0' * 9 + b'\1\xff' + target[-3:]

    def packet(self, source, destination, payload, hop=255, next_header=58):
        payload = bytearray(payload)
        if next_header == 58:
            payload[2:4] = b'\0\0'
            struct.pack_into('!H', payload, 2, checksum(source + destination +
                             struct.pack('!I3xB', len(payload), 58) + payload))
        mac = b'\x33\x33' + destination[-4:] if destination[0] == 255 else self.guest
        return (mac + self.mac + b'\x86\xdd' +
                struct.pack('!IHBB', 6 << 28, len(payload), next_header, hop) +
                source + destination + payload)

    def ns(self, source=None, target=None, hop=255):
        return self.packet(source or self.remote, self.multicast(target or self.local),
            b'\x87\0\0\0' + bytes(4) + (target or self.local) + b'\1\1' + self.mac, hop)

    def na(self, target, destination):
        return self.packet(target, destination, b'\x88\0\0\0' +
            bytes([0x20 if destination[0] == 255 else 0x60, 0, 0, 0]) + target + b'\2\1' + self.mac)

    def echo(self, source=None):
        data = bytes((n * 17 + self.lane + self.phase) & 255 for n in range(101))
        self.expected = b'\x81\0' + bytes(2) + data[4:]
        return self.packet(source or self.remote, self.local, b'\x80\0' + bytes(2) + data[4:], 64)

    def ack(self):
        if self.phase:
            self.complete.append(self.phase)
        self.outgoing.append(self.guest + self.control + b'\x88\xb6IP6H' +
                             bytes([self.lane, self.phase, 1]) + bytes(39))
        self.wait = None

    def receive(self, frame):
        require(len(frame) >= 14 and frame[6:12] == self.guest, 'actual guest interface source MAC')
        if self.queued_sources.receive(frame):
            require(self.complete == [1, 2, 3, 4, 5] and self.lifetimes.passed and self.wait is None,
                    'queued-source cohort follows every original host and lifetime phase')
            return
        if frame[12:14] == b'\x88\xb6':
            require(len(frame) == 60 and frame[:6] == self.control and
                    frame[14:19] == b'IP6H' + bytes([self.lane]) and not any(frame[20:]),
                    'exact IPv6 client phase ownership')
            phase = frame[19]
            if not self.ready:
                require(phase == 0, 'explicit client readiness precedes address assignment')
                self.ready = True
                self.ack()
                return
            require(phase == self.phase + 1 and self.wait is None, 'ordered completed phases')
            self.phase = phase
            if phase == 1:
                require(set(self.dad) == {self.local.hex(), self.link.hex()}, 'both real DAD probes')
                self.wait = 'NA'
                self.outgoing.append(self.ns())
            elif phase == 2:
                self.wait = 'NS'
                self.outgoing.append(self.echo(self.unknown))
            elif phase == 3:
                # Every invalid request uses its own return address, so any
                # erroneous advertisement cannot impersonate the valid barrier.
                for kind in range(5):
                    source = bytearray(self.remote)
                    source[-1] = 40 + kind
                    bad = bytearray(self.ns(bytes(source), hop=254 if kind == 0 else 255))
                    if kind == 1:
                        bad[-1] ^= 1
                    elif kind == 2:
                        bad[55] = 1
                    elif kind == 3:
                        bad[79] = 0
                    elif kind == 4:
                        body = bytes([58, 0, 0, 0, 0, 0, 0, 1]) + bytes(bad[54:])
                        bad = bytearray(self.packet(bytes(source), self.multicast(self.local),
                                                    body, next_header=44))
                    if kind in (2, 3):
                        bad[56:58] = b'\0\0'
                        body = bytes(bad[54:])
                        struct.pack_into('!H', bad, 56, checksum(bytes(source) + bytes(bad[38:54]) +
                                         struct.pack('!I3xB', len(body), 58) + body))
                    self.outgoing.append(bytes(bad))
                self.wait = 'NA-invalid-barrier'
                self.outgoing.append(self.ns())
            elif phase == 4:
                require(self.duplicate_seen, 'actual duplicate conflict was observed')
                self.wait = 'NA-duplicate-barrier'
                self.outgoing += [self.ns(target=self.duplicate), self.ns()]
            elif phase == 5:
                self.wait = 'NS-no-SLLA'
                self.outgoing.append(self.packet(self.unresolved, self.local,
                    b'\x87\0\0\0' + bytes(4) + self.local))
            else:
                raise ValueError('unknown IPv6 phase')
            return
        if not self.ready and not self.native:
            require(len(self.firmware_frames) < 256, 'bounded firmware network prelude')
            self.firmware_frames.append(hashlib.sha256(frame).hexdigest())
            return
        if frame[12:14] != b'\x86\xdd':
            return
        if self.lifetimes.receive(frame):
            require(self.complete == [1, 2, 3, 4, 5] and self.wait is None,
                    'lifetime traffic follows all original host phases')
            return
        if self.native and len(frame) >= 78 and frame[20] == 0:
            size = int.from_bytes(frame[18:20], 'big')
            payload = frame[62:54 + size]
            destination = ipaddress.IPv6Address('ff02::16').packed
            require(frame[:6] == b'\x33\x33\0\0\0\x16' and frame[21] == 1 and
                    len(frame) >= size + 54 and frame[14:18] == b'\x60\0\0\0' and
                    frame[22:38] in (bytes(16), self.link) and
                    frame[38:54] == destination and frame[54:62] == b'\x3a\0\5\2\0\0\1\0' and
                    payload[:2] == b'\x8f\0' and not checksum(frame[22:54] +
                    struct.pack('!I3xB', len(payload), 58) + payload), 'native MLD report envelope')
            require(len(payload) >= 8, 'native MLD report header')
            self.mld_reports += 1
            return
        require(len(frame) >= 54 and frame[14] == 0x60 and frame[15:18] == bytes(3),
                'IPv6 fixed version, traffic class and flow')
        length, protocol, hop = struct.unpack('!HBB', frame[18:22])
        require(54 + length <= len(frame) and protocol == 58, 'complete original ICMPv6 frame')
        source, destination = frame[22:38], frame[38:54]
        payload = frame[54:54 + length]
        require(len(payload) >= 8 and not checksum(source + destination +
                struct.pack('!I3xB', length, 58) + payload), 'actual ICMPv6 pseudo-header checksum')
        require(payload[1] == 0, 'zero ICMPv6 code')
        self.records.append(dict(type=payload[0], source=source.hex(), destination=destination.hex()))
        if self.native and payload[0] == 135 and destination == payload[8:24]:
            learned = {target for phase, target in ((1, self.remote), (2, self.unknown),
                                                   (5, self.unresolved)) if phase in self.complete}
            require(hop == 255 and length == 32 and frame[:6] == self.mac and
                    source in (self.local, self.link) and
                    destination in learned and
                    payload[4:8] == bytes(4) and payload[24:] == b'\1\1' + self.guest,
                    'owned native unicast neighbor maintenance probe')
            self.maintenance_probes += 1
            require(self.maintenance_probes <= 9, 'bounded native neighbor maintenance')
            self.outgoing.append(self.na(destination, source))
            return
        if payload[0] == 135:
            target = payload[8:24]
            require(hop == 255 and destination == self.multicast(target) and
                    frame[:6] == b'\x33\x33' + destination[-4:], 'NS hop, target and multicast MAC')
            if source == bytes(16):
                require(length == 24, 'DAD has no source link-layer option')
                if target == self.duplicate:
                    self.duplicate_seen = True
                    self.outgoing.append(self.na(target, self.all_nodes))
                else:
                    require(target in (self.local, self.link), 'configured DAD target')
                    self.dad.append(target.hex())
            else:
                bare = self.wait == 'NS-no-SLLA'
                require(self.wait in ('NS', 'NS-no-SLLA') and
                        target == (self.unresolved if bare else self.unknown) and source == self.local and
                        length == 32 and payload[24:] == b'\1\1' + self.guest,
                        'pending echo triggers owned neighbor resolution')
                self.wait = 'NA-resolved' if bare else 'echo-unknown'
                self.outgoing.append(self.na(target, self.local))
        elif payload[0] == 136:
            require(self.wait in ('NA', 'NA-invalid-barrier', 'NA-duplicate-barrier', 'NA-resolved') and
                    source == self.local and destination == (self.unresolved if self.wait == 'NA-resolved'
                                                            else self.remote) and hop == 255 and
                    payload[4:8] == (b'\x40\0\0\0' if self.wait == 'NA-resolved' else b'\x60\0\0\0') and
                    payload[8:24] == self.local and
                    payload[24:] == (b'' if self.wait == 'NA-resolved' else b'\2\1' + self.guest) and
                    frame[:6] == self.mac,
                    'only the exact valid solicitation receives an advertisement')
            if self.wait == 'NA':
                self.wait = 'echo'
                self.outgoing.append(self.echo())
            else:
                self.ack()
        elif payload[0] == 129:
            expected_destination = self.unknown if self.wait == 'echo-unknown' else self.remote
            require(self.wait in ('echo', 'echo-unknown') and hop == 64 and source == self.local and
                    destination == expected_destination and frame[:6] == self.mac and
                    payload[:2] + bytes(2) + payload[4:] == self.expected,
                    'exact original kernel-generated echo reply')
            self.ack()
        else:
            raise ValueError('unexpected guest ICMPv6 output')

    @property
    def passed(self):
        return (self.ready and self.complete == [1, 2, 3, 4, 5] and self.duplicate_seen and
                self.lifetimes.passed and self.queued_sources.passed)

    def result(self):
        return dict(passed=self.passed, lane=self.lane, phases=self.complete,
                    dad=self.dad, duplicate=self.duplicate_seen, packets=self.records,
                    firmware_frames=len(self.firmware_frames), firmware_sha256=self.firmware_frames,
                    native_MLD_reports=self.mld_reports, native_maintenance_probes=self.maintenance_probes,
                    lifetimes=self.lifetimes.result(), queued_sources=self.queued_sources.result())
