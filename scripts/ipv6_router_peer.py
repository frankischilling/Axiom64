# SPDX-License-Identifier: GPL-3.0-or-later
"""Controlled advertisements and independent Ethernet checks for IPv6 hosts."""
import hashlib
import ipaddress
import re
import struct
import time

from ipv6_host_peer import checksum, require


class Peer:
    def __init__(self, lane, native=False):
        self.lane, self.native = lane, native
        self.guest = bytes.fromhex(f'5254001234{16 + lane:02x}')
        self.mac = bytes([2, 0x49, 0x50, 0x36, lane, 1])
        self.control = bytes([2, ord('I'), ord('P'), ord('6'), lane, 0])
        identifier = bytes([self.guest[0] ^ 2]) + self.guest[1:3] + b'\xff\xfe' + self.guest[3:]
        self.link = ipaddress.IPv6Address('fe80::').packed[:8] + identifier
        self.router = ipaddress.IPv6Address('fe80::42').packed
        self.prefixes = {kind: ipaddress.IPv6Address(f'2001:db8:{0x40 + lane:x}:{kind:x}::').packed
                         for kind in (1, 2, 3, 4)}
        self.addresses = {kind: prefix[:8] + identifier for kind, prefix in self.prefixes.items()}
        self.remote = self.prefixes[2][:-1] + b'\x42'
        self.distant = ipaddress.IPv6Address('2001:db8:ffff::42').packed
        self.outgoing, self.output, self.flows = [], bytearray(), []
        self.ready, self.pending = False, None
        self.complete, self.rs, self.dad, self.udp, self.advertisements = [], [], [], [], []
        self.firmware, self.mld = [], []
        self.bad_sent = False
        self.mac_policy = None
        self.neighbor_retries = []
        self.retry_target = self.prefixes[1][:-1] + b'\x44'
        self.replacements = []
        self.started = time.monotonic_ns()

    def frame(self, source, destination, payload, hops=255, protocol=58):
        payload = bytearray(payload)
        if protocol == 58:
            payload[2:4] = bytes(2)
            struct.pack_into('!H', payload, 2, checksum(source + destination +
                struct.pack('!I3xB', len(payload), 58) + payload))
        mac = b'\x33\x33' + destination[-4:] if destination[0] == 255 else self.guest
        return mac + self.mac + b'\x86\xdd' + struct.pack('!IHBB', 6 << 28, len(payload), protocol, hops) + source + destination + payload

    def advertisement(self, lifetime=4, valid=8, preferred=2, hops=61, mtu=1300, prefixes=True,
                      source=None, bad_prefix=None, retransmit=0):
        body = bytearray(struct.pack('!BBHBBHII', 134, 0, 0, hops, 0, lifetime, 0, retransmit))
        body += b'\x01\x01' + self.mac
        if prefixes:
            for kind, flags in ((1, 0xc0), (2, 0x80), (3, 0x40), (4, 0)):
                prefix = bad_prefix if bad_prefix is not None else self.prefixes[kind]
                body += struct.pack('!BBBBIII16s', 3, 4, 64, flags, valid, preferred, 0, prefix)
        body += struct.pack('!BBHI', 5, 1, 0, mtu)
        return self.frame(source or self.router, ipaddress.IPv6Address('ff02::1').packed, body)

    def ack(self, phase):
        self.outgoing.append(self.guest + self.control + b'\x88\xbfIP6R' +
                             bytes([self.lane, phase, 1]) + bytes(39))
        self.complete.append(phase)
        self.pending = None

    def bad_advertisements(self):
        require(not self.bad_sent, 'one complete malformed advertisement cohort')
        self.bad_sent = True
        for kind in range(9):
            if kind == 7:
                continue
            prefix = ipaddress.IPv6Address(f'2001:db8:{0x40 + self.lane:x}:{100 + kind:x}::').packed
            frame = bytearray(self.advertisement(lifetime=60, valid=100, preferred=60,
                hops=17, bad_prefix=prefix, source=self.distant if kind == 0 else None))
            if kind == 1:
                frame[21] = 254
            elif kind == 2:
                frame[55] = 1
            elif kind == 3:
                frame[56] ^= 1
            elif kind == 4:
                frame += b'\x01'
                struct.pack_into('!H', frame, 18, len(frame) - 54)
            elif kind == 5:
                frame[79] = 0
            elif kind == 6:
                frame[71] = 2
            elif kind == 7:
                frame[72] |= 1
            if kind in (2, 4, 5, 6, 7):
                frame[56:58] = bytes(2)
                struct.pack_into('!H', frame, 56, checksum(bytes(frame[22:54]) +
                    struct.pack('!I3xB', len(frame) - 54, 58) + bytes(frame[54:])))
            if kind == 8:
                body = bytes([58, 0, 0, 0, 0, 0, 0, 1]) + bytes(frame[54:])
                frame = self.frame(self.router, bytes(frame[38:54]), body, protocol=44)
            self.outgoing.append(bytes(frame))
        if self.pending == 1:
            self.ack(1)

    def control_frame(self, frame):
        require(len(frame) == 60 and frame[:6] == self.control and
                frame[14:19] == b'IP6R' + bytes([self.lane]) and not any(frame[20:]),
                'exact router client barrier')
        phase = frame[19]
        require(phase == len(self.complete) and self.pending is None, 'ordered router client phases')
        if phase == 0:
            self.ready = True
            self.ack(0)
        elif phase == 1:
            if self.bad_sent:
                self.ack(1)
            else:
                self.pending = 1
        elif phase == 2:
            self.outgoing.append(self.advertisement(lifetime=0, prefixes=False, hops=48, mtu=1400))
            self.ack(2)
        elif phase == 3:
            require(len(self.rs) >= (1 if self.native else 2),
                    'zero-lifetime RA cannot stop RFC 7559 guest solicitation')
            if len(self.rs) >= 2:
                require(3.5e9 <= self.rs[1] - self.rs[0] <= 4.6e9,
                        'original four-second randomized solicitation interval')
            self.outgoing.append(self.advertisement())
            self.advertisements.append(dict(phase=phase, observed_ns=time.monotonic_ns(), valid=8, preferred=2, router=4))
            self.ack(3)
        elif phase == 4:
            require(self.udp == [2, 3, 4], 'all learned-parameter UDP exchanges precede lifetime checks')
            self.ack(4)
        elif phase == 5:
            require(time.monotonic_ns() - self.advertisements[0]['observed_ns'] >= 3.9e9,
                    'natural default expiry retains its real lifetime')
            self.outgoing.append(self.advertisement(lifetime=0, valid=0, preferred=0))
            self.ack(5)
        elif phase == 6:
            require(time.monotonic_ns() - self.advertisements[0]['observed_ns'] >= 7.9e9,
                    'finite address expiry retains its real eight-second lifetime')
            self.outgoing.append(self.advertisement(lifetime=0, valid=10000, preferred=6000))
            self.advertisements.append(dict(phase=phase, observed_ns=time.monotonic_ns(), valid=10000, preferred=6000, router=0))
            self.ack(6)
        elif phase == 7:
            self.outgoing.append(self.advertisement(lifetime=0, valid=0, preferred=0))
            self.ack(7)
        elif phase == 8:
            self.ack(8)
        elif phase == 9:
            prefix = ipaddress.IPv6Address(f'2001:db8:{0x40 + self.lane:x}:6b::').packed
            frame = bytearray(self.advertisement(lifetime=60, valid=100, preferred=60,
                hops=17, bad_prefix=prefix))
            frame[72] |= 1
            frame[56:58] = bytes(2)
            struct.pack_into('!H', frame, 56, checksum(bytes(frame[22:54]) +
                struct.pack('!I3xB', len(frame) - 54, 58) + bytes(frame[54:])))
            self.outgoing.append(bytes(frame))
            self.ack(9)
        elif phase == 10:
            if self.mac_policy is None:
                self.pending = 10
            else:
                self.ack(10)
        elif phase in range(11, 17):
            self.pending = phase
            self.replacement_ready()
        elif phase == 17:
            self.outgoing.append(self.advertisement(lifetime=0, prefixes=False,
                                                   retransmit=2000 + self.lane * 1000))
            self.ack(phase)
        elif phase == 18:
            require(self.udp == [2, 3, 4, 5] and len(self.neighbor_retries) == 2,
                    'actual delayed neighbor resolution and UDP completion')
            self.ack(phase)
        else:
            raise ValueError('unknown router phase')

    def replacement_ready(self):
        phase = self.pending
        if phase not in range(11, 17) or len(self.replacements) != phase - 10:
            return
        if phase in (11, 14):
            self.outgoing.append(self.advertisement(lifetime=0, valid=0, preferred=0))
        elif phase in (12, 15):
            self.outgoing.append(self.advertisement(lifetime=0, valid=100, preferred=60))
        self.ack(phase)

    def line(self, line):
        if line.startswith(f'IPV6_ROUTER_REPLACEMENT lane={self.lane} '.encode()):
            match = re.fullmatch(rb'IPV6_ROUTER_REPLACEMENT lane=([01]) phase=(replaced|zero|finite|readded|readd-zero|readd-finite) '
                rb'flags=([0-9a-f]+) preferred=(\d+) valid=(\d+) prefix_routes=1 prefix_permanent=1',
                line.strip())
            require(match is not None and len(self.replacements) < 6, 'actual replacement metadata')
            phase, flags, preferred, valid = match.group(2).decode(), int(match.group(3), 16), int(match.group(4)), int(match.group(5))
            expected = (('replaced', 0x82, 4294967295, 4294967295), ('zero', 0xa2, 0, 7200), ('finite', 0x82, 60, 7200), ('readded', 0x82, 4294967295, 4294967295),
                        ('readd-zero', 0xa2, 0, 7200), ('readd-finite', 0x82, 60, 7200))[len(self.replacements)]
            require((phase, flags) == expected[:2] and expected[2] - (2 if expected[2] == 60 else 0) <= preferred <= expected[2] and
                    expected[3] - (0 if expected[3] == 4294967295 else 2) <= valid <= expected[3],
                    'Linux replacement flags, preferred time and two-hour valid lifetime')
            self.replacements.append(dict(phase=phase, flags=flags, preferred=preferred, valid=valid))
            self.replacement_ready()
            return
        prefix = f'IPV6_ROUTER_MAC_POLICY lane={self.lane} installed='.encode()
        if not line.startswith(prefix):
            return
        value = line[len(prefix):].strip()
        require(value in (b'0', b'1') and self.mac_policy is None,
                'one actual multicast source-link-layer acceptance observation')
        self.mac_policy = value == b'1'
        require(self.mac_policy == self.native,
                'measured Linux 6/7 acceptance and strict guest MAC rejection remain explicit')
        if self.pending == 10:
            self.ack(10)

    def receive(self, frame):
        require(len(frame) >= 14 and frame[6:12] == self.guest, 'router Ethernet source')
        if frame[12:14] == b'\x88\xbf':
            self.control_frame(frame)
            return
        if not self.ready:
            require(len(self.firmware) < 256, 'bounded router firmware prelude')
            self.firmware.append(hashlib.sha256(frame).hexdigest())
            return
        require(frame[12:14] == b'\x86\xdd' and len(frame) >= 54, 'router fixture emits IPv6')
        length, protocol, hops = struct.unpack_from('!HBB', frame, 18)
        require(frame[14] >> 4 == 6 and len(frame) >= 54 + length, 'bounded router IPv6 packet')
        source, destination = frame[22:38], frame[38:54]
        body = frame[54:54 + length]
        if self.native and protocol == 0 and len(body) >= 16 and body[0] == 58 and body[1] == 0:
            payload = body[8:]
            require(hops == 1 and destination[0] == 255 and payload[0] in (131, 132, 143) and
                not checksum(source + destination + struct.pack('!I3xB', len(payload), 58) + payload),
                'native multicast report fields and checksum')
            self.mld.append(hashlib.sha256(frame).hexdigest())
            return
        require(protocol in (17, 58) and not checksum(source + destination +
                struct.pack('!I3xB', len(body), protocol) + body), 'router upper-layer checksum')
        if protocol == 17:
            require(len(body) == 24 and body[:4] == struct.pack('!HH', 47000 + self.lane, 47001) and
                    int.from_bytes(body[4:6], 'big') == len(body) and body[6:8] != bytes(2),
                    'router UDP lengths and ports')
            phase = body[13]
            expected = b'RATR' + bytes([self.lane, phase]) + bytes(at * 7 + phase for at in range(6, 16))
            require(phase in (2, 3, 4, 5) and phase not in self.udp and body[8:] == expected and
                    source == (self.link if phase == 2 else self.addresses[1]) and
                    destination == (self.router if phase == 2 else self.distant if phase == 3 else self.retry_target if phase == 5 else self.remote) and
                    hops == (48 if phase == 2 else 61) and frame[:6] == self.mac,
                    'actual generated source, learned hop limit and selected next hop')
            self.udp.append(phase)
            reply = bytearray(struct.pack('!HHHH', 47001, 47000 + self.lane, len(body), 0) + body[8:])
            struct.pack_into('!H', reply, 6, checksum(destination + source +
                struct.pack('!I3xB', len(reply), 17) + reply) or 65535)
            self.outgoing.append(self.frame(destination, source, reply, hops=64, protocol=17))
            return
        require(hops == 255 and body[1] == 0, 'router neighbor-control hop and code')
        if body[0] == 133:
            require(source == self.link and destination == ipaddress.IPv6Address('ff02::2').packed and
                    len(body) == 16 and body[4:8] == bytes(4) and body[8:] == b'\x01\x01' + self.guest,
                    'router solicitation source and source-link-layer option')
            self.rs.append(time.monotonic_ns())
            if not self.bad_sent:
                self.bad_advertisements()
        elif body[0] == 135:
            require(len(body) >= 24, 'complete router neighbor solicitation')
            target = body[8:24]
            if source == bytes(16):
                extra = (self.native and 9 in self.complete and target ==
                    ipaddress.IPv6Address(f'2001:db8:{0x40 + self.lane:x}:6b::').packed[:8] + self.link[8:])
                require((target in (self.link, self.addresses[1], self.addresses[3]) or extra) and
                        len(body) == 32 and body[24:26] == b'\x0e\x01' and
                        destination == b'\xff\x02' + bytes(9) + b'\x01\xff' + target[-3:] and
                        frame[:6] == b'\x33\x33\xff' + target[-3:],
                        'enhanced DAD target, nonce and solicited-node destination')
                self.dad.append(dict(target=target.hex(), nonce=body[26:].hex(), observed_ns=time.monotonic_ns()))
            else:
                require(target in (self.router, self.remote, self.retry_target) and source in
                        (self.link, self.addresses[1], self.addresses[3]) and
                        len(body) == 32 and body[24:] == b'\x01\x01' + self.guest,
                        'owned next-hop neighbor resolution')
                if target == self.retry_target:
                    require(17 in self.complete and source == self.addresses[1] and
                            destination == b'\xff\x02' + bytes(9) + b'\x01\xff' + target[-3:] and
                            frame[:6] == b'\x33\x33\xff' + target[-3:],
                            'per-interface unresolved neighbor fields')
                    self.neighbor_retries.append(time.monotonic_ns())
                    require(len(self.neighbor_retries) <= 2, 'one initial solicitation and one retry')
                    if len(self.neighbor_retries) == 1:
                        return
                    expected = (2000 + self.lane * 1000) * 1000000
                    elapsed = self.neighbor_retries[1] - self.neighbor_retries[0]
                    require(expected - 20000000 <= elapsed <= expected + 500000000,
                            'actual per-interface advertised neighbor retransmission interval')
                flags = 0xe0 if target == self.router else 0x60
                self.outgoing.append(self.frame(target, source, b'\x88\0\0\0' +
                    bytes([flags, 0, 0, 0]) + target + b'\x02\x01' + self.mac))
        else:
            raise ValueError('unexpected router ICMPv6 output')

    def result(self):
        counts = {target.hex():sum(row['target'] == target.hex() for row in self.dad)
                  for target in (self.link, self.addresses[1], self.addresses[3])}
        passed = (self.complete == list(range(19)) and len(self.replacements) == 6 and self.udp == [2, 3, 4, 5] and len(self.neighbor_retries) == 2 and self.bad_sent and
                  self.mac_policy == self.native and
                  counts[self.link.hex()] == 1 and counts[self.addresses[1].hex()] == 2 and
                  counts[self.addresses[3].hex()] == 2 and len(self.rs) >= (1 if self.native else 2))
        return dict(passed=passed, lane=self.lane, phases=self.complete, UDP=self.udp,
                    malformed_advertisements=8 if self.bad_sent else 0,
                    multicast_source_link_layer_installed=self.mac_policy,
                    multicast_source_link_layer_cases=1 if 9 in self.complete else 0, solicitations_ns=self.rs,
                    dad=self.dad, dad_counts=counts, advertisements=self.advertisements, replacements=self.replacements,
                    neighbor_retries_ns=self.neighbor_retries, retransmit_milliseconds=2000 + self.lane * 1000,
                    native_zero_lifetime_RA_stopped_solicitation=self.native and len(self.rs) == 1,
                    firmware_frames=self.firmware, native_MLD=self.mld, packet_clock_qualified=False)
