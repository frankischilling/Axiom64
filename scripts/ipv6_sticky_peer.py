# SPDX-License-Identifier: GPL-3.0-or-later
"""Observe copied sticky headers and source fragments on actual Ethernet."""
import ipaddress
import struct
import time
from ipv6_host_peer import Peer as HostPeer, checksum, require


def plan(sequence, lane):
    require(0 <= sequence < 80, 'bounded sticky wire sequence')
    variant, scope, kind = sequence % 20, sequence // 20 % 2, 2 + sequence // 40
    mode = 1 if variant in (1, 9, 10, 13, 14) else 2 if variant == 2 else 3 if variant in (3, 8) else 0
    has_route = variant not in (5, 6, 7, 15, 16)
    selected = 0 if variant == 4 else mode
    hop = 0 if variant in (4, 5, 7, 15, 19) else 8
    before = 8 if has_route and variant != 4 else 0
    destination = 0 if variant in (4, 6, 7, 15, 19) else 8
    source = ipaddress.IPv6Address('fe80::2' if scope else f'2001:db8:{lane + 1}::2').packed
    final = ipaddress.IPv6Address('fe80::47' if scope else f'2001:db8:{0x91 + lane:x}::47' if has_route else f'2001:db8:{lane + 1}::47').packed
    first = 240 + sequence // 20 * 4 if variant == 9 else 1
    target = ipaddress.IPv6Address(f'fe80::{first:x}' if scope else f'2001:db8:{lane + 1}::{first:x}').packed if has_route else final
    return dict(variant=variant, scope=scope, kind=kind, size=16384 if variant == 9 else 2048 if variant in (8, 10) else 128,
                error=90 if variant == 10 else 1 if variant == 14 else 22 if variant in (11, 12) else 0,
                mode=selected, route=24 if selected in (0, 2) else 40 if selected == 1 else 64,
                has_route=has_route, hop=hop, before=before, destination=destination,
                hop_value=0x44 if variant in (6, 11, 14) else 0x11,
                destination_value=0x66 if variant in (5, 17) else 0x55,
                source=source, target=target, final=final, fragmented=variant in (8, 9), lane=lane)


def route_bytes(policy, following):
    mode = policy['mode']
    length = policy['route']
    result = bytearray(length)
    result[:8] = bytes([following, length // 8 - 1, 4 if mode else 2,
                       0 if mode == 2 else 2 if mode == 3 else 1,
                       0 if mode == 2 else 2 if mode == 3 else 1 if mode else 0x71,
                       0 if mode else 0x72, 0x73, 0x74])
    if not mode and policy['variant'] == 4:
        result[4:8] = bytes([0x81, 0x82, 0x83, 0x84])
    for n in range(result[4] + 1 if mode else 1):
        address = ipaddress.IPv6Address(f'fe80::{77 + n:x}' if policy['scope'] else f"2001:db8:{policy['lane'] + 1}::{77 + n:x}").packed
        result[8 + n * 16:24 + n * 16] = address
    if mode:
        at = 8 + result[3] * 16
        result[at:at + 16] = policy['target']
    result[8:24] = policy['final']
    if mode == 3:
        result[56:] = bytes([0x1e, 6]) + b'\x9a' * 6
    return bytes(result)


def header(length, value, following):
    return bytes((following, length // 8 - 1, 0x1e, length - 4)) + bytes([value]) * (length - 4)


class Peer(HostPeer):
    def __init__(self, lane, native=False):
        super().__init__(lane, native)
        self.active = None
        self.completed = 0
        self.identities = set()
        self.fragments = 0
        self.quiet = []

    def reply(self, frame):
        reply = bytearray(frame)
        reply[:6], reply[6:12] = self.guest, self.control
        reply[20] = 1
        self.outgoing.append(bytes(reply))

    def finish(self):
        item = self.active
        if item is None or 'end' not in item:
            return
        if item['policy']['error']:
            elapsed = time.monotonic() - item['end_time']
            if elapsed < .05:
                return
            self.quiet.append(elapsed)
        elif not item['done']:
            return
        self.reply(item['end'])
        self.completed += 1
        self.active = None

    def release_neighbor(self):
        item = self.active
        if item is not None and 'mutation' in item and 'neighbor' in item and not item.get('released'):
            self.reply(item['mutation'])
            self.outgoing.append(self.na(*item['neighbor']))
            item['released'] = True

    def tick(self):
        self.finish()

    def receive(self, frame):
        require(len(frame) >= 14 and frame[6:12] == self.guest, 'sticky sender interface MAC')
        if frame[12:14] == b'\x88\xc3':
            require(len(frame) == 60 and frame[:6] == self.control and
                    frame[14:19] == b'IP6S' + bytes([self.lane]) and not any(frame[20:]),
                    'exact sticky phase envelope')
            phase = frame[19]
            if phase >= 193:
                item = self.active
                require(item is not None and item['policy']['variant'] == 9 and
                        phase == 193 + item['sequence'] // 20 and 'mutation' not in item,
                        'one sticky mutation after copied inputs and closed owners')
                item['mutation'] = frame
                self.release_neighbor()
            elif not self.ready:
                require(phase == 0, 'sticky phase readiness')
                self.ready = True
                self.reply(frame)
            elif phase == self.completed * 2 + 1:
                require(self.active is None, 'one sticky send in progress')
                self.active = dict(sequence=self.completed, policy=plan(self.completed, self.lane),
                                   data=bytearray(), identity=None, done=False)
                self.reply(frame)
            else:
                require(self.active is not None and phase == self.completed * 2 + 2 and
                        'end' not in self.active, 'one sticky send completion request')
                self.active.update(end=frame, end_time=time.monotonic())
                self.finish()
            return
        require(self.ready and frame[12:14] == b'\x86\xdd' and len(frame) >= 54,
                'complete sticky IPv6 frame')
        if self.native and frame[38:54] == ipaddress.IPv6Address('ff02::16').packed:
            super().receive(frame)
            return
        size, protocol, hop = struct.unpack_from('!HBB', frame, 18)
        require(len(frame) >= 54 + size, 'complete original sticky packet')
        source, target, body = frame[22:38], frame[38:54], frame[54:54 + size]
        if protocol == 58 and body[:1] == b'\x87':
            destination = body[8:24]
            scoped_peer = ipaddress.IPv6Address('fe80::1').packed
            deferred = self.active is not None and self.active['policy']['variant'] == 9 and destination == self.active['policy']['target']
            group = self.multicast(destination)
            require(frame[14:18] == b'\x60\0\0\0' and hop == 255 and len(body) == 32 and
                    source in (self.local, self.link) and (destination in (self.remote, scoped_peer) or self.active is not None and destination == self.active['policy']['target']) and
                    body[:2] == b'\x87\0' and not any(body[4:8]) and body[24:] == b'\1\1' + self.guest and
                    (target == group and frame[:6] == b'\x33\x33' + group[-4:] or target == destination and frame[:6] == self.mac) and
                    not checksum(source + target + struct.pack('!I3xB', len(body), 58) + body),
                    'sticky neighbor resolution envelope')
            if deferred:
                require(not self.active.get('released'), 'sticky neighbor withheld until owner retirement')
                self.active['neighbor'] = destination, source
                self.release_neighbor()
            else:
                self.outgoing.append(self.na(destination, source))
            return
        item = self.active
        require(item is not None and not item['policy']['error'] and not item['done'],
                'sticky data belongs to one accepted call')
        policy = item['policy']
        require(policy['variant'] != 9 or item.get('released'), 'sticky data follows actual neighbor release')
        transport = 17 if policy['kind'] == 2 else 58
        after_route = 44 if policy['fragmented'] else 60 if policy['destination'] else transport
        following = 60 if policy['before'] else 43 if policy['has_route'] else after_route
        require(frame[:6] == self.mac and source == policy['source'] and target == policy['target'] and
                int.from_bytes(frame[14:18], 'big') == 6 << 28 | 0xcd << 20 and hop == 47 and size + 40 <= 1500,
                'sticky source, route, class, hop and actual MTU')
        if policy['hop']:
            require(protocol == 0 and body[:8] == header(8, policy['hop_value'], following),
                    'all copied sticky Hop-by-Hop bytes')
            protocol, body = body[0], body[8:]
        if policy['before']:
            require(protocol == 60 and body[:8] == header(8, 0x22, 43), 'copied sticky pre-routing options')
            protocol, body = body[0], body[8:]
        if policy['has_route']:
            require(protocol == 43 and body[:policy['route']] == route_bytes(policy, after_route),
                    'all original type-2/type-4 route addresses, tags and TLV bytes')
            protocol, body = body[0], body[policy['route']:]
        if policy['fragmented']:
            require(protocol == 44 and len(body) > 8, 'Fragment header follows copied Hop-by-Hop and Destination options')
            next_header, reserved, offset, identity = struct.unpack_from('!BBHI', body)
            require(next_header == (60 if policy['destination'] else transport) and not reserved and
                    identity and not offset & 6 and offset & 0xfff8 == len(item['data']),
                    'original sticky fragment chain and contiguous offsets')
            if item['identity'] is None:
                require((source, target, identity) not in self.identities, 'fresh sticky fragment identity')
                self.identities.add((source, target, identity))
                item['identity'] = identity
            require(item['identity'] == identity and len(item['data']) + len(body) - 8 <=
                    policy['destination'] + policy['size'] + (8 if transport == 17 else 0),
                    'bounded copied sticky datagram')
            item['data'].extend(body[8:])
            self.fragments += 1
            if offset & 1:
                require((len(body) - 8) % 8 == 0, 'aligned nonfinal sticky fragment')
                return
            protocol, body = next_header, bytes(item['data'])
        else:
            require(protocol != 44 and not item['data'], 'small sticky send remains unfragmented')
        if policy['destination']:
            require(protocol == 60 and body[:8] == header(8, policy['destination_value'], transport),
                    'copied final Destination options in reconstructed transport')
            protocol, body = body[0], body[8:]
        require(protocol == transport and not checksum(source + policy['final'] + struct.pack('!I3xB', len(body), transport) + body),
                'sticky transport excludes sticky bytes from its pseudo-header checksum')
        payload = bytes((n * 23 + item['sequence'] * 13 + self.lane) & 255 for n in range(policy['size']))
        if transport == 17:
            require(len(body) == policy['size'] + 8 and struct.unpack_from('!HHH', body) ==
                    (53000 + self.lane + policy['scope'] * 10, 54000 + self.lane + policy['scope'] * 10, len(body)) and
                    body[6:8] != bytes(2) and body[8:] == payload, 'every original sticky UDP byte')
        else:
            require(len(body) == policy['size'] and body[:2] + bytes(2) + body[4:] == b'\x81\0\0\0' + payload[4:],
                    'every original sticky raw byte')
        item['done'] = True
        self.finish()

    @property
    def passed(self):
        return self.ready and self.completed == 80 and self.active is None

    def result(self):
        return dict(passed=self.passed, lane=self.lane, cases=self.completed,
                    fragment_groups=len(self.identities), fragments=self.fragments,
                    quiet_intervals=self.quiet, native_MLD_reports=self.mld_reports)
