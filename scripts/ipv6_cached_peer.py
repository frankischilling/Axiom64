# SPDX-License-Identifier: GPL-3.0-or-later
"""Observe UDP cached-route reuse and raw fresh lookups on actual Ethernet."""
import hashlib
import ipaddress
import struct
import time
from ipv6_host_peer import Peer as HostPeer, checksum, require


def address(lane, host, scope):
    return ipaddress.IPv6Address(f'fe80::{host:x}' if scope else f'2001:db8:{lane + 1}::{host:x}').packed


def plan(number, lane):
    require(0 <= number < 64, 'bounded cached route case')
    scope, kind, form, variant = number // 32, 2 + number // 16 % 2, number // 8 % 2, number % 8
    mode = (3 if scope and kind == 2 else 2 if kind == 3 else 1) if form else 0
    first = 176 if variant == 0 else 160 if variant == 6 else 192 if variant == 7 else 128
    final = address(lane, 71, scope) if scope else ipaddress.IPv6Address(f'2001:db8:{0x91 + lane:x}::47').packed
    target = address(lane, first, scope)
    return dict(number=number, scope=scope, kind=kind, mode=mode, variant=variant,
                source=address(lane, 2, scope), target=target, final=final,
                effective=target if kind == 2 and variant in (1, 4, 5, 6) else final,
                hops=55 if variant == 5 else 64, traffic_class=0x25 if variant == 3 and mode else 0)


def routing(policy, lane):
    mode = 0 if policy['variant'] == 7 else policy['mode']
    size = (24, 24, 40, 64)[mode]
    left = (1, 0, 1, 2)[mode]
    value = bytearray(size)
    value[:8] = bytes((17 if policy['kind'] == 2 else 58, size // 8 - 1, 4 if mode else 2,
                       left, left if mode else 0, 0, 0, 0))
    for n in range((left if mode else 0) + 1):
        value[8 + n * 16:24 + n * 16] = address(lane, 77 + n, policy['scope'])
    at = 8 + (left * 16 if mode else 0)
    value[at:at + 16] = policy['target']
    value[8:24] = policy['effective']
    if mode == 3:
        value[56:] = bytes((30, 6)) + b'\x99' * 6
    return bytes(value)


class Peer(HostPeer):
    def __init__(self, lane, native=False):
        super().__init__(lane, native)
        self.phase = -1
        self.active = None
        self.pending = None
        self.completed = 0
        self.seeds = 0
        self.observe_input = None

    def ack(self, frame):
        reply = bytearray(frame)
        reply[:12] = self.guest + self.control
        reply[20] = 1
        self.outgoing.append(bytes(reply))

    def tick(self):
        item = self.active
        if self.pending is None or item is None or 'frame' not in item:
            return
        if item['seed']:
            if 'watch' not in item:
                source = address(self.lane, 250, item['scope'])
                body = b'\x02\0\0\0' + struct.pack('!I', 1400) + item['frame'][14:]
                packet = self.packet(source, address(self.lane, 2, item['scope']), body, 64)
                require(callable(self.observe_input), 'actual seed observation hook')
                item['watch'] = self.observe_input(packet)
                self.outgoing.append(packet)
                return
            observed = item['watch']()
            if observed is None or time.monotonic() - observed < .05:
                return
            self.seeds += 1
        else:
            self.completed += 1
        self.ack(self.pending)
        self.pending = self.active = None

    def receive(self, frame):
        require(len(frame) >= 14 and frame[6:12] == self.guest, 'cached-route Ethernet ownership')
        if frame[12:14] == b'\x88\xc6':
            require(len(frame) == 60 and frame[:6] == self.control and
                    frame[14:19] == b'IP6K' + bytes((self.lane,)) and not any(frame[20:]),
                    'exact cached route transaction envelope')
            phase = frame[19]
            require(phase == self.phase + 1 and phase <= 132 and self.pending is None,
                    'one ordered cached route phase')
            self.phase = phase
            if phase == 0:
                self.ready = True
            elif phase in (1, 67):
                require(self.active is None, 'one seed in flight')
                self.active = dict(seed=True, scope=int(phase == 67))
            elif phase % 2:
                require(self.active is None, 'one route send in flight')
                number = (phase - 3) // 2 if phase < 67 else 32 + (phase - 69) // 2
                require(number == self.completed, 'ordered original cached case')
                self.active = dict(seed=False, policy=plan(number, self.lane))
            else:
                require(self.active is not None, 'transaction end follows its begin')
                self.pending = frame
                self.tick()
                return
            self.ack(frame)
            return
        if not self.ready:
            require(not self.native and len(self.firmware_frames) < 256, 'bounded pre-client firmware')
            self.firmware_frames.append(hashlib.sha256(frame).hexdigest())
            return
        if self.native and len(frame) >= 78 and frame[12:14] == b'\x86\xdd' and frame[20] == 0:
            super().receive(frame)
            return
        require(len(frame) >= 54 and frame[12:14] == b'\x86\xdd', 'complete cached IPv6 packet')
        size, protocol, hops = struct.unpack_from('!HBB', frame, 18)
        require(len(frame) >= 54 + size and frame[14] >> 4 == 6, 'fixed original IPv6 envelope')
        source, target, body = frame[22:38], frame[38:54], frame[54:54 + size]
        if protocol == 58 and body[:1] == b'\x87':
            require(size == 32 and hops == 255, 'complete neighbor solicitation')
            destination = body[8:24]
            scope = destination[:2] == b'\xfe\x80'
            require(source == address(self.lane, 2, scope) and
                    destination in [address(self.lane, n, scope) for n in (128, 160, 176, 192)] and
                    target == self.multicast(destination) and body[24:] == b'\1\1' + self.guest and
                    not checksum(source + target + struct.pack('!I3xB', size, 58) + body),
                    'owned first-hop neighbor query')
            self.outgoing.append(self.na(destination, source))
            return
        item = self.active
        require(item is not None and 'frame' not in item and frame[:6] == self.mac, 'one original send per transaction')
        if item['seed']:
            scope = item['scope']
            require(frame[14:18] == b'\x60\0\0\0' and protocol == 17 and size == 40 and source == address(self.lane, 2, scope) and
                    target == address(self.lane, 128, scope) and hops == 64 and
                    struct.unpack_from('!HHH', body) == (55000 + scope, 57000, 40) and
                    body[8:] == bytes((n * 19 + self.lane) & 255 for n in range(32)) and
                    not checksum(source + target + struct.pack('!I3xB', 40, 17) + body),
                    'actual unchanged seed datagram')
        else:
            policy = item['policy']
            extension = routing(policy, self.lane)
            require(protocol == 43 and source == policy['source'] and target == policy['target'] and
                    frame[14:18] == struct.pack('!I', 0x60000000 | policy['traffic_class'] << 20) and
                    hops == policy['hops'] and body[:len(extension)] == extension,
                    'actual cached/fresh route, copied header and hop limit')
            body = body[len(extension):]
            transport = 17 if policy['kind'] == 2 else 58
            payload = bytes((n * 19 + policy['number'] * 7 + self.lane) & 255 for n in range(32))
            if transport == 17:
                require(len(body) == 40 and struct.unpack_from('!HHH', body) ==
                        (56000 + policy['number'], 57000, 40) and body[8:] == payload,
                        'every original cached UDP byte')
            else:
                require(len(body) == 32 and body[:2] == b'\x81\0' and body[4:] == payload[4:],
                        'every original cached raw byte')
            require(not checksum(source + policy['effective'] + struct.pack('!I3xB', len(body), transport) + body),
                    'checksum uses the effective cached or fresh destination')
        item['frame'] = frame[:54 + size]
        self.tick()

    @property
    def passed(self):
        return self.ready and self.phase == 132 and self.active is None and self.pending is None and self.completed == 64 and self.seeds == 2

    def result(self):
        return dict(passed=self.passed, lane=self.lane, cases=self.completed, seeds=self.seeds,
                    firmware_sha256=self.firmware_frames, native_MLD_reports=self.mld_reports)
