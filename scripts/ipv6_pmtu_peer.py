# SPDX-License-Identifier: GPL-3.0-or-later
"""Controlled routers quote actual IPv6 datagrams and observe subsequent output."""
import struct
import time
from ipv6_host_peer import Peer as HostPeer, checksum, require


def plan(sequence):
    require(0 <= sequence < 60, 'bounded PMTU case')
    if sequence < 24:
        return sequence // 12 + 2, sequence % 12 // 6, sequence % 6, 2, 0
    if sequence < 50:
        n = (sequence - 24) % 13
        types = (1,) * 8 + (3, 3, 4, 4, 4)
        codes = (0, 1, 2, 3, 4, 5, 6, 7, 0, 1, 0, 1, 2)
        return (sequence - 24) // 13 + 2, 0, 1, types[n], codes[n]
    return (sequence - 50) // 5 + 2, 0, 1, 1, 4


class Peer(HostPeer):
    barrier_protocol = b'\x88\xba'
    barrier_magic = b'IP6P'
    quote_length = 48

    def __init__(self, lane, native=False):
        super().__init__(lane, native)
        self.sequence = 0
        self.active = None
        self.phase = 0
        self.quiet = []
        self.fragments = 0
        self.observe_input = None

    def reply(self, request):
        response = bytearray(request)
        response[:6], response[6:12] = self.guest, self.control
        response[20] = 1
        self.outgoing.append(bytes(response))

    def tick(self):
        item = self.active
        if item is None or 'boundary' not in item:
            return
        phase = item['boundary'][19] % 3
        if phase == 2 and 'original' in item and 'observation' not in item:
            quote = bytearray(item['original'][14:14 + self.quote_length])
            sequence = self.sequence
            if sequence >= 50:
                damage = (sequence - 50) % 5
                if damage == 1:
                    quote[23] ^= 64
                elif damage == 2:
                    quote[39] ^= 64
                elif damage == 3:
                    quote = quote[:47]
                elif damage == 4:
                    quote[6] = 44
                    quote[4:6] = (int.from_bytes(quote[4:6], 'big') + 8).to_bytes(2, 'big')
                    quote[40:40] = bytes([item['protocol'], 0, 0, 8, 0, 0, 0, 1])
            kind, scoped, mode, typ, code = plan(sequence)
            body = bytes([typ, code, 0, 0]) + struct.pack('!I', 1280 if typ == 2 else 0) + quote
            router = bytearray(item['remote'])
            router[-1] = 250
            packet = bytearray(self.packet(bytes(router), item['local'], body, hop=64))
            if sequence >= 50 and (sequence - 50) % 5 == 0:
                packet[57] ^= 1
            require(self.observe_input is not None, 'actual quoted-error observation is bound')
            item['observation'] = self.observe_input(bytes(packet))
            self.outgoing.append(bytes(packet))
        if phase == 2:
            if 'injected' not in item:
                observed = item['observation']() if 'observation' in item else None
                if observed is None:
                    return
                item['injected'] = observed
            if time.monotonic() - item['injected'] < .05:
                return
        elif self.sequence < 24:
            mode = self.sequence % 6
            if mode == 2:
                if time.monotonic() - item['boundary_time'] < .05:
                    return
                self.quiet.append(time.monotonic() - item['boundary_time'])
            elif not item.get('done'):
                return
        self.reply(item.pop('boundary'))
        if phase == 0:
            self.sequence += 1
            self.active = None

    def receive(self, frame):
        require(len(frame) >= 14 and frame[6:12] == self.guest, 'PMTU frame source ownership')
        if frame[12:14] == self.barrier_protocol:
            require(len(frame) == 60 and frame[:6] == self.control and
                    frame[14:19] == self.barrier_magic + bytes([self.lane]) and not any(frame[20:]),
                    'exact PMTU phase request')
            phase = frame[19]
            if not self.ready:
                require(phase == 0, 'PMTU readiness before configuration')
                self.ready = True
                self.reply(frame)
                return
            require(phase == self.phase + 1 and phase <= 180, 'ordered PMTU phases')
            self.phase = phase
            if phase % 3 == 1:
                require(self.active is None, 'one live PMTU case')
                kind, scoped, mode, _, _ = plan(self.sequence)
                remote = bytearray(self.link if scoped else self.remote)
                remote[-1] = 16 + self.sequence
                self.active = dict(kind=kind, scoped=scoped, mode=mode,
                                   protocol=17 if kind == 2 else 58,
                                   local=self.link if scoped else self.local, remote=bytes(remote),
                                   data=bytearray(), identification=None)
                self.reply(frame)
            else:
                require(self.active is not None and 'boundary' not in self.active, 'owned PMTU boundary')
                self.active.update(boundary=frame, boundary_time=time.monotonic())
                self.tick()
            return
        if not self.ready and not self.native:
            require(len(self.firmware_frames) < 256, 'bounded PMTU firmware traffic')
            import hashlib
            self.firmware_frames.append(hashlib.sha256(frame).hexdigest())
            return
        if self.native and frame[12:14] == b'\x86\xdd' and len(frame) >= 78 and frame[20] == 0:
            super().receive(frame)
            return
        require(self.ready and frame[12:14] == b'\x86\xdd' and len(frame) >= 54 and
                frame[14:18] == b'\x60\0\0\0', 'PMTU original IPv6 envelope')
        size, protocol, hop = struct.unpack_from('!HBB', frame, 18)
        require(size + 54 <= len(frame), 'bounded PMTU packet')
        source, destination, body = frame[22:38], frame[38:54], frame[54:54 + size]
        item = self.active
        require(item is not None, 'data belongs to a live PMTU case')
        if protocol == 58 and body[:1] == b'\x87':
            require(source == item['local'] and body[8:24] == item['remote'] and hop == 255 and
                    destination == self.multicast(item['remote']) and len(body) == 32 and
                    not checksum(source + destination + struct.pack('!I3xB', size, 58) + body),
                    'PMTU neighbor resolution')
            self.outgoing.append(self.na(item['remote'], source))
            return
        require(frame[:6] == self.mac and source == item['local'] and destination == item['remote'] and
                hop == 64, 'quoted datagram route and source')
        second = 'original' in item
        if second:
            require(self.sequence < 24 and item.get('injected') and item['mode'] != 2 and
                    not item.get('done'), 'only a successful second send emits data')
        mtu = 1280 if second and item['mode'] < 3 else 1500
        require(size + 40 <= mtu, 'wire output obeys learned or interface MTU')
        if protocol == 44:
            require(second and item['mode'] < 2 and len(body) >= 8, 'permitted PMTU fragmentation')
            protocol, reserved, offset, identification = struct.unpack_from('!BBHI', body)
            require(not reserved and not offset & 6 and offset & 0xfff8 == len(item['data']) and identification,
                    'contiguous PMTU fragments')
            require(protocol == item['protocol'] and len(item['data']) + len(body) - 8 <= 1308,
                    'bounded PMTU fragment protocol and data')
            if item['identification'] is None:
                item['identification'] = identification
            require(item['identification'] == identification, 'one PMTU fragment identity')
            item['data'].extend(body[8:])
            self.fragments += 1
            if offset & 1:
                require((len(body) - 8) % 8 == 0, 'aligned PMTU fragment')
                return
            body = bytes(item['data'])
        require(protocol == item['protocol'] and not checksum(source + destination +
                struct.pack('!I3xB', len(body), protocol) + body), 'complete quoted transport checksum')
        length = 1300 if self.sequence < 24 else 16
        expected = bytes((n * 19 + self.sequence * 3 + self.lane) & 255 for n in range(length))
        if item['kind'] == 2:
            require(len(body) == length + 8 and struct.unpack_from('!HHH', body) ==
                    (47000 + self.sequence, 48000 + self.sequence, length + 8) and body[8:] == expected,
                    'complete PMTU UDP application bytes')
        else:
            require(body[:2] == b'\x81\0' and body[4:] == expected[4:] and len(body) == length,
                    'complete PMTU raw application bytes')
        if second:
            item['done'] = True
        else:
            item['original'] = frame
        self.tick()

    @property
    def passed(self):
        return self.ready and self.sequence == 60 and self.active is None

    def result(self):
        return dict(passed=self.passed, lane=self.lane, cases=self.sequence,
                    fragments=self.fragments, quiet=self.quiet,
                    firmware_sha256=self.firmware_frames, native_MLD_reports=self.mld_reports)
