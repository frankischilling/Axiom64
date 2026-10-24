# SPDX-License-Identifier: GPL-3.0-or-later
"""Observe actual per-message IPv6 output and retain rejected-send intervals."""
import ipaddress
import struct
import time
from ipv6_host_peer import Peer as HostPeer, checksum, require


def plan(sequence, lane, minus_one_class):
    require(0 <= sequence < 96, 'bounded ancillary-output sequence')
    variant, scoped, kind = sequence % 24, sequence // 24 % 2, 2 + sequence // 48
    size = 16384 if variant == 8 else 2048 if variant in (6, 7) else 128
    error = 90 if variant == 7 else 19 if variant == 13 else 14 if variant == 20 else (
        22 if 14 <= variant <= 21 or variant == 23 else 0)
    hop = 43 if variant in (4, 8) else 0 if variant == 9 else 255 if variant == 10 else 44 if variant == 12 else 33
    traffic = 0xab if variant in (5, 8) else 255 if variant == 10 else minus_one_class if variant == 11 else 0xac if variant == 12 else 18
    source = ipaddress.IPv6Address(f'2001:db8:{(lane ^ 1) + 1}::2' if variant == 22 else
                                 'fe80::2' if scoped else f'2001:db8:{lane + 1}::2').packed
    destination = ipaddress.IPv6Address(f'fe80::{100 + sequence:x}' if scoped else
                                       f'2001:db8:{lane + 1}::{100 + sequence:x}').packed if variant == 8 else (
                                       ipaddress.IPv6Address('fe80::1' if scoped else f'2001:db8:{lane + 1}::1').packed)
    return dict(variant=variant, scoped=scoped, kind=kind, size=size, error=error, hop=hop,
                traffic=traffic, source=source, destination=destination, fragmented=variant in (6, 8))


class Peer(HostPeer):
    def __init__(self, lane, native=False):
        super().__init__(lane, native)
        self.minus_one_class = None if native else 255
        self.active = None
        self.completed = 0
        self.identifications = set()
        self.fragment_frames = 0
        self.quiet = []
        self.remote_link = ipaddress.IPv6Address('fe80::1').packed

    def set_send_model(self, model):
        require(self.native and model['minus_one_class'] in (18, 255), 'independent native wire class model')
        self.minus_one_class = model['minus_one_class']

    def reply(self, frame):
        reply = bytearray(frame)
        reply[:6], reply[6:12] = self.guest, self.control
        reply[20] = 1
        self.outgoing.append(bytes(reply))

    def finish(self):
        if self.active is None or 'end' not in self.active:
            return
        item = self.active
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
        require(len(frame) >= 14 and frame[6:12] == self.guest, 'ancillary output source interface MAC')
        if frame[12:14] == b'\x88\xc0':
            require(len(frame) == 60 and frame[:6] == self.control and
                    frame[14:19] == b'IP6W' + bytes([self.lane]) and not any(frame[20:]),
                    'exact ancillary-output boundary')
            phase = frame[19]
            if phase >= 193:
                item = self.active
                require(item is not None and item['policy']['variant'] == 8 and
                        phase == 193 + item['sequence'] // 24 and 'mutation' not in item,
                        'one mutation boundary after copied inputs and retired owners')
                item['mutation'] = frame
                self.release_neighbor()
                return
            if not self.ready:
                require(phase == 0 and self.minus_one_class in (18, 255), 'owned wire readiness and actual class model')
                self.ready = True
                self.reply(frame)
            elif phase == self.completed * 2 + 1:
                require(self.active is None, 'one ordered ancillary send')
                self.active = dict(sequence=self.completed,
                    policy=plan(self.completed, self.lane, self.minus_one_class), data=bytearray(),
                    done=False, identification=None)
                self.reply(frame)
            else:
                require(phase == self.completed * 2 + 2 and self.active is not None and 'end' not in self.active,
                        'one original ancillary-send end')
                self.active.update(end=frame, end_time=time.monotonic())
                self.finish()
            return
        require(self.ready and frame[12:14] == b'\x86\xdd' and len(frame) >= 54,
                'complete owned ancillary-output IPv6 frame')
        if self.native and frame[20] == 0:
            super().receive(frame)
            return
        length, protocol, hop = struct.unpack_from('!HBB', frame, 18)
        require(len(frame) >= 54 + length, 'complete original IPv6 ancillary payload')
        source, target, body = frame[22:38], frame[38:54], frame[54:54 + length]
        if protocol == 58 and body[:1] == b'\x87':
            destination = body[8:24]
            group = self.multicast(destination)
            deferred = self.active is not None and self.active['policy']['variant'] == 8 and destination == self.active['policy']['destination']
            require(frame[14:18] == b'\x60\0\0\0' and (destination in (self.remote, self.remote_link) or deferred) and
                    source in (self.local, self.link) and hop == 255 and len(body) == 32 and body[:2] == b'\x87\0' and
                    body[4:8] == bytes(4) and body[24:] == b'\1\1' + self.guest and
                    (target == group and frame[:6] == b'\x33\x33' + group[-4:] or
                     target == destination and frame[:6] == self.mac) and
                    not checksum(source + target + struct.pack('!I3xB', length, 58) + body),
                    'owned ancillary-output neighbor resolution')
            if deferred:
                require(not self.active.get('released'), 'no neighbor response before mutation acknowledgement')
                self.active['neighbor'] = (destination, source)
                self.release_neighbor()
            else:
                self.outgoing.append(self.na(destination, source))
            return
        item = self.active
        require(item is not None and not item['done'] and not item['policy']['error'],
                'actual data belongs to one accepted controlled send')
        policy = item['policy']
        remote = policy['destination']
        require(policy['variant'] != 8 or item.get('released'), 'queued fragments follow actual owner retirement')
        require(frame[:6] == self.mac and source == policy['source'] and target == remote and
                hop == policy['hop'] and struct.unpack_from('!I', frame, 14)[0] ==
                (6 << 28 | policy['traffic'] << 20) and length + 40 <= 1500,
                'actual selected source, egress, hop, traffic class and MTU')
        if protocol == 44:
            require(policy['fragmented'] and len(body) > 8 and body[1] == 0, 'complete permitted original Fragment header')
            protocol, _, offset, identity = struct.unpack_from('!BBHI', body)
            require(identity and not offset & 6 and offset & 0xfff8 == len(item['data']),
                    'original contiguous fragment offsets')
            if item['identification'] is None:
                require((source, target, identity) not in self.identifications, 'fresh controlled fragment identification')
                self.identifications.add((source, target, identity))
                item['identification'] = identity
            require(identity == item['identification'] and len(item['data']) + len(body) - 8 <=
                    policy['size'] + (8 if policy['kind'] == 2 else 0), 'one bounded original fragment group')
            item['data'].extend(body[8:])
            self.fragment_frames += 1
            if offset & 1:
                require((len(body) - 8) % 8 == 0, 'aligned controlled nonfinal fragment')
                return
            body = bytes(item['data'])
        else:
            require(not item['data'] and not policy['fragmented'], 'large accepted controlled datagram is actually fragmented')
        require(protocol == (17 if policy['kind'] == 2 else 58) and
                not checksum(source + target + struct.pack('!I3xB', len(body), protocol) + body),
                'complete independently checked controlled transport')
        expected = bytes((n * 19 + item['sequence'] * 11 + self.lane) & 255 for n in range(policy['size']))
        if protocol == 17:
            require(len(body) == policy['size'] + 8 and struct.unpack_from('!HHH', body) ==
                    (47000 + self.lane + policy['scoped'] * 10, 48000 + self.lane + policy['scoped'] * 10, len(body)) and
                    body[6:8] != bytes(2) and body[8:] == expected, 'every original controlled UDP field and payload byte')
        else:
            require(len(body) == policy['size'] and body[:2] + bytes(2) + body[4:] == b'\x81\0\0\0' + expected[4:],
                    'every original controlled raw payload byte')
        item['done'] = True
        self.finish()

    @property
    def passed(self):
        return self.ready and self.completed == 96 and self.active is None

    def result(self):
        return dict(passed=self.passed, lane=self.lane, cases=self.completed,
                    native_minus_one_class=self.minus_one_class, fragment_groups=len(self.identifications),
                    fragment_frames=self.fragment_frames, quiet_intervals=self.quiet, native_MLD_reports=self.mld_reports)
