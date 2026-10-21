# SPDX-License-Identifier: GPL-3.0-or-later
"""Controlled Ethernet peer for source-fragmented IPv6 socket output."""
import struct
import time
from ipv6_host_peer import Peer as HostPeer, checksum, require


def plan(sequence):
    require(0 <= sequence < 216, 'bounded output case identifier')
    kind = 2 + sequence // 108
    scoped = sequence % 108 // 54
    configuration, number = sequence % 54 // 6, sequence % 6
    sizes = (0, 1452, 1453, 1472, 65527, 65528) if kind == 2 else (4, 1460, 1461, 1472, 65535, 65536)
    size = sizes[number]
    mode = configuration - 1 if 1 <= configuration <= 6 else 1
    mtu = 1280 if configuration == 8 else 1500
    fragmentable = configuration != 7 and (mode < 2 or mode == 5)
    error = size > (65527 if kind == 2 else 65535) or (not fragmentable and size + (48 if kind == 2 else 40) > mtu)
    return dict(kind=kind, scoped=scoped, configuration=configuration, size=size,
                mtu=mtu, fragmentable=fragmentable, error=error)


class Peer(HostPeer):
    def __init__(self, lane, native=False):
        super().__init__(lane, native)
        self.pending = None
        self.completed = 0
        self.fragment_ids = set()
        self.fragment_frames = 0
        self.quiet = []
        self.remote_link = bytes.fromhex('fe800000000000000000000000000001')

    def reply(self, request):
        result = bytearray(request)
        result[:6], result[6:12] = self.guest, self.control
        result[32] = 1
        self.outgoing.append(bytes(result))

    def finish(self):
        item = self.pending
        if item is None or 'finish' not in item:
            return
        if item['policy']['error']:
            if time.monotonic() - item['end_time'] < .05:
                return
            self.quiet.append(time.monotonic() - item['end_time'])
        elif not item['done']:
            return
        self.reply(item['finish'])
        self.completed += 1
        self.pending = None

    def tick(self):
        self.finish()

    def receive(self, frame):
        require(len(frame) >= 14 and frame[6:12] == self.guest, 'output Ethernet source ownership')
        if frame[12:14] == b'\x88\xb8':
            require(not self.ready and len(frame) == 60 and frame[:6] == self.control and
                    frame[14:21] == b'IP6O' + bytes([self.lane, 0, 0]) and not any(frame[21:]),
                    'exact output readiness')
            self.ready = True
            reply = bytearray(frame)
            reply[:6], reply[6:12] = self.guest, self.control
            reply[20] = 1
            self.outgoing.append(bytes(reply))
            return
        if not self.ready and not self.native:
            require(len(self.firmware_frames) < 256, 'bounded output firmware prelude')
            import hashlib
            self.firmware_frames.append(hashlib.sha256(frame).hexdigest())
            return
        if frame[12:14] == b'\x88\xb9':
            require(self.ready and len(frame) == 60 and frame[:6] == self.control and
                    frame[14:19] == b'IP6O' + bytes([self.lane]) and
                    frame[31:] == bytes(29), 'exact output case boundary')
            kind = frame[19]
            sequence, size = struct.unpack_from('!II', frame, 20)
            policy = plan(sequence)
            require((size, *frame[28:31]) == (policy['size'], policy['kind'], policy['scoped'], policy['configuration']),
                    'case boundary describes the original application workload')
            if kind == 2:
                require(self.pending is None and sequence == self.completed, 'ordered case begin')
                self.pending = dict(sequence=sequence, policy=policy, data=bytearray(), done=False,
                                    identification=None)
                self.reply(frame)
            else:
                require(kind == 3 and self.pending is not None and self.pending['sequence'] == sequence and
                        'finish' not in self.pending, 'one ordered case end')
                self.pending.update(finish=frame, end_time=time.monotonic())
                self.finish()
            return
        if frame[12:14] != b'\x86\xdd':
            require(False, 'unexpected output Ethernet protocol')
        if self.native and len(frame) >= 78 and frame[20] == 0:
            super().receive(frame)
            return
        require(self.ready and len(frame) >= 54 and frame[14:18] == b'\x60\0\0\0',
                'complete output IPv6 header')
        length, protocol, hop = struct.unpack_from('!HBB', frame, 18)
        require(54 + length <= len(frame), 'output IPv6 payload bounds')
        source, destination = frame[22:38], frame[38:54]
        body = frame[54:54 + length]
        if protocol == 58 and body[:1] == b'\x87':
            target = body[8:24]
            local = self.link if target == self.remote_link else self.local
            require(target in (self.remote, self.remote_link) and source == local and hop == 255 and
                    destination == self.multicast(target) and len(body) == 32 and
                    body[:2] == b'\x87\0' and body[4:8] == bytes(4) and
                    body[24:] == b'\1\1' + self.guest and
                    not checksum(source + destination + struct.pack('!I3xB', length, 58) + body),
                    'owned output neighbor resolution')
            self.outgoing.append(self.na(target, source))
            return
        item = self.pending
        require(item is not None and not item['policy']['error'] and not item['done'],
                'data belongs to one successful application case')
        policy = item['policy']
        local, remote = (self.link, self.remote_link) if policy['scoped'] else (self.local, self.remote)
        require(source == local and destination == remote and frame[:6] == self.mac and hop == 64 and
                length + 40 <= 1500, 'source, destination and interface MTU of output data')
        if protocol == 44:
            require(policy['fragmentable'] and length + 40 <= policy['mtu'] and len(body) >= 8 and not body[1],
                    'permitted source Fragment header and socket fragment size')
            protocol, _, offset, identification = struct.unpack_from('!BBHI', body)
            require(not offset & 6 and offset & 0xfff8 == len(item['data']) and identification,
                    'contiguous fragment offsets and identification')
            if item['identification'] is None:
                require((source, destination, identification) not in self.fragment_ids, 'fresh source fragment identity')
                self.fragment_ids.add((source, destination, identification))
                item['identification'] = identification
            require(item['identification'] == identification, 'one identity through the original datagram')
            more = offset & 1
            require(not more or (len(body) > 8 and (len(body) - 8) % 8 == 0), 'aligned nonfinal fragment')
            require(len(item['data']) + len(body) - 8 <= policy['size'] + (8 if policy['kind'] == 2 else 0),
                    'bounded source fragment contents')
            item['data'].extend(body[8:])
            self.fragment_frames += 1
            if more:
                return
            body = bytes(item['data'])
        else:
            require(not item['data'], 'unfragmented data does not replace earlier fragments')
        wanted_protocol = 17 if policy['kind'] == 2 else 58
        require(protocol == wanted_protocol and not checksum(source + destination +
                struct.pack('!I3xB', len(body), protocol) + body), 'complete output transport checksum')
        expected = bytes((n * 17 + item['sequence'] * 7 + self.lane) & 255 for n in range(policy['size']))
        if protocol == 17:
            require(len(body) == policy['size'] + 8, 'complete UDP datagram')
            sport, dport, declared, check = struct.unpack_from('!HHHH', body)
            require((sport, dport, declared) == (45000 + self.lane + policy['scoped'] * 10,
                    46000 + self.lane + policy['scoped'] * 10, len(body)) and check and body[8:] == expected,
                    'original UDP fields and every application byte')
        else:
            expected = b'\x81\0\0\0' + expected[4:]
            require(body[:2] + bytes(2) + body[4:] == expected, 'every original raw application byte')
        item['done'] = True
        self.finish()

    @property
    def passed(self):
        return self.ready and self.completed == 216 and self.pending is None

    def result(self):
        return dict(passed=self.passed, lane=self.lane, cases=self.completed,
                    fragment_frames=self.fragment_frames, quiet_intervals=self.quiet,
                    firmware_frames=len(self.firmware_frames), firmware_sha256=self.firmware_frames,
                    native_MLD_reports=self.mld_reports)
