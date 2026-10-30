# SPDX-License-Identifier: GPL-3.0-or-later
"""Hold real neighbor resolution while the client changes accepted-packet state."""
import struct

from ipv4_fragments import checksum


class RawHeaderQueuePeer:
    def __init__(self, lane, selected_case=-1):
        if lane not in (0, 1) or not -1 <= selected_case < 6:
            raise ValueError('bounded raw-header queue fixture')
        self.lane = lane
        self.guest = bytes((0x52, 0x54, 0, 0x12, 0x34, 0x10 + lane))
        self.mac = bytes((2, 0x41, 0x58, 0x49, 0x50, lane))
        self.local = bytes((10, 23, lane + 1, 2))
        self.order = [selected_case] if selected_case >= 0 else list(range(6))
        self.completed = self.arp_requests = self.frames = self.controls = 0
        self.state = 'idle'
        self.request = None
        self.release = None
        self.acknowledged = False

    def acknowledgement(self, frame):
        reply = bytearray(frame)
        reply[:12] = self.guest + self.mac
        reply[21] ^= 0x80
        return bytes(reply)

    def receive_frame(self, frame):
        if len(frame) < 14:
            return None
        kind = frame[12:14]
        if kind == b'\x88\xb5' and frame[14:18] == b'RHQ1':
            if len(frame) != 60 or frame[:12] != self.mac + self.guest or frame[18] != self.lane:
                raise ValueError('complete selected raw queue control Ethernet frame')
            sample, phase = frame[19:21]
            if frame[21:] != bytes((at * 19 + sample * 11 + self.lane * 31) & 255 for at in range(21, 60)):
                raise ValueError('complete original raw queue control payload')
            self.controls += 1
            if sample == 6:
                if self.acknowledged or phase or self.state != 'idle' or self.completed != len(self.order):
                    raise ValueError('raw queue terminal control requires every selected output')
                self.acknowledged = True
                return [self.acknowledgement(frame)]
            if self.acknowledged or self.completed >= len(self.order) or sample != self.order[self.completed]:
                raise ValueError('ordered original raw queue case')
            if phase == 0 and self.state == 'idle':
                self.state = 'waiting-arp'
                return [self.acknowledgement(frame)]
            if phase == 1 and self.state == 'waiting-arp' and self.request is not None:
                self.state = 'held'
                return [self.acknowledgement(frame)]
            if phase != 2 or self.state != 'held' or self.request is None:
                raise ValueError('raw queue release follows its actual held ARP and preparation acknowledgement')
            self.release = frame
            self.state = 'released'
            remote = bytes((10, 23, self.lane + 1, 200 + sample))
            target = bytes((10, 23, self.lane + 1, 3 if sample == 0 else 2))
            reply = (self.guest + self.mac + b'\x08\x06' + struct.pack('!HHBBH', 1, 0x0800, 6, 4, 2) +
                     self.mac + remote + self.guest + target).ljust(60, b'\0')
            return [reply]
        if kind == b'\x08\x06' and len(frame) >= 42 and frame[38:41] == self.local[:3] and 200 <= frame[41] <= 205:
            sample = frame[41] - 200
            if (self.acknowledged or self.completed >= len(self.order) or sample != self.order[self.completed] or
                    self.state not in ('waiting-arp', 'held', 'released')):
                raise ValueError('raw queue ARP belongs to its active selected output')
            expected = (b'\xff' * 6 + self.guest + b'\x08\x06' +
                        struct.pack('!HHBBH', 1, 0x0800, 6, 4, 1) + self.guest + self.local +
                        b'\0' * 6 + bytes((10, 23, self.lane + 1, 200 + sample)))
            if frame[:42] != expected or any(frame[42:]):
                raise ValueError('actual raw queue ARP selected source, target, hardware and padding')
            self.request = frame
            self.arp_requests += 1
            return []
        if kind != b'\x08\0' or len(frame) < 34 or frame[23] != 76 or frame[18:20] != b'\x13\x57':
            return None
        if self.acknowledged or self.completed >= len(self.order) or self.state != 'released':
            raise ValueError('retained raw queue output precedes explicit neighbor release')
        sample = self.order[self.completed]
        length = 1500 if sample == 1 else 28
        packet = bytearray(struct.pack('!BBHHHBBH4s4s', 0x45, 0x5a, length, 0x1357, 0, 35, 76, 0,
            bytes((192, 0, 2, 1)), bytes((10, 23, self.lane + 1, 77))))
        packet[10:12] = checksum(bytes(packet)).to_bytes(2, 'big')
        packet.extend((at * 37 + sample * 11 + self.lane * 31) & 255 for at in range(20, length))
        if (frame[:12] != self.mac + self.guest or frame[14:14 + length] != packet or
                len(frame) < 14 + length or any(frame[14 + length:])):
            raise ValueError('complete immutable accepted raw queue packet and selected Ethernet destination')
        reply = self.acknowledgement(self.release)
        self.frames += 1
        self.completed += 1
        self.state = 'idle'
        self.request = self.release = None
        return [reply]
