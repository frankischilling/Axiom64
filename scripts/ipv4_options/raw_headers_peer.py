# SPDX-License-Identifier: GPL-3.0-or-later
"""Acknowledge complete literal raw-header output on the existing Ethernet peers."""
import struct

from ipv4_fragments import checksum


class RawHeaderPeer:
    lengths = (28, 28, 28, 28, 28, 28, 68, 36, 36, 36, 28, 28, 28,
               28, 28, 28, 1500, 1501, 19, 28, 68, 69, 28, 28, 65535, 65536)
    rejected = {10: 22, 11: 22, 12: 22, 13: 22, 17: 90, 18: 22, 19: 22, 21: 90, 24: 90, 25: 90}

    def __init__(self, parent):
        self.parent = parent
        self.completed = self.frames = 0
        self.waiting = None
        self.acknowledged = False

    def accepts(self, packet):
        return len(packet) >= 20 and (packet[9] == 75 or
            ((packet[0] & 15) == 5 and packet[9] == 1 and packet[24:26] == b'RH'))

    def pending_literal(self, packet):
        return self.waiting is not None and len(packet) >= 20 and packet[9] == 75

    def acknowledgement(self, test, phase):
        lane = self.parent.lane
        body = bytearray((0, 0, 0, 0, ord('R'), ord('H'), test, phase))
        body.extend((at * 17 + lane * 31) & 255 for at in range(8, 32))
        struct.pack_into('!H', body, 2, checksum(bytes(body)))
        return self.parent.packet(bytes(body), 0x7e00 + lane * 32 + test)

    def receive(self, packet):
        lane = self.parent.lane
        if packet[9] == 75:
            test = self.waiting
            if test is None or test in self.rejected or test == 14:
                raise ValueError('unexpected literal-header packet outside its acknowledged send')
            length = self.lengths[test]
            header = 60 if test == 6 else 28 if 7 <= test <= 9 else 20
            expected = bytearray(length)
            expected[:4] = bytes(((0x60 if test == 5 else 0x40) | header // 4, 0x5a)) + length.to_bytes(2, 'big')
            expected[4:6] = packet[4:6] if test == 1 else (0 if test == 2 else 0x1357).to_bytes(2, 'big')
            expected[6:10] = bytes((0x40 if test == 2 else 0, 0, 35, 75))
            expected[12:16] = bytes((192, 0, 2, 1)) if test == 3 else bytes((10, 23, lane + 1, 2))
            expected[16:20] = bytes((10, 23, lane + 1, 77 if test == 4 else 1))
            expected[header:] = bytes((at * 37 + lane * 31 + test * 11) & 255 for at in range(header, length))
            if test == 6:
                expected[20:60] = b'\1' * 40
            elif test in (7, 8, 9):
                expected[20:28] = (bytes((7, 7, 4, 99, 98, 97, 96, 0)),
                                   bytes((131, 7, 4, 10, 23, 9, 77, 0)),
                                   bytes((134, 8, 0, 0, 0, 0, 0, 0)))[test - 7]
            expected[10:12] = checksum(bytes(expected[:header])).to_bytes(2, 'big')
            if packet != expected:
                raise ValueError('literal raw-header fields, options, payload or checksum differ: ' + str(test))
            self.frames += 1
            self.waiting = None
            self.completed += 1
            return [self.acknowledgement(test, 1)]
        local, remote = bytes((10, 23, lane + 1, 2)), bytes((10, 23, lane + 1, 1))
        if (len(packet) != 52 or packet[:2] != b'\x45\0' or packet[9] != 1 or
                packet[12:20] != local + remote or checksum(packet[:20]) or
                packet[20:22] != b'\x08\0' or packet[24:26] != b'RH' or checksum(packet[20:]) or
                packet[28:] != bytes((at * 17 + lane * 31) & 255 for at in range(8, 32))):
            raise ValueError('raw-header control bytes or route differ')
        test, phase = packet[26:28]
        if self.acknowledged or test != self.completed:
            raise ValueError('raw-header output skipped or repeated its case')
        if test == len(self.lengths):
            if phase or self.waiting is not None:
                raise ValueError('raw-header terminal control precedes completed output')
            self.acknowledged = True
            return [self.acknowledgement(test, 0)]
        if phase == 0 and self.waiting is None:
            self.waiting = test
            return [self.acknowledgement(test, 0)]
        if phase != 1 or self.waiting != test or (test not in self.rejected and test != 14):
            raise ValueError('raw-header no-output report conflicts with its actual wire packets')
        self.waiting = None
        self.completed += 1
        return [self.acknowledgement(test, 1)]
