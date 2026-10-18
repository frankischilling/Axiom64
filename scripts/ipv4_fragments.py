# SPDX-License-Identifier: GPL-3.0-or-later
"""Controlled IPv4 fragment corpora; transport observation stays in the caller."""
import struct


def checksum(data):
    if len(data) % 2:
        data += b'\0'
    value = sum(struct.unpack(f'!{len(data) // 2}H', data))
    while value >> 16:
        value = (value & 65535) + (value >> 16)
    return (~value) & 65535


class FragmentPeer:
    def __init__(self, lane):
        self.lane = lane
        self.completed = 0
        self.waiting = None
        self.frames = 0
        self.acknowledged = False
        self.output = OutputFragmentPeer(self)

    def accepts(self, packet):
        return (packet[24:26] in (b'FR', b'FO') or
                (self.output.waiting is not None and len(packet) >= 20 and packet[9] in (1, 17)))

    def packet(self, payload, identifier, offset=0, more=False):
        header = bytearray(struct.pack('!BBHHHBBH4s4s', 0x45, 0, 20 + len(payload),
                                      identifier, offset // 8 | (0x2000 if more else 0),
                                      51, 1, 0, bytes([10, 23, self.lane + 1, 1]),
                                      bytes([10, 23, self.lane + 1, 2])))
        struct.pack_into('!H', header, 10, checksum(bytes(header)))
        return bytes(header) + payload

    def barrier(self, test, identifier=0x7064):
        body = bytearray([0, 0, 0, 0, ord('F'), ord('B'), test, self.lane])
        struct.pack_into('!H', body, 2, checksum(bytes(body)))
        return self.packet(bytes(body), identifier)

    def body(self, test):
        length = 65515 if test == 5 else 65 if test == 1 else 64
        body = bytearray([0, 0, 0, 0, ord('F'), ord('R'), test, self.lane])
        body.extend((i * 17 + self.lane * 31 + test) & 255 for i in range(8, length))
        struct.pack_into('!H', body, 2, checksum(bytes(body)))
        return bytes(body)

    def receive(self, packet):
        """Return IP packets only after validating the real guest's exact request."""
        if packet[24:26] != b'FR':
            return self.output.receive(packet)
        if len(packet) != 52 or packet[:2] != b'\x45\0' or checksum(packet[:20]):
            raise ValueError('fragment control IP header differs')
        if (packet[2:4] != b'\0\x34' or packet[6:10] != b'\x40\0\x40\x01' or
                packet[12:20] != bytes([10, 23, self.lane + 1, 2, 10, 23, self.lane + 1, 1])):
            raise ValueError('fragment control route or policy differs')
        control = packet[20:]
        test, phase = control[6:8]
        expected = bytes((i * 17 + self.lane * 31) & 255 for i in range(8, 32))
        if (control[:2] != b'\x08\0' or control[4:6] != b'FR' or checksum(control) or
                control[8:] != expected or test != self.completed or phase not in (0, 1)):
            raise ValueError('fragment control bytes or sequence differ')
        identifier = 0x7100 + self.lane * 32 + test * 2
        if test == 6:
            if phase or self.waiting is not None or self.acknowledged:
                raise ValueError('fragment final acknowledgement differs')
            self.acknowledged = True
            return []
        body = self.body(test)

        def piece(at, size, more, identity=identifier):
            return self.packet(body[at:at + size], identity, at, more)

        if phase == 1:
            if self.waiting != test:
                raise ValueError('fragment release has no ordered pending case')
            self.waiting = None
            result = [piece(24, 24, True)] if test == 2 else [
                piece(0, 24, True, identifier + 1), piece(24, len(body) - 24, False, identifier + 1)]
            if test == 4:
                result.append(self.barrier(test, identifier))
            self.completed += 1
        elif self.waiting is not None:
            raise ValueError('fragment control skipped a pending release')
        elif test == 0:
            result = [piece(0, 24, True), piece(24, 24, True), piece(48, 16, False)]
            self.completed += 1
        elif test == 1:
            middle = piece(24, 24, True)
            result = [piece(48, 17, False), middle, middle, piece(0, 24, True)]
            self.completed += 1
        elif test == 2:
            result = [piece(0, 24, True), piece(48, 16, False), self.barrier(test)]
            self.waiting = test
        elif test == 3:
            result = [piece(0, 32, True), piece(16, 48, False), self.barrier(test)]
            self.waiting = test
        elif test == 4:
            corrupt = bytearray(piece(0, 24, True))
            corrupt[10] ^= 1
            result = [bytes(corrupt), piece(24, 40, False), self.barrier(test)]
            self.waiting = test
        elif test == 5:
            result = [piece(at, min(1472, len(body) - at), at + 1472 < len(body))
                      for at in range(0, len(body), 1472)]
            result.reverse()
            self.completed += 1
        else:
            raise ValueError('unknown fragment case')
        self.frames += len(result)
        return result


class OutputFragmentPeer:
    # protocol, discovery policy, MTU, application payload size
    cases = [(1, 0, 1500, 65515), (1, 1, 1500, 65515), (17, 0, 1500, 65507),
             (17, 1, 1500, 65507), (1, 2, 1500, 1481), (1, 3, 1500, 1481),
             (17, 2, 1500, 1473), (17, 3, 1500, 1473), (1, 0, 68, 4096),
             (17, 1, 68, 4096), (1, 1, 1500, 1480), (17, 0, 1500, 1472),
             (1, 1, 1500, 1481), (17, 1, 1500, 1473), (1, 0, 68, 65515),
             (1, 4, 1500, 1481), (17, 4, 1500, 1473), (1, 5, 1500, 65515),
             (17, 5, 1500, 65507), (1, 4, 1500, 1480), (17, 4, 1500, 1472)]

    def __init__(self, parent):
        self.parent = parent
        self.completed = self.frames = 0
        self.waiting = None
        self.payload = bytearray()
        self.identifier = None
        self.acknowledged = False

    def acknowledgement(self, test, phase):
        lane = self.parent.lane
        body = bytearray([0, 0, 0, 0, ord('F'), ord('O'), test, phase])
        body.extend((i * 17 + lane * 31) & 255 for i in range(8, 32))
        struct.pack_into('!H', body, 2, checksum(bytes(body)))
        return self.parent.packet(bytes(body), 0x7300 + lane * 32 + test)

    def receive(self, packet):
        lane = self.parent.lane
        if (len(packet) < 20 or packet[0] != 0x45 or checksum(packet[:20]) or
                int.from_bytes(packet[2:4], 'big') != len(packet) or
                packet[12:20] != bytes([10, 23, lane + 1, 2, 10, 23, lane + 1, 1]) or
                packet[1] or packet[8] != 64):
            raise ValueError('output IP header, route or checksum differs')
        flags = int.from_bytes(packet[6:8], 'big')
        if packet[9] == 1 and not (flags & 0x3fff) and packet[24:26] == b'FO':
            body = packet[20:]
            if (len(body) != 32 or body[:2] != b'\x08\0' or checksum(body) or
                    body[8:] != bytes((i * 17 + lane * 31) & 255 for i in range(8, 32))):
                raise ValueError('output control body differs')
            test, phase = body[6:8]
            if test != self.completed:
                raise ValueError('output control skipped its case')
            if test == len(self.cases):
                if phase or self.waiting is not None or self.acknowledged:
                    raise ValueError('output final acknowledgement differs')
                self.acknowledged = True
                return []
            if phase == 0 and self.waiting is None:
                self.waiting = test
                self.payload.clear()
                self.identifier = None
                return [self.acknowledgement(test, 0)]
            protocol, policy, mtu, length = self.cases[test]
            oversized = length + (28 if protocol == 17 else 20) > mtu
            if (phase == 1 and self.waiting == test and policy in (2, 3, 4) and
                    oversized and not self.payload):
                self.waiting = None
                self.completed += 1
                return [self.acknowledgement(test, 1)]
            raise ValueError('output rejection barrier differs')
        if self.waiting is None:
            raise ValueError('output data has no acknowledged case')
        test = self.waiting
        protocol, policy, mtu, length = self.cases[test]
        total_payload = length + (8 if protocol == 17 else 0)
        if ((policy in (2, 3, 4) and total_payload + 20 > mtu) or
                packet[9] != protocol or len(packet) > mtu or flags & 0x8000):
            raise ValueError('output violated protocol, DF rejection or MTU')
        fragment = total_payload + 20 > mtu
        expected_df = policy in (1, 2, 3) and not fragment
        if bool(flags & 0x4000) != expected_df:
            raise ValueError('output DF policy differs')
        offset = (flags & 0x1fff) * 8
        body = packet[20:]
        if offset != len(self.payload) or not body:
            raise ValueError('output offset, ordering or duplicate differs')
        identifier = packet[4:6]
        if self.identifier is None:
            self.identifier = identifier
        if identifier != self.identifier:
            raise ValueError('output fragments changed identification')
        more = bool(flags & 0x2000)
        if (more and len(body) % 8) or offset + len(body) > total_payload:
            raise ValueError('output fragment payload bounds differ')
        self.payload.extend(body)
        self.frames += 1
        if more:
            if len(self.payload) >= total_payload:
                raise ValueError('output final fragment retained MF')
            return []
        if len(self.payload) != total_payload:
            raise ValueError('output final fragment left a hole')
        data = bytes(self.payload)
        if protocol == 17:
            if (data[:6] != struct.pack('!HHH', 45000 + lane, 24000 + lane, total_payload) or
                    data[6:8] == b'\0\0' or
                    checksum(packet[12:20] + bytes([0, 17]) +
                             struct.pack('!H', total_payload) + data)):
                raise ValueError('output UDP tuple, length or pseudo-header checksum differs')
            data = data[8:]
        expected = bytearray([8, 0, 0, 0, ord('F'), ord('D'), test, lane])
        expected.extend((i * 17 + lane * 31 + test) & 255 for i in range(8, length))
        struct.pack_into('!H', expected, 2, checksum(bytes(expected)))
        if data != expected:
            raise ValueError('output did not retain every original application byte')
        self.waiting = None
        self.completed += 1
        return [self.acknowledgement(test, 1)]
