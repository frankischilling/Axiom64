# SPDX-License-Identifier: GPL-3.0-or-later
"""Ethernet peer for actual labelled-address ownership and deletion checks."""
import struct


def checksum(data):
    if len(data) % 2:
        data += b'\0'
    value = sum(struct.unpack(f'!{len(data) // 2}H', data))
    while value >> 16:
        value = (value & 65535) + (value >> 16)
    return (~value) & 65535


class AliasPeer:
    def __init__(self, lane):
        self.lane = lane
        self.guest = bytes([0x52, 0x54, 0, 0x12, 0x34, 0x10 + lane])
        self.mac = bytes([2, 0x41, 0x4c, 0x49, 0x41, lane])
        self.primary = bytes([10, 23, lane + 1, 2])
        self.alias = self.primary[:3] + b'\x03'
        self.other = bytes([10, 33, lane + 1, 2])
        self.cases = self.arp_requests = self.arp_replies = self.kernel_replies = 0
        self.pending = None

    def packet(self, source, destination, body):
        header = bytearray(struct.pack('!BBHHHBBH4s4s', 0x45, 0, 20 + len(body),
                                      0x414c, 0, 51, 1, 0, source, destination))
        struct.pack_into('!H', header, 10, checksum(bytes(header)))
        return self.guest + self.mac + b'\x08\0' + bytes(header) + body

    def receive(self, frame):
        if len(frame) < 42:
            return None
        if frame[12:14] == b'\x08\x06':
            source, destination = frame[28:32], frame[38:42]
            remote = destination
            if remote not in (self.primary[:3] + b'\x09', self.other[:3] + b'\x09'):
                return None
            if frame[14:20] != b'\0\x01\x08\0\x06\x04' or frame[6:12] != self.guest:
                raise ValueError('alias ARP header or Ethernet source differs')
            if frame[20:22] == b'\0\x01':
                expected = self.alias if remote[:3] == self.primary[:3] and self.cases == 0 else self.primary if remote[:3] == self.primary[:3] else self.other
                if (source != expected or frame[22:28] != self.guest or
                        frame[:6] != b'\xff' * 6 or frame[32:38] != b'\0' * 6 or any(frame[42:])):
                    raise ValueError('alias ARP request source, target or padding differs')
                self.arp_requests += 1
                reply = (self.guest + self.mac + b'\x08\x06' +
                         struct.pack('!HHBBH', 1, 0x0800, 6, 4, 2) +
                         self.mac + remote + self.guest + source).ljust(60, b'\0')
                return [reply]
            if (frame[20:22] != b'\0\x02' or source != self.alias or
                    frame[:6] != self.mac or frame[22:28] != self.guest or
                    frame[32:38] != self.mac or destination != self.primary[:3] + b'\x09' or
                    any(frame[42:])):
                raise ValueError('guest did not own the alias ARP reply')
            self.arp_replies += 1
            return self.release()
        if frame[12:14] != b'\x08\0' or len(frame) < 42:
            return None
        total = int.from_bytes(frame[16:18], 'big')
        packet = frame[14:14 + total]
        if len(packet) < 28 or packet[24:26] not in (b'AL', b'AH'):
            return None
        body = packet[20:]
        if (total != 84 or total > len(frame) - 14 or len(packet) != 84 or
                packet[:2] != b'\x45\0' or checksum(packet[:20]) or
                packet[8:10] != b'\x40\x01' or packet[6:8] not in (b'\0\0', b'\x40\0') or
                checksum(body) or frame[:12] != self.mac + self.guest or any(frame[14 + total:])):
            raise ValueError('alias IPv4 frame shape, checksum or ownership differs')
        if body[4:6] == b'AH':
            if (body[0:2] != b'\0\0' or packet[12:20] != self.other + self.other[:3] + b'\x09' or
                    body[6:8] != bytes([1, self.lane]) or body[8:] != bytes(range(8, 64))):
                raise ValueError('kernel alias echo reply differs')
            self.kernel_replies += 1
            return self.release()
        test = body[6]
        source = [self.alias, self.other, self.other, self.primary][min(test, 3)]
        destination = source[:3] + b'\x09'
        if (test != self.cases or test > 3 or body[:2] != b'\x08\0' or body[7] != self.lane or
                packet[12:20] != source + destination or
                body[8:] != bytes((n * 17 + self.lane * 31 + test) & 255 for n in range(8, 64))):
            raise ValueError('alias wire sequence, route or payload differs')
        self.cases += 1
        reply = bytearray(body)
        reply[0:4] = b'\0' * 4
        struct.pack_into('!H', reply, 2, checksum(bytes(reply)))
        response = self.packet(destination, source, bytes(reply))
        if test == 3:
            self.pending = response
            return self.release()
        frames = [response]
        if test == 0:
            frames.append((b'\xff' * 6 + self.mac + b'\x08\x06' +
                           struct.pack('!HHBBH', 1, 0x0800, 6, 4, 1) + self.mac + destination +
                           b'\0' * 6 + self.alias).ljust(60, b'\0'))
        if test == 1:
            request = bytearray(b'\x08\0\0\0AH' + bytes([1, self.lane]) + bytes(range(8, 64)))
            struct.pack_into('!H', request, 2, checksum(bytes(request)))
            frames.append(self.packet(destination, self.other, bytes(request)))
        return frames

    def release(self):
        if self.pending is not None and self.arp_replies == 1 and self.kernel_replies == 1:
            result, self.pending = self.pending, None
            return [result]
        return []

    @property
    def passed(self):
        return self.cases == 4 and self.arp_requests >= 2 and self.arp_replies == 1 and self.kernel_replies == 1 and self.pending is None
