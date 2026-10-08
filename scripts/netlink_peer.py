"""Independent Ethernet/ARP/IPv4/UDP peer for route ownership packet checks."""
import struct


def check(condition, reason):
    if not condition:
        raise RuntimeError(reason)


def checksum(data):
    if len(data) % 2:
        data += b'\0'
    total = sum(struct.unpack(f'!{len(data) // 2}H', data))
    while total > 65535:
        total = (total & 65535) + (total >> 16)
    return total ^ 65535


class Peer:
    def __init__(self, lane):
        self.lane = lane
        self.guest = bytes([0x52, 0x54, 0, 0x12, 0x34, 0x10 + lane])
        self.mac = bytes([2, 0x41, 0x58, 0x4e, 0x4c, lane])
        self.address = bytes([10, 23, 1 + lane, 40])
        self.gateway = bytes([10, 23, 1 + lane, 1])
        self.foreign = bytes([10, 23, 1 + lane, 9])
        self.direct = bytes([10, 244, 0, 44])
        self.distant = bytes([203, 0, 113, 44])
        self.input = bytearray()
        self.output = bytearray()
        self.connection = None
        self.resolutions = [0, 0, 0]
        self.packets = [0, 0, 0]
        self.resolved = None

    def send(self, packet):
        self.output += struct.pack('!I', len(packet)) + packet

    def packet(self, frame):
        check(42 <= len(frame) <= 1518 and frame[6:12] == self.guest,
              'route packet Ethernet source/length')
        if frame[12:14] == bytes.fromhex('0806'):
            arp = frame[14:42]
            check(frame[:6] == b'\xff' * 6 and arp[:8] == bytes.fromhex('0001080006040001') and
                  arp[8:14] == self.guest and arp[14:18] == self.address and
                  arp[18:24] == b'\0' * 6, 'independent ARP request fields')
            target = arp[24:28]
            check(target in [self.gateway, self.direct, self.foreign], 'route-specific ARP target')
            stage = [self.gateway, self.direct, self.foreign].index(target)
            check(stage == sum(self.packets), 'ARP follows route transition order')
            self.resolutions[stage] += 1
            self.resolved = target
            reply = bytes.fromhex('0001080006040002') + self.mac + target + self.guest + self.address
            self.send((self.guest + self.mac + bytes.fromhex('0806') + reply).ljust(60, b'\0'))
            return
        check(frame[:6] == self.mac and frame[12:14] == bytes.fromhex('0800'),
              'routed output uses independently resolved MAC')
        ip = frame[14:34]
        total = int.from_bytes(ip[2:4], 'big')
        check(ip[0] == 0x45 and ip[9] == 17 and ip[8] and checksum(ip) == 0 and
              total == 36 and total <= len(frame) - 14 and ip[12:16] == self.address,
              'independent routed IPv4 header/source/checksum')
        udp = frame[34:14 + total]
        check(udp[:4] == struct.pack('!HH', 46000 + self.lane, 46002) and
              int.from_bytes(udp[4:6], 'big') == len(udp) and udp[6:8] != b'\0\0',
              'independent routed UDP fields')
        pseudo = ip[12:20] + bytes([0, 17]) + struct.pack('!H', len(udp))
        check(checksum(pseudo + udp) == 0, 'independent routed UDP checksum')
        stage = udp[13]
        check(stage < 3 and udp[8:] == b'AXNR' + bytes([self.lane, stage, 0x73, 0x91]) and
              stage == sum(self.packets), 'exact routed payload and transition order')
        check(ip[16:20] == (self.distant if stage == 0 else self.direct) and
              self.resolved == [self.gateway, self.direct, self.foreign][stage],
              'default/on-link/preserved-unowned route selects the required next hop')
        self.packets[stage] += 1
        response = bytearray(struct.pack('!HHHH', 46002, 46000 + self.lane, 16, 0) + udp[8:])
        source = ip[16:20]
        pseudo = source + self.address + bytes([0, 17]) + struct.pack('!H', len(response))
        struct.pack_into('!H', response, 6, checksum(pseudo + response) or 65535)
        header = bytearray(struct.pack('!BBHHHBBH4s4s', 0x45, 0, 36, 0x744,
                                     0x4000, 61, 17, 0, source, self.address))
        struct.pack_into('!H', header, 10, checksum(header))
        self.send((self.guest + self.mac + bytes.fromhex('0800') + header + response).ljust(60, b'\0'))

    def verify(self):
        check(self.resolutions == [1, 1, 1] and self.packets == [1, 1, 1],
              f'route packet counts differ: ARP={self.resolutions} UDP={self.packets}')
        return dict(arp=self.resolutions, udp=self.packets)
