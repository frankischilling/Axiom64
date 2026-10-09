"""Independently validate DHCP acquisition, renewal, rebinding, ARP, and release."""
import struct


def check(value, reason):
    if not value:
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
        self.mac = bytes([2, 0x41, 0x58, 0x44, 0x48, lane])
        self.ip = bytes([10, 23, lane + 1, 1])
        self.other = bytes([10, 23, lane + 1, 2])
        self.address = bytes([10, 23, lane + 1, 40])
        self.input = bytearray()
        self.output = bytearray()
        self.connection = None
        self.discovers = self.selecting = self.renewals = self.rebindings = self.releases = 0
        self.probes = self.announcements = self.resolutions = 0
        self.transaction = None
        self.ack_server = None
        self.lease_timers = (30, 8, 15)
        self.rebound_timers = (100, 50, 87)

    def send(self, frame):
        self.output += struct.pack('!I', len(frame)) + frame

    def answer(self, kind, transaction, changed=False):
        message = bytearray(240)
        message[:3] = bytes([2, 1, 6])
        message[4:8] = transaction
        message[16:20] = self.address
        message[28:34] = self.guest
        message[236:240] = bytes.fromhex('63825363')
        lease, renewal, rebinding = self.rebound_timers if changed else self.lease_timers
        options = [(53, bytes([kind])), (54, self.other if changed else self.ip),
            (61, b'\x01' + self.guest), (1, bytes.fromhex('ffffff80' if changed else 'ffffff00')),
            (3, self.other if changed else self.ip),
            (6, bytes([10, 23, self.lane + 1, 99 if kind == 2 else 54 if changed else 53])),
            (15, b'lab.example'), (51, struct.pack('!I', lease)),
            (58, struct.pack('!I', renewal)), (59, struct.pack('!I', rebinding))]
        for code, data in options:
            message += bytes([code, len(data)]) + data
        message += b'\xff'
        udp = bytearray(struct.pack('!HHHH', 67, 68, len(message) + 8, 0) + message)
        source = self.other if changed else self.ip
        if kind == 5:
            self.ack_server = source
        destination = b'\xff' * 4
        pseudo = source + destination + bytes([0, 17]) + struct.pack('!H', len(udp))
        struct.pack_into('!H', udp, 6, checksum(pseudo + udp) or 65535)
        ip = bytearray(struct.pack('!BBHHHBBH4s4s', 0x45, 0, len(udp) + 20, 0x66,
                                  0x4000, 64, 17, 0, source, destination))
        struct.pack_into('!H', ip, 10, checksum(ip))
        self.send(b'\xff' * 6 + self.mac + bytes.fromhex('0800') + ip + udp)

    def packet(self, frame):
        check(len(frame) >= 42 and frame[6:12] == self.guest, 'guest source or frame length')
        protocol = frame[12:14]
        if protocol == bytes.fromhex('0806'):
            self.arp(frame)
            return
        check(protocol == bytes.fromhex('0800'),
              f'unexpected Ethernet protocol={protocol.hex()} size={len(frame)} header={frame[:54].hex()}')
        ip = frame[14:34]
        total = int.from_bytes(ip[2:4], 'big')
        check(ip[0] == 0x45 and ip[9] == 17 and checksum(ip) == 0 and total <= len(frame) - 14,
              'independent guest IPv4 fields/checksum')
        udp = frame[34:14 + total]
        check(len(udp) >= 248 and udp[:4] == struct.pack('!HH', 68, 67) and
              int.from_bytes(udp[4:6], 'big') == len(udp) and udp[6:8] != b'\0\0',
              'independent guest UDP ports/length/checksum presence')
        pseudo = ip[12:20] + bytes([0, 17]) + struct.pack('!H', len(udp))
        check(checksum(pseudo + udp) == 0, 'independent routed UDP checksum')
        message = udp[8:]
        check(message[:3] == bytes([1, 1, 6]) and message[28:34] == self.guest and
              message[236:240] == bytes.fromhex('63825363'), 'BOOTP identity/cookie')
        options = {}
        position = 240
        ended = False
        while position < len(message):
            code = message[position]
            position += 1
            if code == 255:
                ended = True
                break
            if not code:
                continue
            check(position < len(message), 'client option length header')
            size = message[position]
            position += 1
            check(position + size <= len(message) and code not in options,
                  'client option bounds/duplicates')
            options[code] = message[position:position + size]
            position += size
        check(ended and options.get(61) == b'\x01' + self.guest, 'end and stable client identifier')
        kind = options.get(53)
        transaction = message[4:8]
        configured = message[12:16] == self.address
        if kind == b'\x01':
            self.discovers += 1
            check(ip[12:16] == b'\0' * 4 and ip[16:20] == b'\xff' * 4 and
                  message[10:12] == b'\x80\x00' and 50 not in options and 54 not in options and
                  options.get(55) == bytes([121, 1, 3, 6, 15, 51, 58, 59, 119]),
                  'initial discover fields and consistent requested parameters')
            self.transaction = transaction
            if self.discovers == 1:
                return
            self.answer(2, bytes([transaction[0] ^ 1]) + transaction[1:])
            self.answer(2, transaction)
        elif kind == b'\x03' and not configured:
            self.selecting += 1
            check(transaction == self.transaction and options.get(50) == self.address and
                  options.get(54) == self.ip and ip[12:16] == b'\0' * 4,
                  'selected offer and raw DHCPREQUEST')
            self.answer(5, transaction)
        elif kind == b'\x03' and configured:
            check(ip[12:16] == self.address and 50 not in options and 54 not in options,
                  'configured UDP request fields')
            if ip[16:20] == self.ip:
                self.renewals += 1
                check(message[10:12] == b'\0\0' and frame[:6] == self.mac,
                      'unicast T1 packet uses routed peer MAC')
                return
            check(ip[16:20] == b'\xff' * 4 and message[10:12] == b'\x80\x00',
                  'T2 broadcast fields')
            self.rebindings += 1
            self.answer(5, transaction, changed=True)
        elif kind == b'\x07':
            self.releases += 1
            server = self.ack_server
            check(configured and ip[12:16] == self.address and ip[16:20] == server and
                  options.get(54) == server and 50 not in options and 55 not in options and
                  12 not in options and message[10:12] == b'\0\0', 'RELEASE fields for the last ACK server')
        else:
            raise RuntimeError('unexpected DHCP request mode')

    def arp(self, frame):
        arp = frame[14:42]
        check(frame[:6] == b'\xff' * 6 and arp[:8] == bytes.fromhex('0001080006040001') and
              arp[8:14] == self.guest and arp[18:24] == b'\0' * 6,
              'independent broadcast ARP request shape')
        source, destination = arp[14:18], arp[24:28]
        if source == b'\0' * 4 and destination == self.address:
            self.probes += 1
            return
        if source == destination == self.address:
            self.announcements += 1
            return
        check(source == self.address and destination in [self.ip, self.other],
              'routed ARP target and owned source')
        self.resolutions += 1
        reply = bytes.fromhex('0001080006040002') + self.mac + destination + self.guest + source
        self.send((self.guest + self.mac + bytes.fromhex('0806') + reply).ljust(60, b'\0'))

    def verify(self):
        expected = dict(discovers=2, selecting=1, renewals=1, rebindings=1,
                        releases=1, probes=3, announcements=2, resolutions=2)
        actual = {name: getattr(self, name) for name in expected}
        check(actual == expected, f'wire counts differ: {actual} expected {expected}')
        return actual
