"""Independent IPv4/UDP packet validation for isolated Ethernet peers."""
import struct


def checksum(data):
    if len(data) % 2:
        data += b'\0'
    total = sum(struct.unpack(f'!{len(data) // 2}H', data))
    while total >> 16:
        total = (total & 65535) + (total >> 16)
    return (~total) & 65535


def ipv4(source, destination, payload, protocol=17, identifier=0x6400):
    header = bytearray(struct.pack('!BBHHHBBH4s4s', 0x45, 0, 20 + len(payload),
                                  identifier, 0, 51, protocol, 0, source, destination))
    struct.pack_into('!H', header, 10, checksum(bytes(header)))
    return bytes(header) + payload


def udp(source, destination, source_port, destination_port, payload, zero=False):
    segment = bytearray(struct.pack('!HHHH', source_port, destination_port, 8 + len(payload), 0) + payload)
    pseudo = source + destination + struct.pack('!BBH', 0, 17, len(segment))
    if not zero:
        struct.pack_into('!H', segment, 6, checksum(pseudo + segment) or 65535)
    return bytes(segment)


def payload(length, lane, phase, sequence):
    return (b'UD' + phase.encode() + bytes([lane]) + struct.pack('!HH', sequence, length) +
            bytes((i * 17 + sequence * 13 + lane * 7) & 255 for i in range(8, length)))


class Peer:
    def __init__(self, lane, fault=False):
        self.lane = lane
        self.fault = fault
        self.guest = bytes([0x52, 0x54, 0, 0x12, 0x34, 0x10 + lane])
        self.mac = bytes([2, 0x41, 0x58, 0x55, 0x44, lane])
        self.guest_ip = bytes([10, 23, lane + 1, 2])
        self.ip = bytes([10, 23, lane + 1, 1])
        self.connection = None
        self.input, self.output = bytearray(), bytearray()
        self.arp = self.frames = self.zero = 0
        self.stack_started = False
        self.foreign = 0
        self.zero_checksum = self.malformed = self.filter_input = 0
        self.server_replies = self.reordered = self.closed = self.quote_errors = 0
        self.controls = set()
        self.closed_packet = None
        self.filter_quotes = []
        self.filter_errors = 0
        self.broadcast_requests = self.broadcast_ingress = self.broadcast_ack = 0
        self.pressure_ip = self.ip[:3] + b'\x03'
        self.pressure_mac = self.mac[:5] + bytes([self.lane + 10])
        self.pressure_arp = self.pressure_frames = self.unanswered = 0
        self.pressure_released = self.pressure_reply_queued = False

    def queue(self, frame):
        self.output.extend(struct.pack('!I', len(frame)) + frame)

    def arp_reply(self, target=None, mac=None):
        target, mac = target or self.ip, mac or self.mac
        return (self.guest + mac + b'\x08\x06' + struct.pack('!HHBBH', 1, 0x0800, 6, 4, 2) +
                mac + target + self.guest + self.guest_ip).ljust(60, b'\0')

    def incoming(self, data, destination_port, source_port=9000, identifier=0x6400,
                 source=None, broadcast=False, zero=False, surplus=b''):
        source = source or self.ip
        destination = b'\xff' * 4 if broadcast else self.guest_ip
        packet = ipv4(source, destination,
                      udp(source, destination, source_port, destination_port, data, zero) + surplus,
                      identifier=identifier)
        self.queue(((b'\xff' * 6 if broadcast else self.guest) + self.mac + b'\x08\x00' + packet).ljust(60, b'\0'))
        return packet

    def reply(self, destination_port, data, source_port=9000):
        return self.incoming(data, destination_port, source_port)

    def malformed_input(self):
        data = payload(31, self.lane, 'V', 0)
        good = udp(self.ip, self.guest_ip, 9000, 41000 + self.lane, data)
        forms = [good[:size] for size in range(8)]
        for length in [0, 7, 9]:
            header = bytearray(good[:8])
            struct.pack_into('!H', header, 4, length)
            header[6:8] = b'\0\0'
            forms.append(bytes(header))
        bad = bytearray(good)
        bad[7] ^= 1
        if not bad[6:8].strip(b'\0'):
            bad[7] = 1
        forms.append(bytes(bad))
        forms.append(udp(self.ip[:3] + b'\x09', self.guest_ip, 9000, 41000 + self.lane, data))
        bad = bytearray(good)
        struct.pack_into('!H', bad, 4, len(bad) - 1)
        forms.append(bytes(bad))
        assert len(forms) == 14
        for sequence, segment in enumerate(forms):
            packet = ipv4(self.ip, self.guest_ip, segment, identifier=0x7000 + sequence)
            self.queue((self.guest + self.mac + b'\x08\x00' + packet).ljust(60, b'\0'))
        self.incoming(data, 41000 + self.lane, identifier=0x700e, zero=True,
                      surplus=b'ignored-UDP-surplus')
        self.malformed += len(forms)

    def filter_packets(self):
        data = payload(31, self.lane, 'F', 0)
        self.filter_quotes = [self.incoming(data, 41000 + self.lane, 9009, identifier=0x7100),
            self.incoming(data, 41000 + self.lane, source=self.ip[:3] + b'\x09', identifier=0x7101)]
        self.incoming(data, 41000 + self.lane, identifier=0x7102)
        self.filter_input += 3

    def unmatched(self):
        data = payload(31, self.lane, 'C', 0)
        self.incoming(data, 49999, 9005, broadcast=True, identifier=0x72ff)
        invalid = bytearray(udp(self.ip, self.guest_ip, 9005, 49999, data))
        invalid[7] ^= 0x40
        self.queue((self.guest + self.mac + b'\x08\x00' +
                    ipv4(self.ip, self.guest_ip, bytes(invalid), identifier=0x72fe)).ljust(60, b'\0'))
        self.closed_packet = self.incoming(data, 49999, 9005, identifier=0x7300)

    def quoted(self, packet):
        quote = packet[:28]
        forms = []
        for offset in [20, 22, 16, 12, 0, 10, 24]:
            bad = bytearray(quote)
            if offset == 24:
                struct.pack_into('!H', bad, offset, 7)
            elif offset in [20, 22]:
                bad[offset + 1] ^= 1
            elif offset in [16, 12]:
                bad[offset + 3] ^= 1
                bad[10:12] = b'\0\0'
                struct.pack_into('!H', bad, 10, checksum(bytes(bad[:20])))
            else:
                bad[offset] ^= 1
            forms.append(bytes(bad))
        for code, quoted in [(3, bad) for bad in forms] + [(4, quote)]:
            error = bytearray(b'\x03' + bytes([code]) + b'\0' * 6 + quoted)
            struct.pack_into('!H', error, 2, checksum(bytes(error)))
            self.queue(self.guest + self.mac + b'\x08\x00' +
                       ipv4(self.ip, self.guest_ip, bytes(error), protocol=1))
        self.quote_errors += len(forms)

    def icmp(self, packet):
        data = packet[20:]
        if len(data) != 36 or data[:2] != b'\x03\x03' or checksum(data) or data[4:8] != b'\0' * 4:
            raise RuntimeError('UDP ICMP port-unreachable header or checksum differs')
        if self.filter_quotes and data[8:] == self.filter_quotes[0][:28] and not self.filter_errors:
            self.filter_errors += 1
            return
        if not self.closed_packet or self.closed or data[8:] != self.closed_packet[:28]:
            raise RuntimeError('UDP closed-port ICMP or suppressed-input error policy differs')
        self.closed += 1
        self.reply(41000 + self.lane, payload(31, self.lane, 'C', 0))

    def group_packet(self, data):
        sequence = self.broadcast_requests
        if data != payload(31, self.lane, 'B', sequence) or sequence >= 3:
            raise RuntimeError('UDP broadcast request sequence or bytes differ')
        self.broadcast_requests += 1
        if sequence == 0:
            self.incoming(data, 44000 + self.lane, broadcast=True)
        elif sequence == 1:
            for seq in [1,2]:
                self.incoming(payload(1400, self.lane, 'B', seq), 44000 + self.lane, broadcast=True)
        else:
            self.group_next()

    def group_next(self):
        if self.broadcast_ingress < 48:
            self.incoming(payload(31, self.lane, 'K', self.broadcast_ingress),
                          44000 + self.lane, broadcast=True)
            self.broadcast_ingress += 1

    def release_pressure(self):
        self.pressure_released = True
        if self.pressure_arp and not self.pressure_reply_queued:
            self.queue(self.arp_reply(self.pressure_ip, self.pressure_mac))
            self.pressure_reply_queued = True

    def packet(self, frame):
        if len(frame) < 14 or frame[6:12] != self.guest:
            raise RuntimeError('UDP peer received unexpected source MAC or short Ethernet frame')
        ours = ((frame[12:14] == b'\x08\x06' and len(frame) >= 42 and frame[28:32] == self.guest_ip) or
                (frame[12:14] == b'\x08\x00' and len(frame) >= 34 and frame[26:30] == self.guest_ip))
        # Firmware discovery precedes the first statically configured kernel packet.
        # After that boundary every frame must satisfy the guest wire contract.
        if not self.stack_started and not ours:
            self.foreign += 1
            return
        self.stack_started = True
        if frame[12:14] == b'\x08\x06':
            if (len(frame) < 42 or frame[:6] != b'\xff' * 6 or frame[6:12] != self.guest or
                    frame[14:22] != struct.pack('!HHBBH', 1, 0x0800, 6, 4, 1) or
                    frame[22:28] != self.guest or frame[28:32] != self.guest_ip):
                raise RuntimeError('UDP peer received invalid or misrouted ARP')
            target = frame[38:42]
            if target == self.pressure_ip:
                self.pressure_arp += 1
                if self.pressure_released:
                    self.release_pressure()
                return
            if target == self.ip[:3] + b'\x63':
                self.unanswered += 1
                return
            if target != self.ip:
                raise RuntimeError('UDP ARP route differs')
            self.arp += 1
            self.queue(self.arp_reply())
            return
        if frame[12:14] != b'\x08\x00':
            raise RuntimeError('UDP peer received unexpected Ethernet type')
        packet = frame[14:]
        broadcast = packet[16:20] == b'\xff' * 4
        pressure = packet[16:20] == self.pressure_ip
        expected_mac = b'\xff' * 6 if broadcast else self.pressure_mac if pressure else self.mac
        if (len(packet) < 28 or frame[:12] != expected_mac + self.guest or packet[:2] != b'\x45\0' or
                checksum(packet[:20]) or packet[6:9] != b'\x40\0\x40' or
                packet[12:16] != self.guest_ip or (not broadcast and not pressure and packet[16:20] != self.ip)):
            raise RuntimeError('UDP guest Ethernet/IPv4 header differs')
        total = int.from_bytes(packet[2:4], 'big')
        if total < 28 or total > len(packet) or any(packet[total:]):
            raise RuntimeError('UDP guest IPv4 length or padding differs')
        packet = packet[:total]
        if packet[9] == 1:
            self.icmp(packet)
            return
        if packet[9] != 17:
            raise RuntimeError('UDP guest protocol differs')
        segment = packet[20:total]
        source_port, destination_port, length, wire_sum = struct.unpack('!HHHH', segment[:8])
        pseudo = self.guest_ip + packet[16:20] + struct.pack('!BBH', 0, 17, length)
        if (length != len(segment) or not wire_sum or checksum(pseudo + segment)):
            raise RuntimeError('UDP guest ports, length, or pseudo-header checksum differ')
        data = segment[8:]
        if self.fault:
            if (self.lane != 1 or source_port != 47001 or destination_port != 9000 or self.frames or
                    data != payload(31, self.lane, 'G', 0)):
                raise RuntimeError('UDP failed-device peer exchange differs')
            self.frames += 1
            self.reply(source_port, data)
            return
        if pressure:
            if (source_port != 45000 + self.lane or destination_port != 9000 or
                    not self.pressure_released or self.pressure_frames >= 33 or
                    data != payload(129, self.lane, 'P', self.pressure_frames)):
                raise RuntimeError('UDP pending send ownership, original ports, or payload differ')
            self.pressure_frames += 1
            if self.pressure_frames == 33:
                self.reply(41000 + self.lane, payload(31, self.lane, 'P', 33))
            return
        if broadcast:
            if source_port != 41000 + self.lane or destination_port != 9000:
                raise RuntimeError('UDP broadcast ports differ')
            self.group_packet(data)
            return
        if source_port == 44000 + self.lane:
            if (destination_port != 9003 or self.broadcast_ack >= self.broadcast_ingress or
                    data != payload(31, self.lane, 'K', self.broadcast_ack)):
                raise RuntimeError('UDP active broadcast acknowledgment differs')
            self.broadcast_ack += 1
            self.group_next()
            return
        if source_port == 42000 + self.lane:
            if destination_port == 9002 and data == payload(73, self.lane, 'Q', 0) and not self.server_replies:
                self.server_replies += 1
                self.reply(41000 + self.lane, payload(31, self.lane, 'S', 0))
            elif (destination_port == 9004 and self.reordered < 4 and
                  data == payload(31, self.lane, 'O', [2,0,2,1][self.reordered])):
                self.reordered += 1
                if self.reordered == 4:
                    self.reply(41000 + self.lane, payload(31, self.lane, 'O', 0))
            else:
                raise RuntimeError('UDP server reply ports, order, or payload differ')
            return
        if source_port != 41000 + self.lane:
            raise RuntimeError('UDP guest source port differs')
        if destination_port == 9001:
            expected = bytearray(struct.pack('!HHHH', source_port, 9001, 10, 0))
            word = checksum(pseudo + expected + b'\0\0')
            if self.zero_checksum or data != struct.pack('!H', word) or wire_sum != 65535:
                raise RuntimeError('UDP computed-zero checksum encoding differs')
            self.zero_checksum += 1
            self.reply(source_port, data, 9001)
            return
        if destination_port != 9000:
            raise RuntimeError('UDP guest destination port differs')
        if self.frames == 4 and self.zero and data:
            if len(data) != 31 or data[:2] != b'UD' or data[3] != self.lane:
                raise RuntimeError('UDP control payload differs')
            phase = chr(data[2])
            if phase in self.controls or data != payload(31, self.lane, phase, 0):
                raise RuntimeError('UDP control phase, repetition, or bytes differ')
            self.controls.add(phase)
            if phase == 'V':
                self.malformed_input()
            elif phase == 'F':
                self.filter_packets()
            elif phase == 'S':
                self.reply(42000 + self.lane, payload(73, self.lane, 'Q', 0), 9002)
            elif phase == 'O':
                for sequence in [2,0,2,1]:
                    self.reply(42000 + self.lane, payload(31, self.lane, 'O', sequence), 9004)
            elif phase == 'C':
                self.unmatched()
            elif phase == 'I':
                self.quoted(packet)
            elif phase in ['L', 'R']:
                self.reply(source_port, data)
            else:
                raise RuntimeError('UDP unexpected control phase')
            return
        expected = [('E', 0, 129), ('E', 1, 47), ('E', 2, 31), ('M', 0, 1472)]
        if not data:
            if self.frames != len(expected) or self.zero:
                raise RuntimeError('UDP zero payload sequence differs')
            self.zero += 1
        else:
            if self.frames >= len(expected):
                raise RuntimeError('UDP unexpected guest payload')
            phase, sequence, size = expected[self.frames]
            if data != payload(size, self.lane, phase, sequence):
                raise RuntimeError('UDP guest payload differs')
            self.frames += 1
        self.reply(source_port, data)
