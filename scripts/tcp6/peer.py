# SPDX-License-Identifier: GPL-3.0-or-later
"""Run the original TCP loss workload over independently encoded IPv6 frames."""
import ipaddress
import struct
import time
from tcp_fault_peer import Flow as IPv4Flow, Peer as IPv4Peer, SYN, check, checksum


def packet(frame):
    check(len(frame) >= 74 and frame[12:14] == b'\x86\xdd', 'complete IPv6 TCP frame')
    ip = frame[14:]
    length = int.from_bytes(ip[4:6], 'big')
    check(ip[0] >> 4 == 6 and ip[6] == 6 and 20 <= length <= len(ip) - 40,
          'IPv6 TCP version, protocol and declared bounds')
    tcp = ip[40:40 + length]
    source, target, sequence, acknowledgment, bits, window, _, urgent = struct.unpack_from('!HHIIHHHH', tcp)
    header = (bits >> 12) * 4
    check(20 <= header <= length and not bits & 0x0e00 and not urgent and
          checksum(ip[8:40] + struct.pack('!I3xB', length, 6) + tcp) == 0,
          'IPv6 TCP checksum and header bounds')
    at = 20
    while at < header:
        kind = tcp[at]
        if kind == 0:
            break
        if kind == 1:
            at += 1
            continue
        check(at + 2 <= header and tcp[at + 1] >= 2 and at + tcp[at + 1] <= header,
              'IPv6 TCP option bounds')
        at += tcp[at + 1]
    return dict(source=source, target=target, seq=sequence, ack=acknowledgment,
                flags=bits & 0x1ff, window=window, data=tcp[header:],
                source_ip=ip[8:24], target_ip=ip[24:40])


class Flow(IPv4Flow):
    def send(self, flags=16, sequence=None, data=b'', window=8192, acknowledgment=None):
        options = bytes.fromhex('02040218') if flags & SYN else b''
        sequence = self.origin + self.sent + int(self.fin_sent) if sequence is None else sequence
        if acknowledgment is None:
            acknowledgment = 0 if self.guest_origin is None else self.guest_next
        if flags == SYN:
            acknowledgment = 0
        tcp = bytearray(struct.pack('!HHIIHHHH', self.local_port, self.guest_port,
            sequence & 0xffffffff, acknowledgment, ((20 + len(options)) // 4) << 12 | flags,
            window, 0, 0) + options + data)
        tcp[16:18] = struct.pack('!H', checksum(self.peer.ip + self.peer.address +
                                              struct.pack('!I3xB', len(tcp), 6) + tcp))
        self.peer.send(self.peer.envelope(self.peer.ip, self.peer.address, bytes(tcp), 6))


class Peer(IPv4Peer):
    flow_type = Flow

    def __init__(self, lane, minimum_fin_ms=850, native=False):
        super().__init__(lane, minimum_fin_ms)
        self.ip = ipaddress.IPv6Address(f'2001:db8:{lane + 1}::1').packed
        self.address = ipaddress.IPv6Address(f'2001:db8:{lane + 1}::2').packed
        self.ready = False
        self.native = native
        self.firmware = []

    def envelope(self, source, target, body, protocol=58, hop=64):
        if protocol == 58:
            body = bytearray(body)
            body[2:4] = bytes(2)
            body[2:4] = struct.pack('!H', checksum(source + target +
                                       struct.pack('!I3xB', len(body), 58) + body))
        mac = b'\x33\x33' + target[-4:] if target[0] == 255 else self.guest
        return (mac + self.mac + b'\x86\xdd' +
                struct.pack('!IHBB', 6 << 28, len(body), protocol, hop) + source + target + body)

    def receive(self, frame):
        check(len(frame) >= 14 and frame[6:12] == self.guest, 'IPv6 loss interface owner')
        record = dict(direction='receive', ms=(time.monotonic() - self.began) * 1000, frame=frame.hex())
        self.frames.append(record)
        if frame[12:14] == b'\x88\xc1':
            control = bytes([2, ord('I'), ord('P'), ord('6'), self.lane, 0])
            check(not self.ready and len(frame) == 60 and frame[:6] == control and
                  frame[14:20] == b'IP6T' + bytes([self.lane, 0]) and not any(frame[20:]),
                  'one original IPv6 readiness barrier')
            self.ready = True
            answer = bytearray(frame)
            answer[:12] = self.guest + control
            answer[20] = 1
            self.send(answer)
            return
        if not self.ready and not self.native:
            check(len(self.firmware) < 256, 'bounded firmware prelude before readiness')
            self.firmware.append(frame.hex())
            return
        check(frame[12:14] == b'\x86\xdd' and len(frame) >= 54, 'IPv6 workload envelope')
        ip = frame[14:]
        length = int.from_bytes(ip[4:6], 'big')
        check(ip[0] >> 4 == 6 and 40 + length <= len(ip), 'IPv6 workload payload bounds')
        if ip[6] == 6:
            segment = packet(frame)
            check(frame[:6] == self.mac and segment['source_ip'] == self.address and
                  segment['target_ip'] == self.ip, 'full IPv6 loss tuple')
            flow = next((item for item in self.flows if segment['target'] == item.local_port), None)
            check(flow is not None and (flow.guest_port is None or segment['source'] == flow.guest_port),
                  'IPv6 loss TCP port owner')
            record['role'] = flow.role
            flow.input(segment, record)
            return
        if ip[6] == 0 and self.native:
            # Native MLDv2 uses the eight-byte Router Alert hop-by-hop header.
            check(ip[40:48] == bytes.fromhex('3a00050200000100') and ip[7] == 1 and
                  ip[24:40] == ipaddress.IPv6Address('ff02::16').packed and
                  ip[48:50] == b'\x8f\0' and checksum(ip[8:40] +
                  struct.pack('!I3xB', length - 8, 58) + ip[48:40 + length]) == 0,
                  'native multicast listener maintenance envelope')
            return
        check(ip[6] == 58 and length >= 8 and checksum(ip[8:40] +
              struct.pack('!I3xB', length, 58) + ip[40:40 + length]) == 0,
              'IPv6 neighbor discovery checksum')
        body = ip[40:40 + length]
        if body[:2] == b'\x85\0':
            automatic = ipaddress.IPv6Address('fe80::').packed[:8] + bytes([
                self.guest[0] ^ 2, *self.guest[1:3], 255, 254, *self.guest[3:]])
            check(ip[7] == 255 and length == 16 and body[4:8] == bytes(4) and
                  body[8:] == b'\1\1' + self.guest and
                  ip[8:24] in (ipaddress.IPv6Address('fe80::2').packed, automatic) and
                  ip[24:40] == ipaddress.IPv6Address('ff02::2').packed,
                  'configured link-local router solicitation')
            return
        check(length >= 24, 'complete neighbor solicitation body')
        check(body[:2] == b'\x87\0' and ip[7] == 255, 'owned neighbor solicitation')
        target = body[8:24]
        if ip[8:24] == bytes(16):
            check(target[-1] == 2 and length == 24, 'local duplicate address detection')
            return
        check(target == self.ip and ip[8:24] == self.address and length == 32 and
              body[24:] == b'\1\1' + self.guest, 'assigned source resolves the controlled peer')
        answer = b'\x88\0\0\0\x60\0\0\0' + self.ip + b'\2\1' + self.mac
        self.send(self.envelope(self.ip, self.address, answer, hop=255))
