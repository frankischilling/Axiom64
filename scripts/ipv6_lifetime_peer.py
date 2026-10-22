# SPDX-License-Identifier: GPL-3.0-or-later
"""Echo the lifetime client's exact UDP datagrams on its isolated link."""
import ipaddress
import struct
from ipv6_host_peer import checksum, require


class LifetimePeer:
    def __init__(self, parent):
        self.parent = parent
        self.remote = ipaddress.IPv6Address(f'2001:db8:{0x420 + parent.lane:x}::100').packed
        self.sources = {ipaddress.IPv6Address(f'2001:db8:{0x420 + parent.lane:x}::{last:x}').packed
                        for last in (0x81, 0x82)}
        self.datagrams, self.probes, self.closed_fresh, self.barriers = [], [], [], []

    def receive(self, frame):
        if len(frame) < 54 or self.remote not in (frame[22:38], frame[38:54]) and not (
                frame[20] == 58 and frame[54:56] == b'\x87\0' and frame[62:78] == self.remote):
            return False
        peer = self.parent
        size, protocol, hop = struct.unpack('!HBB', frame[18:22])
        source, destination, body = frame[22:38], frame[38:54], frame[54:54 + size]
        require(len(body) == size and frame[6:12] == peer.guest and
                frame[14:18] == b'\x60\0\0\0' and source in self.sources and
                protocol in (17, 58) and not checksum(source + destination +
                struct.pack('!I3xB', size, protocol) + body), 'complete lifetime transport envelope')
        if protocol == 58 and body[:2] == b'\x87\0':
            require(size == 32 and hop == 255 and body[4:8] == bytes(4) and
                    body[8:24] == self.remote and body[24:] == b'\1\1' + peer.guest and
                    destination in (self.remote, peer.multicast(self.remote)) and
                    frame[:6] == (peer.mac if destination == self.remote else
                                  b'\x33\x33' + destination[-4:]), 'owned lifetime neighbor resolution')
            self.probes.append(source.hex())
            require(len(self.probes) <= 12, 'bounded lifetime neighbor probes')
            peer.outgoing.append(peer.na(self.remote, source))
        elif protocol == 58:
            require(size == 72 and hop == 64 and frame[:6] == peer.mac and
                    destination == self.remote and body[:2] == b'\1\4' and body[4:8] == bytes(4),
                    'closed fresh lifetime socket error')
            quote, udp = body[8:48], body[48:]
            require(quote[:8] == b'\x60\0\0\0\0\x18\x11\x40' and
                    quote[8:24] == self.remote and quote[24:] == source and
                    udp[:6] == struct.pack('!HHH', 55123, 59200 + peer.lane, 24) and
                    not checksum(quote[8:] + struct.pack('!I3xB', 24, 17) + udp),
                    'complete original closed fresh socket quote')
            payload = udp[8:]
            self.payload(payload)
            require(payload[6] == 2 and (payload[5], 2) in self.datagrams and
                    payload[5] not in self.closed_fresh, 'one error for an emitted fresh echo')
            self.closed_fresh.append(payload[5])
        else:
            require(size == 24 and hop == 64 and destination == self.remote and
                    frame[:6] == peer.mac, 'owned lifetime UDP destination')
            payload = body[8:]
            if payload[:4] == b'LIFB':
                self.payload(b'LIF6' + payload[4:])
                kind = payload[6]
                permanent = ipaddress.IPv6Address(f'2001:db8:{0x420 + peer.lane:x}::81').packed
                require(payload[5] == 2 and kind < 2 and kind not in self.barriers and
                        (2, kind) in self.datagrams and source == permanent and
                        body[:6] == struct.pack('!HHH', 59300 + peer.lane, 55123, 24),
                        'permanent-source barrier follows its original expired-source datagram')
                self.barriers.append(kind)
                reply = bytearray(struct.pack('!HHHH', 55123, 59300 + peer.lane, 24, 0) + payload)
                struct.pack_into('!H', reply, 6, checksum(destination + source +
                                 struct.pack('!I3xB', 24, 17) + reply) or 65535)
                peer.outgoing.append(peer.packet(destination, source, reply, hop=64, next_header=17))
                return True
            self.payload(payload)
            stage, kind = payload[5:7]
            require(body[:6] == struct.pack('!HHH', 59000 + kind * 100 + peer.lane, 55123, 24) and
                    (stage, kind) not in self.datagrams, 'exact lifetime UDP ports and one datagram')
            expected = ipaddress.IPv6Address(
                f'2001:db8:{0x420 + peer.lane:x}::{0x81 if stage and kind == 2 else 0x82:x}').packed
            require(source == expected, 'retained and fresh lifetime source selection')
            self.datagrams.append((stage, kind))
            reply = bytearray(struct.pack('!HHHH', 55123, 59000 + kind * 100 + peer.lane, 24, 0) + payload)
            struct.pack_into('!H', reply, 6, checksum(destination + source +
                             struct.pack('!I3xB', 24, 17) + reply) or 65535)
            peer.outgoing.append(peer.packet(destination, source, reply, hop=64, next_header=17))
        return True

    def payload(self, data):
        lane = self.parent.lane
        require(len(data) == 16 and data[:5] == b'LIF6' + bytes([lane]) and
                data[5] in range(3) and data[6] in range(3) and data[7] == 0x5a and
                data[8:] == bytes((at * 17 + lane + data[5] + data[6]) & 255 for at in range(8, 16)),
                'complete deterministic lifetime payload')

    @property
    def passed(self):
        return self.datagrams == [(stage, kind) for stage in range(3) for kind in range(3)] and self.barriers == [0, 1]

    def result(self):
        return dict(passed=self.passed, datagrams=self.datagrams, neighbor_probes=self.probes,
                    closed_fresh_errors=self.closed_fresh, barriers=self.barriers)
