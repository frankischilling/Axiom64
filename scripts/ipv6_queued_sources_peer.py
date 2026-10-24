# SPDX-License-Identifier: GPL-3.0-or-later
"""Hold real neighbor resolution until admitted source ownership is withdrawn."""
import ipaddress
import struct
from ipv4_expiry_capture import checksum


def require(value, reason):
    if not value:
        raise ValueError(reason)


class QueuedSourcesPeer:
    def __init__(self, parent):
        self.parent = parent
        self.control = bytes([2, ord('Q'), ord('S'), ord('R'), parent.lane, 0])
        self.ready = False
        self.stages = []
        self.initial = {number: [] for number in range(8)}
        self.probes = {number: [] for number in range(8)}
        self.originals, self.fresh, self.fragments = {}, {}, {}
        self.waiting = set()
        self.completed = []

    def address(self, host):
        return ipaddress.IPv6Address(f'2001:db8:{0x460 + self.parent.lane:x}::{host:x}').packed

    def acknowledge(self, number, stage):
        self.parent.outgoing.append(self.parent.guest + self.control + b'\x88\xb7QSRC' +
            bytes([self.parent.lane, number, stage, 1, int(number in self.originals)]) + bytes(37))

    def receive(self, frame):
        peer = self.parent
        if frame[12:14] == b'\x88\xb7':
            require(len(frame) == 60 and frame[:12] == self.control + peer.guest and
                    frame[14:19] == b'QSRC' + bytes([peer.lane]) and not any(frame[21:]),
                    'exact queued-source phase request')
            number, stage = frame[19:21]
            if not self.ready:
                require((number, stage) == (255, 0), 'queued-source readiness before admission')
                self.ready = True
                self.acknowledge(number, stage)
                return True
            require(number in range(8) and stage in range(5) and
                    (number, stage) == (len(self.stages) // 5, len(self.stages) % 5),
                    'complete ordered queued-source cases and barriers')
            self.stages.append((number, stage))
            if stage == 0:
                require(number not in self.originals and not self.probes[number], 'creation barrier precedes source selection')
                self.acknowledge(number, stage)
            elif stage == 1:
                require(number not in self.originals, 'neighbor resolution still held at admission')
                if self.initial[number]:
                    self.acknowledge(number, stage)
                else:
                    self.waiting.add((number, stage))
            elif stage == 2:
                require(self.initial[number] and number not in self.originals,
                        'selected source witnessed before actual withdrawal')
                peer.outgoing.append(peer.na(self.address(0x83 + number * 16), peer.all_nodes))
                self.acknowledge(number, stage)
            elif stage == 3:
                if number in self.originals:
                    self.acknowledge(number, stage)
                else:
                    self.waiting.add((number, stage))
            elif number in self.fresh:
                self.completed.append(number)
                self.acknowledge(number, stage)
            else:
                self.waiting.add((number, stage))
            return True
        if len(frame) < 54 or frame[12:14] != b'\x86\xdd':
            return False
        prefix = self.address(1)[:6]
        if frame[22:28] != prefix and frame[38:44] != prefix:
            return False
        require(self.ready and frame[6:12] == peer.guest, 'queued-source adapter ownership')
        size, protocol, hop = struct.unpack('!HBB', frame[18:22])
        source, destination, body = frame[22:38], frame[38:54], frame[54:54 + size]
        require(frame[14:18] == b'\x60\0\0\0' and len(body) == size,
                'complete queued-source IPv6 envelope')
        if protocol == 58 and body[:2] == b'\x87\0':
            number = next((number for number in range(8) if body[8:24] == self.address(0x83 + number * 16)), None)
            require(number is not None and size == 32 and hop == 255 and
                    source in (self.address(0x82 + number * 16), self.address(1)) and
                    destination == peer.multicast(body[8:24]) and
                    frame[:6] == b'\x33\x33' + destination[-4:] and body[4:8] == bytes(4) and
                    body[24:] == b'\1\1' + peer.guest and
                    not checksum(source + destination + struct.pack('!I3xB', size, 58) + body),
                    'exact selected-source or surviving companion neighbor query')
            self.probes[number].append(source.hex())
            require(len(self.probes[number]) <= 4, 'original bounded neighbor attempts')
            if source == self.address(0x82 + number * 16):
                self.initial[number].append(source.hex())
                if (number, 1) in self.waiting:
                    self.waiting.remove((number, 1))
                    self.acknowledge(number, 1)
            return True
        number = next((number for number in range(8) if destination == self.address(0x83 + number * 16)), None)
        require(number is not None and frame[:12] == peer.mac + peer.guest and hop == 64,
                'queued-source original output destination and Ethernet ownership')
        if protocol == 44:
            require(number >= 4 and len(frame) <= 1514 and 8 < size <= 1460 and body[:2] == b'\x3a\0',
                    'bounded original raw fragment')
            field, identity = struct.unpack('!HI', body[2:8])
            offset, more = field & 0xfff8, bool(field & 1)
            require(identity and not field & 6 and (not more or (size - 8) % 8 == 0), 'raw fragment alignment')
            parts = self.fragments.setdefault((source, destination, identity), {})
            require(offset not in parts and len(parts) < 3, 'unique original fragment offsets')
            parts[offset] = body[8:], more
            if not any(not more for _, more in parts.values()):
                return True
            payload = bytearray()
            for position, (start, (data, continued)) in enumerate(sorted(parts.items())):
                if start != len(payload):
                    return True
                require(continued == (position < len(parts) - 1), 'complete original fragment sequence')
                payload.extend(data)
            require(len(parts) == 3, 'all original raw fragments at the selected MTU')
            self.transport(number, source, destination, bytes(payload), 58, True)
        else:
            require(protocol == (58 if number >= 4 else 17), 'selected queued-source transport')
            self.transport(number, source, destination, body, protocol, False)
        return True

    def transport(self, number, source, destination, body, protocol, fragmented):
        lane = self.parent.lane
        require(not checksum(source + destination + struct.pack('!I3xB', len(body), protocol) + body),
                'original queued-source transport checksum')
        if protocol == 17:
            require(not fragmented and len(body) == 24 and
                    body[:6] == struct.pack('!HHH', 59400 + lane * 10 + number, 55124, 24),
                    'original queued-source UDP ports and size')
            payload = body[8:]
            tag, actual_lane, actual_number = payload[:4], payload[4], payload[5]
            original = tag == b'QSRC'
            require(tag in (b'QSRC', b'QSRA') and payload[6:8] == bytes([0x5a, 0x71 if original else 0x72]),
                    'original UDP copy and companion tags')
        else:
            require(body[:2] == b'\x80\0' and len(body) >= 8, 'complete original raw record')
            payload = body
            tag, actual_lane, actual_number = payload[4:6], payload[6], payload[7]
            original = tag == b'QR'
            require(tag in (b'QR', b'QA') and len(body) == (4000 if original else 16) and
                    fragmented == original, 'complete original raw copy or companion')
        require(actual_lane == lane and actual_number == number and
                payload[8:] == bytes((at * 13 + lane + number) & 255 for at in range(8, len(payload))),
                'every original copied payload byte')
        records = self.originals if original else self.fresh
        require(number not in records and source == self.address(0x82 + number * 16 if original else 1) and
                (number, 2 if original else 3) in self.stages, 'retained copy and fresh companion source ordering')
        records[number] = len(payload)
        stage = 3 if original else 4
        if (number, stage) in self.waiting:
            self.waiting.remove((number, stage))
            if not original:
                self.completed.append(number)
            self.acknowledge(number, stage)

    @property
    def passed(self):
        return self.ready and self.completed == list(range(8)) and not self.waiting and len(self.originals) == len(self.fresh) == 8

    def result(self):
        return dict(passed=self.passed, completed=self.completed, probes=self.probes,
                    original_bytes=self.originals, companion_bytes=self.fresh, stages=self.stages)
