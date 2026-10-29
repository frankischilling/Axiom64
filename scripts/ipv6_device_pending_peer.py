# SPDX-License-Identifier: GPL-3.0-or-later
"""Supply selected DAD conflicts through the healthy companion adapter."""
import hashlib
import ipaddress
import struct
import time
from ipv6_device_peer import Peer as ReadyPeer
from ipv6_host_peer import require

STATE, CONFLICT = 11, 12
STATES = ('probing', 'regenerating', 'retrying', 'exhausted')

class Peer(ReadyPeer):
    def __init__(self, lane, action, state, native=False, carrier=None, delivery=None):
        super().__init__(lane, action, native, carrier)
        require(state in STATES, 'explicit pending-device state')
        self.state = state
        self.conflicts, self.pending_conflict = [], None
        self.mode_seen = False
        self.delivery = delivery

    def acknowledge(self, frame):
        phase = frame[19]
        self.controls.append(frame.hex())
        self.outgoing.append(self.guest + self.control + b'\x88\xc4IP6V' +
                             bytes([self.lane, phase, 1]) + bytes(39))
        self.complete.append(phase)

    def receive(self, frame):
        if len(frame) >= 21 and frame[12:14] == b'\x88\xc4' and frame[20] in (STATE, CONFLICT):
            require(len(self.frames) < 2048, 'bounded pending device traffic')
            self.frames.append(hashlib.sha256(frame).hexdigest())
            require(len(frame) == 60 and frame[:12] == self.control + self.guest and
                    frame[14:19] == b'IP6V' + bytes([self.lane]) and
                    frame[19] == len(self.controls) and frame[21] == ('administrative','mtu','carrier').index(self.action) and
                    frame[22] == 1 - self.lane and self.pending_conflict is None,
                    'complete ordered pending-device companion request')
            if frame[20] == STATE:
                require(not self.mode_seen and frame[23] == 0 and
                        frame[24:52] == struct.pack('!I', STATES.index(self.state)) + bytes(24),
                        'one explicit pending-device state')
                self.mode_seen = True
                self.acknowledge(frame)
                return
            require(self.mode_seen and self.state != 'probing' and frame[23] == len(self.conflicts) and
                    len(self.conflicts) < (4 if self.state == 'exhausted' else 1),
                    'bounded selected pending-device conflicts')
            subject = self.peers[1 - self.lane]
            target = frame[36:52]
            probes = [value for value in subject.probes if bytes.fromhex(value['frame'])[62:78] == target]
            require(len(probes) == 1 and target not in [value['target'] for value in self.conflicts] and
                    struct.unpack_from('!III', frame, 24) == (0x8c0, 0xffffffff, 0xffffffff),
                    'queried fresh tentative target has one real selected probe')
            body = b'\x88\0\0\0' + struct.pack('!I', 0x20000000) + target + b'\x02\x01' + subject.mac
            conflict = subject.frame(subject.router, ipaddress.IPv6Address('ff02::1').packed, body)
            subject.outgoing.append(conflict)
            self.pending_conflict = frame
            self.conflicts.append(dict(target=target, scheduled_ns=time.monotonic_ns(), frame=conflict.hex()))
            return
        super().receive(frame)

    def tick(self):
        if self.pending_conflict is None:
            return
        subject = self.peers[1 - self.lane]
        if subject.outgoing or subject.output:
            return
        if not self.native:
            require(self.delivery is not None, 'guest conflicts require physical capture receipts')
            receipt = self.delivery.receipt(1 - self.lane, bytes.fromhex(self.conflicts[-1]['frame']))
            if receipt is None:
                return
            self.conflicts[-1]['capture_delivery'] = receipt
        self.acknowledge(self.pending_conflict)
        self.pending_conflict = None

    def result(self):
        result = super().result()
        expected = 0 if self.state == 'probing' else 4 if self.state == 'exhausted' else 1
        result['passed'] &= self.mode_seen and self.pending_conflict is None and len(self.conflicts) == expected
        result.update(state=self.state, conflict_frames=[{**value, 'target':value['target'].hex()} for value in self.conflicts],
                      full_DAD_acceptance=False)
        return result
