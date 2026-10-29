# SPDX-License-Identifier: GPL-3.0-or-later
"""Observe device DAD through the healthy companion Ethernet adapter."""
import hashlib
import json
from pathlib import Path
import struct
import subprocess
import time

from ipv6_host_peer import checksum, require
from ipv6_owner_peer import multicast_report
from ipv6_router_peer import Peer as RouterPeer
from qmp import Qmp

ACTIONS = ('administrative', 'mtu', 'carrier')
HELLO, BEGIN, ADDRESS, SUMMARY, ARM, CHANGE, LINK, SECRET, END, FINISH, READY = range(11)


class Carrier:
    def __init__(self, path, monitor_path=None):
        self.path, self.monitor_path = Path(path), monitor_path
        self.monitor, self.events = None, []

    def change(self, subject, up):
        require((subject, up) == [(0, False), (0, True), (1, False), (1, True)][len(self.events)],
                'ordered physical carrier transitions')
        row = dict(subject=subject, up=up, begin_monotonic_ns=time.monotonic_ns())
        if self.monitor_path is None:
            command = ['ip', 'link', 'set', f'peer{subject}', 'up' if up else 'down']
            done = subprocess.run(command, capture_output=True, timeout=5)
            row.update(command=command, returncode=done.returncode,
                       stdout=done.stdout.decode(), stderr=done.stderr.decode())
            require(done.returncode == 0, 'actual native carrier transition')
            command = ['ip', '-j', 'link', 'show', 'dev', f'eth{subject}']
            result = subprocess.run(command, capture_output=True, timeout=5)
            row.update(query_command=command, query_returncode=result.returncode,
                       query_stdout=result.stdout.decode(), query_stderr=result.stderr.decode())
            require(result.returncode == 0, 'query actual native carrier state')
            values = json.loads(result.stdout)
            require(len(values) == 1 and 'UP' in values[0]['flags'] and
                    ('LOWER_UP' in values[0]['flags']) == up,
                    'carrier changes preserve selected administrative state')
        else:
            if self.monitor is None:
                self.monitor = Qmp(self.monitor_path)
            result = self.monitor.command('set_link', dict(name=f'carrier{subject}', up=up))
            require(result == {}, 'actual QEMU carrier transition')
            row['qmp'] = dict(command='set_link', name=f'carrier{subject}', up=up, result=result)
        row['end_monotonic_ns'] = time.monotonic_ns()
        self.events.append(row)
        self.path.write_text(json.dumps(dict(native=self.monitor_path is None, events=self.events),
                                        indent=2) + '\n')

    def close(self):
        if self.monitor is not None:
            self.monitor.close()
            self.monitor = None


class Peer(RouterPeer):
    def __init__(self, lane, action, native=False, carrier=None):
        super().__init__(lane, native)
        require(action in ACTIONS, 'known device action')
        self.action, self.carrier = action, carrier
        self.controls, self.probes, self.frames = [], [], []
        self.begun = self.finished = False

    def line(self, line):
        pass

    def receive(self, frame):
        require(len(frame) >= 14 and len(self.frames) < 2048 and frame[6:12] == self.guest,
                'bounded traffic from the actual device')
        self.frames.append(hashlib.sha256(frame).hexdigest())
        if frame[12:14] == b'\x88\xc4':
            require(len(frame) == 60 and frame[:12] == self.control + self.guest and
                    frame[14:19] == b'IP6V' + bytes([self.lane]), 'complete companion control identity')
            phase, kind, action, subject, stage = frame[19:24]
            require(phase == len(self.controls) and kind < 11 and action == ACTIONS.index(self.action) and
                    subject == 1 - self.lane, 'ordered companion controls identify their selected device')
            if kind == BEGIN:
                self.peers[subject].begun = True
            if kind == CHANGE:
                require(self.action == 'carrier' and stage in (0, 1) and self.carrier is not None,
                        'carrier change has an actual physical controller')
                self.carrier.change(subject, bool(stage))
            if kind == FINISH:
                require(not self.finished, 'one final companion control')
                self.finished = True
            self.controls.append(frame.hex())
            self.outgoing.append(self.guest + self.control + b'\x88\xc4IP6V' +
                                 bytes([self.lane, phase, 1]) + bytes(39))
            self.complete.append(phase)
            return
        if not self.begun:
            require(len(self.firmware) < 256, 'bounded original firmware traffic')
            self.firmware.append(frame.hex())
            return
        require(len(frame) >= 62 and frame[12:14] == b'\x86\xdd' and frame[14] >> 4 == 6 and
                len(frame) == 54 + int.from_bytes(frame[18:20], 'big'), 'complete original device IPv6 packet')
        if frame[20] == 0:
            require(self.native and len(self.mld) < 512, 'bounded native multicast reports')
            multicast_report(frame)
            self.mld.append(hashlib.sha256(frame).hexdigest())
            return
        source, destination, body = frame[22:38], frame[38:54], frame[54:]
        require(frame[20:22] == b'\x3a\xff' and source == bytes(16) and len(body) == 32 and
                body[:2] == b'\x87\0' and body[4:8] == bytes(4) and body[24:26] == b'\x0e\x01' and
                not checksum(source + destination + struct.pack('!I3xB', 32, 58) + body),
                'complete original enhanced DAD packet')
        target = body[8:24]
        require(target[:8] == b'\xfe\x80' + bytes(6) and
                destination == b'\xff\x02' + bytes(9) + b'\x01\xff' + target[-3:] and
                frame[:6] == b'\x33\x33\xff' + target[-3:], 'exact device DAD multicast identity')
        self.probes.append(dict(frame=frame.hex(), observed_ns=time.monotonic_ns()))

    def tick(self):
        pass

    def result(self):
        return dict(passed=self.finished and self.complete == list(range(len(self.controls))),
                    lane=self.lane, action=self.action, controls=self.controls, probes=self.probes,
                    frames=self.frames, firmware=self.firmware, native_MLD=self.mld,
                    packet_clock_qualified=False, full_F12_complete=False)
