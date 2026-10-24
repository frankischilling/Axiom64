# SPDX-License-Identifier: GPL-3.0-or-later
"""Inject conflicts only after the actual DAD probe and tentative address observation."""
import hashlib
import ipaddress
import struct
import time

from ipv6_host_peer import checksum, require
from ipv6_router_peer import Peer as RouterPeer


class Peer(RouterPeer):
    def __init__(self, lane, native=False, retain_routes=False):
        super().__init__(lane, native)
        self.retain_routes = retain_routes
        self.frames = []
        self.controls = []
        self.scenario = 0
        self.finished = 0
        self.targets = {scenario: [] for scenario in range(1, 7)}
        self.observed = {}
        self.probes = {}
        self.conflicts = []
        self.recovered = []
        self.link_target = None
        self.link_eui = None
        self.link_stage = 0

    def line(self, line):
        pass

    def ack(self, phase):
        self.outgoing.append(self.guest + self.control + b'\x88\xc2IP6D' +
                             bytes([self.lane, phase, 1]) + bytes(39))
        self.complete.append(phase)

    def conflict(self, scenario, trial):
        key = scenario, trial
        value = self.observed.get(key)
        probes = self.probes.get(key, [])
        if value is None or value['kind'] != 2 or value.get('sent'):
            return
        needed = 3 if scenario == 6 else 1
        if len(probes) != needed:
            return
        require(probes[-1]['target'] == value['target'], 'observed candidate owns the actual DAD probe')
        target = bytes.fromhex(value['target'])
        body = bytes([136, 0, 0, 0]) + struct.pack('!I', 0x20000000) + target + b'\x02\x01' + self.mac
        self.outgoing.append(self.frame(self.router, ipaddress.IPv6Address('ff02::1').packed, body))
        value['sent'] = True
        self.conflicts.append(dict(scenario=scenario, trial=trial, target=target.hex(),
            observed_monotonic_ns=time.monotonic_ns(), prerequisite_probes=needed))

    def control_frame(self, frame):
        require(len(frame) == 60 and frame[:6] == self.control and
                frame[14:19] == b'IP6D' + bytes([self.lane]),
                'complete DAD candidate control frame')
        phase, kind, scenario, trial = frame[19:23]
        require(frame[23] == (int(self.retain_routes) if kind == 0 else 0),
                'explicit source-pinned prefix-cleanup policy')
        flags, preferred, valid = struct.unpack_from('!III', frame, 24)
        target, stamp = frame[36:52], int.from_bytes(frame[52:60], 'big')
        require(phase == len(self.controls) and phase < 31 and stamp > 0,
                'ordered bounded original DAD controls')
        value = dict(phase=phase, kind=kind, scenario=scenario, trial=trial, flags=flags,
                     preferred=preferred, valid=valid, target=target.hex(), guest_monotonic_ns=stamp,
                     observed_monotonic_ns=time.monotonic_ns())
        if kind not in (2, 3):
            require((flags, preferred, valid) == (0, 0, 0) and target == bytes(16) and trial == 0,
                    'control without an address has no synthesized address metadata')
        if kind == 0:
            require(phase == 0 and scenario == 0, 'one initial DAD control')
            self.ready = True
        elif kind == 1:
            require(scenario == self.scenario + 1 and self.finished == self.scenario,
                    'six ordered complete DAD scenarios')
            self.scenario = scenario
            if scenario != 5:
                self.outgoing.append(self.advertisement(lifetime=0, valid=60, preferred=30,
                    hops=64, mtu=1500, pio_flags=((scenario, 0x40 if scenario == 2 else 0xc0),)))
        elif kind in (2, 3):
            count = 4 if scenario in (2, 3) else 2 if scenario in (1, 6) else 1
            key = scenario, trial
            require(scenario == self.scenario and 0 <= trial < count and key not in self.observed,
                    'one complete tentative observation per actual trial')
            expected_flags = 0x140 if scenario == 4 else 0xc0 if scenario == 5 else 0x940
            expected_lifetimes = (0xffffffff, 0xffffffff) if scenario == 5 else (30, 60)
            require(flags == expected_flags and (preferred, valid) == expected_lifetimes and
                    target[:8] == self.prefixes[scenario][:8], 'exact tentative flags, lifetimes and prefix')
            require(kind == (3 if scenario in (1, 6) and trial == 1 else 2),
                    'only the recovery trial proceeds without a conflict')
            require(trial == 0 or (scenario, trial - 1) in self.observed,
                    'candidate counters advance in order')
            self.observed[key] = value
            self.conflict(scenario, trial)
        elif kind == 4:
            require(scenario == self.scenario and self.finished == scenario - 1,
                    'one completion per active DAD scenario')
            count = 4 if scenario in (2, 3) else 2 if scenario in (1, 6) else 1
            require(len(self.targets[scenario]) == count and
                    all((scenario, trial) in self.observed for trial in range(count)),
                    'all actual trials precede the completed inventory')
            if scenario in (2, 3, 4, 5):
                last = next(row for row in reversed(self.conflicts) if row['scenario'] == scenario)
                require(time.monotonic_ns() - last['observed_monotonic_ns'] >= 3e9,
                        'full real three-second exhausted or permanent observation')
            if scenario in (1, 6):
                require(scenario in self.recovered, 'actual UDP exchange from the recovered stable address')
            self.finished = scenario
        elif kind == 5:
            require(scenario == self.finished == 5, 'manual permanent object is explicitly removed after inspection')
        elif kind == 6:
            require(scenario in (4, 5) and self.finished == self.scenario == scenario - 1 and
                    self.link_stage == (0 if scenario == 4 else 4),
                    'explicit ordered link-local generation mode change')
            self.link_stage = scenario
        elif kind == 9:
            require(scenario == 0 and self.finished == 6 and phase == 30,
                    'all six DAD scenarios finish before the final control')
        else:
            raise ValueError('unknown DAD control operation')
        self.controls.append(value)
        self.ack(phase)

    def receive(self, frame):
        require(len(self.frames) < 1024 and len(frame) >= 14 and frame[6:12] == self.guest,
                'bounded complete DAD traffic from the actual adapter')
        self.frames.append(dict(frame=frame.hex(), sha256=hashlib.sha256(frame).hexdigest(),
                                observed_monotonic_ns=time.monotonic_ns()))
        if frame[12:14] == b'\x88\xc2':
            self.control_frame(frame)
            return
        if not self.ready:
            self.firmware.append(frame.hex())
            return
        require(len(frame) >= 62 and frame[12:14] == b'\x86\xdd' and frame[14] >> 4 == 6,
                'complete DAD IPv6 frame')
        length, protocol, hops = struct.unpack_from('!HBB', frame, 18)
        require(len(frame) == 54 + length, 'exact DAD IPv6 payload length')
        source, destination, body = frame[22:38], frame[38:54], frame[54:]
        if protocol == 0:
            require(self.native and len(body) >= 16 and body[:2] == bytes([58, 0]) and hops == 1 and
                    body[8] in (131, 132, 143) and not checksum(source + destination +
                    struct.pack('!I3xB', len(body) - 8, 58) + body[8:]), 'complete original native multicast report')
            self.mld.append(frame.hex())
            return
        require(protocol in (17, 58) and not checksum(source + destination +
                struct.pack('!I3xB', len(body), protocol) + body), 'complete original DAD upper-layer checksum')
        if protocol == 17:
            require(len(body) == 24 and body[8:13] == b'DADC' + bytes([self.lane]) and
                    frame[:6] == self.mac and hops == 64 and body[6:8] != bytes(2),
                    'complete recovered unicast UDP payload, checksum and destination')
            scenario = body[13]
            require(scenario == self.scenario and scenario in (1, 6) and scenario not in self.recovered and
                    source.hex() == self.observed[scenario, 1]['target'] and
                    destination == self.prefixes[scenario][:-1] + b'\x42' and
                    struct.unpack_from('!HHH', body) == (48000 + self.lane, 48010 + scenario, 24) and
                    body[14:] == bytes(scenario * 7 + at for at in range(6, 16)),
                    'one exact recovered-source UDP request per recovery case')
            reply = bytearray(struct.pack('!HHHH', 48010 + scenario, 48000 + self.lane, 24, 0) + body[8:])
            struct.pack_into('!H', reply, 6, checksum(destination + source + struct.pack('!I3xB', 24, 17) + reply) or 0xffff)
            self.outgoing.append(self.frame(destination, source, reply, hops=64, protocol=17))
            self.recovered.append(scenario)
            return
        require(hops == 255 and body[0:2] == b'\x87\0' and len(body) == 32 and not any(body[4:8]),
                'only complete expected DAD and neighbor solicitations')
        target = body[8:24]
        solicited = b'\xff\x02' + bytes(9) + b'\x01\xff' + target[-3:]
        require(destination == solicited and frame[:6] == b'\x33\x33\xff' + target[-3:],
                'exact solicited-node IPv6 and Ethernet destinations')
        if source != bytes(16):
            require(self.scenario in (1, 6) and target == self.prefixes[self.scenario][:-1] + b'\x42' and
                    source in (self.link_target, self.link_eui, bytes.fromhex(self.observed[self.scenario, 1]['target'])) and
                    body[24:] == b'\x01\x01' + self.guest, 'complete recovered-address neighbor query')
            answer = b'\x88\0\0\0' + struct.pack('!I', 0x60000000) + target + b'\x02\x01' + self.mac
            self.outgoing.append(self.frame(target, source, answer))
            return
        require(body[24:26] == b'\x0e\x01', 'one complete enhanced DAD nonce option')
        if ipaddress.IPv6Address(target).is_link_local:
            if self.link_stage == 0:
                require(self.link_target is None and self.scenario == 0 and target != self.link,
                        'one actual stable link-local DAD probe')
                self.link_target = target
            else:
                require(self.link_stage == 4 and self.link_eui is None and target == self.link,
                        'one actual EUI-64 link-local DAD probe after the explicit mode change')
                self.link_eui = target
            return
        scenario = int.from_bytes(target[6:8], 'big')
        require(scenario == self.scenario and target[:8] == self.prefixes[scenario][:8],
                'DAD candidate belongs to the current exact prefix')
        targets = self.targets[scenario]
        if target not in targets:
            maximum = 4 if scenario in (2, 3) else 2 if scenario in (1, 6) else 1
            require(len(targets) < maximum, 'bounded distinct DAD regeneration attempts')
            targets.append(target)
        trial = targets.index(target)
        if scenario == 4:
            require(target == self.addresses[4], 'plain autoconfiguration retains the EUI-64 address algorithm')
        elif scenario == 5:
            require(target == self.prefixes[5][:-2] + b'\xab\xcd', 'actual configured permanent DAD target')
        else:
            require(target != self.addresses[scenario], 'stable generation never falls back to EUI-64')
        probes = self.probes.setdefault((scenario, trial), [])
        require(len(probes) < (3 if scenario == 6 else 1), 'complete configured DAD probe count')
        probes.append(dict(target=target.hex(), frame=frame.hex(), observed_monotonic_ns=time.monotonic_ns()))
        self.conflict(scenario, trial)

    def result(self):
        passed = (self.complete == list(range(31)) and self.finished == 6 and self.link_target is not None and
                  self.link_eui is not None and self.link_stage == 5 and
                  len(self.observed) == 14 and len(self.conflicts) == 12 and self.recovered == [1, 6] and
                  sum(map(len, self.probes.values())) == 18)
        return dict(passed=passed, lane=self.lane, phases=self.complete, controls=self.controls,
            conflicts=self.conflicts, probes=[dict(scenario=key[0], trial=key[1], packets=value)
                for key, value in self.probes.items()], recovered_UDP=self.recovered,
            link_local_target=self.link_target.hex() if self.link_target is not None else None,
            EUI64_link_local_target=self.link_eui.hex() if self.link_eui is not None else None,
            retained_exhausted_prefix_policy=self.retain_routes,
            received_frames=self.frames, firmware_frames=self.firmware, native_MLD=self.mld,
            full_F12_complete=False, packet_clock_qualified=False)
