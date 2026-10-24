# SPDX-License-Identifier: GPL-3.0-or-later
"""Control address-owner conflicts after the actual probe and queried metadata."""
import hashlib
import ipaddress
import struct
import time

from ipv6_host_peer import checksum, require
from ipv6_router_peer import Peer as RouterPeer

HELLO, BEGIN, ADDRESS, SUMMARY, CONFLICT, MODE, DELETE, END, FINISH, FIRST, READY = range(11)
INFINITY = 0xffffffff


def multicast_report(frame):
    """Validate complete native MLD; reports never advance an ownership barrier."""
    source, destination, payload = frame[22:38], frame[38:54], frame[54:]
    require(frame[21] == 1 and len(payload) >= 16 and payload[:8] == b'\x3a\0\x05\x02\0\0\x01\0' and
            frame[:6] == b'\x33\x33' + destination[-4:] and
            (source == bytes(16) or ipaddress.IPv6Address(source).is_link_local),
            'complete native MLD hop-by-hop router alert, source and multicast destination')
    body = payload[8:]
    require(not checksum(source + destination + struct.pack('!I3xB', len(body), 58) + body) and
            body[1] == 0, 'complete native MLD checksum and code')
    if body[0] in (131, 132):
        require(len(body) == 24 and body[4:8] == bytes(4) and body[8] == 255 and
                destination == (body[8:24] if body[0] == 131 else ipaddress.IPv6Address('ff02::2').packed),
                'complete native MLDv1 report or leave')
    else:
        require(body[0] == 143 and body[4:6] == bytes(2) and
                destination == ipaddress.IPv6Address('ff02::16').packed,
                'complete native MLDv2 destination and header')
        count, at = int.from_bytes(body[6:8], 'big'), 8
        require(0 < count <= 32, 'bounded native multicast record count')
        for _ in range(count):
            require(at + 20 <= len(body) and 1 <= body[at] <= 6 and body[at+1] == 0 and
                    body[at+4] == 255, 'complete native multicast record')
            at += 20 + 16 * int.from_bytes(body[at+2:at+4], 'big')
        require(at == len(body), 'complete native multicast record framing')


class Peer(RouterPeer):
    def __init__(self, lane, group='global', native=False, retain_routes=False):
        super().__init__(lane, native)
        require(group in ('global', 'lifecycle', 'secret'), 'known ownership group')
        self.group, self.retain_routes = group, retain_routes
        self.cases = list(range(1, 5) if group == 'global' else (1, 7) if group == 'secret' else range(5, 10))
        self.prefixes.update({case: ipaddress.IPv6Address(f'2001:db8:{0x40+lane:x}:{case:x}::').packed
                              for case in self.cases})
        self.frames, self.controls, self.ended = [], [], []
        self.case, self.finished, self.pending = 0, False, None
        self.inventories, self.samples, self.probes, self.conflicts, self.removals = {}, {}, {}, {}, {}
        self.mode_changed = False

    def line(self, line):
        pass

    def ack(self, phase):
        self.outgoing.append(self.guest + self.control + b'\x88\xc3IP6O' +
                             bytes([self.lane, phase, 1]) + bytes(39))
        self.complete.append(phase)

    def conflict(self):
        if self.pending is None:
            return
        value = self.pending
        key = value['case'], value['stage']
        target = value['target']
        packets = self.probes.get(value['case'], {}).get(target, [])
        if not packets:
            return
        require(len(packets) == 1 and key not in self.conflicts,
                'one actual selected DAD probe precedes each ownership conflict')
        body = b'\x88\0\0\0' + struct.pack('!I', 0x20000000) + target + b'\x02\x01' + self.mac
        # Conflict must reach the adapter before the ACK starts the client's wait.
        self.outgoing.append(self.frame(self.router, ipaddress.IPv6Address('ff02::1').packed, body))
        self.conflicts[key] = dict(target=target, observed_ns=time.monotonic_ns())
        self.ack(value['phase'])
        self.pending = None

    def inventory(self, case, stage, rows, count, routes):
        require(count == len(rows) and len({row['target'] for row in rows}) == count,
                'actual complete unique address inventory')
        if case <= 4:
            if stage == 0:
                require(count == 1 and rows[0]['flags'] == (0x80 if case == 2 else 0x880) and
                        rows[0]['preferred'] == rows[0]['valid'] == INFINITY and
                        ipaddress.IPv6Address(rows[0]['target']).is_link_local and
                        (rows[0]['target'] == self.link) == (case == 2),
                        'one ready permanent link-local owner in the selected generation mode')
                require(len(self.probes[case].get(rows[0]['target'], [])) == 1,
                        'actual initial link-local DAD precedes global advertisement')
                self.outgoing.append(self.advertisement(lifetime=0, valid=100 if case == 2 else 60,
                    preferred=60 if case == 2 else 30, hops=64, mtu=1500, pio_flags=((case, 0xc0),)))
            else:
                require(all(row['target'][:8] == self.prefixes[case][:8] for row in rows),
                        'all global owners belong to the actual advertised prefix')
                if stage == 1:
                    require(count == 1 and rows[0]['flags'] == (0x100 if case == 2 else 0x940),
                            'actual original automatic address metadata')
                    if case == 2:
                        require(58 <= rows[0]['preferred'] <= 60 and rows[0]['valid'] == rows[0]['preferred'] + 40,
                                'finite completed EUI64 cache naturally ages')
                    else:
                        require((rows[0]['preferred'], rows[0]['valid']) == (30, 60),
                                'actual original stable tentative lifetimes')
                elif stage == 2:
                    flags = {1:0x8c0, 2:0x82, 3:0x8c2, 4:0x840}[case]
                    lifetimes = (6, 10) if case == 4 else (INFINITY, INFINITY)
                    require(count == 1 and rows[0]['flags'] == flags and
                            (rows[0]['preferred'], rows[0]['valid']) == lifetimes,
                            'takeover preserves exact requested raw flags and lifetimes')
                elif stage in (3, 4):
                    require(case != 2 and count == (2 if stage == 3 and case != 4 else 1),
                            'permanent failed owner retained; finite failed owner removed')
                    failed = [row for row in rows if row['flags'] & 8]
                    active = [row for row in rows if not row['flags'] & 8]
                    require(len(active) == 1 and active[0]['flags'] == {1:0x880,3:0x882,4:0x800}[case],
                            'one ready retry keeps raw owner flags')
                    require(len(failed) == int(stage == 3 and case != 4) and
                            all(row['flags'] == (0x8ca if case == 3 else 0x8c8) and
                                row['preferred'] == row['valid'] == INFINITY for row in failed),
                            'failed permanent identity and lifetimes remain intact')
                    if case == 4:
                        require(1 <= active[0]['preferred'] <= 2 and active[0]['valid'] == active[0]['preferred'] + 4,
                                'finite retry naturally ages its copied six/ten-second cache')
                    else:
                        require(active[0]['preferred'] == active[0]['valid'] == INFINITY,
                                'infinite retry owner remains infinite')
                elif stage == 5:
                    require(count == 0, 'last explicit removal leaves no global owner')
                else:
                    raise ValueError('unknown global ownership inventory stage')
                require(routes == (int(self.retain_routes and case == 4) if stage == 5 else 1),
                        'actual connected prefix follows preselected finite cleanup policy')
        elif case <= 7:
            require(stage == 3 and count == {5:2,6:3,7:4}[case] and
                    all(ipaddress.IPv6Address(row['target']).is_link_local and
                        row['preferred'] == row['valid'] == INFINITY for row in rows),
                    'complete permanent link-local owner inventory')
            failed = [row for row in rows if row['flags'] & 8]
            require(len(failed) == (4 if case == 7 else 1) and all(row['flags'] == 0x8c8 for row in failed),
                    'every failed permanent link-local identity remains owned')
            active = [row for row in rows if not row['flags'] & 8]
            require(sorted(row['flags'] for row in active) == ([] if case == 7 else [0x80,0x880] if case == 6 else [0x880]),
                    'mode changes preserve stable retry plus independent EUI64 owner')
            require(case != 6 or any(row['target'] == self.link and row['flags'] == 0x80 for row in active),
                    'actual mode-zero EUI64 identity is independently ready')
        else:
            if stage == 3:
                require(count == 0 and routes == int(self.retain_routes),
                        'failed nonpermanent configured owner disappears before expiry')
            elif stage in (4, 5):
                require(count == 1 and routes == 1 and rows[0]['target'] == self.prefixes[case][:-1] + b'\x23',
                        'same finite recreation owns its exact requested address and connected prefix')
                value = rows[0]
                expected_flags = (2 if case == 9 else 0x40) if stage == 4 else (
                    2 if case == 9 else 0x20 if value['preferred'] == 0 else 0)
                require(value['flags'] == expected_flags and value['valid'] == value['preferred'] + 6 and
                        ((value['preferred'],value['valid']) == (2,8) if stage == 4 else
                         (0 < value['preferred'] <= 1 if case == 9 else 0 <= value['preferred'] <= 1)),
                        'finite DAD or NODAD recreation completes and cache ages naturally')
            else:
                raise ValueError('unknown finite configured inventory stage')

    def control_frame(self, frame):
        require(len(frame) == 60 and frame[:12] == self.control + self.guest and
                frame[14:19] == b'IP6O' + bytes([self.lane]), 'complete ownership control identity')
        phase, kind, case, stage, policy = frame[19:24]
        require(phase == len(self.controls) and phase < 255 and self.pending is None,
                'ordered ownership controls wait for prior acknowledgment')
        flags, preferred, valid = struct.unpack_from('!III', frame, 24)
        stamp = int.from_bytes(frame[52:60], 'big')
        value = dict(phase=phase, kind=kind, case=case, stage=stage, flags=flags,
                     preferred=preferred, valid=valid, target=frame[36:52], guest_ns=stamp)
        require(stamp > 0 and (not self.controls or stamp >= self.controls[-1]['guest_ns']) and
                policy == (int(self.retain_routes) if kind == HELLO else 0),
                'actual monotonic observation and exact pinned cleanup policy')
        if kind in (HELLO,BEGIN,MODE,END,FINISH):
            require(frame[24:52] == bytes(28), 'non-address ownership operations contain no invented metadata')
        if kind == HELLO:
            require(phase == case == 0 and stage == {'global':0, 'lifecycle':1, 'secret':2}[self.group], 'one explicit initial group')
            self.ready = True
        elif kind == BEGIN:
            require(self.ready and len(self.ended) < len(self.cases) and case == self.cases[len(self.ended)] and
                    (not self.case or self.ended[-1:] == [self.case]) and
                    stage == (0 if case == 2 else 1 if case >= 8 else 2),
                    'ordered ownership cases and actual selected generation mode')
            self.case, self.mode_changed = case, False
            self.probes[case] = {}
        elif kind == ADDRESS:
            require(case == self.case, 'snapshot belongs to active ownership case')
            self.inventories.setdefault((case,stage), []).append(value)
        elif kind == SUMMARY:
            require(case == self.case and valid == 0, 'complete actual ownership inventory summary')
            self.inventory(case,stage,self.inventories.get((case,stage),[]),flags,preferred)
            if stage == 3 and case != 2:
                latest = max(row['observed_ns'] for key,row in self.conflicts.items() if key[0] == case)
                require(time.monotonic_ns() - latest >= 4e9, 'full real four-second post-conflict observation')
        elif kind == CONFLICT:
            require(case == self.case and (case,stage) not in self.conflicts and
                    stage in (range(4) if case == 7 else range(1)), 'one selected actual conflict per trial')
            expected = {1:0x8c0,3:0x8c2,4:0x840}.get(case, 0x8c0 if case <= 7 else 0x40)
            lifetimes = (6,10) if case == 4 else (2,8) if case >= 8 else (INFINITY,INFINITY)
            require(flags == expected and (preferred,valid) == lifetimes and
                    (ipaddress.IPv6Address(value['target']).is_link_local if case <= 7 and case >= 5 else
                     value['target'][:8] == self.prefixes[case][:8]), 'queried exact selected conflict owner')
            require(case != 6 or self.mode_changed, 'mode write precedes conflict release')
            self.pending = value
        elif kind == MODE:
            require(case == self.case == 6 and stage == 0 and not self.mode_changed,
                    'one explicit mode-zero write during old stable DAD')
            self.mode_changed = True
        elif kind in (FIRST,READY):
            key = case,kind
            require(case == self.case and case in (1,3,4,5,6) and stage == 0 and key not in self.samples,
                    'one actual first and ready retry observation')
            expected = ({1:0x8c0,3:0x8c2,4:0x840}.get(case,0x8c0) if kind == FIRST else
                        {1:0x880,3:0x882,4:0x800}.get(case,0x880))
            require(flags == expected and (preferred,valid) == ((6,10) if case == 4 else (INFINITY,INFINITY))
                    if kind == FIRST else flags == expected,
                    'actual retry retains raw flags and first inherited lifetimes')
            self.samples[key] = value
        elif kind == DELETE:
            require(case == self.case and case <= 4 and stage in (0,1) and preferred == valid == 0 and
                    flags == (0xffffff9d if case == 4 and stage == 0 else 0),
                    'actual old and replacement deletion results')
            require((case,stage) not in self.removals, 'one explicit removal per selected owner')
            self.removals[case,stage] = value
        elif kind == END:
            expected_stages = ([0,1,2,5] if case == 2 else [0,1,2,3,4,5] if case <= 4 else
                               [3] if case <= 7 else [3,4,5])
            summaries = [row['stage'] for row in self.controls if row['case'] == case and row['kind'] == SUMMARY]
            require(case == self.case and stage == 0 and summaries == expected_stages,
                    'every required actual ownership inventory completes before case end')
            probes = self.probes[case]
            require(sum(map(len,probes.values())) == {1:3,2:2,3:2,4:3,5:2,6:3,7:4,8:2,9:1}[case],
                    'exact original DAD probes; NODAD adds none and exhaustion remains quiet')
            require(len([key for key in self.conflicts if key[0] == case]) == (0 if case == 2 else 4 if case == 7 else 1),
                    'all selected ownership conflicts completed')
            self.ended.append(case)
        elif kind == FINISH:
            require(case == stage == 0 and self.ended == self.cases and not self.finished,
                    'all ownership cases finish exactly once')
            self.finished = True
        else:
            raise ValueError('unknown ownership control operation')
        self.controls.append(value)
        if kind == CONFLICT:
            self.conflict()
        else:
            self.ack(phase)

    def receive(self, frame):
        require(len(self.frames) < 2048 and len(frame) >= 14 and frame[6:12] == self.guest,
                'bounded ownership traffic from the actual adapter')
        self.frames.append(dict(sha256=hashlib.sha256(frame).hexdigest(), observed_ns=time.monotonic_ns()))
        if frame[12:14] == b'\x88\xc3':
            self.control_frame(frame)
            return
        if not self.ready:
            require(len(self.firmware) < 256, 'bounded original firmware prelude')
            self.firmware.append(frame.hex())
            return
        require(len(frame) >= 62 and frame[12:14] == b'\x86\xdd' and frame[14] >> 4 == 6 and
                len(frame) == 54 + int.from_bytes(frame[18:20], 'big'), 'complete original ownership IPv6 frame')
        if frame[20] == 0:
            require(self.native and len(self.mld) < 512, 'bounded native-only multicast reports')
            multicast_report(frame)
            self.mld.append(hashlib.sha256(frame).hexdigest())
            return
        source,destination,body = frame[22:38],frame[38:54],frame[54:]
        require(self.case in self.cases and frame[20:22] == b'\x3a\xff' and source == bytes(16) and
                len(body) == 32 and body[:2] == b'\x87\0' and body[4:8] == bytes(4) and
                body[24:26] == b'\x0e\x01' and not checksum(source+destination+struct.pack('!I3xB',32,58)+body),
                'complete actual enhanced DAD probe and checksum')
        target=body[8:24]
        require(destination == b'\xff\x02'+bytes(9)+b'\x01\xff'+target[-3:] and
                frame[:6] == b'\x33\x33\xff'+target[-3:], 'exact ownership solicited-node destinations')
        link=ipaddress.IPv6Address(target).is_link_local
        require((link and self.case <= 7) or (not link and target[:8] == self.prefixes[self.case][:8]),
                'DAD target belongs to current ownership case')
        if self.case == 2:
            require(target == (self.link if link else self.prefixes[2][:8]+self.link[8:]), 'exact EUI64 generation')
        elif self.case in (8,9):
            require(target == self.prefixes[self.case][:-1]+b'\x23', 'actual finite configured DAD identity')
        elif target == self.link:
            require(self.case == 6 and self.mode_changed, 'EUI64 probe only after explicit mode-zero write')
        probes=self.probes[self.case].setdefault(target,[])
        maximum=2 if self.case == 8 else 1
        require(len(probes)<maximum, 'no unrequested DAD retransmission')
        probes.append(dict(observed_ns=time.monotonic_ns(), frame=frame.hex()))
        self.conflict()

    def tick(self):
        pass

    def result(self):
        # Only packet/log readers qualify capture clocks and timer windows.
        def serializable(value):
            if isinstance(value,bytes):return value.hex()
            if isinstance(value,dict):return {str(key):serializable(item) for key,item in value.items()}
            if isinstance(value,list):return [serializable(item) for item in value]
            return value
        return dict(passed=self.finished and self.pending is None and self.complete == list(range(len(self.controls))),
            lane=self.lane,group=self.group,cases=self.ended,controls=serializable(self.controls),
            conflicts=serializable(self.conflicts),actual_probes=serializable(self.probes),
            received_frames=self.frames,native_MLD=self.mld,firmware_frames=self.firmware,
            retained_finite_prefix_policy=self.retain_routes,packet_clock_qualified=False,full_F12_complete=False)
