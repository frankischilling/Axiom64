# SPDX-License-Identifier: GPL-3.0-or-later
"""Request closed/listener TCP replies on identical interface-scoped tuples."""
import ipaddress
import struct
import time
from types import SimpleNamespace
from tcp6.peer import Peer as EthernetPeer, packet
from tcp_fault_peer import check, checksum, ACK, SYN, FIN, RST


class Peer(EthernetPeer):
    barrier_protocol = b'\x88\xc5'
    barrier_magic = b'IP6R'

    def __init__(self, lane, minimum_fin_ms=0, native=False):
        super().__init__(lane, minimum_fin_ms, native)
        self.flows = [SimpleNamespace(done=False)]
        self.phase, self.scenario = 0, None
        self.boundary = self.observation = self.injected = None
        self.responded = False
        self.observe_input = None
        self.completed = 0

    def request(self, scenario):
        kind = scenario % 10
        link = scenario < 10
        prefix = 'fe80' if link else f'2001:db8:{self.lane+1}'
        self.ip = ipaddress.IPv6Address(prefix+'::1').packed
        self.address = ipaddress.IPv6Address(prefix+'::2').packed
        flags = (ACK, SYN, SYN, FIN, 8, RST, ACK, ACK, ACK, ACK)[kind]
        data = b'scope-syn' if kind == 2 else b'scope-data' if kind == 4 else b''
        sequence = (0xfffffff0+scenario*17+self.lane*4096) & 0xffffffff
        acknowledgment = 0x12340000+scenario*31+self.lane*4096
        body = bytearray(struct.pack('!HHIIHHHH',49360,49460,sequence,acknowledgment,
                                    5<<12|flags,8192,0,0)+data)
        body[16:18] = struct.pack('!H',checksum(self.ip+self.address+struct.pack('!I3xB',len(body),6)+body))
        self.expected = dict(flags=RST if flags & ACK else RST|ACK,
                             sequence=acknowledgment if flags & ACK else 0,
                             acknowledgment=0 if flags & ACK else (sequence+len(data)+bool(flags&SYN)+bool(flags&FIN))&0xffffffff)
        self.responded = False
        frame = self.envelope(self.ip,self.address,bytes(body),6)
        check(self.observe_input is not None, 'independent original reply-input observation')
        self.observation = self.observe_input(frame)
        self.injected = None
        self.send(frame)

    def tick(self):
        if self.observation is not None:
            self.injected = self.observation()
            if self.injected is None:
                return
            self.observation = None
        if self.boundary is None or self.injected is None or time.monotonic()-self.injected < .1:
            return
        if self.scenario % 10 != 5 and not self.responded:
            return
        answer, self.boundary = bytearray(self.boundary), None
        answer[:12] = self.guest+answer[:6]
        answer[20] = 1
        self.send(answer)

    def receive(self, frame):
        if len(frame) >= 20 and frame[12:14] == self.barrier_protocol and frame[19] != 0:
            check(self.ready and len(frame) == 60 and frame[:6] == bytes([2,73,80,54,self.lane,0]) and frame[6:12] == self.guest and
                  frame[14:19] == self.barrier_magic+bytes([self.lane]) and frame[19] == self.phase+1 and
                  frame[20:] == bytes(40) and self.boundary is None, 'ordered original reply barrier')
            self.phase = frame[19]
            self.frames.append(dict(direction='receive',ms=(time.monotonic()-self.began)*1000,frame=frame.hex()))
            if self.phase % 2:
                self.scenario = (self.phase-1)//2
                check(self.scenario == self.completed < 20, 'every original reply scenario in order')
                self.boundary = frame
                self.request(self.scenario)
            else:
                self.completed += 1
                answer = bytearray(frame)
                answer[:12] = self.guest+frame[:6]
                answer[20] = 1
                self.send(answer)
                if self.completed == 20:
                    self.flows[0].done = True
            return
        if len(frame) >= 54 and frame[12:14] == b'\x86\xdd' and frame[20] == 6:
            check(self.scenario is not None and self.boundary is not None and self.scenario % 10 != 5 and
                  not self.responded and frame[:12] == self.mac+self.guest, 'one reply on the actual receiving interface')
            value = packet(frame)
            check(value['source_ip'] == self.address and value['target_ip'] == self.ip and
                  value['source'] == 49460 and value['target'] == 49360 and
                  value['flags'] == self.expected['flags'] and value['seq'] == self.expected['sequence'] and
                  value['ack'] == self.expected['acknowledgment'] and not value['window'] and not value['data'],
                  'exact original closed-port or listener reset')
            self.frames.append(dict(direction='receive',ms=(time.monotonic()-self.began)*1000,frame=frame.hex()))
            self.responded = True
            return
        super().receive(frame)

    def result(self):
        check(self.ready and self.phase == 40 and self.completed == 20 and self.flows[0].done,
              'all link-local and global reply observations complete')
        return dict(lane=self.lane,passed=True,cases=20,quiet_ms=50,frames=self.frames)
