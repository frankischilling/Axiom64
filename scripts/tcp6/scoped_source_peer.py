# SPDX-License-Identifier: GPL-3.0-or-later
import ipaddress
import struct
import time
from tcp6.source_peer import Peer as SourcePeer,Flow as SourceFlow
from tcp_fault_peer import ACK,check,checksum

MARKER='TCP6_SCOPED_SOURCE_LIFETIME_PASS lanes=2 rounds_each=2 flows_each=4 data_each=12 withdrawn_each=6'

class Flow(SourceFlow):
    def __init__(self,peer,round_,companion):
        super().__init__(peer,round_,companion)
        self.local-=peer.lane;self.remote-=peer.lane;self.echo_ack=False
    def receive(self,value,header):
        super().receive(value,header)
        if not self.companion and self.tags==[0] and value['flags']==ACK and not value['data']:
            self.echo_ack=True;self.peer.complete_if_ready()

class Peer(SourcePeer):
    barrier_protocol=b'\x88\xcc';barrier_magic=b'IP6Z'
    def __init__(self,lane,minimum_fin_ms=0,native=False):
        super().__init__(lane,minimum_fin_ms,native)
        self.ip=ipaddress.IPv6Address('fe80::1').packed;self.address=ipaddress.IPv6Address('fe80::2').packed
        self.flows=[Flow(self,r,c) for r in range(2) for c in (False,True)]
    def complete_if_ready(self):
        if self.waiting is not None:
            phase,frame=self.waiting;r,step=divmod(phase,16)
            if step in (8,9,10):
                if step!=8 or self.flows[r*2].echo_ack:self.answer(frame);self.waiting=None
                return
        return super().complete_if_ready()
    def receive(self,frame):
        if (len(frame)>=70 and frame[12:14]==b'\x86\xdd' and frame[20]==58 and
                frame[22:38]==ipaddress.IPv6Address('fe80::3').packed and frame[54:56]==b'\x85\0'):
            # A configured companion remains a valid router-solicitation source
            # while the original address is withdrawn or being restored.
            body=frame[54:70]
            check(self.ready and len(frame)==70 and frame[:12]==bytes.fromhex('333300000002')+self.guest and
                frame[14]>>4==6 and frame[18:22]==b'\0\x10\x3a\xff' and
                frame[38:54]==ipaddress.IPv6Address('ff02::2').packed and body[4:8]==bytes(4) and
                body[8:]==b'\1\1'+self.guest and
                checksum(frame[22:54]+struct.pack('!I3xB',16,58)+body)==0,
                'configured companion link-local router solicitation')
            self.frames.append(dict(direction='receive',ms=(time.monotonic()-self.began)*1000,frame=frame.hex()))
            return
        if len(frame)>=21 and frame[12:14]==self.barrier_protocol and frame[19]:
            phase=frame[19];expected=[r*16+s for r in range(2) for s in (1,8,9,10,2,3,4,5,6,7)]
            check(self.ready and len(self.phases)<len(expected) and phase==expected[len(self.phases)] and
                self.waiting is None and len(frame)==60 and frame[:12]==bytes([2,73,80,54,self.lane,0])+self.guest and
                frame[14:19]==self.barrier_magic+bytes([self.lane]) and not any(frame[20:]),'ordered scoped source barriers')
            self.frames.append(dict(direction='receive',ms=(time.monotonic()-self.began)*1000,frame=frame.hex()))
            self.phases.append(phase);self.waiting=(phase,frame);self.complete_if_ready();return
        return super().receive(frame)
    def result(self):
        check(all(f.done for f in self.flows) and len(self.phases)==20 and self.waiting is None,
            'complete actual scoped source-lifetime scenario')
        return dict(passed=True,lane=self.lane,frames=self.frames,scoped_source_withdrawal=True,
            full_scoped_source_device_semantics_qualified=False,
            flows=[dict(round=f.round,companion=f.companion,tags=f.tags,headers=f.headers) for f in self.flows])
