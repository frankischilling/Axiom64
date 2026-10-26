# SPDX-License-Identifier: GPL-3.0-or-later
"""Observe established-source output without delivering to a withdrawn address."""
import struct
import time
from tcp6.peer import Peer as EthernetPeer,packet
from tcp_fault_peer import ACK,FIN,SYN,check,checksum

MARKER='TCP6_SOURCE_LIFETIME_PASS lanes=2 rounds_each=2 flows_each=4 data_each=12 withdrawn_each=6'

def payload(lane,round_,tag):return bytes((lane*53+round_*31+tag*17+n*7)&255 for n in range(16))

class Flow:
    def __init__(self,peer,round_,companion):
        self.peer,self.round,self.companion=peer,round_,companion
        self.local=(50200 if companion else 50000)+round_*10+peer.lane
        self.remote=(50300 if companion else 50100)+round_*10+peer.lane
        self.address=peer.address[:-1]+bytes([3 if companion else 2])
        self.origin=0x44660000+peer.lane*0x1000+round_*0x100+companion*16
        self.remote_next=self.origin+1;self.guest_next=None
        self.tags=[];self.headers=[];self.established=False;self.fin=False;self.done=False

    def send(self,flags=ACK,data=b'',sequence=None):
        options=b'\x02\x04\x02\x18' if flags&SYN else b''
        segment=bytearray(struct.pack('!HHIIHHHH',self.remote,self.local,
            (self.remote_next if sequence is None else sequence)&0xffffffff,self.guest_next,
            ((20+len(options))//4)<<12|flags,8192,0,0)+options+data)
        segment[16:18]=struct.pack('!H',checksum(self.peer.ip+self.address+
            struct.pack('!I3xB',len(segment),6)+segment))
        self.peer.send(self.peer.envelope(self.peer.ip,self.address,segment,6))

    def receive(self,value,header):
        check(not self.done and value['source_ip']==self.address and value['target_ip']==self.peer.ip,
            'exact retained/fresh source ownership')
        if value['flags']==SYN:
            check(self.guest_next is None,'one source stream SYN')
            self.guest_next=(value['seq']+1)&0xffffffff
            self.send(SYN|ACK,sequence=self.origin)
            return
        check(self.guest_next is not None and value['ack']==self.remote_next,'source stream acknowledgment')
        if not self.established:
            check(value['flags']==ACK and not value['data'],'source stream handshake')
            self.established=True
        if value['data']:
            tags=[9] if self.companion else [0,1,2,3,4]
            check(len(self.tags)<len(tags) and value['seq']==self.guest_next and
                value['data']==payload(self.peer.lane,self.round,tags[len(self.tags)]), 'exact source stream bytes')
            tag=tags[len(self.tags)];self.tags.append(tag);self.headers.append(header)
            self.guest_next=(self.guest_next+16)&0xffffffff
            # The local address route is absent during withdrawal. Observe output
            # through Ethernet barriers; do not send TCP input to that address.
            if self.companion or tag in (0,4):
                self.send(ACK|8,value['data']);self.remote_next=(self.remote_next+16)&0xffffffff
            self.peer.complete_if_ready()
        if value['flags']&FIN:
            check(not self.fin and self.tags==([9] if self.companion else [0,1,2,3,4]), 'complete source stream before FIN')
            self.guest_next=(self.guest_next+1)&0xffffffff;self.send(FIN|ACK);self.remote_next=(self.remote_next+1)&0xffffffff;self.fin=True
        elif self.fin:
            check(value['flags']==ACK and not value['data'] and value['seq']==self.guest_next,
                'source stream final close acknowledgment')
            self.done=True;self.peer.complete_if_ready()

class Peer(EthernetPeer):
    barrier_protocol=b'\x88\xc9';barrier_magic=b'IP6L'
    def __init__(self,lane,minimum_fin_ms=0,native=False):
        super().__init__(lane,minimum_fin_ms,native)
        self.flows=[Flow(self,round_,companion) for round_ in range(2) for companion in (False,True)]
        self.phases=[];self.waiting=None

    def answer(self,frame):
        value=bytearray(frame);value[:12]=self.guest+frame[:6];value[20]=1;self.send(value)

    def complete_if_ready(self):
        if self.waiting is None:return
        phase,frame=self.waiting;round_,step=divmod(phase,16)
        main,companion=self.flows[round_*2:round_*2+2]
        if step in (1,2) or step in (3,4,5) and len(main.tags)>=step-1 or step==6 and companion.done or step==7 and main.done and companion.done:
            if step==6:main.send()
            self.answer(frame);self.waiting=None

    def tick(self):pass

    def receive(self,frame):
        if len(frame)>=21 and frame[12:14]==self.barrier_protocol and frame[19]:
            phase=frame[19];expected=[r*16+s for r in range(2) for s in range(1,8)]
            check(self.ready and len(self.phases)<len(expected) and phase==expected[len(self.phases)] and
                self.waiting is None and len(frame)==60 and frame[:12]==bytes([2,73,80,54,self.lane,0])+self.guest and
                frame[14:19]==self.barrier_magic+bytes([self.lane]) and not any(frame[20:]),'exact source mutation barrier')
            self.frames.append(dict(direction='receive',ms=(time.monotonic()-self.began)*1000,frame=frame.hex()))
            self.phases.append(phase);self.waiting=(phase,frame);self.complete_if_ready();return
        if len(frame)>=74 and frame[12:14]==b'\x86\xdd' and frame[20]==6:
            value=packet(frame)
            check(self.ready and frame[:12]==self.mac+self.guest and not value['flags']&4,'source TCP frame owner and no reset')
            flows=[flow for flow in self.flows if (value['source'],value['target'])==(flow.local,flow.remote)]
            check(len(flows)==1,'source TCP complete tuple')
            self.frames.append(dict(direction='receive',ms=(time.monotonic()-self.began)*1000,frame=frame.hex()))
            flows[0].receive(value,(frame[21],(int.from_bytes(frame[14:18],'big')>>20)&255));return
        previous=self.address
        if len(frame)>=54 and frame[12:14]==b'\x86\xdd' and frame[22:38]==previous[:-1]+b'\3':
            self.address=previous[:-1]+b'\3'
        try:return super().receive(frame)
        finally:self.address=previous

    def result(self):
        check(all(flow.done for flow in self.flows) and len(self.phases)==14 and self.waiting is None,
            'complete actual source-lifetime scenario')
        return dict(passed=True,lane=self.lane,frames=self.frames,
            retained_source_output=True,fresh_source_constrained=True,
            flows=[dict(round=flow.round,companion=flow.companion,tags=flow.tags,headers=flow.headers) for flow in self.flows])
