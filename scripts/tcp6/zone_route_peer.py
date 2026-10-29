# SPDX-License-Identifier: GPL-3.0-or-later
"""Observe one retained TCP flow crossing physical links after route changes."""
import ipaddress
import struct
import time
from tcp6.peer import Peer as EthernetPeer,packet
from tcp_fault_peer import ACK,FIN,SYN,check,checksum

MARKER='TCP6_ZONE_ROUTE_PASS lanes=2 rounds_each=2 flows=4 exchanges=20'

def payload(lane,round_,tag):return bytes((lane*53+round_*31+tag*17+n*7)&255 for n in range(16))

class Flow:
    def __init__(self,owner,round_):
        self.owner,self.round=owner,round_;self.local=52000+owner.lane*100+round_*10;self.remote=self.local+1000
        self.origin=0x66880000+owner.lane*0x1000+round_*0x100
        self.server=self.origin+1;self.client=None;self.established=False;self.tags=[];self.zones=[]
        self.acked=[];self.fin=False;self.done=False
    def send(self,peer,flags=ACK,data=b'',sequence=None):
        options=b'\x02\x04\x02\x18' if flags&SYN else b''
        tcp=bytearray(struct.pack('!HHIIHHHH',self.remote,self.local,
            (self.server if sequence is None else sequence)&0xffffffff,self.client,
            ((20+len(options))//4)<<12|flags,8192,0,0)+options+data)
        tcp[16:18]=struct.pack('!H',checksum(peer.ip+peer.address+struct.pack('!I3xB',len(tcp),6)+tcp))
        peer.send(peer.envelope(peer.ip,peer.address,tcp,6))
    def receive(self,peer,value,header):
        check(not self.done and value['source_ip']==peer.address and value['target_ip']==peer.ip,
            'unchanged complete route stream IPv6 tuple')
        if value['flags']==SYN:
            check(self.client is None and peer.lane==self.owner.lane,'one zone-bound initial SYN')
            self.client=(value['seq']+1)&0xffffffff;self.send(peer,SYN|ACK,sequence=self.origin);return
        check(self.client is not None and value['ack']==self.server,'actual route stream acknowledgment')
        if not self.established:
            check(value['flags'] in (ACK,ACK|8) and value['seq']==self.client,'actual route stream final handshake')
            self.established=True
        if value['data']:
            tag=len(self.tags);expected_lane=self.owner.lane^(tag in (1,3))
            check(tag<5 and peer.lane==expected_lane and value['seq']==self.client and
                value['data']==payload(self.owner.lane,self.round,tag) and
                header==((64,0) if tag==0 else (37,168)), 'actual preferred/fallback/rebound route stream bytes and link')
            self.tags.append(tag);self.zones.append(peer.lane);self.client=(self.client+16)&0xffffffff
            self.send(peer,ACK|8,value['data']);self.server=(self.server+16)&0xffffffff
        elif value['flags']==ACK and not self.fin and self.tags:
            check(value['seq']==self.client,'actual complete route echo acknowledgment')
            tag=len(self.tags)-1
            if tag not in self.acked:self.acked.append(tag)
        if value['flags']&FIN:
            check(not self.fin and self.tags==list(range(5)) and peer.lane==self.owner.lane and
                value['seq']==self.client,'complete rebound stream before FIN')
            self.client=(self.client+1)&0xffffffff;self.send(peer,FIN|ACK);self.server=(self.server+1)&0xffffffff;self.fin=True
        elif self.fin:
            check(value['flags']==ACK and not value['data'] and value['seq']==self.client,'actual final route close acknowledgment')
            self.done=True
        for item in self.owner.peers:item.complete_if_ready()

class Peer(EthernetPeer):
    barrier_protocol=b'\x88\xcd';barrier_magic=b'IP6G'
    def __init__(self,lane,minimum_fin_ms=0,native=False):
        super().__init__(lane,minimum_fin_ms,native)
        self.ip=ipaddress.IPv6Address('fe80::1').packed;self.address=ipaddress.IPv6Address('fe80::2').packed
        self.flows=[Flow(self,r) for r in range(2)];self.phases=[];self.waiting=None
    def bind_peers(self,peers):self.peers=peers
    def tick(self):pass
    def complete_if_ready(self):
        if self.waiting is None:return
        phase,frame=self.waiting;origin,rest=divmod(phase,64);round_,step=divmod(rest,16)
        flow=self.peers[origin].flows[round_]
        ready=step in (1,3,5,7,9) or step in (2,4,6,8) and (step//2-1) in flow.acked or step==10 and flow.done
        if ready:
            answer=bytearray(frame);answer[:12]=self.guest+frame[:6];answer[20]=1
            self.send(answer);self.waiting=None
    def receive(self,frame):
        if len(frame)>=21 and frame[12:14]==self.barrier_protocol and frame[19]:
            phase=frame[19];expected=[n*64+r*16+s for n in range(2) for r in range(2) for s in range(1,11)]
            check(self.ready and len(self.phases)<len(expected) and phase==expected[len(self.phases)] and
                self.waiting is None and len(frame)==60 and frame[:12]==bytes([2,73,80,54,self.lane,0])+self.guest and
                frame[14:19]==self.barrier_magic+bytes([self.lane]) and not any(frame[20:]),'ordered physical route fences')
            self.frames.append(dict(direction='receive',ms=(time.monotonic()-self.began)*1000,frame=frame.hex()))
            self.phases.append(phase);self.waiting=(phase,frame);self.complete_if_ready();return
        if len(frame)>=74 and frame[12:14]==b'\x86\xdd' and frame[20]==6:
            value=packet(frame);check(self.ready and frame[:12]==self.mac+self.guest and not value['flags']&4,
                'physical route frame owner and no reset')
            matches=[flow for peer in self.peers for flow in peer.flows if (value['source'],value['target'])==(flow.local,flow.remote)]
            check(len(matches)==1,'one full route port tuple')
            self.frames.append(dict(direction='receive',ms=(time.monotonic()-self.began)*1000,frame=frame.hex()))
            matches[0].receive(self,value,(frame[21],(int.from_bytes(frame[14:18],'big')>>20)&255));return
        return super().receive(frame)
    def result(self):
        check(all(flow.done for flow in self.flows) and len(self.phases)==40 and self.waiting is None,
            'complete actual route transitions and streams')
        return dict(passed=True,lane=self.lane,frames=self.frames,scoped_route_transitions=True,
            full_scoped_source_device_semantics_qualified=False,
            flows=[dict(round=f.round,tags=f.tags,zones=f.zones,acked=f.acked) for f in self.flows])
