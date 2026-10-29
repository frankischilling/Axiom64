# SPDX-License-Identifier: GPL-3.0-or-later
"""Withhold handshake input until a withdrawn source emits a natural retry."""
import struct
import time
from tcp6.peer import Peer as EthernetPeer,packet
from tcp_fault_peer import ACK,FIN,SYN,check,checksum

MARKER='TCP6_PENDING_SOURCE_PASS lanes=2 rounds_each=4 flows_each=8'
MASK=(1<<32)-1
def plus(value,delta=1):return (value+delta)&MASK
def payload(lane,round_,companion):return bytes((lane*53+round_*31+companion*17+n*7)&255 for n in range(16))

class Flow:
    def __init__(self,peer,round_,companion):
        self.peer,self.round,self.companion=peer,round_,companion
        self.passive=round_==3 and not companion
        self.local=(51200 if companion else 51000)+round_*10+peer.lane
        self.remote=(51300 if companion else 51100)+round_*10+peer.lane
        self.address=peer.address[:-1]+bytes([3 if companion else 2])
        self.origin=0x55770000+peer.lane*0x1000+round_*0x100+companion*16
        self.remote_next=plus(self.origin);self.guest_next=None;self.guest_origin=None
        self.handshakes=[];self.established=False;self.data=False;self.fin=False;self.done=False;self.done_ns=None

    def send(self,flags=ACK,data=b'',sequence=None):
        options=b'\x02\x04\x02\x18' if flags&SYN else b''
        acknowledgment=0 if flags==SYN else self.guest_next
        check(acknowledgment is not None,'known pending source acknowledgment')
        segment=bytearray(struct.pack('!HHIIHHHH',self.remote,self.local,
            self.remote_next if sequence is None else sequence,acknowledgment,
            ((20+len(options))//4)<<12|flags,8192,0,0)+options+data)
        segment[16:18]=struct.pack('!H',checksum(self.peer.ip+self.address+
            struct.pack('!I3xB',len(segment),6)+segment))
        self.peer.send(self.peer.envelope(self.peer.ip,self.address,segment,6))

    def receive(self,value):
        check(not self.done and value['source_ip']==self.address and value['target_ip']==self.peer.ip,
            'complete pending/fresh source tuple')
        if value['flags']&(SYN):
            check(value['flags']==(SYN|ACK if self.passive else SYN) and not value['data'],
                'exact pending source handshake kind')
            if self.guest_origin is None:self.guest_origin=value['seq'];self.guest_next=plus(value['seq'])
            check(value['seq']==self.guest_origin and value['ack']==(self.remote_next if self.passive else 0),
                'same pending source handshake sequence')
            self.handshakes.append(time.monotonic_ns())
            if self.companion:self.send(SYN|ACK,sequence=self.origin)
            self.peer.complete_if_ready();return
        check(self.guest_next is not None and value['ack']==self.remote_next,
            'exact pending source stream acknowledgment')
        if not self.established:
            check(not self.passive and value['flags']==ACK and not value['data'],
                'active source handshake final acknowledgment')
            self.established=True
        if value['data']:
            check(not self.data and value['seq']==self.guest_next and
                value['data']==payload(self.peer.lane,self.round,self.companion),
                'one exact pending source application block')
            self.data=True;self.guest_next=plus(self.guest_next,16)
            self.send(ACK|8,value['data']);self.remote_next=plus(self.remote_next,16)
        if value['flags']&FIN:
            check(self.data and not self.fin and value['seq']==self.guest_next,
                'pending source complete stream before FIN')
            self.guest_next=plus(self.guest_next);self.send(FIN|ACK)
            self.remote_next=plus(self.remote_next);self.fin=True
        elif self.fin:
            check(value['flags']==ACK and not value['data'] and value['seq']==self.guest_next,
                'pending source final close acknowledgment')
            self.done=True;self.done_ns=time.monotonic_ns();self.peer.complete_if_ready()

class Peer(EthernetPeer):
    barrier_protocol=b'\x88\xca';barrier_magic=b'IP6P'
    def __init__(self,lane,minimum_fin_ms=0,native=False):
        super().__init__(lane,minimum_fin_ms,native)
        self.flows=[Flow(self,r,c) for r in range(4) for c in (False,True)]
        self.phases=[];self.waiting=None

    def answer(self,frame):
        reply=bytearray(frame);reply[:12]=self.guest+frame[:6];reply[20]=1;self.send(reply)

    def complete_if_ready(self):
        if self.waiting is None:return
        phase,frame=self.waiting;round_,step=divmod(phase,16)
        main,companion=self.flows[round_*2:round_*2+2]
        ready=(step==1 or step==2 and (companion.done if not round_ else bool(main.handshakes)) or
            step==3 and companion.done and len(main.handshakes)>=2 and main.handshakes[-1]>companion.done_ns or step==4 or
            step==5 and main.done and companion.done)
        if not ready:return
        if step==4:
            if main.passive:main.established=True;main.send()
            else:main.send(SYN|ACK,sequence=main.origin)
        self.answer(frame);self.waiting=None

    def tick(self):pass

    def receive(self,frame):
        if len(frame)>=21 and frame[12:14]==self.barrier_protocol and frame[19]:
            phase=frame[19];expected=[r*16+s for r in range(4) for s in range(1,6)]
            check(self.ready and len(self.phases)<len(expected) and phase==expected[len(self.phases)] and
                self.waiting is None and len(frame)==60 and frame[:12]==bytes([2,73,80,54,self.lane,0])+self.guest and
                frame[14:19]==self.barrier_magic+bytes([self.lane]) and not any(frame[20:]),
                'complete ordered pending source barrier')
            self.frames.append(dict(direction='receive',ms=(time.monotonic()-self.began)*1000,frame=frame.hex()))
            self.phases.append(phase);self.waiting=(phase,frame)
            round_,step=divmod(phase,16)
            if round_==3 and step==2:self.flows[6].send(SYN,sequence=self.flows[6].origin)
            self.complete_if_ready();return
        if len(frame)>=74 and frame[12:14]==b'\x86\xdd' and frame[20]==6:
            value=packet(frame)
            check(self.ready and frame[:12]==self.mac+self.guest and not value['flags']&4,
                'pending source TCP frame owner and no reset')
            flows=[flow for flow in self.flows if (value['source'],value['target'])==(flow.local,flow.remote)]
            check(len(flows)==1,'known pending source TCP ports')
            self.frames.append(dict(direction='receive',ms=(time.monotonic()-self.began)*1000,frame=frame.hex()))
            flows[0].receive(value);return
        previous=self.address
        if len(frame)>=54 and frame[12:14]==b'\x86\xdd' and frame[22:38]==previous[:-1]+b'\3':
            self.address=previous[:-1]+b'\3'
        try:return super().receive(frame)
        finally:self.address=previous

    def result(self):
        check(all(flow.done for flow in self.flows) and len(self.phases)==20 and self.waiting is None,
            'complete actual pending source workload')
        return dict(passed=True,lane=self.lane,frames=self.frames,global_pending_source_withdrawal=True,
            full_source_route_device_expiry_acceptance=False,
            flows=[dict(round=f.round,companion=f.companion,passive=f.passive,
                handshake_count=len(f.handshakes),handshake_monotonic_ns=f.handshakes) for f in self.flows])
