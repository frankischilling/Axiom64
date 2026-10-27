# SPDX-License-Identifier: GPL-3.0-or-later
"""Observe retained routes and fresh companion streams during source withdrawal."""
import ipaddress
import struct
import time
from tcp6.zone_route_peer import Peer as RoutePeer,Flow as RouteFlow,payload
from tcp6.peer import packet
from tcp_fault_peer import ACK,FIN,SYN,check,checksum

MARKER='TCP6_ZONE_SOURCE_ROUTE_PASS lanes=2 rounds_each=2 retained_flows=4 companion_flows=4'
COMPANION=ipaddress.IPv6Address('fe80::3').packed

class Retained(RouteFlow):
    def __init__(self,owner,round_):
        super().__init__(owner,round_);self.deferred=None;self.input_restored=False
    def send(self,peer,flags=ACK,data=b'',sequence=None):
        if data==payload(self.owner.lane,self.round,2) and not self.input_restored:
            check(self.deferred is None,'one actual withheld fallback echo')
            self.deferred=(peer,flags,data,self.server if sequence is None else sequence);return
        return super().send(peer,flags,data,sequence)
    def restore_input(self):
        check(self.deferred is not None and not self.input_restored,'actual fallback output precedes restored input')
        self.input_restored=True;peer,flags,data,sequence=self.deferred;self.deferred=None
        super().send(peer,flags,data,sequence)

class Companion:
    def __init__(self,peer,round_):
        self.peer=peer;self.round=round_;self.local=54000+peer.lane*100+round_*10;self.remote=self.local+1000
        self.origin=0x77990000+peer.lane*0x1000+round_*0x100
        self.server=self.origin+1;self.client=None;self.data=False;self.fin=False;self.done=False
    def send(self,flags=ACK,data=b'',sequence=None):
        options=b'\x02\x04\x02\x18' if flags&SYN else b''
        tcp=bytearray(struct.pack('!HHIIHHHH',self.remote,self.local,
            (self.server if sequence is None else sequence)&0xffffffff,self.client,
            ((20+len(options))//4)<<12|flags,8192,0,0)+options+data)
        tcp[16:18]=struct.pack('!H',checksum(self.peer.ip+COMPANION+struct.pack('!I3xB',len(tcp),6)+tcp))
        self.peer.send(self.peer.envelope(self.peer.ip,COMPANION,tcp,6))
    def receive(self,value,header):
        check(not self.done and value['source_ip']==COMPANION and value['target_ip']==self.peer.ip and header==(64,0),
            'actual fresh companion selected source and original controls')
        if value['flags']==SYN:
            check(self.client is None,'one actual fresh companion SYN')
            self.client=(value['seq']+1)&0xffffffff;self.send(SYN|ACK,sequence=self.origin);return
        check(self.client is not None and value['seq']==self.client and value['ack']==self.server,
            'exact fresh companion stream acknowledgment')
        if value['data']:
            check(not self.data and value['flags'] in (ACK,ACK|8) and value['data']==payload(self.peer.lane,self.round,9),
                'actual fresh companion bytes')
            self.data=True;self.client=(self.client+16)&0xffffffff
            self.send(ACK|8,value['data']);self.server=(self.server+16)&0xffffffff
        elif value['flags']&FIN:
            check(self.data and not self.fin and value['flags']==FIN|ACK,'fresh companion echo before close')
            self.client=(self.client+1)&0xffffffff;self.send(FIN|ACK);self.server=(self.server+1)&0xffffffff;self.fin=True
        elif self.fin:
            check(value['flags']==ACK,'actual final fresh companion acknowledgment');self.done=True
            for peer in self.peer.peers:peer.complete_if_ready()
        else:check(value['flags']==ACK,'actual fresh companion pure acknowledgment')

class Peer(RoutePeer):
    def __init__(self,lane,minimum_fin_ms=0,native=False):
        super().__init__(lane,minimum_fin_ms,native);self.flows=[Retained(self,r) for r in range(2)]
        self.companions=[Companion(self,r) for r in range(2)];self.ownership_phases=[];self.ownership_waiting=None
    def complete_if_ready(self):
        if self.ownership_waiting is not None:
            phase,frame=self.ownership_waiting;origin,rest=divmod(phase,64);round_,step=divmod(rest,16)
            flow=self.peers[origin].flows[round_]
            if step==11 and flow.deferred is not None or step==12 and (self.lane!=origin or 2 in flow.acked):
                answer=bytearray(frame);answer[:12]=self.guest+frame[:6];answer[20]=1
                self.send(answer);self.ownership_waiting=None
        if self.waiting is not None:
            phase,_=self.waiting;origin,rest=divmod(phase,64);round_,step=divmod(rest,16)
            if step==3 and not self.peers[origin].companions[round_].done:return
        return super().complete_if_ready()
    def receive(self,frame):
        if len(frame)>=21 and frame[12:14]==self.barrier_protocol and frame[19]%16 in (11,12):
            phase=frame[19];expected=[n*64+r*16+s for n in range(2) for r in range(2) for s in (11,12)]
            check(self.ready and len(self.ownership_phases)<len(expected) and phase==expected[len(self.ownership_phases)] and
                self.ownership_waiting is None and len(frame)==60 and frame[:12]==bytes([2,73,80,54,self.lane,0])+self.guest and
                frame[14:19]==self.barrier_magic+bytes([self.lane]) and not any(frame[20:]),'ordered actual source ownership fences')
            self.frames.append(dict(direction='receive',ms=(time.monotonic()-self.began)*1000,frame=frame.hex()))
            self.ownership_phases.append(phase);self.ownership_waiting=(phase,frame)
            origin,rest=divmod(phase,64);round_,step=divmod(rest,16)
            if step==12 and self.lane==origin:
                flow=self.peers[origin].flows[round_]
                if not flow.input_restored:flow.restore_input()
            self.complete_if_ready();return
        if len(frame)>=74 and frame[12:14]==b'\x86\xdd' and frame[20]==6:
            value=packet(frame)
            matches=[flow for flow in self.companions if (value['source'],value['target'])==(flow.local,flow.remote)]
            if matches:
                check(self.ready and len(matches)==1 and frame[:12]==self.mac+self.guest,
                    'actual companion physical Ethernet owner')
                self.frames.append(dict(direction='receive',ms=(time.monotonic()-self.began)*1000,frame=frame.hex()))
                matches[0].receive(value,(frame[21],(int.from_bytes(frame[14:18],'big')>>20)&255));return
        if len(frame)>=62 and frame[12:14]==b'\x86\xdd' and frame[20]==58 and frame[22:38]==COMPANION:
            length=int.from_bytes(frame[18:20],'big');body=frame[54:54+length]
            check(self.ready and len(frame)==54+length and frame[14]>>4==6 and frame[21]==255 and
                not checksum(frame[22:54]+struct.pack('!I3xB',length,58)+body),
                'actual configured companion neighbor checksum and bounds')
            if body[:2]==b'\x85\0':
                check(length==16 and frame[:12]==bytes.fromhex('333300000002')+self.guest and
                    frame[38:54]==ipaddress.IPv6Address('ff02::2').packed and body[4:8]==bytes(4) and
                    body[8:]==b'\1\1'+self.guest,'configured companion router solicitation')
            else:
                check(length==32 and body[:2]==b'\x87\0' and body[4:8]==bytes(4) and body[8:24]==self.ip and
                    body[24:]==b'\1\1'+self.guest and frame[6:12]==self.guest,
                    'configured companion resolves the actual controlled peer')
                answer=b'\x88\0\0\0\x60\0\0\0'+self.ip+b'\2\1'+self.mac
                self.send(self.envelope(self.ip,COMPANION,answer,hop=255))
            self.frames.append(dict(direction='receive',ms=(time.monotonic()-self.began)*1000,frame=frame.hex()));return
        return super().receive(frame)
    def result(self):
        result=super().result();check(all(flow.done for flow in self.companions),'all actual companion streams complete')
        check(len(self.ownership_phases)==8 and self.ownership_waiting is None,'all original source ownership fences complete')
        result.update(combined_scoped_source_route=True,companion_flows=2)
        return result
