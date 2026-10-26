# SPDX-License-Identifier: GPL-3.0-or-later
"""Exercise live and detached TCP controls over real IPv6 and IPv4 frames."""
import ipaddress
import struct
import time
from types import SimpleNamespace
from tcp6.peer import Peer as EthernetPeer, packet as packet6
from tcp_fault_peer import ACK, FIN, SYN, check, checksum, packet as packet4

FAMILIES=('ipv6','mapped','ipv4')
def marker(family):
    return f'TCP_CONTROL_FAMILY_PASS family={family} lanes=2 exchanges_each=16 router_hops=41,51 detached_replies=3 passive_flows_each=2 pending_retry=1 listener_closed=1'
def payload(lane,tag):return bytes((tag*17+lane*53+n*7)&255 for n in range(16))

class ActivePeer(EthernetPeer):
    barrier_protocol=b'\x88\xc8'
    barrier_magic=b'IP6F'

    def __init__(self,lane,minimum_fin_ms=0,native=False,*,family):
        check(family in FAMILIES,'known actual wire family')
        super().__init__(lane,minimum_fin_ms,native)
        self.family=family
        self.ip4=bytes([10,23,lane+1,1]);self.address4=bytes([10,23,lane+1,2])
        self.flows=[SimpleNamespace(done=False)]
        self.phases=[];self.tags=[];self.state=None;self.pending=None
        self.closed=False;self.late_sent=False;self.late_seen=False

    @property
    def local(self):return self.address if self.family=='ipv6' else self.address4
    @property
    def remote(self):return self.ip if self.family=='ipv6' else self.ip4

    def transmit(self,flags=ACK,data=b'',sequence=None):
        state=self.state
        options=b'\x02\x04\x02\x18' if flags&SYN else b''
        sequence=state['server_next'] if sequence is None else sequence
        segment=bytearray(struct.pack('!HHIIHHHH',49890+self.lane,49880+self.lane,sequence&0xffffffff,
            state['client_next'],((20+len(options))//4)<<12|flags,8192,0,0)+options+data)
        pseudo=(self.remote+self.local+(struct.pack('!I3xB',len(segment),6) if self.family=='ipv6' else struct.pack('!BBH',0,6,len(segment))))
        segment[16:18]=struct.pack('!H',checksum(pseudo+segment))
        if self.family=='ipv6':frame=self.envelope(self.remote,self.local,segment,6)
        else:
            header=bytearray(struct.pack('!BBHHHBBH4s4s',0x45,0,20+len(segment),0,0x4000,64,6,0,self.remote,self.local))
            header[10:12]=struct.pack('!H',checksum(header))
            frame=self.guest+self.mac+b'\x08\0'+header+segment
        self.send(frame)

    def answer(self,frame):
        answer=bytearray(frame);answer[:12]=self.guest+frame[:6];answer[20]=1
        self.send(answer)

    def router(self,hops):
        body=struct.pack('!BBHBBHII',134,0,0,hops,0,0,0,0)+b'\1\1'+self.mac
        self.send(self.envelope(ipaddress.IPv6Address('fe80::1').packed,
            ipaddress.IPv6Address('fe80::2').packed,body,58,255))

    def tick(self):
        if self.pending is not None and self.closed and not self.late_sent:
            self.late_sent=True
            self.transmit(FIN|ACK,sequence=self.state['server_next']-1)

    def receive(self,frame):
        if not self.ready and not self.native and frame[12:14]!=self.barrier_protocol:
            return super().receive(frame)
        if len(frame)>=42 and frame[12:14]==b'\x08\x06':
            check(frame[6:12]==self.guest,'actual IPv4 ARP interface owner')
            self.frames.append(dict(direction='receive',ms=(time.monotonic()-self.began)*1000,frame=frame.hex()))
            arp=frame[14:42]
            check(arp[:6]==bytes.fromhex('000108000604'),'complete actual ARP')
            if arp[6:8]==b'\0\1' and arp[24:28]==self.ip4:
                answer=struct.pack('!HHBBH',1,0x800,6,4,2)+self.mac+self.ip4+self.guest+arp[14:18]
                self.send(self.guest+self.mac+b'\x08\x06'+answer)
            return
        if len(frame)>=21 and frame[12:14]==self.barrier_protocol and frame[19]:
            phase=frame[19]
            check(self.ready and phase==len(self.phases)+1 and phase in (1,2,3) and
                len(frame)==60 and frame[:6]==bytes([2,73,80,54,self.lane,0]) and
                frame[6:12]==self.guest and frame[14:19]==self.barrier_magic+bytes([self.lane]) and
                not any(frame[20:]),'exact actual family control barrier')
            self.frames.append(dict(direction='receive',ms=(time.monotonic()-self.began)*1000,frame=frame.hex()))
            self.phases.append(phase)
            if phase in (1,2):
                check((not self.tags) if phase==1 else self.tags==list(range(5)),'actual family RA boundary')
                self.router(41 if phase==1 else 51);self.answer(frame)
            else:
                check(self.tags==list(range(11)),'all family bytes precede detached reply')
                self.pending=frame
            return
        v6=len(frame)>=74 and frame[12:14]==b'\x86\xdd' and frame[20]==6
        v4=len(frame)>=54 and frame[12:14]==b'\x08\0' and frame[23]==6
        if v6 or v4:
            check(v6==(self.family=='ipv6'),'actual expected wire address family')
            value=packet6(frame) if v6 else packet4(frame)
            check(self.ready and frame[:12]==self.mac+self.guest and value['source_ip']==self.local and
                value['target_ip']==self.remote and value['source']==49880+self.lane and value['target']==49890+self.lane,
                'actual family interface and complete TCP tuple')
            self.frames.append(dict(direction='receive',ms=(time.monotonic()-self.began)*1000,frame=frame.hex()))
            header=(frame[21],(int.from_bytes(frame[14:18],'big')>>20)&255) if v6 else (frame[22],frame[15])
            if value['flags']==SYN:
                check(self.state is None and self.phases==[1] and header==((41,168) if v6 else (77,44)),
                    'actual native-derived initial family header')
                origin=0x12340000+self.lane*256
                self.state=dict(client_next=(value['seq']+1)&0xffffffff,server_next=origin+1,established=False,fin=False)
                self.transmit(SYN|ACK,sequence=origin);return
            state=self.state
            check(state is not None and value['seq']==state['client_next'],'actual family stream sequence')
            if not state['established']:
                check(value['flags']==ACK and value['ack']==state['server_next'] and not value['data'],'actual family handshake')
                state['established']=True;return
            if value['data']:
                tag=len(self.tags)
                check(tag<11,'bounded actual family transfer inventory')
                expected=([(41,168),(41,24),(41,24),(0,24),(37,24),(37,24)]+[(51,24)]*5)[tag] if v6 else (77,44 if tag<2 else 108)
                check(tag<11 and value['data']==payload(self.lane,tag) and header==expected,'actual independent family packet controls')
                self.tags.append(tag);state['client_next']=(state['client_next']+16)&0xffffffff
                self.transmit(ACK|8,value['data']);state['server_next']=(state['server_next']+16)&0xffffffff
            if value['flags']&FIN:
                check(self.tags==list(range(11)) and not state['fin'] and header==((37,168) if v6 else (77,108)),
                    'actual configured family live FIN')
                state['client_next']=(state['client_next']+1)&0xffffffff
                self.transmit(FIN|ACK);state['server_next']=(state['server_next']+1)&0xffffffff;state['fin']=True
            elif state['fin']:
                check(value['flags']==ACK and not value['data'] and value['ack']==state['server_next'],'actual family final close ACK')
                self.closed=True
                if self.late_sent:
                    expected=(51,168) if v6 else (64,168 if self.family=='mapped' else 108)
                    check(header==expected,f'actual detached {self.family} header expected={expected} observed={header}')
                    self.late_seen=True;self.answer(self.pending);self.pending=None;self.flows[0].done=True
            return
        super().receive(frame)

    def result(self):
        check(self.phases==[1,2,3] and self.tags==list(range(11)) and self.closed and
            self.late_sent and self.late_seen and self.pending is None and self.flows[0].done,'complete actual family probe')
        return dict(lane=self.lane,family=self.family,passed=True,tags=self.tags,router_hops=[41,51],detached_reply=True,frames=self.frames)


class Child:
    def __init__(self,peer,slot):
        self.peer,self.slot=peer,slot
        self.port=49920+peer.lane+slot*10
        self.origin=0x33220000+peer.lane*0x1000+slot*0x100
        self.remote_next=self.origin+1
        self.guest_next=None
        self.tags=[];self.synacks=[];self.headers=[]
        self.established=self.fin=self.closed=self.late_sent=self.late_seen=self.done=False

    def send(self,flags=ACK,data=b'',sequence=None):
        options=b'\x02\x04\x02\x18' if flags&SYN else b''
        sequence=self.remote_next if sequence is None else sequence
        ack=0 if flags==SYN else self.guest_next
        segment=bytearray(struct.pack('!HHIIHHHH',self.port,49910+self.peer.lane,sequence&0xffffffff,
            ack,((20+len(options))//4)<<12|flags,8192,0,0)+options+data)
        pseudo=self.peer.remote+self.peer.local+(struct.pack('!I3xB',len(segment),6) if self.peer.family=='ipv6' else struct.pack('!BBH',0,6,len(segment)))
        segment[16:18]=struct.pack('!H',checksum(pseudo+segment))
        if self.peer.family=='ipv6':frame=self.peer.envelope(self.peer.remote,self.peer.local,segment,6)
        else:
            ip=bytearray(struct.pack('!BBHHHBBH4s4s',0x45,0,20+len(segment),0,0x4000,64,6,0,self.peer.remote,self.peer.local))
            ip[10:12]=struct.pack('!H',checksum(ip))
            frame=self.peer.guest+self.peer.mac+b'\x08\0'+ip+segment
        self.peer.send(frame)

    def start(self):
        self.send(SYN,sequence=self.origin)

    def receive(self,value,header):
        check(not self.done,'no passive packet after its completed original scenario')
        self.headers.append(dict(flags=value['flags'],data=value['data'].hex(),header=header,
            sequence=value['seq'],acknowledgment=value['ack']))
        if value['flags']==SYN|ACK:
            check(not value['data'] and value['ack']==self.remote_next,'actual passive SYN-ACK acknowledges original SYN')
            if not self.synacks:self.guest_next=(value['seq']+1)&0xffffffff
            check(value['seq']==(self.guest_next-1)&0xffffffff,'actual passive retry retains original ISN')
            self.synacks.append(header)
            if not self.slot and len(self.synacks)==1:
                self.peer.complete(4)
            else:
                phase=6 if self.slot else 5
                check(len(self.synacks)==(1 if self.slot else 2),'one original retry of the pending request')
                check(self.peer.waiting is not None and self.peer.waiting[0]==phase,'actual retry follows listener-update barrier')
                self.send();self.established=True;self.peer.complete(phase)
            return
        check(self.established and value['seq']==self.guest_next and value['ack']==self.remote_next,
            'actual passive stream sequence and acknowledgment')
        if value['data']:
            tags=(20,21,22) if not self.slot else (30,31)
            check(len(self.tags)<len(tags),'bounded original passive transfer count')
            tag=tags[len(self.tags)]
            check(value['data']==payload(self.peer.lane,tag),'actual passive application bytes')
            self.tags.append(tag);self.guest_next=(self.guest_next+16)&0xffffffff
            self.send(ACK|8,value['data']);self.remote_next=(self.remote_next+16)&0xffffffff
        if value['flags']&FIN:
            check(not self.fin and self.tags==list((20,21,22) if not self.slot else (30,31)),
                  'all original passive bytes precede one close')
            self.guest_next=(self.guest_next+1)&0xffffffff
            self.send(FIN|ACK);self.remote_next=(self.remote_next+1)&0xffffffff;self.fin=True
        elif self.fin:
            check(value['flags']==ACK and not value['data'],'actual passive final close acknowledgment')
            self.closed=True
            if self.late_sent:
                self.late_seen=self.done=True
                self.peer.complete(7+self.slot)

    def result(self):
        check(self.done and self.closed and self.late_seen,'complete passive original and detached exchange')
        return dict(slot=self.slot,synack_headers=self.synacks,headers=self.headers,tags=self.tags,passed=True)


class Peer(ActivePeer):
    def __init__(self,*args,**kwargs):
        super().__init__(*args,**kwargs)
        self.children=[Child(self,slot) for slot in range(2)]
        self.flows.extend(self.children)
        self.passive_phases=[];self.waiting=None

    def complete(self,phase):
        check(self.waiting is not None and self.waiting[0]==phase,'exact passive barrier completion')
        self.answer(self.waiting[1]);self.waiting=None

    def tick(self):
        super().tick()
        for child in self.children:
            if self.waiting is not None and self.waiting[0]==7+child.slot and child.closed and not child.late_sent:
                child.late_sent=True
                child.send(FIN|ACK,sequence=child.remote_next-1)

    def receive(self,frame):
        if len(frame)>=21 and frame[12:14]==self.barrier_protocol and frame[19]>=4:
            phase=frame[19]
            check(self.ready and phase==len(self.passive_phases)+4 and phase<=8 and self.waiting is None and
                len(frame)==60 and frame[:6]==bytes([2,73,80,54,self.lane,0]) and frame[6:12]==self.guest and
                frame[14:19]==self.barrier_magic+bytes([self.lane]) and not any(frame[20:]),'original passive barrier and Ethernet owner')
            self.frames.append(dict(direction='receive',ms=(time.monotonic()-self.began)*1000,frame=frame.hex()))
            self.passive_phases.append(phase);self.waiting=(phase,frame)
            if phase==4:
                check(self.flows[0].done,'active close precedes passive listener probe')
                self.children[0].start()
            elif phase==5:check(len(self.children[0].synacks)==1,'listener changes while final ACK remains withheld')
            elif phase==6:
                check(self.children[0].tags==[20,21],'retained child exchanges through listener update')
                self.children[1].start()
            elif phase==7:check(self.children[0].tags==[20,21,22] and self.children[1].tags==[30],'first descriptor closes with other child alive')
            elif phase==8:check(self.children[0].done and self.children[1].tags==[30,31],'second child survives first detached reply')
            return
        v6=len(frame)>=74 and frame[12:14]==b'\x86\xdd' and frame[20]==6
        v4=len(frame)>=54 and frame[12:14]==b'\x08\0' and frame[23]==6
        if v6 or v4:
            value=packet6(frame) if v6 else packet4(frame)
            if value['source']==49910+self.lane:
                check(v6==(self.family=='ipv6') and frame[:12]==self.mac+self.guest and
                    value['source_ip']==self.local and value['target_ip']==self.remote,'actual passive family, tuple and interface')
                matches=[child for child in self.children if child.port==value['target']]
                check(len(matches)==1,'actual original passive remote port')
                self.frames.append(dict(direction='receive',ms=(time.monotonic()-self.began)*1000,frame=frame.hex()))
                header=(frame[21],(int.from_bytes(frame[14:18],'big')>>20)&255) if v6 else (frame[22],frame[15])
                matches[0].receive(value,header)
                return
        super().receive(frame)

    def result(self):
        result=super().result()
        check(self.passive_phases==[4,5,6,7,8] and self.waiting is None,'complete passive control phases')
        result.update(passive=[child.result() for child in self.children],
                      exchanges_each=16,detached_replies=3,listener_closed=True)
        return result
