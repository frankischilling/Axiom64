# SPDX-License-Identifier: GPL-3.0-or-later
"""Drive duplicate scoped tuples while both real application streams stay open."""
import ipaddress
import struct
import time
from types import SimpleNamespace
from tcp6.peer import Peer as EthernetPeer, packet
from tcp_fault_peer import check, checksum, ACK, SYN, FIN, RST

MASK = 0xffffffff


def payload(round_, lane, tag, size=32):
    return bytes((round_*53+lane*97+tag*29+n*7)&255 for n in range(size))


class Peer(EthernetPeer):
    barrier_protocol = b'\x88\xc6'
    barrier_magic = b'IP6I'

    def __init__(self, lane, minimum_fin_ms=0, native=False):
        super().__init__(lane, minimum_fin_ms, native)
        self.ip = ipaddress.IPv6Address('fe80::1').packed
        self.address = ipaddress.IPv6Address('fe80::2').packed
        self.flows = [SimpleNamespace(done=False)]
        self.states = {}
        self.controls = [round_*8+step for round_ in range(4) for step in range(1,7)]
        self.completed = 0
        self.boundary = None
        self.observe_input = None
        self.peers = None

    def bind_peers(self, peers):
        self.peers = peers

    def transmit(self, round_, flags=ACK, data=b'', sequence=None, window=8192):
        state = self.states[round_]
        options = b'\x02\x04\x02\x18' if flags&SYN else b''
        sequence = state['server_next'] if sequence is None else sequence
        header = bytearray(struct.pack('!HHIIHHHH',49300+round_,49200+round_,sequence&MASK,
            state['client_next'],((20+len(options))//4)<<12|flags,window,0,0)+options+data)
        header[16:18] = struct.pack('!H',checksum(self.ip+self.address+struct.pack('!I3xB',len(header),6)+header))
        frame = self.envelope(self.ip,self.address,bytes(header),6)
        self.send(frame)
        return frame

    def observed_input(self, frame):
        check(self.observe_input is not None, 'independent original isolation input observation')
        return self.observe_input(frame)

    def tick(self):
        if self.boundary is None:
            return
        item = self.boundary
        frame, round_, step = item['frame'], item['round'], item['step']
        state = self.states.get(round_)
        if not state or not state['established']:
            return
        if step == 1:
            if not all(peer.states.get(round_,{}).get('established') for peer in self.peers):
                return
            item.setdefault('since',time.monotonic())
        elif step in (2,4,5):
            inject = step == 2 or (step == 4 and self.lane == round_%2) or (step == 5 and self.lane != round_%2)
            if inject and 'observation' not in item:
                check(not state['reset'], 'no payload reaches an already reset zone')
                if step == 4:
                    body = self.transmit(round_,RST|ACK,window=0)
                    state['reset'] = True
                else:
                    tag = int(step == 5)
                    body = self.transmit(round_,ACK|8,payload(round_,self.lane,tag))
                    state['server_next'] = (state['server_next']+32)&MASK
                item['observation'] = self.observed_input(body)
            if inject:
                observed = item['observation']()
                if observed is None:
                    return
                item.setdefault('since',observed)
                if step != 4 and state['last_ack'] != state['server_next']:
                    return
        elif step == 3 and len(state['payloads']) != 1:
            return
        elif step == 6 and not (state['reset'] if self.lane == round_%2 else state['closed']):
            return
        if 'since' in item and time.monotonic()-item['since'] < .1:
            return
        answer = bytearray(frame)
        answer[:12] = self.guest+frame[:6]
        answer[20] = 1
        self.send(answer)
        self.boundary = None
        if self.completed == len(self.controls):
            self.flows[0].done = True

    def receive(self, frame):
        if len(frame) >= 20 and frame[12:14] == self.barrier_protocol and frame[19]:
            phase = frame[19]
            check(self.ready and self.boundary is None and self.completed < len(self.controls) and
                  phase == self.controls[self.completed] and len(frame) == 60 and
                  frame[:6] == bytes([2,73,80,54,self.lane,0]) and frame[6:12] == self.guest and
                  frame[14:19] == self.barrier_magic+bytes([self.lane]) and not any(frame[20:]),
                  'ordered original concurrent-zone control')
            self.frames.append(dict(direction='receive',ms=(time.monotonic()-self.began)*1000,frame=frame.hex()))
            self.completed += 1
            self.boundary = dict(frame=frame,round=phase//8,step=phase%8)
            return
        if len(frame) >= 54 and frame[12:14] == b'\x86\xdd' and frame[20] == 6:
            value = packet(frame)
            round_ = value['source']-49200
            check(self.ready and 0 <= round_ < 4 and value['target'] == 49300+round_ and
                  value['source_ip'] == self.address and value['target_ip'] == self.ip and
                  frame[:12] == self.mac+self.guest, 'actual connected-zone Ethernet tuple')
            self.frames.append(dict(direction='receive',ms=(time.monotonic()-self.began)*1000,frame=frame.hex()))
            if value['flags'] == SYN:
                check(round_ not in self.states and not value['ack'] and not value['data'],
                      'one actual scoped active open per generation')
                origin = (0xfffffff0+round_*4096)&MASK
                self.states[round_] = dict(client_next=(value['seq']+1)&MASK,
                    server_next=(origin+1)&MASK,last_ack=origin,established=False,
                    payloads=[],reset=False,fin=False,closed=False)
                self.transmit(round_,SYN|ACK,sequence=origin)
                return
            state = self.states.get(round_)
            check(state is not None and not state['reset'] and value['flags'] in (ACK,ACK|8,ACK|FIN,ACK|8|FIN),
                  'only the surviving zone can emit stream packets')
            check(value['ack'] == state['server_next'], 'actual connected-zone peer acknowledgment')
            state['last_ack'] = value['ack']
            if not state['established']:
                check(not value['data'] and value['seq'] == state['client_next'] and value['flags'] == ACK,
                      'actual connected-zone three-way handshake completion')
                state['established'] = True
                return
            check(value['seq'] == state['client_next'], 'exact connected-zone client sequence')
            if value['data']:
                tag = 2+len(state['payloads'])
                check(tag in (2,3) and (tag == 2 or self.lane != round_%2) and
                      value['data'] == payload(round_,self.lane,tag,32 if tag == 2 else 16),
                      'actual bytes leave only their owning interface zone')
                state['payloads'].append(value['data'])
                state['client_next'] = (state['client_next']+len(value['data']))&MASK
                self.transmit(round_)
            if value['flags']&FIN:
                check(self.lane != round_%2 and len(state['payloads']) == 2 and not state['fin'],
                      'one complete surviving-zone half-close')
                state['client_next'] = (state['client_next']+1)&MASK
                self.transmit(round_,FIN|ACK)
                state['server_next'] = (state['server_next']+1)&MASK
                state['fin'] = True
            elif state['fin']:
                check(value['flags'] == ACK and not value['data'], 'actual final surviving-zone ACK')
                state['closed'] = True
            return
        super().receive(frame)

    def result(self):
        check(self.ready and self.completed == 24 and self.boundary is None and self.flows[0].done and
              len(self.states) == 4 and all(state['reset'] if self.lane == round_%2 else state['closed']
              for round_,state in self.states.items()), 'all concurrent scoped generations complete')
        return dict(lane=self.lane,passed=True,rounds=4,reset_zones=2,surviving_zones=2,frames=self.frames)
