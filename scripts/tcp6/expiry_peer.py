# SPDX-License-Identifier: GPL-3.0-or-later
"""Observe retained TCP tuples through a real configured address lifetime."""
import time
from tcp6.pending_peer import Peer as PendingPeer
from tcp_fault_peer import check

MARKER='TCP6_SOURCE_EXPIRY_PASS lanes=2 rounds_each=4 flows_each=8 valid_seconds=5 preferred_seconds=2'

class Peer(PendingPeer):
    barrier_protocol=b'\x88\xcb';barrier_magic=b'IP6E'
    def complete_if_ready(self):
        if self.waiting is not None and self.waiting[0]%16 in (6,7,8):
            self.answer(self.waiting[1]);self.waiting=None;return
        return super().complete_if_ready()

    def receive(self,frame):
        if len(frame)>=21 and frame[12:14]==self.barrier_protocol and frame[19]:
            phase=frame[19]
            expected=[r*16+s for r in range(4) for s in ((1,6,7,8,2,3,4,5) if r==0 else (1,2,6,7,8,3,4,5))]
            check(self.ready and len(self.phases)<len(expected) and phase==expected[len(self.phases)] and
                self.waiting is None and len(frame)==60 and frame[:12]==bytes([2,73,80,54,self.lane,0])+self.guest and
                frame[14:19]==self.barrier_magic+bytes([self.lane]) and not any(frame[20:]),
                'complete ordered finite source lifetime barrier')
            self.frames.append(dict(direction='receive',ms=(time.monotonic()-self.began)*1000,frame=frame.hex()))
            self.phases.append(phase);self.waiting=(phase,frame)
            round_,step=divmod(phase,16)
            if round_==3 and step==2:self.flows[6].send(2,sequence=self.flows[6].origin)
            self.complete_if_ready();return
        return super().receive(frame)

    def result(self):
        check(all(flow.done for flow in self.flows) and len(self.phases)==32 and self.waiting is None,
            'complete actual finite source lifetime workload')
        return dict(passed=True,lane=self.lane,frames=self.frames,finite_source_expiry=True,
            full_source_route_device_expiry_acceptance=False,
            flows=[dict(round=f.round,companion=f.companion,passive=f.passive,
                handshake_count=len(f.handshakes),handshake_monotonic_ns=f.handshakes) for f in self.flows])
