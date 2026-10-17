# SPDX-License-Identifier: GPL-3.0-or-later
"""Require exact TCP recovery after each interface is administratively restored."""
import re
from tcp_fault_peer import Peer as EthernetPeer, Flow as EthernetFlow, check, MASK, SYN, ACK, FIN, RST
from tcp_recovery_fault import OutputHold


def pattern(lane, size):
    return bytes(((at * 29) ^ (at >> 7) ^ (lane * 53)) & 255 for at in range(size))


class Flow(EthernetFlow):
    def __init__(self, peer, role):
        super().__init__(peer, role)
        self.local_port = 49000 + peer.lane
        self.guest_port = 48000 + peer.lane
        self.expected = pattern(peer.lane, 6224)
        self.barrier = 1040 + peer.lane * 512
        self.expiry_barrier = 2064 + peer.lane * 512
        self.reply = (self.expected[:self.barrier] + b'QH' + self.expected[self.barrier:self.expiry_barrier] +
                      b'QH' + self.expected[self.expiry_barrier:])
        self.commands = 0

    def flush(self):
        permitted = len(self.received) + self.commands
        if self.peer.carrier is not None:
            permitted = self.peer.carrier.reply_limit(self.peer.lane, permitted)
        while self.sent < permitted:
            length = min(536, permitted - self.sent)
            self.send(data=self.reply[self.sent:self.sent + length])
            self.sent += length

    def input(self, segment, record):
        flags, data = segment['flags'], segment['data']
        check(not flags & RST, 'established stream survives temporary administrative outage')
        if flags & SYN:
            check(not flags & ACK and not data, 'actual active handshake')
            if self.guest_initial is None:
                self.guest_initial = segment['seq']
                self.guest_origin = (self.guest_initial + 1) & MASK
            check(segment['seq'] == self.guest_initial, 'stable SYN')
            self.send(SYN | ACK, sequence=self.initial)
            return
        check(flags & ACK and self.guest_origin is not None, 'established ACK')
        acknowledgment = (segment['ack'] - self.origin) & MASK
        check(acknowledgment <= self.sent + int(self.fin_sent), 'only emitted peer bytes acknowledged')
        self.acknowledged = max(self.acknowledged, min(6228, acknowledgment))
        if data:
            position = (segment['seq'] - self.guest_origin) & MASK
            check(position + len(data) <= 6224 and data == self.expected[position:position + len(data)],
                  'exact distinct stream payload')
            if position <= len(self.received):
                self.received.extend(data[max(0, len(self.received) - position):])
        if flags & FIN:
            check(len(self.received) == 6224 and
                  ((segment['seq'] - self.guest_origin) & MASK) + len(data) == 6224, 'complete FIN')
            self.fin_received = True
        if data or flags & FIN:
            self.send()
        self.flush()
        if self.fin_received and self.acknowledged == 6228 and not self.fin_sent:
            self.send(FIN | ACK)
            self.fin_sent = True
        if self.fin_sent and acknowledgment == 6229:
            self.done = True

    def result(self):
        check(self.done and self.received == self.expected and self.acknowledged == 6228 and self.commands == 4,
              'complete recovered stream with exact echo and both FINs')
        return dict(done=self.done, received=len(self.received), acknowledged=self.acknowledged)


class Peer(EthernetPeer):
    def __init__(self, lane, minimum_fin_ms=0):
        super().__init__(lane, minimum_fin_ms)
        self.flows = [Flow(self, 0)]
        self.hold = None
        self.expiry_hold = None
        self.down = False
        self.carrier = None

    def native_profile(self, pid, label):
        self.hold = OutputHold(self.lane, label, native_pid=pid)
        self.expiry_hold = OutputHold(self.lane, label + '-expiry', native_pid=pid, expiry=True)

    def guest_profile(self, port, label):
        self.hold = OutputHold(self.lane, label, gdb_port=port)
        self.expiry_hold = OutputHold(self.lane, label + '-expiry', gdb_port=port, expiry=True)

    def line(self, line):
        line = line.rstrip(b'\r')
        flow = self.flows[0]
        transition = re.fullmatch(rb'TCP_RECOVERY_CARRIER_REQUEST lane=([01]) up=([01])', line)
        held = re.fullmatch(rb'TCP_RECOVERY_CARRIER_HELD lane=([01]) error=(\d+) available=(\d+) flags=([0-9a-f]+)', line)
        if transition and int(transition[1]) == self.lane:
            check(self.carrier is not None, 'actual physical carrier controller is attached')
            self.carrier.change(self.lane, bool(int(transition[2])))
        if held and int(held[1]) == self.lane:
            check(self.carrier is not None, 'actual physical carrier controller observes held bytes')
            self.carrier.confirm(self.lane, int(held[2]), int(held[3]), int(held[4], 16))
        if line == f'TCP_RECOVERY_QUEUE_ARM lane={self.lane}'.encode():
            check(self.hold is not None and not flow.commands and len(flow.received) == flow.barrier,
                  'queue hold begins after the exact warm prefix')
            self.hold.arm()
            flow.commands = 1
            flow.flush()
        if line == f'TCP_RECOVERY_QUEUE_HELD lane={self.lane}'.encode():
            check(flow.commands == 1 and len(flow.received) == flow.barrier,
                  'fault bytes remain outside the peer before interface mutation')
            self.hold.confirm()
            flow.commands = 2
            flow.flush()
        if flow.commands == 2 and line == f'TCP_RECOVERY_FLAGS lane={self.lane} up=0'.encode():
            check(not self.down and len(flow.received) == flow.barrier,
                  'queued bytes remain undelivered at actual interface down')
            self.down = True
        if self.down and line == f'TCP_RECOVERY_FLAGS lane={self.lane} up=1'.encode():
            self.hold.release()
            self.down = False
        if line == f'TCP_RECOVERY_EXPIRY_ARM lane={self.lane}'.encode():
            check(self.expiry_hold is not None and flow.commands == 2 and
                  len(flow.received) == flow.expiry_barrier, 'expiry hold starts after its exact warm prefix')
            self.expiry_hold.arm()
            flow.commands = 3
            flow.flush()
        if line == f'TCP_RECOVERY_EXPIRY_HELD lane={self.lane}'.encode():
            check(flow.commands == 3 and len(flow.received) == flow.expiry_barrier,
                  'expiry fault bytes remain in the real output queue')
            self.expiry_hold.confirm()
            flow.commands = 4
            flow.flush()
        if line.startswith(f'TCP_RECOVERY_EXPIRY_RELEASE lane={self.lane} elapsed_ms='.encode()):
            elapsed = int(line.rsplit(b'=', 1)[1])
            check(flow.commands == 4 and len(flow.received) == flow.expiry_barrier and elapsed >= 4500,
                  'the actual held bytes outlast the full queue lifetime')
            self.expiry_hold.release()

    def result(self):
        result = super().result()
        check(self.hold is not None and not self.down, 'both interface transitions completed')
        result['output_hold'] = self.hold.result()
        result['expiry_hold'] = self.expiry_hold.result()
        check(self.carrier is not None, 'both physical carriers have their actual controller')
        result['carrier'] = self.carrier.result()
        return result

    def close(self):
        if self.hold is not None:
            self.hold.close()
        if self.expiry_hold is not None:
            self.expiry_hold.close()
        if self.carrier is not None:
            self.carrier.close()
