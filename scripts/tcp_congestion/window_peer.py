# SPDX-License-Identifier: GPL-3.0-or-later
"""Measure real ACK-gated flight, retransmissions and receiver-window ownership."""
import struct
import time
from tcp_fault_peer import Peer as EthernetPeer, check, checksum, payload, MASK, SYN, ACK, FIN, RST


class Flow:
    role = 0

    def __init__(self, peer):
        self.peer = peer
        self.local_port, self.guest_port = 49500 + peer.lane, 48500 + peer.lane
        self.initial, self.origin = None, None
        self.peer_initial, self.peer_origin = 0xfffffff0, 0xfffffff1
        self.expected, self.reply = payload(peer.lane, 0, 0), payload(peer.lane, 0, 1)[:16]
        self.received = bytearray(65536)
        self.present = bytearray(65536)
        self.prefix = self.highest = self.acked = self.reply_sent = 0
        self.window = 65535
        self.stage, self.stage_at = 'opening', None
        self.retries, self.measurements = [], []
        self.fin_received = self.fin_sent = self.done = False

    def send(self, flags=ACK, data=b''):
        sequence = self.peer_initial if flags & SYN else self.peer_origin + self.reply_sent + int(self.fin_sent)
        options = bytes.fromhex('020405b4') if flags & SYN else b''
        body = bytearray(struct.pack('!HHIIHHHH', self.local_port, self.guest_port, sequence & MASK,
            (self.origin + self.acked + int(self.fin_received)) & MASK,
            ((20 + len(options)) // 4) << 12 | flags, self.window, 0, 0) + options + data)
        body[16:18] = checksum(self.peer.ip + self.peer.address + struct.pack('!BBH', 0, 6, len(body)) + body).to_bytes(2, 'big')
        ip = bytearray(struct.pack('!BBHHHBBH4s4s', 0x45, 0, len(body) + 20, 0, 0x4000,
                                   64, 6, 0, self.peer.ip, self.peer.address))
        ip[10:12] = checksum(ip).to_bytes(2, 'big')
        self.peer.send(self.peer.guest + self.peer.mac + b'\x08\x00' + ip + body)
        self.peer.frames[-1].update(stage=self.stage, owned_ack=self.acked, window=self.window)

    def snapshot(self):
        self.measurements.append(dict(stage=self.stage, monotonic_ns=time.monotonic_ns(),
            acknowledged=self.acked, prefix=self.prefix, highest=self.highest,
            observed_flight=self.highest - self.acked, window=self.window))

    def input(self, segment, record):
        flags, data = segment['flags'], segment['data']
        check(not flags & RST, 'window probe is never reset')
        if flags & SYN:
            check(not flags & ACK and not data, 'real active window handshake')
            if self.initial is None:
                self.initial, self.origin = segment['seq'], (segment['seq'] + 1) & MASK
            check(self.initial == segment['seq'], 'stable window handshake sequence')
            self.send(SYN | ACK)
            return
        check(flags & ACK and self.origin is not None, 'established actual window stream')
        acknowledgment = (segment['ack'] - self.peer_origin) & MASK
        check(acknowledgment <= self.reply_sent + int(self.fin_sent), 'actual ACK owns only emitted bytes')
        if data:
            position = (segment['seq'] - self.origin) & MASK
            check(position + len(data) <= 65536 and data == self.expected[position:position + len(data)],
                  'window probe retains exact application bytes')
            repeated = all(self.present[position:position + len(data)])
            record.update(stage=self.stage, offset=position, retransmitted=repeated)
            if self.stage_at is None:
                self.stage_at = time.monotonic()
            self.received[position:position + len(data)] = data
            self.present[position:position + len(data)] = b'\1' * len(data)
            self.highest = max(self.highest, position + len(data))
            while self.prefix < 65536 and self.present[self.prefix]:
                self.prefix += 1
            if self.stage == 'loss' and repeated and position == self.acked:
                self.retries.append(dict(monotonic_ns=time.monotonic_ns(), offset=position, size=len(data)))
        if flags & FIN:
            check(self.stage == 'complete' and self.prefix == 65536 and
                  (segment['seq'] - self.origin) & MASK == 65536, 'FIN follows the entire window test')
            self.fin_received = True
        if self.stage == 'complete' and (data or flags & FIN):
            self.acked = self.prefix
            self.send()
        if self.stage == 'complete' and self.prefix == 65536 and not self.reply_sent:
            self.send(data=self.reply)
            self.reply_sent = 16
        if self.fin_received and acknowledgment == 16 and not self.fin_sent:
            self.send(FIN | ACK)
            self.fin_sent = True
        if self.fin_sent and acknowledgment == 17:
            self.done = True
        self.pump()

    def pump(self):
        if self.stage_at is None or self.done:
            return
        now = time.monotonic()
        elapsed = now - self.stage_at
        if self.stage == 'opening' and elapsed >= .1:
            check(self.prefix >= 2920, 'actual initial burst supplies the window probe')
            self.snapshot()
            self.acked = 1460
            self.stage, self.stage_at = 'growth', now
            self.send()
        elif self.stage == 'growth' and elapsed >= .1:
            self.snapshot()
            self.stage, self.stage_at = 'loss', now
        elif self.stage == 'loss' and len(self.retries) == 2:
            self.snapshot()
            self.acked = self.prefix
            self.stage, self.stage_at = 'recovery', now
            self.send()
        elif self.stage == 'recovery' and elapsed >= .1:
            self.snapshot()
            self.acked, self.window = self.prefix, 1024
            self.stage, self.stage_at = 'receiver', now
            self.send()
        elif self.stage == 'receiver' and elapsed >= .35:
            self.snapshot()
            self.acked, self.window = self.prefix, 65535
            self.stage, self.stage_at = 'complete', now
            self.send()

    def result(self):
        check(self.done and self.received == self.expected and len(self.retries) == 2 and len(self.measurements) == 5,
              'all actual window observations and exact close complete')
        return dict(done=True, role=0, initial=self.initial, measurements=self.measurements, retries=self.retries,
                    exact_bytes=65536, exact_stream_recovered=True)


class Peer(EthernetPeer):
    def __init__(self, lane, minimum_fin_ms=0):
        super().__init__(lane, minimum_fin_ms)
        self.flows = [Flow(self)]

    def tick(self):
        self.flows[0].pump()
