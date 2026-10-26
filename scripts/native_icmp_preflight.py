# SPDX-License-Identifier: GPL-3.0-or-later
"""Complete one real native error before releasing the fragment peer's input."""
import json
import os
from pathlib import Path
import struct
import time
from ipv4_fragments import checksum

POLICY = {'icmp_ratelimit':'1000\n', 'icmp_ratemask':'6168\n',
          'icmp_msgs_per_sec':'1000\n', 'icmp_msgs_burst':'50\n'}


def require(value, reason):
    if not value:
        raise ValueError('native ICMP preflight: '+reason)


class NativeIcmpPreflight:
    def __init__(self, directory):
        self.path = directory/'native-icmp-preflight.json'
        self.held = []
        self.lane = None
        self.request = None
        self.passed = False
        self.evidence = dict(schema=1, passed=False, held=[], releases=[], policy_before=None,
                             policy_after=None, request=None, response=None)
        self.save()

    def save(self):
        self.path.write_text(json.dumps(self.evidence, indent=2)+'\n')

    def policy(self, name):
        values = {key:(Path('/proc/sys/net/ipv4')/key).read_text() for key in POLICY}
        self.evidence[name] = dict(monotonic_ns=time.monotonic_ns(), values=values)
        self.save()
        require(values == POLICY, 'unchanged default native error-rate parameters')

    def hold(self, lane, frame, taps, captures):
        require(not self.passed and len(self.held) < 64, 'bounded pending original controls')
        self.held.append((lane, bytes(frame)))
        self.evidence['held'].append(dict(lane=lane, frame_hex=frame.hex(), observed_ns=time.monotonic_ns()))
        self.save()
        if self.lane is not None:
            return
        self.lane = lane
        self.policy('policy_before')
        guest = bytes([0x52,0x54,0,0x12,0x34,0x10+lane])
        peer = bytes([2,0x41,0x58,0x49,0x50,lane])
        remote, local = bytes([10,23,lane+1,1]), bytes([10,23,lane+1,2])
        udp = struct.pack('!HHHH',61398,61399,8,0)
        header = bytearray(struct.pack('!BBHHHBBH4s4s',0x45,0,28,0x7b00+lane,0,51,17,0,remote,local))
        struct.pack_into('!H',header,10,checksum(bytes(header)))
        self.request = bytes(header)+udp
        wire = (guest+peer+b'\x08\0'+self.request).ljust(60,b'\0')
        self.evidence['request'] = dict(lane=lane, frame_hex=wire.hex(), begin_ns=time.monotonic_ns())
        self.save()
        observed = captures[lane].observe_injection(wire, lambda data:os.write(taps[lane],data))
        self.evidence['request']['capture_observed_ns'] = round(observed*1e9)
        self.evidence['request']['end_ns'] = time.monotonic_ns()
        self.save()

    def receive(self, lane, frame):
        if self.request is None or len(frame) < 42 or frame[12:14] != b'\x08\0':
            return False
        packet = frame[14:]
        if packet[9] != 1 or packet[20:22] != b'\x03\x03':
            return False
        # Only this preflight owns a quote of its exact UDP identity. A changed
        # quote on the selected lane fails while awaiting the first response.
        selected = lane == self.lane and (not self.passed or packet[32:34] == self.request[4:6])
        if not selected:
            return False
        self.evidence['response'] = dict(lane=lane,frame_hex=frame.hex(),observed_ns=time.monotonic_ns())
        self.save()
        require(not self.passed, 'one actual primer response')
        total = int.from_bytes(packet[2:4],'big')
        packet = packet[:total]
        guest = bytes([0x52,0x54,0,0x12,0x34,0x10+lane])
        peer = bytes([2,0x41,0x58,0x49,0x50,lane])
        require(frame[:12] == peer+guest and len(packet) == total == 56 and
                packet[:2] == b'\x45\xc0' and packet[6:10] == b'\0\0\x40\x01' and
                packet[12:20] == self.request[16:20]+self.request[12:16] and
                not checksum(packet[:20]) and not checksum(packet[20:]) and
                packet[24:28] == b'\0'*4 and packet[28:] == self.request,
                'exact original UDP error quote, tuple, Ethernet ownership and checksums')
        self.policy('policy_after')
        self.passed = self.evidence['passed'] = True
        self.save()
        return True

    def release(self):
        require(self.passed, 'actual error acknowledged before releasing original controls')
        while self.held:
            lane,frame = self.held.pop(0)
            self.evidence['releases'].append(dict(lane=lane,frame_hex=frame.hex(),begin_ns=time.monotonic_ns()))
            self.save()
            yield lane,frame

    def tick(self):
        if self.request is not None and not self.passed:
            require(time.monotonic_ns()-self.evidence['request']['begin_ns'] <= 2000000000,
                    'actual error quote arrives within the setup deadline')
