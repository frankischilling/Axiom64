# SPDX-License-Identifier: GPL-3.0-or-later
"""Bound actual packet arrival using empty-queue observations on a monotonic clock.

SO_TIMESTAMPNS uses system realtime (see Linux networking/timestamping.html).
Keep those original timestamps. An EAGAIN observed after monotonic time A proves
that a subsequently received packet arrived after A; its completed recvmsg at B
proves arrival before B. Check timer lower bounds using later.A - earlier.B.
No clock translation, interval rescaling or scheduling delay can enlarge them.
"""
import hashlib
import json
import socket
import struct
import time
from tcp_fault_native import Capture as OriginalCapture, clock_pair
from tcp6.capture import require


class Capture(OriginalCapture):
    def collect(self):
        empty = None
        try:
            self.socket.setblocking(False)
            while True:
                began = time.monotonic_ns()
                try:
                    frame, ancillary, flags, _ = self.socket.recvmsg(
                        65535, socket.CMSG_SPACE(16), socket.MSG_DONTWAIT)
                    observed = clock_pair()
                except BlockingIOError:
                    empty = began
                    if self.stopping.is_set():
                        break
                    self.stopping.wait(.001)
                    continue
                require(empty is not None and not flags & (socket.MSG_TRUNC | socket.MSG_CTRUNC),
                        'complete packet follows an independently observed empty queue')
                require(0 <= observed['receipt_monotonic_after_ns'] - empty <= 50000000,
                        'packet arrival bracket is at most fifty real milliseconds')
                stamps = [value for level, kind, value in ancillary
                          if level == socket.SOL_SOCKET and kind == 64]
                require(len(stamps) == 1 and len(stamps[0]) == 16, 'one original kernel timestamp')
                seconds, nanos = struct.unpack('=qq', stamps[0])
                require(seconds >= 0 and 0 <= nanos < 1000000000, 'original packet timestamp bounds')
                stamp = seconds * 1000000000 + nanos
                self.output.write(struct.pack('<IIII', seconds, nanos // 1000, len(frame), len(frame)) + frame)
                self.clocks.write(json.dumps(dict(frame=self.frame_count,
                    sha256=hashlib.sha256(frame).hexdigest(), kernel_realtime_ns=stamp,
                    arrival_lower_ns=empty, **observed)) + '\n')
                self.frame_count += 1
                if self.injection is not None:
                    with self.injection_lock:
                        waiting = self.injection
                        if waiting is not None and waiting['frame'] == frame and not waiting['ready'].is_set():
                            waiting['monotonic_ns'] = observed['receipt_monotonic_after_ns']
                            waiting['ready'].set()
        except Exception as failure:
            self.error = failure


def bind(path, rows, statistics):
    require(statistics.get('original_packet_times_not_rescaled') is True and
            statistics.get('dropped') == 0 and statistics.get('packets') == len(rows) > 0 and
            statistics.get('receipt_frames') == len(rows), 'complete lossless bounded packet capture')
    name = statistics.get('monotonic_receipts')
    require(name == path.with_suffix('.clocks.jsonl').name, 'bounded packet clock sidecar name')
    encoded = (path.parent / name).read_bytes()
    require(hashlib.sha256(encoded).hexdigest() == statistics.get('monotonic_receipts_sha256'),
            'original packet arrival observations')
    clocks = [json.loads(line) for line in encoded.splitlines()]
    require(len(clocks) == len(rows), 'one arrival bracket for every original frame')
    previous, widest = 0, 0
    start = statistics['clock_start']['receipt_monotonic_after_ns']
    end = statistics['clock_end']['receipt_monotonic_ns']
    for index, (row, clock) in enumerate(zip(rows, clocks)):
        require(set(clock) == {'frame', 'sha256', 'kernel_realtime_ns', 'arrival_lower_ns',
            'receipt_monotonic_ns', 'receipt_realtime_ns', 'receipt_monotonic_after_ns'} and
            all(type(value) is int for key, value in clock.items() if key != 'sha256'),
            'exact bounded arrival observation fields')
        lower, before, upper = clock['arrival_lower_ns'], clock['receipt_monotonic_ns'], clock['receipt_monotonic_after_ns']
        require(clock['frame'] == index and clock['sha256'] == hashlib.sha256(row['frame']).hexdigest() and
                clock['kernel_realtime_ns'] // 1000 * 1000 == row['ns'],
                'arrival bracket binds the unchanged actual frame and kernel timestamp')
        require(start <= lower <= before <= upper <= end and previous <= before and
                upper - lower <= 50000000, 'ordered actual arrival brackets within the capture')
        row.update(arrival_lower_ns=lower, arrival_upper_ns=upper)
        previous = upper
        widest = max(widest, upper - lower)
    return dict(passed=True, frames=len(rows), widest_bracket_ns=widest,
                original_packet_times_not_rescaled=True, arrival_timer_lower_bounds=True)
