#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Prove a quiet nonblocking observer can bound later actual TAP packets."""
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time
from types import SimpleNamespace
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from ipv4_expiry_capture import read_capture
from tcp6.native import Tap
from tcp6.observation import Capture, bind
from tcp6.pmtu_peer import Flow, SIZE
from tcp_fault_peer import ACK


def delayed_pmtu_receipt():
    sent = []
    observed = []
    peer = SimpleNamespace(lane=0, ip=bytes(16), address=bytes(16),
                           envelope=lambda source, target, body: body,
                           observe_input=lambda packet: lambda: None, send=sent.append)
    flow = Flow(peer, 9)
    flow.guest_origin = 1000
    flow.sent = flow.prefix = SIZE
    flow.notices = [dict(mtu=1400), dict(mtu=1280)]
    flow.observation = lambda: observed[0] if observed else None
    ack = dict(data=b'', flags=ACK, window=8192, seq=flow.guest_next, ack=(flow.origin + SIZE) & 0xffffffff)
    frame = bytes(range(74))
    flow.input(ack, dict(frame=frame.hex()))
    flow.tick()
    assert flow.pending_idle_quote == frame and not sent
    observed.append(time.monotonic())
    flow.tick()
    assert flow.pending_idle_quote is None and len(sent) == 1
    assert sent[0] == b'\2\0\0\0' + (1500).to_bytes(4, 'big') + frame[14:62]
    assert flow.notices[1]['observed_monotonic_seconds'] == observed[0]
    flow.input(ack, dict(frame=frame.hex()))
    flow.tick()
    assert len(sent) == 1


def child():
    with tempfile.TemporaryDirectory(prefix='axiom64-tcp6-clock-') as scratch:
        path = Path(scratch) / 'actual.pcap'
        tap = Tap('clock0')
        subprocess.run(['ip', 'link', 'set', 'clock0', 'up'], check=True)
        capture = Capture('clock0', path)
        try:
            time.sleep(.08)
            frame = bytes.fromhex('02000000000102000000000288c1') + bytes(46)
            first = time.monotonic_ns()
            assert os.write(tap.fd, frame) == len(frame)
            time.sleep(.12)
            second = time.monotonic_ns()
            assert os.write(tap.fd, frame) == len(frame)
            time.sleep(.08)
        finally:
            statistics = capture.close()
            tap.close()
        rows = read_capture(path)
        bind(path, rows, statistics)
        selected = [row for row in rows if row['frame'] == frame]
        assert len(selected) == 2
        for row, sent in zip(selected, (first, second)):
            assert row['arrival_lower_ns'] <= sent <= row['arrival_upper_ns']
        assert selected[1]['arrival_lower_ns'] - selected[0]['arrival_upper_ns'] >= 100000000
        print(json.dumps(dict(passed=True, packets=statistics['packets'], quiet_gaps=3)))


if __name__ == '__main__':
    if '--child' in sys.argv:
        child()
    else:
        delayed_pmtu_receipt()
        subprocess.run(['unshare', '--net', sys.executable, '-B', __file__, '--child'], check=True)
