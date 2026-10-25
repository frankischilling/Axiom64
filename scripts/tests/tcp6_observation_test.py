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
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from ipv4_expiry_capture import read_capture
from tcp6.native import Tap
from tcp6.observation import Capture, bind


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
        subprocess.run(['unshare', '--net', sys.executable, '-B', __file__, '--child'], check=True)
