#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""An actual peer failure must retire the native wrapper, client and TAP owners."""
import json
import os
from pathlib import Path
import socket
import signal
import subprocess
import sys
import tempfile
import time
from unittest.mock import patch
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from tcp6 import native
from tcp6.inputs import program
from tcp6 import observation


def child(directory, parent_namespace, mode='raised'):
    children = []
    def fail(process, *args, **kwargs):
        began = time.monotonic()
        path = Path(f'/proc/{process.pid}/task/{process.pid}/children')
        while not children:
            children.extend(int(value) for value in path.read_text().split())
            assert process.poll() is None and time.monotonic() - began < 2
            time.sleep(.005)
        assert all(os.getpgid(pid) == process.pid for pid in children)
        if mode == 'returned':
            for pid in children:
                os.kill(pid, signal.SIGSTOP)
            return '', [], 'deliberate monitored TCP6 input failure', None
        raise ValueError('deliberate TCP6 peer failure after real client creation')
    if mode != 'monitor':
        native.exercise = fail
    if mode == 'returned':
        close = native.Capture.close
        def failed_close(capture):
            result = close(capture)
            if capture.clocks_path.name == 'lane0.clocks.jsonl':
                raise ValueError('deliberate lane zero capture finalization failure')
            return result
        native.Capture.close = failed_close
    if mode == 'monitor':
        clock_pair = observation.clock_pair
        def delayed_receipt():
            # Delay an actual socket receipt, retaining the original clocks.
            # This must fail the existing fifty millisecond bound.
            time.sleep(.075)
            return clock_pair()
        with patch.object(observation, 'clock_pair', delayed_receipt):
            assert native.child(directory, 'static', parent_namespace, 'errors') == 1
        execution = json.loads((directory / 'client-execution.json').read_text())
        children.append(execution['pid'])
    else:
        assert native.child(directory, 'static', parent_namespace) == 1
    receipt = json.loads((directory / 'receipt.json').read_text())
    assert not receipt['passed'] and not receipt['independent_capture_audited']
    if mode == 'returned':
        assert receipt['error'] == 'deliberate monitored TCP6 input failure', receipt['error']
        finalization = receipt['capture_finalization']
        assert [row['lane'] for row in finalization] == [0, 1]
        assert finalization[0]['statistics'] is None
        assert finalization[0]['error'] == 'ValueError: deliberate lane zero capture finalization failure'
        assert finalization[1]['error'] is None and finalization[1]['statistics']['dropped'] == 0
    elif mode == 'monitor':
        assert receipt['error'] == 'independent input monitor remains healthy', receipt['error']
        finalization = receipt['capture_finalization']
        assert [row['lane'] for row in finalization] == [0, 1]
        for row in finalization:
            assert row['statistics'] is None and 'fifty real milliseconds' in row['error']
            assert row['failure']['sha256'] == native.digest(directory / row['failure']['path'])
            failure = json.loads((directory / row['failure']['path']).read_text())
            assert failure['error'] == 'ValueError: packet arrival bracket is at most fifty real milliseconds'
            assert failure['receipt']['receipt_monotonic_after_ns'] - failure['arrival_lower_ns'] > 50000000
            assert len(bytes.fromhex(failure['frame'])) >= 60
            assert len([value for value in failure['ancillary']
                        if value['level'] == socket.SOL_SOCKET and value['kind'] == 64]) == 1
    else:
        assert receipt['error'] == 'ValueError: deliberate TCP6 peer failure after real client creation'
    for pid in children:
        state = Path(f'/proc/{pid}/stat')
        assert not state.exists() or state.read_text().partition(') ')[2].split()[0] == 'Z'
    for name in ('eth0', 'eth1'):
        try:
            socket.if_nametoindex(name)
        except OSError:
            pass
        else:
            raise AssertionError('failed fixture retained a TAP owner')
    print(f'TCP6_NATIVE_CLEANUP_PASS mode={mode} actual_clients_retired=1 taps_retired=2 primary_error_retained=1')


if __name__ == '__main__':
    if len(sys.argv) == 5 and sys.argv[1] == '--child':
        child(Path(sys.argv[2]), int(sys.argv[3]), sys.argv[4])
    else:
        subprocess.run(['make', '-s', 'build/tcp6-fault-static', 'build/tcp6-errors-static'],
                       cwd=native.ROOT, check=True)
        for mode in ('raised', 'returned', 'monitor'):
            with tempfile.TemporaryDirectory(prefix='axiom64-tcp6-native-failure-') as scratch:
                directory = Path(scratch)
                program(directory, 'static', 'errors' if mode == 'monitor' else 'loss')
                subprocess.run(['unshare', '--net', sys.executable, '-B', __file__, '--child',
                    str(directory), str(Path('/proc/self/ns/net').stat().st_ino), mode], check=True)
