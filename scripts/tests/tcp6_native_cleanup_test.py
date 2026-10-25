#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""An actual peer failure must retire the native wrapper, client and TAP owners."""
import os
from pathlib import Path
import socket
import subprocess
import sys
import tempfile
import time
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from tcp6 import native
from tcp6.inputs import program


def child(directory, parent_namespace):
    children = []
    def fail(process, *args, **kwargs):
        began = time.monotonic()
        path = Path(f'/proc/{process.pid}/task/{process.pid}/children')
        while not children:
            children.extend(int(value) for value in path.read_text().split())
            assert process.poll() is None and time.monotonic() - began < 2
            time.sleep(.005)
        assert all(os.getpgid(pid) == process.pid for pid in children)
        raise ValueError('deliberate TCP6 peer failure after real client creation')
    native.exercise = fail
    assert native.child(directory, 'static', parent_namespace) == 1
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
    print('TCP6_NATIVE_CLEANUP_PASS actual_clients_retired=1 taps_retired=2')


if __name__ == '__main__':
    if len(sys.argv) == 4 and sys.argv[1] == '--child':
        child(Path(sys.argv[2]), int(sys.argv[3]))
    else:
        with tempfile.TemporaryDirectory(prefix='axiom64-tcp6-native-failure-') as scratch:
            directory = Path(scratch)
            program(directory, 'static')
            subprocess.run(['unshare', '--net', sys.executable, '-B', __file__, '--child',
                str(directory), str(Path('/proc/self/ns/net').stat().st_ino)], check=True)
