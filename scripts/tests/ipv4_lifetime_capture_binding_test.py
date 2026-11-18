#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Check real native packet capture ownership across the bind boundary."""
import os
from pathlib import Path
import socket
import subprocess
import sys
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from ipv4_lifetimes.wire_worker import capture_socket

ETHERTYPE = 0x88b5
BASE = bytes.fromhex('ffffffffffff020000000001') + ETHERTYPE.to_bytes(2, 'big')


def frame(value):
    return BASE + value.ljust(46, b'\0')


def exercise(parent_namespace):
    if Path('/proc/self/ns/net').stat().st_ino == parent_namespace:
        raise RuntimeError('packet binding test requires a private network namespace')
    for target, source in (('target0', 'source0'), ('other0', 'unrelated0')):
        subprocess.run(['ip', 'link', 'add', target, 'type', 'veth', 'peer', 'name', source], check=True)
        for name in (target, source):
            subprocess.run(['ip', 'link', 'set', name, 'up'], check=True)
    stray, allowed = frame(b'before bind'), frame(b'bound device')
    with socket.socket(socket.AF_PACKET, socket.SOCK_RAW, 0) as wrong, \
         socket.socket(socket.AF_PACKET, socket.SOCK_RAW, 0) as sender:
        wrong.bind(('unrelated0', ETHERTYPE))
        sender.bind(('source0', ETHERTYPE))

        class InjectBeforeBind(socket.socket):
            def bind(self, address):
                if wrong.send(stray) != len(stray):
                    raise RuntimeError('incomplete test frame before capture bind')
                return super().bind(address)

        # Reproduce the old registration window with real packet metadata.
        with InjectBeforeBind(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(3)) as legacy:
            legacy.bind(('target0', 0))
            legacy.settimeout(2)
            while True:
                data, source = legacy.recvfrom(65535)
                if data == stray:
                    break
            if source[0] != 'unrelated0' or source[2] != 4:
                raise RuntimeError('baseline did not queue unrelated outgoing traffic')

        with patch('ipv4_lifetimes.wire_worker.socket.socket', InjectBeforeBind):
            captured = capture_socket('target0')
        with captured:
            if sender.send(allowed) != len(allowed):
                raise RuntimeError('incomplete frame on the bound device')
            captured.settimeout(2)
            while True:
                data, _, flags, source = captured.recvmsg(65535, 512)
                if flags or source[0] != 'target0' or data == stray:
                    raise RuntimeError('capture queued unbound or wrong-interface traffic')
                if data == allowed:
                    break
    print('IPV4_LIFETIME_CAPTURE_BINDING_PASS')


if __name__ == '__main__':
    if len(sys.argv) == 2:
        exercise(int(sys.argv[1]))
    else:
        if os.geteuid() != 0:
            raise RuntimeError('packet binding test requires root for its private veth namespace')
        namespace = Path('/proc/self/ns/net').stat().st_ino
        subprocess.run(['unshare', '-n', '--', sys.executable, '-B', __file__, str(namespace)],
                       timeout=15, check=True)
