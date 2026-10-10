# SPDX-License-Identifier: GPL-3.0-or-later
"""Exercise actual AF_PACKET capture bursts and drop rejection in a private namespace."""
from collections import Counter
import os
from pathlib import Path
import socket
import struct
import subprocess
import sys
import tempfile
import threading
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from tcp_fault_native import Capture, check, command


class HeldWriter:
    def __init__(self, output):
        self.output = output
        self.entered, self.release = threading.Event(), threading.Event()

    def write(self, data):
        self.entered.set()
        check(self.release.wait(10), 'bounded capture writer pause')
        return self.output.write(data)

    def close(self):
        self.output.close()


def burst(directory, overflow):
    path = directory / ('overflow.pcap' if overflow else 'complete.pcap')
    monitor = Capture('capture-peer', path)
    if overflow:
        monitor.socket.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 4096)
    held = HeldWriter(monitor.output)
    monitor.output = held
    prefix = bytes.fromhex('02415854431002415854431188b5')
    sender = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(3))
    sender.bind(('capture-send', 0))
    error, statistics = None, None
    try:
        for index in range(1000):
            frame = prefix + struct.pack('!I', index) + bytes(582)
            check(sender.send(frame) == 600, 'complete actual burst frame send')
            if index == 0:
                check(held.entered.wait(2), 'actual capture thread reaches its output writer')
    finally:
        held.release.set()
        try:
            statistics = monitor.close()
        except ValueError as exception:
            error = str(exception)
        finally:
            sender.close()
    if overflow:
        check(error is not None and 'dropped=' in error, 'real receive-buffer overflow is rejected')
        return
    check(error is None and statistics['dropped'] == 0, 'complete burst capture has no kernel drops')
    data, offset, captured = path.read_bytes(), 24, Counter()
    while offset < len(data):
        check(offset + 16 <= len(data), 'complete burst PCAP record header')
        _, _, size, original = struct.unpack_from('<IIII', data, offset)
        offset += 16
        check(size == original and offset + size <= len(data), 'complete burst PCAP frame bounds')
        frame = data[offset:offset + size]
        offset += size
        if frame[:14] == prefix:
            captured[struct.unpack_from('!I', frame, 14)[0]] += 1
    check(captured == Counter(range(1000)), 'every actual burst frame is captured exactly once')


def isolated(parent):
    check(os.readlink('/proc/self/ns/net') != parent, 'capture burst fixture has a private network namespace')
    command('ip', 'link', 'add', 'capture-peer', 'type', 'veth', 'peer', 'name', 'capture-send')
    command('ip', 'link', 'set', 'capture-peer', 'up')
    command('ip', 'link', 'set', 'capture-send', 'up')
    with tempfile.TemporaryDirectory(prefix='axiom64-capture-burst-') as temporary:
        burst(Path(temporary), False)
        burst(Path(temporary), True)


if __name__ == '__main__':
    if len(sys.argv) == 3 and sys.argv[1] == '--namespace':
        isolated(sys.argv[2])
    else:
        check(len(sys.argv) == 1, 'known capture burst fixture arguments')
        parent = os.readlink('/proc/self/ns/net')
        subprocess.run(['unshare', '--net', sys.executable, __file__, '--namespace', parent], check=True, timeout=30)
        check(os.readlink('/proc/self/ns/net') == parent, 'capture burst fixture preserves the host network namespace')
        print('TCP_FAULT_NATIVE_CAPTURE_PASS burst=1000 exact_packets=1000 drops_rejected=1 host_namespace_preserved=1')
