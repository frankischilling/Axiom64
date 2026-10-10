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
import time
from unittest import mock
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


def pair_times(path, prefix):
    data, offset, timestamps = path.read_bytes(), 24, {}
    while offset < len(data):
        check(offset + 16 <= len(data), 'complete timing PCAP header')
        seconds, micros, size, original = struct.unpack_from('<IIII', data, offset)
        offset += 16
        check(size == original and offset + size <= len(data), 'complete timing PCAP packet')
        frame = data[offset:offset + size]
        offset += size
        if frame[:14] == prefix:
            index = struct.unpack_from('!I', frame, 14)[0]
            check(index not in timestamps, 'each actual timing packet is captured once')
            timestamps[index] = seconds * 1000 + micros / 1000
    check(set(timestamps) == {0, 1}, 'both actual timing packets are captured')
    return timestamps


def wall_step(directory, direction):
    path = directory / f'clock-{direction}.pcap'
    prefix = bytes.fromhex('02415854431002415854431188b6')
    events = [threading.Event(), threading.Event()]
    stepped = threading.Event()
    realtime = time.time_ns

    class MarkWriter:
        def __init__(self, output):
            self.output = output

        def write(self, data):
            written = self.output.write(data)
            if len(data) >= 34 and data[16:30] == prefix:
                index = struct.unpack_from('!I', data, 30)[0]
                if index < 2:
                    events[index].set()
            return written

        def close(self):
            self.output.close()

    def adjusted_wall_clock():
        return realtime() + (direction * 5000000000 if stepped.is_set() else 0)

    with mock.patch('tcp_fault_native.time.time_ns', side_effect=adjusted_wall_clock):
        monitor = Capture('capture-peer', path)
        monitor.output = MarkWriter(monitor.output)
        sender = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(3))
        sender.bind(('capture-send', 0))
        try:
            check(sender.send(prefix + struct.pack('!I', 0) + bytes(582)) == 600, 'first actual clock frame')
            check(events[0].wait(2), 'first actual frame is timestamped before wall adjustment')
            time.sleep(.03)
            stepped.set()
            check(sender.send(prefix + struct.pack('!I', 1) + bytes(582)) == 600, 'second actual clock frame')
            check(events[1].wait(2), 'second actual frame is timestamped after wall adjustment')
        finally:
            statistics = monitor.close()
            sender.close()
    check(statistics['dropped'] == 0, 'clock fixture loses no actual packets')
    timestamps = pair_times(path, prefix)
    elapsed = timestamps[1] - timestamps[0]
    check(20 <= elapsed <= 1000, f'actual capture interval survives a wall-clock step: elapsed_ms={elapsed}')


def queued_timestamps(directory):
    path = directory / 'queued.pcap'
    prefix = bytes.fromhex('02415854431002415854431188b7')
    entered, release = threading.Event(), threading.Event()
    original = Capture.collect

    def paused(monitor):
        entered.set()
        check(release.wait(2), 'bounded pause before actual queued capture reads')
        original(monitor)

    with mock.patch.object(Capture, 'collect', paused):
        monitor = Capture('capture-peer', path)
        sender = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(3))
        sender.bind(('capture-send', 0))
        try:
            check(entered.wait(2), 'actual collector pauses before reading queued packets')
            check(sender.send(prefix + struct.pack('!I', 0) + bytes(582)) == 600, 'first actual queued packet')
            time.sleep(.03)
            check(sender.send(prefix + struct.pack('!I', 1) + bytes(582)) == 600, 'second actual queued packet')
            time.sleep(.1)
        finally:
            release.set()
            statistics = monitor.close()
            sender.close()
    check(statistics['dropped'] == 0, 'paused collector loses no actual packets')
    timestamps = pair_times(path, prefix)
    elapsed = timestamps[1] - timestamps[0]
    check(20 <= elapsed <= 1000, f'kernel receipt interval survives delayed collection: elapsed_ms={elapsed}')


def isolated(parent):
    check(os.readlink('/proc/self/ns/net') != parent, 'capture burst fixture has a private network namespace')
    command('ip', 'link', 'add', 'capture-peer', 'type', 'veth', 'peer', 'name', 'capture-send')
    command('ip', 'link', 'set', 'capture-peer', 'up')
    command('ip', 'link', 'set', 'capture-send', 'up')
    with tempfile.TemporaryDirectory(prefix='axiom64-capture-burst-') as temporary:
        burst(Path(temporary), False)
        burst(Path(temporary), True)
        wall_step(Path(temporary), 1)
        wall_step(Path(temporary), -1)
        queued_timestamps(Path(temporary))


if __name__ == '__main__':
    if len(sys.argv) == 3 and sys.argv[1] == '--namespace':
        isolated(sys.argv[2])
    else:
        check(len(sys.argv) == 1, 'known capture burst fixture arguments')
        parent = os.readlink('/proc/self/ns/net')
        subprocess.run(['unshare', '--net', sys.executable, __file__, '--namespace', parent], check=True, timeout=30)
        check(os.readlink('/proc/self/ns/net') == parent, 'capture burst fixture preserves the host network namespace')
        print('TCP_FAULT_NATIVE_CAPTURE_PASS burst=1000 exact_packets=1000 drops_rejected=1 '
              'wall_steps=2 delayed_collection=1 kernel_timestamps=1 host_namespace_preserved=1')
