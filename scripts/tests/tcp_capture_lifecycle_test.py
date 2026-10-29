# SPDX-License-Identifier: GPL-3.0-or-later
"""Keep the packet socket and its independent reader inside one capture interval."""
from collections import deque
import ctypes
from pathlib import Path
import socket
import struct
import sys
import tempfile
import threading
import time
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from tcp_fault_native import Capture


class PacketSocket:
    def __init__(self, protocol):
        self.enabled = bool(protocol)
        self.records = deque()
        self.condition = threading.Condition()
        self.packets = 0
        self.dropped = 0
        self.closed = False

    def deliver(self, frame):
        with self.condition:
            if self.enabled:
                self.packets += 1
                self.records.append((frame, time.time_ns()))
                self.condition.notify_all()

    def setsockopt(self, level, option, value):
        if (level, option) == (socket.SOL_SOCKET, 26):
            length, pointer = struct.unpack('@HP', value)
            instruction = struct.unpack('=HBBI', ctypes.string_at(pointer, 8))
            if length != 1 or instruction != (6, 0, 0, 0):
                raise AssertionError('capture stops new input with a complete reject filter')
            self.enabled = False

    def getsockopt(self, level, option, size=None):
        if (level, option) == (socket.SOL_SOCKET, socket.SO_RCVBUF):
            return 8 * 1024 * 1024
        if (level, option, size) != (263, 6, 8):
            raise AssertionError('actual packet statistics request')
        return struct.pack('II', self.packets, self.dropped)

    def bind(self, address):
        self.enabled = bool(address[1]) or self.enabled

    def settimeout(self, timeout):
        self.timeout = timeout

    def recvmsg(self, size, control):
        with self.condition:
            if not self.records:
                self.condition.wait(timeout=self.timeout)
            if not self.records:
                raise socket.timeout()
            frame, stamp = self.records.popleft()
        timestamp = struct.pack('=qq', stamp // 1000000000, stamp % 1000000000)
        return frame, [(socket.SOL_SOCKET, 64, timestamp)], 0, ('capture0', 3)

    def close(self):
        self.closed = True


class CaptureLifecycle(unittest.TestCase):
    def capture(self, directory, early=False):
        sockets = []

        def create(family, kind, protocol):
            self.assertEqual((family, kind), (socket.AF_PACKET, socket.SOCK_RAW))
            value = PacketSocket(protocol)
            sockets.append(value)
            if early:
                value.deliver(b'foreign interface before bind')
            return value

        with patch('tcp_fault_native.socket.socket', side_effect=create):
            capture = Capture('capture0', Path(directory) / 'lane0.pcap')
        return capture, sockets[0]

    def test_initialization_does_not_capture_foreign_interface_traffic(self):
        with tempfile.TemporaryDirectory() as directory:
            capture, source = self.capture(directory, early=True)
            statistics = capture.close()
            self.assertEqual((statistics['packets'], statistics['receipt_frames']), (0, 0))
            self.assertTrue(source.closed)

    def test_shutdown_stops_new_input_before_the_reader_finishes(self):
        with tempfile.TemporaryDirectory() as directory:
            capture, source = self.capture(directory)
            source.deliver(b'complete original captured frame')
            began = time.monotonic()
            while capture.frame_count != 1:
                self.assertIsNone(capture.error)
                self.assertLess(time.monotonic() - began, 1)
                time.sleep(.001)
            original_thread = capture.thread

            class JoinBoundary:
                def join(self, timeout):
                    original_thread.join(timeout=timeout)
                    source.deliver(b'late packet after the reader finishes')

                def is_alive(self):
                    return original_thread.is_alive()

            capture.thread = JoinBoundary()
            statistics = capture.close()
            self.assertEqual((statistics['packets'], statistics['receipt_frames']), (1, 1))
            self.assertEqual((Path(directory) / 'lane0.clocks.jsonl').read_text().count('\n'), 1)
            self.assertTrue(source.closed)

    def test_actual_receive_drops_still_reject_the_capture(self):
        with tempfile.TemporaryDirectory() as directory:
            capture, source = self.capture(directory)
            source.dropped = 1
            with self.assertRaisesRegex(ValueError, 'loses no actual frames'):
                capture.close()
            self.assertTrue(source.closed)

    def test_missing_clock_records_still_reject_the_capture(self):
        with tempfile.TemporaryDirectory() as directory:
            capture, source = self.capture(directory)
            source.packets = 1
            with self.assertRaisesRegex(ValueError, 'every captured frame has one independent clock record'):
                capture.close()
            self.assertTrue(source.closed)


if __name__ == '__main__':
    unittest.main()
