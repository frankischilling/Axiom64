# SPDX-License-Identifier: GPL-3.0-or-later
"""Keep expiry suppression spacing valid when the capture reader is delayed."""
from pathlib import Path
import hashlib
import json
import os
import queue
import socket
import struct
import sys
import tempfile
import time
import unittest
from unittest.mock import patch
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from ipv4_fragments import FragmentPeer, checksum


def start(peer, now):
    lane = peer.parent.lane
    body = bytearray([8, 0, 0, 0, ord('F'), ord('E'), lane, 0])
    body.extend((i * 17 + lane * 31) & 255 for i in range(8, 32))
    struct.pack_into('!H', body, 2, checksum(bytes(body)))
    header = bytearray(struct.pack('!BBHHHBBH4s4s', 0x45, 0, 52, 1, 0x4000, 64, 1, 0,
                                  bytes([10, 23, lane + 1, 2]), bytes([10, 23, lane + 1, 1])))
    struct.pack_into('!H', header, 10, checksum(bytes(header)))
    with patch('ipv4_fragments.time.monotonic', return_value=now):
        return peer.receive(bytes(header + body))


class ExpiryObservation(unittest.TestCase):
    def test_original_delayed_reader_cases(self):
        # Two original native captures read the first context late after a burst.
        # The sender's eight seconds then became less than eight between reads.
        for lag, next_tick in [(0.052332382, 8.006660172), (0.054717228, 8.017604959)]:
            with self.subTest(lag=lag):
                expiry = FragmentPeer(1, native=True).expiry
                start(expiry, 100)
                expiry.contexts[-1]['capture_monotonic'] = 100 + lag
                with patch('ipv4_fragments.time.monotonic', return_value=100 + next_tick):
                    self.assertEqual(expiry.tick(), [])
                with patch('ipv4_fragments.time.monotonic', return_value=108 + lag):
                    self.assertEqual(len(expiry.tick()), 1)
                self.assertEqual(len(expiry.contexts), 2)

    def test_every_suppression_context_uses_its_observation(self):
        expiry = FragmentPeer(0, native=True).expiry
        start(expiry, 100)
        for case in range(1, 4):
            previous = expiry.contexts[-1]
            previous['capture_monotonic'] = previous['monotonic'] + 0.05
            deadline = previous['capture_monotonic'] + 8
            with patch('ipv4_fragments.time.monotonic', return_value=deadline - 0.01):
                self.assertEqual(expiry.tick(), [])
            with patch('ipv4_fragments.time.monotonic', return_value=deadline):
                self.assertEqual(len(expiry.tick()), 1)
            self.assertEqual(len(expiry.contexts), case + 1)

    def test_quiet_window_starts_after_last_capture(self):
        expiry = FragmentPeer(0, native=True).expiry
        start(expiry, 100)
        for now in (108, 116, 124):
            with patch('ipv4_fragments.time.monotonic', return_value=now):
                expiry.tick()
        expiry.contexts[-1]['capture_monotonic'] = 124.05
        expiry.quote, expiry.duplicate = 160, 130
        with patch('ipv4_fragments.time.monotonic', return_value=193):
            self.assertEqual(expiry.tick(), [])
        with patch('ipv4_fragments.time.monotonic', return_value=193.05):
            self.assertEqual(len(expiry.tick()), 1)
        self.assertEqual(expiry.stage, 2)

    def test_duplicate_keeps_original_thirty_second_deadline(self):
        expiry = FragmentPeer(0, native=True).expiry
        start(expiry, 100)
        expiry.contexts[-1]['capture_monotonic'] = 100.05
        with patch('ipv4_fragments.time.monotonic', return_value=130):
            packets = expiry.tick()
        self.assertIn((expiry.first, False), packets)
        self.assertEqual(expiry.duplicate, 130)

    def test_guest_keeps_original_two_second_spacing(self):
        expiry = FragmentPeer(0).expiry
        start(expiry, 100)
        with patch('ipv4_fragments.time.monotonic', return_value=101.99):
            self.assertEqual(expiry.tick(), [])
        with patch('ipv4_fragments.time.monotonic', return_value=102):
            self.assertEqual(len(expiry.tick()), 1)
        self.assertEqual(expiry.context_gap_seconds, 2)


class CaptureSocket:
    """Supply complete timestamped packets to the production collector thread."""
    def __init__(self):
        self.frames = queue.Queue()
        self.received = 0

    def setsockopt(self, *args):
        pass

    def settimeout(self, *args):
        pass

    def bind(self, *args):
        pass

    def close(self):
        pass

    def getsockopt(self, level, option, *args):
        return 8388608 if option == socket.SO_RCVBUF else struct.pack('II', self.received, 0)

    def recvmsg(self, *args):
        try:
            frame = self.frames.get(timeout=.01)
        except queue.Empty:
            raise socket.timeout()
        self.received += 1
        seconds, nanos = divmod(time.time_ns(), 1000000000)
        return frame, [(socket.SOL_SOCKET, 64, struct.pack('=qq', seconds, nanos))], 0, None

    def send(self, frame):
        self.frames.put(frame)
        return len(frame)


@unittest.skipIf(os.name == 'nt', 'the native collector imports Linux namespace support')
class InjectionObservation(unittest.TestCase):
    def test_production_reader_and_native_sender_bind_the_exact_context(self):
        from ipv4_fragment_native import send_packets
        from tcp_fault_native import Capture
        source = CaptureSocket()
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / 'lane0.pcap'
            with patch('tcp_fault_native.socket.socket', return_value=source):
                capture = Capture('test0', path)
            try:
                peers = [FragmentPeer(0, native=True), FragmentPeer(1, native=True)]
                packets = start(peers[0].expiry, time.monotonic())
                source.send(b'unrelated captured frame')
                def write(descriptor, frame):
                    self.assertEqual(descriptor, 73)
                    return source.send(frame)
                with patch('ipv4_fragment_native.os.write', side_effect=write):
                    send_packets([73, 74], [capture, None], peers, 0, packets)
                    observed = peers[0].expiry.contexts[0]['capture_monotonic']
                    # An identical duplicate must not replace the original receipt.
                    send_packets([73, 74], [capture, None], peers, 0, packets[:1])
                self.assertEqual(peers[0].expiry.contexts[0]['capture_monotonic'], observed)
                self.assertNotIn('capture_monotonic', peers[1].expiry.contexts[0]
                                 if peers[1].expiry.contexts else {})
            finally:
                statistics = capture.close()
            rows = [json.loads(line) for line in path.with_suffix('.clocks.jsonl').read_text().splitlines()]
            frame = (bytes([0x52, 0x54, 0, 0x12, 0x34, 0x10]) +
                     bytes([2, 0x41, 0x58, 0x49, 0x50, 0]) + b'\x08\0' + packets[0][0]).ljust(60, b'\0')
            matching = [row for row in rows if row['sha256'] == hashlib.sha256(frame).hexdigest()]
            self.assertEqual(len(matching), 2)
            self.assertEqual(observed, matching[0]['receipt_monotonic_ns'] / 1e9)
            self.assertEqual(statistics['dropped'], 0)
            self.assertEqual(statistics['packets'], 4)

    def test_missing_or_short_injection_fails_and_releases_the_waiter(self):
        from tcp_fault_native import Capture
        source = CaptureSocket()
        with tempfile.TemporaryDirectory() as temporary:
            with patch('tcp_fault_native.socket.socket', return_value=source):
                capture = Capture('test0', Path(temporary) / 'lane0.pcap')
            try:
                with self.assertRaisesRegex(Exception, 'observes the injected frame'):
                    capture.observe_injection(b'expected', lambda frame: len(frame), timeout=.01)
                self.assertIsNone(capture.injection)
                with self.assertRaisesRegex(Exception, 'complete independently observed injection'):
                    capture.observe_injection(b'expected', lambda frame: len(frame) - 1)
                self.assertIsNone(capture.injection)
                self.assertGreater(capture.observe_injection(b'expected', source.send), 0)
            finally:
                self.assertEqual(capture.close()['dropped'], 0)


if __name__ == '__main__':
    unittest.main()
