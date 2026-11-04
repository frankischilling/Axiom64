#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Keep congestion observation gates behind complete backend ACK writes."""
from pathlib import Path
import socket
import sys
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from tcp_congestion.fast_peer import Peer as FastPeer
from tcp_congestion.window_peer import Peer as WindowPeer
import tcp_fault_test


class Clock:
    def __init__(self):
        self.now = 20.0

    def monotonic(self):
        return self.now

    def monotonic_ns(self):
        return int(self.now * 1_000_000_000)


class CongestionGateTest(unittest.TestCase):
    def setUp(self):
        self.clock = Clock()
        for name in ('monotonic', 'monotonic_ns'):
            guard = patch('time.' + name, getattr(self.clock, name))
            guard.start()
            self.addCleanup(guard.stop)

    def opening(self, peer_type):
        peer = peer_type(0)
        flow = peer.flows[0]
        flow.origin, flow.prefix, flow.highest = 100, 4096, 4096
        flow.stage_at = self.clock.now - .101
        original = flow.snapshot

        def delayed_snapshot():
            original()
            self.clock.now += .002

        with patch.object(flow, 'snapshot', delayed_snapshot):
            flow.pump()
        self.assertEqual(flow.stage, 'growth')
        self.assertEqual(len(peer.frames), 1)
        return peer, flow

    def test_duplicate_ack_cannot_start_before_backend_write(self):
        peer, flow = self.opening(FastPeer)
        # Serialization and a blocked backend consume the old timer's budget.
        # The next ACK must still wait for the first ACK to leave the backend.
        self.clock.now += .101
        peer.tick()
        self.assertEqual(len(peer.frames), 1, 'duplicate ACK escaped while the preceding ACK remained queued')
        self.assertEqual(flow.stage, 'growth')

    def test_window_gate_cannot_start_before_backend_write(self):
        peer, flow = self.opening(WindowPeer)
        self.clock.now += .101
        peer.tick()
        self.assertEqual(flow.stage, 'growth', 'RTO observation started before its advancing ACK was written')

    def channels(self, kind):
        writer, reader = socket.socketpair(type=kind)
        self.addCleanup(writer.close)
        self.addCleanup(reader.close)
        reader.settimeout(1)
        return writer, reader

    def test_complete_raw_write_starts_the_full_duplicate_ack_wait(self):
        peer, flow = self.opening(FastPeer)
        writer, reader = self.channels(socket.SOCK_DGRAM)
        queued = peer.outgoing[0]
        self.clock.now += .25
        tcp_fault_test.flush_peer(peer, writer, raw=True)
        self.assertEqual(reader.recv(65536), queued)
        started = flow.stage_at
        self.assertFalse(flow.awaiting_ack_write)
        self.assertEqual(peer.frames[0]['backend_write_completed_monotonic_ns'], self.clock.monotonic_ns())
        self.clock.now = started + .099999
        peer.tick()
        self.assertEqual(len(peer.frames), 1)
        self.clock.now = started + .100001
        peer.tick()
        self.assertEqual(len(peer.frames), 4)
        self.assertGreaterEqual(peer.frames[1]['ms'] - peer.frames[0]['ms'], 100)

    def test_blocked_and_partial_stream_writes_keep_the_gate_closed(self):
        peer, flow = self.opening(FastPeer)
        writer, reader = self.channels(socket.SOCK_STREAM)

        class Partial:
            blocked = True

            def send(self, data):
                if self.blocked:
                    raise BlockingIOError
                return writer.send(data[:7])

        channel = Partial()
        tcp_fault_test.flush_peer(peer, channel)
        self.assertTrue(flow.awaiting_ack_write)
        channel.blocked = False
        received = bytearray()
        while peer.output:
            self.clock.now += .101
            peer.tick()
            self.assertEqual(len(peer.frames), 1)
            tcp_fault_test.flush_peer(peer, channel)
            received.extend(reader.recv(65536))
            if peer.output:
                self.assertIsNone(flow.stage_at)
        self.assertEqual(int.from_bytes(received[:4], 'big'), len(received) - 4)
        self.assertFalse(flow.awaiting_ack_write)
        self.assertEqual(flow.stage_at, self.clock.monotonic_ns() / 1_000_000_000)

    def test_failed_raw_write_cannot_start_a_gate(self):
        peer, flow = self.opening(FastPeer)

        class Incomplete:
            def send(self, data):
                return len(data) - 1

        with self.assertRaisesRegex(ValueError, 'complete independent Ethernet packet send'):
            tcp_fault_test.flush_peer(peer, Incomplete(), raw=True)
        self.assertTrue(flow.awaiting_ack_write)
        self.assertIsNone(flow.stage_at)

    def test_arriving_data_cannot_start_a_pending_ack_timer(self):
        peer, flow = self.opening(FastPeer)
        data = flow.expected[4096:4144]
        flow.input(dict(flags=16, data=data, seq=flow.origin + 4096, ack=flow.peer_origin), {})
        self.assertIsNone(flow.stage_at)
        self.assertTrue(flow.awaiting_ack_write)

    def test_every_fast_stage_retains_its_original_wait_after_the_write(self):
        for stage, minimum in (('growth', .1), ('fast', .05), ('extra', .05),
                               ('recovery', .1), ('receiver', .35)):
            with self.subTest(stage=stage):
                peer = FastPeer(0)
                flow = peer.flows[0]
                flow.origin, flow.prefix, flow.highest, flow.acked = 100, 4096, 4096, 1460
                flow.fast_retries = [dict(offset=1460, size=1460)]
                flow.begin_observation(stage)
                flow.send()
                writer, reader = self.channels(socket.SOCK_DGRAM)
                self.clock.now += .25
                tcp_fault_test.flush_peer(peer, writer, raw=True)
                reader.recv(65536)
                started = flow.stage_at
                self.clock.now = started + minimum - .000001
                peer.tick()
                self.assertEqual(flow.stage, stage)
                self.clock.now = started + minimum + .000001
                peer.tick()
                self.assertNotEqual(flow.stage, stage)
                self.assertTrue(flow.awaiting_ack_write)

    def test_window_recovery_and_receiver_keep_their_full_waits(self):
        for stage, minimum in (('recovery', .1), ('receiver', .35)):
            with self.subTest(stage=stage):
                peer = WindowPeer(0)
                flow = peer.flows[0]
                flow.origin, flow.prefix, flow.highest, flow.acked = 100, 4096, 4096, 1460
                flow.begin_observation(stage)
                flow.send()
                writer, reader = self.channels(socket.SOCK_DGRAM)
                tcp_fault_test.flush_peer(peer, writer, raw=True)
                reader.recv(65536)
                started = flow.stage_at
                self.clock.now = started + minimum - .000001
                peer.tick()
                self.assertEqual(flow.stage, stage)
                self.clock.now = started + minimum + .000001
                peer.tick()
                self.assertNotEqual(flow.stage, stage)


if __name__ == '__main__':
    unittest.main()
