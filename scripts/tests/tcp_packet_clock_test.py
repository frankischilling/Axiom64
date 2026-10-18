# SPDX-License-Identifier: GPL-3.0-or-later
"""Reader scheduling must not enlarge or compress independently captured packet gaps."""
import hashlib
import json
from pathlib import Path
import struct
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from tcp_capture_clock import bind_native_clock, milliseconds


class PacketClockRegression(unittest.TestCase):
    def bind(self, gap_ms, delays_ms, offset_step_ns=0, queued_step_ns=0):
        fixture = json.loads((Path(__file__).with_name('fixtures') /
                              'tcp-recovery-source-port-clock.json').read_text())
        frames = [bytes.fromhex(row['frame']) for row in fixture['original'][2:]]
        base, offset = 1000000000000, 900000000000
        with tempfile.TemporaryDirectory(prefix='axiom64-packet-clock-') as temporary:
            root = Path(temporary)
            path, clocks = root / 'capture.pcap', root / 'capture.clocks.jsonl'
            data = bytearray(struct.pack('<IHHIIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1))
            rows, receipts = [], []
            for index, frame in enumerate(frames):
                kernel = base + round(index * gap_ms * 1000000)
                read = kernel - offset + round(delays_ms[index] * 1000000)
                realtime = read + offset + index * offset_step_ns + queued_step_ns
                if index:
                    kernel += queued_step_ns
                data.extend(struct.pack('<IIII', kernel // 1000000000,
                    kernel // 1000 % 1000000, len(frame), len(frame)) + frame)
                rows.append(dict(stamp=kernel // 1000, frame=frame))
                receipts.append(dict(frame=index, sha256=hashlib.sha256(frame).hexdigest(),
                    kernel_realtime_ns=kernel, receipt_monotonic_ns=read,
                    receipt_realtime_ns=realtime, receipt_monotonic_after_ns=read + 100))
            path.write_bytes(data)
            clocks.write_text(''.join(json.dumps(row) + '\n' for row in receipts))
            statistics = dict(packets=2, dropped=0, receipt_frames=2,
                original_packet_times_not_rescaled=True, monotonic_receipts=clocks.name,
                monotonic_receipts_sha256=hashlib.sha256(clocks.read_bytes()).hexdigest())
            start = base - offset - 1000000
            end = max(row['receipt_monotonic_after_ns'] for row in receipts) + 1000000
            statistics['clock_start'] = dict(receipt_monotonic_ns=start,
                receipt_realtime_ns=start + offset, receipt_monotonic_after_ns=start + 100)
            statistics['clock_end'] = dict(receipt_monotonic_ns=end,
                receipt_realtime_ns=end + offset + queued_step_ns, receipt_monotonic_after_ns=end + 100)
            original = path.read_bytes(), clocks.read_bytes()
            bind_native_clock(path, rows, statistics)
            self.assertEqual((path.read_bytes(), clocks.read_bytes()), original)
            return milliseconds(rows[1]) - milliseconds(rows[0])

    def test_delayed_reader_cannot_satisfy_a_short_wire_barrier(self):
        gap = self.bind(10, (.2, 90.2))
        self.assertAlmostEqual(gap, 10)
        self.assertLess(gap, 95)

    def test_queued_reads_cannot_compress_a_complete_wire_wait(self):
        self.assertAlmostEqual(self.bind(110, (100, 1)), 110)

    def test_one_constant_translation_preserves_short_and_long_gaps(self):
        for gap, delays in ((.01, (.001, .002)), (100, (.1, .1)), (120000, (.1, 300))):
            with self.subTest(gap_ms=gap):
                self.assertAlmostEqual(self.bind(gap, delays), gap)

    def test_step_between_queued_packets_before_the_first_read_is_rejected(self):
        with self.assertRaisesRegex(ValueError, 'stable native.*offset'):
            self.bind(10, (200, 191), queued_step_ns=100000000)

    def test_inconsistent_realtime_to_monotonic_offset_is_rejected(self):
        with self.assertRaisesRegex(ValueError, 'stable native.*offset'):
            self.bind(100, (.1, .1), offset_step_ns=1000000)


if __name__ == '__main__':
    unittest.main()
