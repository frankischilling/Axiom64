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
from tcp_capture_clock import bind_native_clock, milliseconds, raw_records
from tcp_clock_mutations import candidate_auditor


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

    def test_reordered_protocol_candidate_keeps_each_packets_clock_receipt(self):
        fixture = json.loads((Path(__file__).with_name('fixtures') /
                              'tcp-recovery-source-port-clock.json').read_text())
        originals = [bytes.fromhex(row['frame']) for row in fixture['original'][2:]]
        base, offset = 1000000000000, 900000000000
        for repeated_frame, delays in ((False, (44337, 33992)), (True, (44337, 33992)),
                                       (False, (33992, 44337)), (True, (33992, 44337))):
            with self.subTest(repeated_frame=repeated_frame, delays=delays), tempfile.TemporaryDirectory(
                    prefix='axiom64-reordered-clock-') as temporary:
                root = Path(temporary)
                original, candidate = root / 'original', root / 'candidate'
                original.mkdir()
                candidate.mkdir()
                frames = [originals[0], originals[0] if repeated_frame else originals[1]]

                def capture(path, records):
                    data = bytearray(struct.pack('<IHHIIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1))
                    for stamp, frame in records:
                        data.extend(struct.pack('<IIII', stamp // 1000000, stamp % 1000000,
                                                len(frame), len(frame)) + frame)
                    path.write_bytes(data)

                clocks = []
                for index, (fraction, delay) in enumerate(zip((113, 227), delays)):
                    kernel = base + index * 100000 + fraction
                    before = kernel - offset + delay
                    clocks.append(dict(frame=index, sha256=hashlib.sha256(frames[index]).hexdigest(),
                        kernel_realtime_ns=kernel, receipt_monotonic_ns=before,
                        receipt_realtime_ns=before + offset, receipt_monotonic_after_ns=before + 100))
                capture(original / 'capture.pcap', [(clock['kernel_realtime_ns'] // 1000, frame)
                        for clock, frame in zip(clocks, frames)])
                encoded = ''.join(json.dumps(clock) + '\n' for clock in clocks).encode()
                (original / 'capture.clocks.jsonl').write_bytes(encoded)
                statistics = dict(packets=2, dropped=0, receipt_frames=2,
                    original_packet_times_not_rescaled=True, monotonic_receipts='capture.clocks.jsonl',
                    monotonic_receipts_sha256=hashlib.sha256(encoded).hexdigest())
                for label, at in (('clock_start', base - offset - 1000000),
                                  ('clock_end', base - offset + 1000000)):
                    statistics[label] = dict(receipt_monotonic_ns=at,
                        receipt_realtime_ns=at + offset, receipt_monotonic_after_ns=at + 100)

                def audit(folder, row):
                    path = folder / row['captures'][0]
                    packets = list(raw_records(path))
                    bind_native_clock(path, packets, row['capture_statistics'][0])
                    return packets

                row = dict(client_namespace='clock-regression', captures=['capture.pcap'],
                           capture_statistics=[statistics])
                audit(original, row)
                capture(candidate / 'capture.pcap', [(base // 1000 - 1, frames[1]),
                                                     (base // 1000, frames[0])])
                packet_bytes = (candidate / 'capture.pcap').read_bytes()
                checked = candidate_auditor(audit, original, row, reschedule_reordered=True)
                checked(candidate, row)
                changed = [json.loads(line) for line in
                           (candidate / 'capture.clocks.jsonl').read_bytes().splitlines()]
                self.assertEqual([clock['kernel_realtime_ns'] for clock in changed],
                                 [base - 1000 + 227, base + 113])
                self.assertEqual((candidate / 'capture.pcap').read_bytes(), packet_bytes)
                self.assertEqual((original / 'capture.clocks.jsonl').read_bytes(), encoded)
                # A pure timestamp corruption must still reach the native
                # receipt-order guard used by the pressure damage checker.
                strict = candidate_auditor(audit, original, row)
                capture(candidate / 'capture.pcap', [(base // 1000, frames[0]),
                                                     (base // 1000 - 200, frames[1])])
                with self.assertRaisesRegex(ValueError, 'ordered bounded native monotonic receipt pairs'):
                    strict(candidate, row)
                # Identical bytes cannot distinguish swapping records from
                # corrupting their timestamps; the default must reject both.
                capture(candidate / 'capture.pcap', [((base + 100000) // 1000, frames[0]),
                                                     (base // 1000 - 1, frames[1])])
                with self.assertRaisesRegex(ValueError, 'ordered bounded native monotonic receipt pairs'):
                    strict(candidate, row)



if __name__ == '__main__':
    unittest.main()
