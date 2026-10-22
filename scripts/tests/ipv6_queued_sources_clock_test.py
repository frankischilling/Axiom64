# SPDX-License-Identifier: GPL-3.0-or-later
"""Exercise queued workload latency gates using real frames and controlled receipts."""
import hashlib
import json
from pathlib import Path
import shutil
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from ipv6_queued_sources_capture import verify_capture
from tcp_capture_clock import ClockEvidenceError, raw_records


class QueuedClock(unittest.TestCase):
    def evidence(self, directory, delayed):
        fixtures = Path(__file__).parent / 'fixtures'
        path = directory / 'lane0.pcap'
        shutil.copyfile(fixtures / 'ipv6-queued-sources-wire.pcap', path)
        log = directory / 'client.log'
        shutil.copyfile(fixtures / 'ipv6-queued-sources-serial.txt', log)
        rows = list(raw_records(path))
        cutoff = next(at for at, row in enumerate(rows) if row['frame'][12:14] == b'\x88\xb7')
        receipts = []
        for at, row in enumerate(rows):
            kernel = row['stamp'] * 1000
            received = kernel + 1000000 + (1500000000 if delayed and at >= cutoff else 0)
            receipts.append(dict(frame=at, sha256=hashlib.sha256(row['frame']).hexdigest(),
                kernel_realtime_ns=kernel, receipt_monotonic_ns=received,
                receipt_realtime_ns=received, receipt_monotonic_after_ns=received + 1000))
        encoded = ''.join(json.dumps(row) + '\n' for row in receipts).encode()
        (directory / 'lane0.clocks.jsonl').write_bytes(encoded)
        anchor = lambda value: dict(receipt_monotonic_ns=value, receipt_realtime_ns=value,
                                    receipt_monotonic_after_ns=value + 1000)
        statistics = dict(original_packet_times_not_rescaled=True, packets=len(rows), dropped=0,
            receipt_frames=len(rows), monotonic_receipts='lane0.clocks.jsonl',
            monotonic_receipts_sha256=hashlib.sha256(encoded).hexdigest(),
            clock_start=anchor(rows[0]['stamp'] * 1000 - 1000000),
            clock_end=anchor(receipts[-1]['receipt_monotonic_after_ns'] + 1000000))
        return verify_capture(path, 0, log, directory / 'controls.zip', native=True, statistics=statistics)

    def test_every_queued_workload_frame_is_bound(self):
        with tempfile.TemporaryDirectory(prefix='ipv6-queued-clock-positive-') as temporary:
            result = self.evidence(Path(temporary), False)
        metadata = json.loads((Path(__file__).parent / 'fixtures/ipv6-queued-sources-wire.json').read_text())
        self.assertEqual(result['native_clock']['timed_frames'], metadata['queued_workload_frames'])

    def test_queued_receipt_latency_does_not_hide_behind_earlier_lifetime_frames(self):
        with tempfile.TemporaryDirectory(prefix='ipv6-queued-clock-negative-') as temporary:
            with self.assertRaisesRegex(ClockEvidenceError, 'bounded independent native workload reader latency'):
                self.evidence(Path(temporary), True)


if __name__ == '__main__':
    unittest.main()
