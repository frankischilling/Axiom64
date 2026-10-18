# SPDX-License-Identifier: GPL-3.0-or-later
"""A real SYN mutation must retain its own clock after unrelated frames disappear."""
import hashlib
import json
from pathlib import Path
import struct
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from tcp_capture_clock import bind_native_clock, raw_records
from tcp_clock_mutations import candidate_verifier
from tcp_recovery_capture import decode


def capture(path, rows):
    with path.open('wb') as output:
        output.write(struct.pack('<IHHIIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1))
        for row in rows:
            frame = bytes.fromhex(row['frame'])
            output.write(struct.pack('<IIII', row['stamp'] // 1000000, row['stamp'] % 1000000,
                                     len(frame), len(frame)) + frame)


class MutationClockRegression(unittest.TestCase):
    def test_changed_syn_retains_its_clock_after_arp_is_omitted(self):
        fixture = json.loads((Path(__file__).with_name('fixtures') /
                              'tcp-recovery-source-port-clock.json').read_text())
        with tempfile.TemporaryDirectory(prefix='axiom64-clock-owner-') as temporary:
            root = Path(temporary)
            original, changed = root / 'original.pcap', root / 'candidate/candidate.pcap'
            changed.parent.mkdir()
            capture(original, fixture['original'])
            capture(changed, fixture['candidate'])
            receipts = root / 'original.clocks.jsonl'
            receipts.write_text(''.join(json.dumps(row) + '\n' for row in fixture['receipts']))
            statistics = dict(packets=4, dropped=0, receipt_frames=4, original_packet_times_not_rescaled=True,
                monotonic_receipts=receipts.name,
                monotonic_receipts_sha256=hashlib.sha256(receipts.read_bytes()).hexdigest())
            originals = {path: path.read_bytes() for path in (original, receipts)}

            def verify(path, lane, evidence, native=False, statistics=None):
                rows = list(raw_records(path))
                bind_native_clock(path, rows, statistics)
                expected = [row['receipt_monotonic_ns'] for row in fixture['receipts'][2:]]
                self.assertEqual([row['monotonic_ns'] for row in rows], expected)
                return decode(path, lane, statistics)

            checked = candidate_verifier(verify, original, statistics)
            with self.assertRaisesRegex(ValueError, 'exact bound recovery tuple'):
                checked(changed, 0, None, True)
            self.assertFalse(checked.timing_changed)
            self.assertEqual({path: path.read_bytes() for path in originals}, originals)


if __name__ == '__main__':
    unittest.main()
