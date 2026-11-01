# SPDX-License-Identifier: GPL-3.0-or-later
"""Replay real native cold rate-limit decisions without changing their inputs."""
import copy
import gzip
import hashlib
import json
from pathlib import Path
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import native_icmp_budget_test as reader


class CapturedBudget(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        directory = Path(__file__).with_name('fixtures') / 'native-icmp-budget-linux7'
        provenance = json.loads((directory / 'provenance.json').read_text())
        compressed = (directory / 'results.jsonl.gz').read_bytes()
        body = gzip.decompress(compressed)
        assert hashlib.sha256(compressed).hexdigest() == provenance['compressed_sha256']
        assert hashlib.sha256(body).hexdigest() == provenance['results_sha256']
        cls.original = [json.loads(line) for line in body.splitlines()]
        assert len(cls.original) == provenance['records'] == 770
        assert cls.original[-1]['passed'] is provenance['original_producer_passed'] is False

    def observations(self):
        rows = copy.deepcopy(self.original)
        # Repair only the outer success flag to reach the observation oracle.
        # The immutable original failed receipt has its own rejection check.
        rows[-1]['passed'] = True
        return rows

    def test_original_failed_receipt_stays_rejected(self):
        with self.assertRaises(ValueError):
            reader.audit(self.original)

    def test_corruption_campaign_requires_a_valid_baseline(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / 'faults.zip'
            with self.assertRaises(ValueError):
                reader.controls(self.original, path)
            self.assertFalse(path.exists())

    def test_both_cold_inputs_are_accounted_by_actual_kernel_counters(self):
        proof = reader.audit(self.observations())
        self.assertEqual(proof['profiles'], 768)
        self.assertEqual(proof['staggered_suppressed_profiles'], 1)
        self.assertEqual(proof['cold_aligned_suppressed_profiles'], 131)
        self.assertEqual(proof['primed_suppressed_profiles'], 0)
        self.assertEqual(proof['suppressed_inputs_by_mode'], [2, 131, 0])
        self.assertEqual(proof['actual_quotes'] + proof['global_suppressed_inputs'], 1792)

    def test_missing_cold_counter_does_not_explain_absent_quotes(self):
        rows = self.observations()
        row = next(row for row in rows[1:-1] if row['trial'] == 192 and row['mode'] == 0)
        row['rate_global'] = 1
        with self.assertRaisesRegex(ValueError, 'fully accounted'):
            reader.audit(rows)

    def test_staggered_gap_still_uses_completed_first_write(self):
        rows = self.observations()
        row = next(row for row in rows[1:-1] if row['trial'] == 192 and row['mode'] == 0)
        row['lanes'][1]['write_before_ns'] = row['lanes'][0]['write_after_ns'] + 999999
        with self.assertRaisesRegex(ValueError, 'original gap'):
            reader.audit(rows)

    def test_primed_pair_still_requires_both_original_quotes(self):
        rows = self.observations()
        row = next(row for row in rows[1:-1] if row['mode'] == 2)
        row['lanes'][1]['reply'] = ''
        row['lanes'][1]['read_ns'] = 0
        row['received'] = row['rate_global'] = 1
        with self.assertRaisesRegex(ValueError, 'primed.*both emit errors'):
            reader.audit(rows)

    def test_serialized_counter_faults_are_reopened_and_rejected(self):
        with tempfile.TemporaryDirectory() as temporary:
            proof = reader.controls(self.observations(), Path(temporary) / 'faults.zip')
        self.assertEqual(len(proof), 16)
        self.assertTrue({'boolean-rate-counter', 'negative-global-counter',
                         'excessive-global-counter', 'false-staggered-summary'} <= proof.keys())


if __name__ == '__main__':
    unittest.main()
