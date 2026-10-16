# SPDX-License-Identifier: GPL-3.0-or-later
"""Require full CI job dimensions and an exact partition of captured rotation targets."""
import itertools
import json
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from account_storage_ci import matrices, outputs
from account_storage_shards import partition_targets, verify_complete_shards


def expand(matrix):
    return [dict(zip(matrix, values)) for values in itertools.product(*matrix.values())]


class StorageCI(unittest.TestCase):
    def test_full_job_dimensions_and_matrix_limits(self):
        jobs = matrices()
        self.assertEqual({name: len(expand(value)) for name, value in jobs.items()},
                         dict(account_clean_matrix=16, account_fault_matrix=32,
                              account_rotation_matrix=256))
        for matrix in jobs.values():
            for name, values in [('provider', ['build', 'runtime']), ('linkage', ['static', 'dynamic']),
                                 ('firmware', ['bios', 'uefi']), ('transport', ['modern', 'legacy'])]:
                self.assertEqual(matrix[name], values)
            self.assertLessEqual(len(expand(matrix)), 256)
        self.assertEqual(jobs['account_fault_matrix']['cache'], ['writeback', 'writethrough'])
        self.assertEqual(jobs['account_rotation_matrix']['scenario'], ['basic', 'expiry'])
        self.assertEqual(jobs['account_rotation_matrix']['cache'], ['writeback', 'writethrough'])
        self.assertEqual(jobs['account_rotation_matrix']['shard'], [0, 1, 2, 3])

    def test_every_captured_target_reaches_exactly_one_job_per_variant(self):
        fixture = json.loads((Path(__file__).parent / 'fixtures/account-rotation-targets.json').read_text())
        grouped = {}
        for job in expand(matrices()['account_rotation_matrix']):
            key = tuple(job[name] for name in ('provider', 'linkage', 'firmware', 'transport', 'scenario', 'cache'))
            phases = fixture['baselines'][job['scenario']]['phases']
            targets = [dict(phase=phase, operation=operation, request=request)
                       for phase, value in phases.items()
                       for operation, request in [('write', value['last_write']), ('flush', value['flush'])]]
            grouped.setdefault(key, []).append(partition_targets(targets, job['shard'], 4))
        self.assertEqual(len(grouped), 64)
        target_count = sum(verify_complete_shards(value)['logical_targets'] for value in grouped.values())
        self.assertEqual(target_count * 3, 3840)
        self.assertLessEqual(max(len(value['selected_targets']) for values in grouped.values()
                                 for value in values), 6)

    def test_outputs_are_complete_single_line_json(self):
        lines = outputs()
        self.assertEqual(len(lines), 4)
        parsed = {}
        for line in lines:
            self.assertNotIn('\n', line)
            name, value = line.split('=', 1)
            self.assertNotIn(name, parsed)
            parsed[name] = json.loads(value)
        self.assertEqual(parsed.pop('rotation_shard_count'), 4)
        self.assertEqual(parsed, matrices())


if __name__ == '__main__':
    unittest.main()
