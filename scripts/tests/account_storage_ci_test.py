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
    def test_one_rotation_baseline_per_complete_profile(self):
        fixture = json.loads((Path(__file__).parent / 'fixtures/account-rotation-targets.json').read_text())
        matrix = matrices()['account_rotation_matrix']
        jobs = expand(matrix)
        profiles, actual, expected = set(), set(), set()
        dimensions = ('provider', 'linkage', 'firmware', 'transport', 'scenario', 'cache')
        for job in jobs:
            profile = tuple(job[name] for name in dimensions)
            profiles.add(profile)
            phases = fixture['baselines'][job['scenario']]['phases']
            targets = [dict(phase=phase, operation=operation, request=request)
                       for phase, value in phases.items()
                       for operation, request in [('write', value['last_write']), ('flush', value['flush'])]]
            selection = partition_targets(targets, job['shard'], len(matrix['shard']))
            for target in targets:
                for mode in ('eio', 'pause-before', 'pause-after'):
                    expected.add((*profile, target['phase'], target['operation'], mode))
            for target in selection['selected_targets']:
                for mode in ('eio', 'pause-before', 'pause-after'):
                    key = (*profile, target['phase'], target['operation'], mode)
                    self.assertNotIn(key, actual)
                    actual.add(key)
        self.assertEqual(actual, expected)
        self.assertEqual(len(actual), 3840)
        self.assertEqual(len(profiles), 64)
        self.assertEqual(len(jobs), len(profiles), 'repeat baseline/setup only when an actual profile needs it')

    def test_full_job_dimensions_and_matrix_limits(self):
        jobs = matrices()
        self.assertEqual({name: len(expand(value)) for name, value in jobs.items()},
                         dict(account_clean_matrix=16, account_fault_matrix=32,
                              account_rotation_matrix=64))
        for matrix in jobs.values():
            for name, values in [('provider', ['build', 'runtime']), ('linkage', ['static', 'dynamic']),
                                 ('firmware', ['bios', 'uefi']), ('transport', ['modern', 'legacy'])]:
                self.assertEqual(matrix[name], values)
            self.assertLessEqual(len(expand(matrix)), 256)
        self.assertEqual(jobs['account_fault_matrix']['cache'], ['writeback', 'writethrough'])
        self.assertEqual(jobs['account_rotation_matrix']['scenario'], ['basic', 'expiry'])
        self.assertEqual(jobs['account_rotation_matrix']['cache'], ['writeback', 'writethrough'])
        self.assertEqual(jobs['account_rotation_matrix']['shard'], [0])

    def test_every_captured_target_reaches_exactly_one_job_per_variant(self):
        fixture = json.loads((Path(__file__).parent / 'fixtures/account-rotation-targets.json').read_text())
        grouped = {}
        matrix = matrices()['account_rotation_matrix']
        for job in expand(matrix):
            key = tuple(job[name] for name in ('provider', 'linkage', 'firmware', 'transport', 'scenario', 'cache'))
            phases = fixture['baselines'][job['scenario']]['phases']
            targets = [dict(phase=phase, operation=operation, request=request)
                       for phase, value in phases.items()
                       for operation, request in [('write', value['last_write']), ('flush', value['flush'])]]
            grouped.setdefault(key, []).append(partition_targets(targets, job['shard'], len(matrix['shard'])))
        self.assertEqual(len(grouped), 64)
        target_count = sum(verify_complete_shards(value)['logical_targets'] for value in grouped.values())
        self.assertEqual(target_count * 3, 3840)
        self.assertTrue(all(value['selected_targets'] == value['all_targets']
                            for values in grouped.values() for value in values))

    def test_outputs_are_complete_single_line_json(self):
        lines = outputs()
        self.assertEqual(len(lines), 4)
        parsed = {}
        for line in lines:
            self.assertNotIn('\n', line)
            name, value = line.split('=', 1)
            self.assertNotIn(name, parsed)
            parsed[name] = json.loads(value)
        self.assertEqual(parsed.pop('rotation_shard_count'), 1)
        self.assertEqual(parsed, matrices())


if __name__ == '__main__':
    unittest.main()
