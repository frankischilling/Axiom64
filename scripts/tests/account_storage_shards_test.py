# SPDX-License-Identifier: GPL-3.0-or-later
"""Require exact target coverage across all shards, including aliased requests."""
from copy import deepcopy
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from account_storage_shards import partition_targets, verify_complete_shards


class StorageShards(unittest.TestCase):
    def setUp(self):
        self.targets = [dict(phase=phase, operation=operation, request=request)
                        for phase, request in [('marker', 12), ('archive-complete', 12),
                                               ('archive-created', 4)]
                        for operation in ('write', 'flush')]

    def test_default_retains_original_order_and_aliases(self):
        selection = partition_targets(self.targets)
        self.assertEqual(selection['selected_targets'], self.targets)
        self.assertEqual(len(selection['selected_targets']), 6)
        self.assertEqual(verify_complete_shards([selection]),
                         dict(shards=1, logical_targets=6, exact_partition=True))

    def test_every_partition_is_exact_and_balanced(self):
        for count in range(1, 7):
            selections = [partition_targets(self.targets, index, count) for index in range(count)]
            proof = verify_complete_shards(list(reversed(selections)))
            self.assertEqual(proof['logical_targets'], 6)
            sizes = [len(value['selected_targets']) for value in selections]
            self.assertLessEqual(max(sizes) - min(sizes), 1)

    def test_assignment_ignores_observation_order_and_physical_request_numbers(self):
        selections = [partition_targets(self.targets, 0, 2)]
        different = [dict(value, request=value['request'] + 1000)
                     for value in reversed(self.targets)]
        selections.append(partition_targets(different, 1, 2))
        self.assertTrue(verify_complete_shards(selections)['exact_partition'])

    def test_selected_targets_do_not_change_the_full_baseline(self):
        selection = partition_targets(self.targets, 0, 2)
        before = deepcopy(selection['all_targets'])
        selection['selected_targets'][0]['request'] += 1
        self.assertEqual(selection['all_targets'], before)
        self.assertEqual(self.targets, before)

    def test_invalid_targets_and_shard_arguments_fail(self):
        for index, count in [(-1, 2), (2, 2), (0, 0), (0, 7), (True, 2), (0, 1.5)]:
            with self.subTest(index=index, count=count), self.assertRaises(ValueError):
                partition_targets(self.targets, index, count)
        for target in [dict(phase='marker', operation='write', request=0),
                       dict(phase='../marker', operation='write', request=1),
                       dict(phase='marker', operation='read', request=1),
                       dict(phase='marker', operation='write', request=True),
                       dict(phase='marker', operation='write', request=1, ignored=True)]:
            with self.subTest(target=target), self.assertRaises(ValueError):
                partition_targets([target])
        for targets in [[], [self.targets[0], self.targets[0]]]:
            with self.assertRaises(ValueError):
                partition_targets(targets)

    def test_missing_duplicate_and_altered_shards_fail(self):
        selections = [partition_targets(self.targets, index, 2) for index in range(2)]
        for values in [[], selections[:1], selections + selections[:1]]:
            with self.assertRaises(ValueError):
                verify_complete_shards(values)
        for field in ['all_targets', 'selected_targets']:
            changed = deepcopy(selections)
            changed[1][field].pop()
            with self.subTest(field=field), self.assertRaises(ValueError):
                verify_complete_shards(changed)
        changed = deepcopy(selections)
        changed[1]['shard_count'] = 3
        with self.assertRaises(ValueError):
            verify_complete_shards(changed)
        changed = deepcopy(selections)
        changed[1]['selected_targets'][0]['request'] += 1
        with self.assertRaises(ValueError):
            verify_complete_shards(changed)


if __name__ == '__main__':
    unittest.main()
