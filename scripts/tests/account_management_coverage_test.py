# SPDX-License-Identifier: GPL-3.0-or-later
"""Require every administration/control variant and all physically distinct faults."""
from copy import deepcopy
import itertools
import json
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from account_management_storage_coverage import identity, validate_index, verify_matrix


def indices():
    fixture = json.loads((Path(__file__).parent / 'fixtures/account-management-targets.json').read_text())
    result = []
    for scope in itertools.product(('build', 'runtime'), ('static', 'dynamic'),
                                   ('bios', 'uefi'), ('modern', 'legacy')):
        sources = {'unit-coverage-only': '0' * 64}
        base = dict(format=1, retained_execution_verified=True, scope=list(scope),
                    guest_timeout_seconds=120, source_inputs=sources, source_identity=identity(sources),
                    kernel_init_sha256={'kernel': '1' * 64, 'init': '2' * 64},
                    evidence_files={'unit-coverage-only': '3' * 64})
        result.append(dict(base, kind='clean-storage',
                           cases=['clean/prepare', 'clean/exercise', 'clean/concurrent', 'clean/verify',
                                  'storage/prepare', 'storage/readonly', 'storage/full'],
                           fresh_boot_equality=True, readonly_bytes_unchanged=True,
                           counts=dict(boots=7, faults=0, vm_kills=0, device_errors=0)))
        for cache in ('writeback', 'writethrough'):
            targets = {}
            for label, value in fixture['baselines'][cache]['phases'].items():
                targets.setdefault((value['operation'], value['request']), []).append(label)
            count = len(targets)
            result.append(dict(base, kind='fault', cache=cache,
                               fault_modes=['eio', 'pause-before', 'pause-after'],
                               physical_targets=[dict(operation=operation, request=request, labels=labels)
                                                 for (operation, request), labels in targets.items()],
                               cases=[dict(operation=operation, request=request, mode=mode)
                                      for operation, request in targets
                                      for mode in ('eio', 'pause-before', 'pause-after')],
                               counts=dict(boots=1 + (count * 3 + 1) * 2, faults=count * 3,
                                           vm_kills=count * 2, device_errors=count)))
    return result


class ManagementCoverage(unittest.TestCase):
    def test_complete_matrix_and_actual_aliases(self):
        rows = indices()
        report = verify_matrix(list(reversed(rows)))
        self.assertTrue(report['matrix_complete'])
        self.assertEqual((report['clean_storage_variants'], report['fault_variants']), (16, 32))
        self.assertEqual(report['counts'], dict(boots=1840, faults=816, vm_kills=544, device_errors=272))
        self.assertEqual(len(rows[1]['physical_targets']), 8)
        self.assertEqual(len(rows[2]['physical_targets']), 9)

    def test_missing_and_duplicate_variants_fail(self):
        rows = indices()
        for changed in [[], rows[:-1], rows[1:], rows + rows[:1]]:
            with self.assertRaises(ValueError):
                verify_matrix(changed)
        for dimension in range(4):
            changed = [row for row in rows if row['scope'][dimension] == rows[0]['scope'][dimension]]
            with self.subTest(dimension=dimension), self.assertRaises(ValueError):
                verify_matrix(changed)

    def test_clean_concurrency_reboot_and_both_storage_controls_are_required(self):
        for case in range(7):
            row = deepcopy(indices()[0])
            row['cases'].pop(case)
            with self.subTest(case=case), self.assertRaises(ValueError):
                validate_index(row)
        for field in ('fresh_boot_equality', 'readonly_bytes_unchanged'):
            row = deepcopy(indices()[0])
            row[field] = False
            with self.subTest(field=field), self.assertRaises(ValueError):
                validate_index(row)

    def test_each_fault_mode_and_alias_label_is_required(self):
        for change in ('case', 'duplicate', 'mode', 'phase', 'alias', 'request'):
            row = deepcopy(indices()[1])
            if change == 'case':
                row['cases'].pop()
            elif change == 'duplicate':
                row['cases'].append(row['cases'][0])
            elif change == 'mode':
                row['fault_modes'].pop()
            elif change == 'phase':
                row['physical_targets'][0]['labels'] = []
            elif change == 'alias':
                target = next(value for value in row['physical_targets'] if len(value['labels']) == 2)
                target['labels'].pop()
            else:
                row['physical_targets'][0]['request'] = True
            with self.subTest(change=change), self.assertRaises(ValueError):
                validate_index(row)

    def test_deadlines_and_actual_counts_are_required(self):
        for field in ('guest_timeout_seconds', 'counts', 'evidence_files'):
            row = deepcopy(indices()[1])
            if field == 'guest_timeout_seconds':
                row[field] = 30
            elif field == 'counts':
                row[field]['vm_kills'] -= 1
            else:
                row[field] = {}
            with self.subTest(field=field), self.assertRaises(ValueError):
                validate_index(row)

    def test_changed_source_or_products_cannot_be_combined(self):
        for field in ('source_inputs', 'kernel_init_sha256'):
            rows = deepcopy(indices())
            rows[0][field]['changed-input'] = 'f' * 64
            if field == 'source_inputs':
                rows[0]['source_identity'] = identity(rows[0]['source_inputs'])
            with self.subTest(field=field), self.assertRaises(ValueError):
                verify_matrix(rows)


if __name__ == '__main__':
    unittest.main()
