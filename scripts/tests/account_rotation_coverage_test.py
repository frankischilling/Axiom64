# SPDX-License-Identifier: GPL-3.0-or-later
"""Check whole-matrix coverage using captured target lists; these tests run no guests."""
from copy import deepcopy
import itertools
import json
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from account_rotation_storage_coverage import identity, validate_index, verify_matrix
from account_storage_shards import partition_targets


def indices():
    fixture = json.loads((Path(__file__).parent / 'fixtures/account-rotation-targets.json').read_text())
    result = []
    dimensions = (('build', 'runtime'), ('static', 'dynamic'), ('bios', 'uefi'),
                  ('modern', 'legacy'), ('basic', 'expiry'), ('writeback', 'writethrough'))
    for scope in itertools.product(*dimensions):
        phases = fixture['baselines'][scope[4]]['phases']
        targets = [dict(phase=phase, operation=operation, request=request)
                   for phase, value in phases.items()
                   for operation, request in [('write', value['last_write']), ('flush', value['flush'])]]
        for number in range(4):
            selection = partition_targets(targets, number, 4)
            count = len(selection['selected_targets'])
            sources = {'unit-coverage-only': '0' * 64}
            result.append(dict(format=1, retained_execution_verified=True, scope=list(scope),
                               guest_timeout_seconds=90, fault_modes=['eio', 'pause-before', 'pause-after'],
                               target_selection=selection,
                               cases=['-'.join((target['phase'], target['operation'], str(target['request']),
                                                scope[5], mode))
                                      for target in selection['selected_targets']
                                      for mode in ['eio', 'pause-before', 'pause-after']],
                               counts=dict(faults=count * 3, baselines=1, vm_kills=count * 2,
                                           device_errors=count, boots=count * 6 + 2),
                               source_inputs=sources, source_identity=identity(sources),
                               kernel_init_sha256={'kernel': fixture['kernel_sha256'], 'init': '1' * 64},
                               evidence_files={'unit-coverage-only': '2' * 64}))
    return result


class RotationCoverage(unittest.TestCase):
    def test_complete_grid_preserves_all_targets_and_fault_modes(self):
        report = verify_matrix(list(reversed(indices())))
        self.assertTrue(report['matrix_complete'])
        self.assertEqual((report['groups'], report['shards'], report['logical_targets']), (64, 256, 1280))
        self.assertEqual(report['counts'], dict(faults=3840, baselines=256, vm_kills=2560,
                                              device_errors=1280, boots=8192))

    def test_missing_and_duplicate_shards_fail(self):
        rows = indices()
        for changed in [[], rows[:-1], rows + rows[:1]]:
            with self.assertRaises(ValueError):
                verify_matrix(changed)

    def test_every_variant_dimension_is_required(self):
        rows = indices()
        for dimension in range(6):
            changed = [row for row in rows if row['scope'][dimension] == rows[0]['scope'][dimension]]
            with self.subTest(dimension=dimension), self.assertRaises(ValueError):
                verify_matrix(changed)

    def test_target_mode_deadline_and_execution_counts_cannot_be_omitted(self):
        for change in ('case', 'duplicate', 'mode', 'deadline', 'kill', 'evidence', 'unverified'):
            row = deepcopy(indices()[0])
            if change == 'case':
                row['cases'].pop()
            elif change == 'duplicate':
                row['cases'].append(row['cases'][0])
            elif change == 'mode':
                row['fault_modes'].pop()
            elif change == 'deadline':
                row['guest_timeout_seconds'] = 30
            elif change == 'kill':
                row['counts']['vm_kills'] -= 1
            elif change == 'evidence':
                row['evidence_files'] = {}
            else:
                row['retained_execution_verified'] = False
            with self.subTest(change=change), self.assertRaises(ValueError):
                validate_index(row)

    def test_source_and_product_changes_cannot_be_combined(self):
        for field in ('source_inputs', 'kernel_init_sha256'):
            rows = indices()
            rows[0][field]['changed-input'] = 'f' * 64
            if field == 'source_inputs':
                rows[0]['source_identity'] = identity(rows[0]['source_inputs'])
            with self.subTest(field=field), self.assertRaises(ValueError):
                verify_matrix(rows)

    def test_captured_phase_or_operation_cannot_disappear_from_all_shards(self):
        for omitted in ('phase', 'flush'):
            rows = indices()
            for row in rows:
                if row['scope'] != rows[0]['scope']:
                    continue
                all_targets = row['target_selection']['all_targets']
                all_targets = [target for target in all_targets if
                               (target['phase'] != 'marker' if omitted == 'phase' else
                                not (target['phase'] == 'marker' and target['operation'] == 'flush'))]
                selection = partition_targets(all_targets, row['target_selection']['shard_index'], 4)
                row['target_selection'] = selection
                count = len(selection['selected_targets'])
                row['cases'] = ['-'.join((target['phase'], target['operation'], str(target['request']),
                                          row['scope'][5], mode))
                                for target in selection['selected_targets']
                                for mode in ['eio', 'pause-before', 'pause-after']]
                row['counts'] = dict(faults=count * 3, baselines=1, vm_kills=count * 2,
                                     device_errors=count, boots=count * 6 + 2)
            message = ('missing required observed rotation phases' if omitted == 'phase' else
                       'missing write/flush target')
            with self.subTest(omitted=omitted), self.assertRaisesRegex(ValueError, message):
                verify_matrix(rows)


if __name__ == '__main__':
    unittest.main()
