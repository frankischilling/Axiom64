# SPDX-License-Identifier: GPL-3.0-or-later
"""Require full CI job dimensions and an exact partition of captured rotation targets."""
import itertools
import json
import os
import tempfile
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from account_storage_ci import matrices, outputs
from account_storage_shards import partition_targets, verify_complete_shards
import local_validation


def expand(matrix):
    return [dict(zip(matrix, values)) for values in itertools.product(*matrix.values())]


def rotation_profiles(matrix):
    for job in expand(matrix):
        for scenario in ('basic', 'expiry'):
            yield dict(job, scenario=scenario)


def rotation_steps():
    plan = local_validation.load_plan()
    return [step for step in plan['step'] if 'account-rotation-storage' in step['suites']]


class StorageCI(unittest.TestCase):
    def test_one_rotation_baseline_per_complete_profile(self):
        fixture = json.loads((Path(__file__).parent / 'fixtures/account-rotation-targets.json').read_text())
        matrix = matrices()['account_rotation_matrix']
        jobs = expand(matrix)
        profiles, actual, expected = set(), set(), set()
        dimensions = ('provider', 'linkage', 'firmware', 'transport', 'scenario', 'cache')
        for job in rotation_profiles(matrix):
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
        self.assertEqual(len(jobs) * 2, len(profiles), 'two complete scenarios share each job setup')

    def test_full_job_dimensions_and_matrix_limits(self):
        jobs = matrices()
        self.assertEqual({name: len(expand(value)) for name, value in jobs.items()},
                         dict(account_clean_matrix=16, account_fault_matrix=32,
                              account_rotation_matrix=32))
        for matrix in jobs.values():
            for name, values in [('provider', ['build', 'runtime']), ('linkage', ['static', 'dynamic']),
                                 ('firmware', ['bios', 'uefi']), ('transport', ['modern', 'legacy'])]:
                self.assertEqual(matrix[name], values)
            self.assertLessEqual(len(expand(matrix)), 256)
        self.assertEqual(jobs['account_fault_matrix']['cache'], ['writeback', 'writethrough'])
        self.assertNotIn('scenario', jobs['account_rotation_matrix'])
        self.assertEqual(jobs['account_rotation_matrix']['cache'], ['writeback', 'writethrough'])
        self.assertEqual(jobs['account_rotation_matrix']['shard'], [0])

    def test_every_captured_target_reaches_exactly_one_job_per_variant(self):
        fixture = json.loads((Path(__file__).parent / 'fixtures/account-rotation-targets.json').read_text())
        grouped = {}
        matrix = matrices()['account_rotation_matrix']
        for job in rotation_profiles(matrix):
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

    def run_rotation_steps(self, jobs, failures=()):
        steps = rotation_steps()
        self.assertEqual(len(steps), 3)
        self.assertFalse(steps[0].get('after_failure', False))
        self.assertTrue(steps[1]['after_failure'])
        self.assertTrue(steps[2]['after_failure'])
        with tempfile.TemporaryDirectory(prefix='rotation-validation-') as temporary:
            directory = Path(temporary)
            bindir = directory / 'bin'
            bindir.mkdir()
            stub = bindir / 'sudo'
            stub.write_text('#!' + sys.executable + '\n' +
                            'import json, os, sys\n' +
                            'args = sys.argv[1:]\n' +
                            'with open(os.environ["CI_CALL_LOG"], "a") as stream:\n' +
                            '    stream.write(json.dumps(args) + "\\n")\n' +
                            'if args[2].endswith("account_logbook_rotation_ext2.py"):\n' +
                            '    scenario = args[args.index("--scenario") + 1]\n' +
                            '    if scenario in json.loads(os.environ["CI_FAIL_SCENARIOS"]): sys.exit(17)\n')
            stub.chmod(0o755)
            log = directory / 'calls.jsonl'
            results = []
            for job in jobs:
                environment = dict(os.environ, **{name.upper():str(value) for name,value in job.items()},
                                   SHARD_COUNT='1', CI_CALL_LOG=str(log),
                                   CI_FAIL_SCENARIOS=json.dumps(failures),
                                   PATH=str(bindir)+os.pathsep+os.environ['PATH'])
                with patch.object(local_validation, 'ROOT', directory):
                    status = local_validation.run_steps(steps, environment)
                self.assertEqual(status, 17 if failures else 0)
                results.append(status)
            calls = [json.loads(line) for line in log.read_text().splitlines()]
        return results, calls

    def test_actual_rotation_steps_dispatch_every_profile_once(self):
        jobs = expand(matrices()['account_rotation_matrix'])
        statuses, calls = self.run_rotation_steps(jobs)
        self.assertEqual(statuses, [0] * 32)
        producers = [row for row in calls if row[2].endswith('account_logbook_rotation_ext2.py')]
        collectors = [row for row in calls if row[2].endswith('account_rotation_storage_coverage.py')]
        self.assertEqual(len(producers), 64)
        self.assertEqual(len(collectors), 64)
        dimensions = ('provider', 'linkage', 'firmware', 'transport', 'scenario', 'cache-model')
        actual, directories = set(), set()
        for row in producers:
            profile = tuple(row[row.index('--'+name)+1] for name in dimensions)
            self.assertNotIn(profile, actual)
            actual.add(profile)
            self.assertIn('--journal', row)
            offset = row.index('--fault-mode')
            self.assertEqual(row[offset+1:offset+4], ['eio', 'pause-before', 'pause-after'])
            self.assertEqual(row[row.index('--shard-count')+1], '1')
            self.assertEqual(row[row.index('--shard-index')+1], '0')
            directory = row[row.index('--directory')+1]
            self.assertNotIn(directory, directories)
            directories.add(directory)
        expected = set(itertools.product(['build', 'runtime'], ['static', 'dynamic'], ['bios', 'uefi'],
                                        ['modern', 'legacy'], ['basic', 'expiry'], ['writeback', 'writethrough']))
        self.assertEqual(actual, expected)
        self.assertEqual({row[row.index('--directory')+1] for row in collectors}, directories)
        self.assertEqual({row[row.index('--output')+1] for row in collectors},
                         {value+'/coverage-index.json' for value in directories})

    def test_failed_scenario_does_not_skip_companion_or_collect_failed_input(self):
        job = expand(matrices()['account_rotation_matrix'])[0]
        for failures in (['basic'], ['expiry'], ['basic', 'expiry']):
            with self.subTest(failures=failures):
                statuses, calls = self.run_rotation_steps([job], failures)
                self.assertTrue(any(statuses), 'either failed step must keep the job failed')
                producers = [row for row in calls if row[2].endswith('account_logbook_rotation_ext2.py')]
                self.assertEqual([row[row.index('--scenario')+1] for row in producers], ['basic', 'expiry'])
                collectors = [row for row in calls if row[2].endswith('account_rotation_storage_coverage.py')]
                self.assertEqual(len(collectors), 2-len(failures))
                self.assertTrue(all(not any('-'+scenario+'-' in row[row.index('--directory')+1]
                                            for scenario in failures) for row in collectors))

    def test_both_retained_indices_keep_their_scenario_directories(self):
        job = expand(matrices()['account_rotation_matrix'])[0]
        _, calls = self.run_rotation_steps([job])
        retained = [row[row.index('--output') + 1] for row in calls
                    if row[2].endswith('account_rotation_storage_coverage.py')]
        self.assertEqual(os.path.commonpath(retained), 'build')
        members = {Path(path).relative_to('build').as_posix() for path in retained}
        self.assertEqual(len(members), 2)
        self.assertTrue(all(Path(path).name == 'coverage-index.json' for path in retained))
        self.assertTrue(any('-basic-' in path for path in members))
        self.assertTrue(any('-expiry-' in path for path in members))

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
