#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
# @file    scripts/local_validation.py
# @brief   Run a selected Axiom64 validation suite on a Linux host.
# @author  frankischilling
# @date    2026-11-20
#
# Dispatches native and guest test commands, including the administration and
# rotation cells, while preserving the failure status and original evidence.
#
# Copyright (C) 2026 frankischilling
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program. If not, see <https://www.gnu.org/licenses/>.

import argparse
from itertools import product
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import tomllib

from account_storage_ci import ROTATION_SHARDS, matrices


ROOT = Path(__file__).resolve().parents[1]
PLAN = Path('scripts/local_test_suites.toml')
ACCOUNT_SUITES = {
    'account-storage-clean': 'account_clean_matrix',
    'account-storage-fault': 'account_fault_matrix',
    'account-rotation-storage': 'account_rotation_matrix',
}
PAIRED_PREFIXES = ('protocol-', 'link-', 'normal-init-')


def read_toml(path):
    with (ROOT / path).open('rb') as stream:
        return tomllib.load(stream)


def plan_parts(index):
    names = index['parts']
    if len(set(names)) != len(names) or any(
            Path(name).name != name or not name.endswith('.toml') for name in names):
        raise ValueError('test plan parts must be distinct TOML filenames')
    return [PLAN.with_suffix('') / name for name in names]


def plan_sources():
    """Return the source paths needed to reproduce the local suite plan."""
    parts = plan_parts(read_toml(PLAN))
    return ('scripts/local_validation.py', PLAN.as_posix(),
            *(path.as_posix() for path in parts))


def load_plan():
    index = read_toml(PLAN)
    steps = [step for path in plan_parts(index) for step in read_toml(path)['step']]
    return dict(matrix=index['matrix'], step=steps)


def selections(plan):
    suites = {'prepare': ('prepare', {})}
    suites.update({suite: (suite, {}) for suite in plan['matrix']})
    for group, matrix in ACCOUNT_SUITES.items():
        axes = matrices()[matrix]
        for values in product(*axes.values()):
            name = '-'.join([group, *map(str, values)])
            env = {axis.upper(): str(value) for axis, value in zip(axes, values, strict=True)}
            if 'shard' in axes:
                env['SHARD_COUNT'] = str(ROTATION_SHARDS)
            suites[name] = (group, env)
    suites['account-storage-coverage'] = ('account-storage-coverage', {})
    return suites


def run_steps(steps, env):
    failed = 0
    for step in steps:
        if failed and not step.get('after_failure', False):
            continue
        print(step['name'], flush=True)
        status = subprocess.run(['bash', '--noprofile', '--norc', '-e', '-o', 'pipefail', '-c', step['run']],
                                cwd=ROOT, env=env).returncode
        if status:
            print(f"{step['name']} failed with status {status}", file=sys.stderr, flush=True)
            if not failed:
                failed = status if status > 0 else 128 - status
    return failed


def main():
    parser = argparse.ArgumentParser(description='Run Axiom64 checks on a Linux host.')
    parser.add_argument('suite', nargs='?', help='one suite name from --list')
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument('--list', action='store_true', help='list available suites')
    mode.add_argument('--plan', action='store_true', help='print the selected commands')
    args = parser.parse_args()
    plan = load_plan()
    suites = selections(plan)
    if args.list:
        if args.suite:
            parser.error('--list takes no suite name')
        print('\n'.join(suites))
        return 0
    if args.suite not in suites:
        parser.error('pick a suite from --list')

    group, parameters = suites[args.suite]
    steps = [step for step in plan['step'] if group in step['suites']]
    if not steps:
        parser.error(f'no commands defined for {args.suite}')
    if args.suite.startswith(PAIRED_PREFIXES):
        steps.insert(0, dict(name='Prepare isolated paired-test inputs',
                             run='mkdir "$RUNNER_TEMP/ci-inputs"\n'
                                 'RUNNER_TEMP="$RUNNER_TEMP/ci-inputs" bash scripts/ci/inputs.sh full'))
    if args.plan:
        for key, value in parameters.items():
            print(f'{key}={value}')
        for step in steps:
            print(f"\n{step['name']}\n{step['run'].rstrip()}")
        return 0
    if sys.platform != 'linux':
        parser.error('run this suite on Linux or WSL Ubuntu')

    (ROOT / 'build').mkdir(exist_ok=True)
    with tempfile.TemporaryDirectory(prefix='axiom64-validation-') as temporary:
        env = dict(os.environ, SUITE=args.suite, RUNNER_TEMP=temporary, **parameters)
        if any('AXIOM64_NATIVE_FIXTURES' in step['run'] for step in steps):
            fixtures = Path(tempfile.mkdtemp(prefix='axiom64-native-fixtures-', dir='/var/tmp'))
            fixtures.chmod(0o755)
            env['AXIOM64_NATIVE_FIXTURES'] = str(fixtures)
            print(f'Native filesystem fixtures: {fixtures}', flush=True)
        return run_steps(steps, env)


if __name__ == '__main__':
    sys.exit(main())
