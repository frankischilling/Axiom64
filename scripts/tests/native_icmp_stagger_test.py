#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Retain real syscall-writer regressions for missed staggered deadlines."""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[2]


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--directory', type=Path, required=True)
    args = parser.parse_args()
    out = args.directory.resolve()
    out.mkdir(parents=True, exist_ok=False)
    sources = ('scripts/tests/native_icmp_budget.c',
               'scripts/tests/native_icmp_stagger_regression.c',
               'scripts/tests/native_icmp_stagger_test.py')
    bindings = {name: digest(ROOT / name) for name in sources}
    saved = out / 'sources'
    saved.mkdir()
    for name in sources:
        (saved / Path(name).name).write_bytes((ROOT / name).read_bytes())
    binary = out / 'client'
    command = ['cc', '-O2', '-g', '-std=c11', '-Wall', '-Wextra', '-Werror', '-pthread',
               str(ROOT / sources[1]), '-o', str(binary)]
    with (out / 'compile.log').open('xb') as log:
        subprocess.run(command, stdout=log, stderr=subprocess.STDOUT, check=True)
    cases = []
    for delay in (20000000, 3000000, 0):
        case = out / str(delay)
        case.mkdir()
        with (case / 'results.jsonl').open('xb') as output, (case / 'client.log').open('xb') as errors:
            result = subprocess.run([str(binary), str(delay)], stdout=output, stderr=errors, timeout=15)
        observed = json.loads((case / 'results.jsonl').read_text())
        gap = observed['actual_gap_after_first_write_ns']
        passed = gap >= 1000000 and observed['real_complete_payloads'] == 2 and result.returncode == 0
        cases.append(dict(first_writer_delay_ns=delay, actual_gap_after_first_write_ns=gap,
                          real_complete_payloads=observed['real_complete_payloads'],
                          returncode=result.returncode, passed=passed))
        print('NATIVE_ICMP_STAGGER_CASE ' + json.dumps(cases[-1]), flush=True)
    assert bindings == {name: digest(ROOT / name) for name in sources}
    proof = dict(passed=all(case['passed'] for case in cases), cases=cases,
                 source_sha256=bindings, compile_command=command, binary_sha256=digest(binary),
                 real_syscall_writers=True, icmp_rate_policy_acceptance=False, guest_acceptance=False)
    (out / 'receipt.json').write_text(json.dumps(proof, indent=2) + '\n')
    return 0 if proof['passed'] else 1


if __name__ == '__main__':
    sys.exit(main())
