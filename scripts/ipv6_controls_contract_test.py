# SPDX-License-Identifier: GPL-3.0-or-later
"""Compare all local IPv6 control cases from the complete native/guest cohort."""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import sys
from fetch import ROOT
from ipv6_copy_model import load as load_copy_model


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--native-directory', type=Path, default=ROOT / 'build/ipv6-controls-native-wire')
    parser.add_argument('--guest-directory', type=Path, default=ROOT / 'build/ipv6-controls-wire')
    parser.add_argument('--output-directory', type=Path, default=ROOT / 'build/ipv6-controls-contract')
    parser.add_argument('--native-copy-order', choices=('address-first', 'length-first'))
    args = parser.parse_args()
    orders = ([args.native_copy_order] * 3 if args.native_copy_order else
              [load_copy_model(args.native_directory / profile) for profile in ('native', 'static', 'dynamic')])
    if len(set(orders)) != 1:
        raise ValueError('native profiles disagree on their independent copy models')
    args.output_directory.mkdir(parents=True, exist_ok=False)
    native = [args.native_directory / profile / 'client.log'
              for profile in ('native', 'static', 'dynamic')]
    guests = [args.guest_directory / f'{linkage}-{firmware}-{transport}' / 'guest.log'
              for linkage in ('static', 'dynamic') for firmware in ('bios', 'uefi')
              for transport in ('modern', 'legacy')]
    originals = {str(path): path.read_bytes() for path in native + guests}
    results = []
    for name in ('ipv6_control_contract', 'ipv6_control_fault_contract', 'ipv6_control_header_contract'):
        command = [sys.executable, '-B', str(ROOT / 'scripts' / (name + '.py'))]
        if name != 'ipv6_control_contract':
            command += ['--native-copy-order', orders[0]]
        for path in native:
            command += ['--native', str(path)]
        for path in guests:
            command += ['--guest', str(path)]
        command += ['--output', str(args.output_directory / (name + '.json')),
                    '--damaged', str(args.output_directory / (name + '-damaged.zip'))]
        with (args.output_directory / (name + '.log')).open('wb') as log:
            run = subprocess.run(command, cwd=ROOT, stdout=log, stderr=subprocess.STDOUT)
        result_path = args.output_directory / (name + '.json')
        result = json.loads(result_path.read_text()) if result_path.exists() else {}
        results.append(dict(reader=name, returncode=run.returncode, passed=result.get('passed', False),
                            cases_each=result.get('cases_each', 0),
                            damaged_rejected=result.get('damaged_rejected', 0)))
    if any(path.read_bytes() != originals[str(path)] for path in native + guests):
        raise ValueError('original complete receive-control logs changed during comparison')
    passed = (all(row['returncode'] == 0 and row['passed'] for row in results) and
              sum(row['cases_each'] for row in results) == 854 and
              sum(row['damaged_rejected'] for row in results) == 240)
    result = dict(passed=passed, native_profiles=3, guest_profiles=8, cases_each=854, native_copy_order=orders[0],
                  independent_native_probe=args.native_copy_order is None,
                  damaged_rejected=sum(row['damaged_rejected'] for row in results), readers=results,
                  original_sha256={name: hashlib.sha256(data).hexdigest()
                                   for name, data in originals.items()}, full_F12_complete=False)
    (args.output_directory / 'result.json').write_text(json.dumps(result, indent=2) + '\n')
    print(json.dumps({key: value for key, value in result.items() if key != 'original_sha256'}))
    return 0 if passed else 1


if __name__ == '__main__':
    raise SystemExit(main())
