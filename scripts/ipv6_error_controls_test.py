# SPDX-License-Identifier: GPL-3.0-or-later
"""Compare local controls from every complete IPv6 error-queue execution."""
import argparse
import json
from pathlib import Path
import subprocess
import sys
from fetch import ROOT
from ipv6_copy_model import load as load_copy_model


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--native-directory', type=Path, default=ROOT / 'build/ipv6-errors-native-wire')
    parser.add_argument('--guest-directory', type=Path, default=ROOT / 'build/ipv6-errors-wire')
    parser.add_argument('--output-directory', type=Path, default=ROOT / 'build/ipv6-errors-contract')
    parser.add_argument('--native-copy-order', choices=('address-first', 'length-first'))
    args = parser.parse_args()
    orders = ([args.native_copy_order] * 3 if args.native_copy_order else
              [load_copy_model(args.native_directory / profile) for profile in ('native', 'static', 'dynamic')])
    if len(set(orders)) != 1:
        raise ValueError('native profiles disagree on their independent copy models')
    args.output_directory.mkdir(parents=True, exist_ok=False)
    command = [sys.executable, '-B', str(ROOT / 'scripts/ipv6_error_controls_contract.py'),
               '--native-copy-order', orders[0]]
    for profile in ('native', 'static', 'dynamic'):
        command += ['--native', str(args.native_directory / profile / 'client.log')]
    for linkage in ('static', 'dynamic'):
        for firmware in ('bios', 'uefi'):
            for transport in ('modern', 'legacy'):
                command += ['--guest', str(args.guest_directory /
                    f'{linkage}-{firmware}-{transport}' / 'guest.log')]
    command += ['--output', str(args.output_directory / 'result.json'),
                '--damaged', str(args.output_directory / 'damaged.zip')]
    status = subprocess.run(command, cwd=ROOT).returncode
    result_path = args.output_directory / 'result.json'
    if result_path.is_file():
        result = json.loads(result_path.read_text())
        result['independent_native_probe'] = args.native_copy_order is None
        result_path.write_text(json.dumps(result, indent=2) + '\n')
    return status


if __name__ == '__main__':
    raise SystemExit(main())
