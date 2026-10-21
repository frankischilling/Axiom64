# SPDX-License-Identifier: GPL-3.0-or-later
"""Compare per-message controls from the same complete IPv6 output executions."""
import argparse
from pathlib import Path
import subprocess
import sys
from fetch import ROOT


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--native-directory',type=Path,default=ROOT/'build/ipv6-output-native-wire')
    parser.add_argument('--guest-directory',type=Path,default=ROOT/'build/ipv6-output-wire')
    parser.add_argument('--output-directory',type=Path,default=ROOT/'build/ipv6-output-contract')
    args=parser.parse_args()
    args.output_directory.mkdir(parents=True,exist_ok=False)
    command=[sys.executable,'-B',str(ROOT/'scripts/ipv6_send_controls_contract.py')]
    for profile in ['native','static','dynamic']:
        command+=['--native',str(args.native_directory/profile/'client.log')]
    for linkage in ['static','dynamic']:
        for firmware in ['bios','uefi']:
            for transport in ['modern','legacy']:
                command+=['--guest',str(args.guest_directory/f'{linkage}-{firmware}-{transport}'/'guest.log')]
    command+=['--output',str(args.output_directory/'result.json'),
              '--damaged',str(args.output_directory/'damaged.zip')]
    return subprocess.run(command,cwd=ROOT).returncode


if __name__=='__main__':
    raise SystemExit(main())
