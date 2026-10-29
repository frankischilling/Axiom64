#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Compare retained TCP controls on real IPv4, IPv6 and mapped loopback streams."""
import argparse
from pathlib import Path
from fetch import ROOT
from tcp6.control_contract import STATE
from tcp6.control_matrix import run_matrix, run_glibc
from tcp6.state_evidence import audit


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output-directory', type=Path, default=ROOT / 'build/tcp-control-state')
    args = parser.parse_args()
    if not args.output_directory.resolve().is_relative_to((ROOT / 'build').resolve()):
        parser.error('output must be a fresh owned directory below build/')
    def complete(directory):
        run_glibc(directory, STATE)
        return audit(directory)
    run_matrix(args.output_directory, STATE, complete)
    print('TCP_CONTROL_STATE_MATRIX_PASS native=3 guests=4 loopback_only=1', flush=True)


if __name__ == '__main__':
    main()
