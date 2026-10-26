#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Run identical IPv6 TCP address and copy clients on Linux and BIOS/UEFI guests."""
import argparse
from pathlib import Path
from fetch import ROOT
from tcp6.control_contract import ABI
from tcp6.control_matrix import run_matrix
from tcp6.abi_evidence import audit

MARKER = ABI.marker


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output-directory', type=Path, default=ROOT / 'build/tcp6-abi')
    args = parser.parse_args()
    if not args.output_directory.resolve().is_relative_to((ROOT / 'build').resolve()):
        parser.error('output must be a fresh owned directory below build/')
    run_matrix(args.output_directory, ABI, audit)
    print('TCP6_ABI_MATRIX_PASS native=2 guests=4 cases_each=200', flush=True)
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
