#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Reopen changed IPv6 TCP control evidence and require semantic rejection."""
import argparse
from pathlib import Path
import sys
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from fetch import ROOT
from tcp6.abi_evidence import audit, PRECHECK
from tcp6.control_contract import ABI
from tcp6.matrix_controls import run_matrix_controls


def changed_prevalidation(body):
    marker = PRECHECK.encode() + b'\n'
    return body.replace(marker, b'') if marker in body else marker + body


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--directory', type=Path, default=ROOT / 'build/tcp6-abi')
    parser.add_argument('--output', type=Path, default=ROOT / 'build/tcp6-abi-damaged')
    args = parser.parse_args()
    report = run_matrix_controls(args.directory, args.output, ABI, audit, changed_prevalidation,
        log_control_label='native-prevalidation',
        log_failure='exact native-only packet-family prevalidation profile')
    assert len(report['controls']) == 24
    print('TCP6_ABI_CONTROLS_PASS serialized_reopened=24 originals_unchanged=1')


if __name__ == '__main__':
    main()
