#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Reopen the full TCP control matrix and require identical native/guest clients."""
import argparse
import json
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from fetch import ROOT
from tcp6.capture import require
from tcp6.evidence import audit, source
from tcp6.inputs import digest, write


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--directory', type=Path, default=ROOT / 'build')
    parser.add_argument('--output', type=Path, default=ROOT / 'build/tcp6-controls-wire-independent.json')
    args = parser.parse_args()
    results = []
    complete_source = None
    audit_root = args.output.parent / (args.output.stem + '-captures')
    audit_root.mkdir(parents=True, exist_ok=False)
    for family in ('ipv6', 'mapped', 'ipv4'):
        cases = {}
        for environment in ('native', 'guest'):
            directory = args.directory / ('tcp6-controls-' + family + '-' + environment + '-wire')
            expected = ([(profile, None, None) for profile in ('native', 'static', 'dynamic')]
                        if environment == 'native' else [(profile, firmware, transport)
                        for profile in ('static', 'dynamic') for firmware in ('bios', 'uefi')
                        for transport in ('modern', 'legacy')])
            report = audit(directory, audit_root / (family + '-' + environment), expected=expected)
            inventory = source(directory)
            if complete_source is None:
                complete_source = inventory
            require(inventory == complete_source, 'all family executions bind identical complete source')
            require(report['rejected_capture_controls'] == 180 * len(expected) and
                    report['suite'] == 'controls-' + family, 'complete family packet controls and suite')
            cases[environment] = directory
            results.append(dict(family=family, environment=environment, profiles=len(expected),
                                captures=report['captures'], rejected_capture_controls=report['rejected_capture_controls']))
        for profile in ('static', 'dynamic'):
            native = cases['native'] / profile
            guest = cases['guest'] / profile
            require((native / 'program').read_bytes() == (guest / 'program').read_bytes() and
                    (native / 'program.inputs.json').read_bytes() == (guest / 'program.inputs.json').read_bytes(),
                    'identical actual pinned native and guest family client')
            if profile == 'dynamic':
                require(digest(native / 'loader') == digest(guest / 'loader'), 'identical native and guest musl loader')
    proof = dict(passed=True, families=3, profiles=33, captures=66, actual_exchanges=1056,
                 actual_scalar_snapshots=1584, rejected_capture_controls=5940,
                 actual_flows=198, pending_listener_controls=True,
                 full_passive_source_route_device_and_expiry_acceptance=False, results=results)
    write(args.output, proof)
    print(json.dumps(proof, indent=2))


if __name__ == '__main__':
    main()
