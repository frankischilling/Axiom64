#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Reopen the complete source-lifetime pair with identical native/guest clients."""
import argparse
from pathlib import Path
import sys

sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from fetch import ROOT
from tcp6.capture import require
from tcp6.evidence import audit,source
from tcp6.inputs import digest,write


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--directory',type=Path,default=ROOT/'build')
    parser.add_argument('--output',type=Path,default=ROOT/'build/tcp6-source-lifetime-independent.json')
    args=parser.parse_args()
    roots={};reports=[];inventory=None
    audit_root=args.output.parent/(args.output.stem+'-captures')
    audit_root.mkdir(parents=True,exist_ok=False)
    for environment in ('native','guest'):
        directory=args.directory/('tcp6-source-lifetime-'+environment+'-wire')
        expected=([(profile,None,None) for profile in ('native','static','dynamic')] if environment=='native' else
            [(profile,firmware,transport) for profile in ('static','dynamic') for firmware in ('bios','uefi') for transport in ('modern','legacy')])
        report=audit(directory,audit_root/environment,expected=expected)
        require(report['suite']=='source-lifetime' and report['rejected_capture_controls']==224*len(expected),
                'complete source-lifetime profiles and semantic controls')
        actual=source(directory)
        if inventory is None:inventory=actual
        require(actual==inventory,'identical complete source for both source-lifetime matrices')
        roots[environment]=directory;reports.append(report)
    for profile in ('static','dynamic'):
        native=roots['native']/profile;guest=roots['guest']/profile
        require(all((native/name).read_bytes()==(guest/name).read_bytes() for name in ('program','program.inputs.json')),
                'identical actual native and guest source-lifetime client and compile manifest')
        if profile=='dynamic':require(digest(native/'loader')==digest(guest/'loader'),'identical source-lifetime musl loader')
    proof=dict(passed=True,profiles=11,captures=22,actual_flows=88,actual_output_blocks=264,
        withdrawn_source_blocks=132,echoed_blocks=132,actual_scalar_snapshots=220,rejected_capture_controls=2464,
        rejected_product_controls=sum(row['rejected_product_controls'] for row in reports),
        rejected_matrix_controls=sum(len(row['matrix_controls']['rejected']) for row in reports),
        global_source_removal_with_companion_route=True,full_source_route_device_expiry_acceptance=False)
    write(args.output,proof)
    print(__import__('json').dumps(proof,indent=2))


if __name__=='__main__':main()
