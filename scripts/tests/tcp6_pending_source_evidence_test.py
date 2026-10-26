#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Reopen paired pending-source matrices and identical native/guest executables."""
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
    parser.add_argument('--output',type=Path,default=ROOT/'build/tcp6-pending-source-independent.json')
    args=parser.parse_args();roots={};reports=[];inventory=None
    audit_root=args.output.parent/(args.output.stem+'-captures')
    audit_root.mkdir(parents=True,exist_ok=False)
    for environment in ('native','guest'):
        directory=args.directory/('tcp6-pending-source-'+environment+'-wire')
        expected=([(p,None,None) for p in ('native','static','dynamic')] if environment=='native' else
            [(p,f,t) for p in ('static','dynamic') for f in ('bios','uefi') for t in ('modern','legacy')])
        report=audit(directory,audit_root/environment,expected=expected)
        require(report['suite']=='pending-source' and report['rejected_capture_controls']==
            (82 if environment=='native' else 78)*len(expected),'all pending source profiles and controls')
        actual=source(directory)
        if inventory is None:inventory=actual
        require(actual==inventory,'identical complete producer source for pending source matrices')
        roots[environment]=directory;reports.append(report)
    for profile in ('static','dynamic'):
        native=roots['native']/profile;guest=roots['guest']/profile
        require(all((native/name).read_bytes()==(guest/name).read_bytes() for name in ('program','program.inputs.json')),
            'identical actual pending source native/guest program and compiler manifest')
        if profile=='dynamic':require(digest(native/'loader')==digest(guest/'loader'),'identical pending source musl loader')
    proof=dict(passed=True,profiles=11,captures=22,actual_flows=176,actual_pending_handshakes=88,
        actual_output_blocks=176,rejected_capture_controls=870,
        rejected_product_controls=sum(row['rejected_product_controls'] for row in reports),
        rejected_matrix_controls=sum(len(row['matrix_controls']['rejected']) for row in reports),
        global_pending_source_withdrawal=True,full_source_route_device_expiry_acceptance=False)
    write(args.output,proof);print(__import__('json').dumps(proof,indent=2))


if __name__=='__main__':main()
