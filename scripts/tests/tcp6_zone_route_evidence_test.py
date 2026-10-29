#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Reopen complete scoped route matrices, actual images and matching clients."""
import argparse
import json
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
    parser.add_argument('--output',type=Path,default=ROOT/'build/tcp6-zone-route-independent.json')
    args=parser.parse_args()
    roots={};reports=[];inventory=None
    audit_root=args.output.parent/(args.output.stem+'-captures')
    audit_root.mkdir(parents=True,exist_ok=False)
    for environment in ('native','guest'):
        directory=args.directory/('tcp6-zone-route-'+environment+'-wire')
        expected=([(profile,None,None) for profile in ('native','static','dynamic')] if environment=='native' else
            [(profile,firmware,transport) for profile in ('static','dynamic') for firmware in ('bios','uefi') for transport in ('modern','legacy')])
        report=audit(directory,audit_root/environment,expected=expected)
        controls=540 if environment=='native' else 536
        require(report['suite']=='zone-route' and report['full_matrix'] and
                report['rejected_capture_controls']==controls*len(expected),
                'complete zone-route profiles and semantic controls')
        actual=source(directory)
        if inventory is None:inventory=actual
        require(actual==inventory,'identical complete source for both zone-route matrices')
        for profile,firmware,transport in expected:
            case=directory/profile
            if firmware:case=case/(firmware+'-'+transport)
            before=json.loads((case/'preexecution.json').read_text())
            saved=json.loads((case/'receipt.json').read_text())
            require(saved['suite']=='zone-route' and before['deadline_seconds']==150 and
                    before['start_monotonic_ns']==saved['start_monotonic_ns'] and
                    0<saved['end_monotonic_ns']-saved['start_monotonic_ns']<=150_000_000_000,
                    'original zone-route execution and deadline')
        roots[environment]=directory;reports.append(report)
    for profile in ('static','dynamic'):
        native=roots['native']/profile;guest=roots['guest']/profile
        require(all((native/name).read_bytes()==(guest/name).read_bytes() for name in ('program','program.inputs.json')),
                'identical actual native and guest zone-route client and compile manifest')
        if profile=='dynamic':require(digest(native/'loader')==digest(guest/'loader'),'identical zone-route musl loader')
    captures=[capture['capture'] for report in reports for row in report['results'] for capture in row['captures']]
    totals=dict(actual_flows=sum(c['actual_flows'] for c in captures),
        actual_output_blocks=sum(c['actual_output_blocks'] for c in captures),
        actual_scalar_snapshots=sum(len(c['points']) for c in captures),
        actual_route_snapshots=sum(c['actual_route_snapshots'] for c in captures),
        actual_route_fence_pairs=sum(c['actual_route_fence_pairs'] for c in captures),
        route_withdrawals=sum(p[2]=='fallback' for c in captures for p in c['points']),
        route_restorations=sum(p[2]=='preferred' for c in captures for p in c['points']))
    require(totals==dict(actual_flows=44,actual_output_blocks=220,actual_scalar_snapshots=220,
        actual_route_snapshots=132,actual_route_fence_pairs=880,route_withdrawals=44,route_restorations=44),
        'complete actual scoped route observations')
    proof=dict(passed=True,profiles=11,captures=22,**totals,
        rejected_capture_controls=sum(row['rejected_capture_controls'] for row in reports),
        rejected_product_controls=sum(row['rejected_product_controls'] for row in reports),
        rejected_matrix_controls=sum(len(row['matrix_controls']['rejected']) for row in reports),
        device_clear_route_fallback_reselection_and_rebinding=True,
        full_scoped_source_device_semantics_qualified=False)
    require((proof['rejected_capture_controls'],proof['rejected_product_controls'],proof['rejected_matrix_controls'])==
            (5908,32,6),'complete route packet, product and matrix control inventories')
    write(args.output,proof)
    print(json.dumps(proof,indent=2))


if __name__=='__main__':main()
