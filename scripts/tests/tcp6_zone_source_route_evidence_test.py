#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Reopen complete scoped source/route matrices with original images and clients."""
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
    parser.add_argument('--output',type=Path,default=ROOT/'build/tcp6-zone-source-route-independent.json')
    args=parser.parse_args();roots={};reports=[];inventory=None
    audit_root=args.output.parent/(args.output.stem+'-captures');audit_root.mkdir(parents=True,exist_ok=False)
    for environment in ('native','guest'):
        directory=args.directory/('tcp6-zone-source-route-'+environment+'-wire')
        expected=([(profile,None,None) for profile in ('native','static','dynamic')] if environment=='native' else
            [(profile,firmware,transport) for profile in ('static','dynamic') for firmware in ('bios','uefi') for transport in ('modern','legacy')])
        report=audit(directory,audit_root/environment,expected=expected)
        require(report['suite']=='zone-source-route' and report['full_matrix'] and
            report['rejected_capture_controls']==(778 if environment=='native' else 774)*len(expected),
            'complete combined source-route matrix and semantic rejection inventory')
        actual=source(directory)
        if inventory is None:inventory=actual
        require(actual==inventory,'identical complete source for native and guest source-route matrices')
        for profile,firmware,transport in expected:
            case=directory/profile
            if firmware:case=case/(firmware+'-'+transport)
            before=json.loads((case/'preexecution.json').read_text());saved=json.loads((case/'receipt.json').read_text())
            require(saved['suite']=='zone-source-route' and before['deadline_seconds']==150 and
                before['start_monotonic_ns']==saved['start_monotonic_ns'] and
                0<saved['end_monotonic_ns']-saved['start_monotonic_ns']<=150_000_000_000,
                'original complete execution interval and unchanged source-route deadline')
        roots[environment]=directory;reports.append(report)
    for profile in ('static','dynamic'):
        native=roots['native']/profile;guest=roots['guest']/profile
        require(all((native/name).read_bytes()==(guest/name).read_bytes() for name in ('program','program.inputs.json')),
            'identical actual native and guest source-route client and compile manifest')
        if profile=='dynamic':require(digest(native/'loader')==digest(guest/'loader'),'identical actual musl loader')
    captures=[c['capture'] for report in reports for row in report['results'] for c in row['captures']]
    totals=dict(retained_flows=sum(c['actual_flows'] for c in captures),
        companion_flows=sum(c['actual_companion_flows'] for c in captures),
        retained_output_blocks=sum(c['actual_output_blocks'] for c in captures),
        companion_output_blocks=sum(len(c['companion_observations']) for c in captures),
        source_withdrawals=sum(c['actual_source_withdrawals'] for c in captures),
        source_snapshots=sum(c['actual_source_snapshots'] for c in captures),
        fresh_bind_observations=sum(c['actual_fresh_bind_observations'] for c in captures),
        ownership_fence_pairs=sum(c['actual_ownership_fence_pairs'] for c in captures),
        route_snapshots=sum(c['actual_route_snapshots'] for c in captures),
        route_fence_pairs=sum(c['actual_route_fence_pairs'] for c in captures),
        scalar_snapshots=sum(len(c['points']) for c in captures))
    require(totals==dict(retained_flows=44,companion_flows=44,retained_output_blocks=220,
        companion_output_blocks=44,source_withdrawals=44,source_snapshots=220,fresh_bind_observations=352,
        ownership_fence_pairs=176,route_snapshots=132,route_fence_pairs=880,scalar_snapshots=220),
        'all actual source withdrawal companion routing restoration and control observations')
    proof=dict(passed=True,profiles=11,captures=22,**totals,
        rejected_capture_controls=sum(r['rejected_capture_controls'] for r in reports),
        rejected_product_controls=sum(r['rejected_product_controls'] for r in reports),
        rejected_matrix_controls=sum(len(r['matrix_controls']['rejected']) for r in reports),
        source_removed_only_in_origin_zone=True,retained_output_observed_before_source_restoration=True,
        actual_ownership_restored_before_fallback_echo=True,original_clocks_and_deadlines_preserved=True,
        full_scoped_source_device_semantics_qualified=False)
    require((proof['rejected_capture_controls'],proof['rejected_product_controls'],proof['rejected_matrix_controls'])==
        (8526,32,6),'complete source-route capture product and matrix controls')
    write(args.output,proof);print(json.dumps(proof,indent=2))


if __name__=='__main__':main()
