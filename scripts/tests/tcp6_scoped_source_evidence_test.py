#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Reopen complete scoped-source matrices and identical native/guest clients."""
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
    parser.add_argument('--output',type=Path,default=ROOT/'build/tcp6-scoped-source-independent.json')
    args=parser.parse_args()
    roots={};reports=[];inventory=None
    audit_root=args.output.parent/(args.output.stem+'-captures')
    audit_root.mkdir(parents=True,exist_ok=False)
    for environment in ('native','guest'):
        directory=args.directory/('tcp6-scoped-source-'+environment+'-wire')
        expected=([(profile,None,None) for profile in ('native','static','dynamic')] if environment=='native' else
            [(profile,firmware,transport) for profile in ('static','dynamic') for firmware in ('bios','uefi') for transport in ('modern','legacy')])
        report=audit(directory,audit_root/environment,expected=expected)
        controls=420 if environment=='native' else 416
        require(report['suite']=='scoped-source' and report['full_matrix'] and
                report['rejected_capture_controls']==controls*len(expected),
                'complete scoped-source profiles and semantic controls')
        actual=source(directory)
        if inventory is None:inventory=actual
        require(actual==inventory,'identical complete source for both scoped-source matrices')
        for profile,firmware,transport in expected:
            case=directory/profile
            if firmware:case=case/(firmware+'-'+transport)
            before=json.loads((case/'preexecution.json').read_text())
            saved=json.loads((case/'receipt.json').read_text())
            require(saved['suite']=='scoped-source' and before['deadline_seconds']==150 and
                    before['start_monotonic_ns']==saved['start_monotonic_ns'] and
                    0<saved['end_monotonic_ns']-saved['start_monotonic_ns']<=150_000_000_000,
                    'original scoped-source execution and deadline')
        roots[environment]=directory;reports.append(report)
    for profile in ('static','dynamic'):
        native=roots['native']/profile;guest=roots['guest']/profile
        require(all((native/name).read_bytes()==(guest/name).read_bytes() for name in ('program','program.inputs.json')),
                'identical actual native and guest scoped-source client and compile manifest')
        if profile=='dynamic':require(digest(native/'loader')==digest(guest/'loader'),'identical scoped-source musl loader')
    captures=[capture['capture'] for report in reports for row in report['results'] for capture in row['captures']]
    totals=dict(actual_flows=sum(c['actual_flows'] for c in captures),
        actual_output_blocks=sum(c['actual_output_blocks'] for c in captures),
        withdrawn_source_blocks=sum(c['withdrawn_source_blocks'] for c in captures),
        actual_scalar_snapshots=sum(len(c['points']) for c in captures),
        quiet_cleared_zone_intervals=sum(p[2]=='device-cleared' for c in captures for p in c['points']),
        other_zone_bind_witnesses=sum(b[0]==c['lane'] for c in captures for b in c['zone_bindings']))
    require(totals==dict(actual_flows=88,actual_output_blocks=264,withdrawn_source_blocks=132,
        actual_scalar_snapshots=308,quiet_cleared_zone_intervals=44,other_zone_bind_witnesses=44),
        'complete actual scoped-source observations')
    proof=dict(passed=True,profiles=11,captures=22,**totals,
        rejected_capture_controls=sum(row['rejected_capture_controls'] for row in reports),
        rejected_product_controls=sum(row['rejected_product_controls'] for row in reports),
        rejected_matrix_controls=sum(len(row['matrix_controls']['rejected']) for row in reports),
        link_local_source_withdrawal_with_companion_route=True,
        full_scoped_source_device_semantics_qualified=False)
    require((proof['rejected_capture_controls'],proof['rejected_product_controls'],proof['rejected_matrix_controls'])==
            (4588,32,6),'complete packet, product and matrix control inventories')
    write(args.output,proof)
    print(json.dumps(proof,indent=2))


if __name__=='__main__':main()
