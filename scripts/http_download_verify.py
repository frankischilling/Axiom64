#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Read actual retained HTTP download sources, products and complete wire captures."""
import argparse
import json
from pathlib import Path

from http_download.audit import verify
from http_download.controls import verify as controls


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('directory', type=Path)
    parser.add_argument('--provider', choices=('build', 'runtime', 'all'), default='all')
    parser.add_argument('--linkage', choices=('static', 'dynamic', 'both'), default='both')
    parser.add_argument('--firmware', choices=('bios', 'uefi', 'both'), default='both')
    parser.add_argument('--transport', choices=('modern', 'legacy', 'both'), default='both')
    parser.add_argument('--source-root', type=Path)
    parser.add_argument('--report', type=Path, required=True)
    parser.add_argument('--negative-controls', type=Path,
                        help='retain damaged copies of actual inputs and require eleven rejections')
    args = parser.parse_args()
    selectors = dict(providers=('build', 'runtime') if args.provider == 'all' else (args.provider,))
    for key, value, full in (('linkages', args.linkage, ('static', 'dynamic')),
                             ('firmwares', args.firmware, ('bios', 'uefi')),
                             ('transports', args.transport, ('modern', 'legacy'))):
        selectors[key] = full if value == 'both' else (value,)
    if args.report.exists():
        parser.error('report already exists; retain the earlier observation')
    report = verify(args.directory.resolve(), source_root=args.source_root, **selectors)
    if args.negative_controls is not None:
        report['negative_controls'] = controls(args.directory.resolve(), args.negative_controls, selectors, report)
    args.report.write_text(json.dumps(report, indent=2)+'\n')
    print('HTTP_ACTUAL_EVIDENCE_PASS profiles='+str(report['profiles'])+
          ' captures='+str(report['captures'])+' flows='+str(report['tcp_flows']))


if __name__ == '__main__':
    main()
