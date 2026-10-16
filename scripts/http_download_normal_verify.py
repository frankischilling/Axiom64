#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Independently inspect actual normal-download logs, boot images, packets and disks."""
import argparse
from pathlib import Path

from http_download.normal_audit import verify
from http_download.normal_controls import verify as controls


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('directory',type=Path)
    parser.add_argument('--provider',choices=('build','runtime','all'),default='all')
    parser.add_argument('--linkage',choices=('static','dynamic','both'),default='both')
    parser.add_argument('--firmware',choices=('bios','uefi','both'),default='both')
    parser.add_argument('--transport',choices=('modern','legacy','both'),default='both')
    parser.add_argument('--storage',choices=('ram','ext2','both'),default='both')
    parser.add_argument('--source-root',type=Path)
    parser.add_argument('--output',type=Path,required=True)
    parser.add_argument('--negative-controls',type=Path)
    args = parser.parse_args()
    selectors = dict(
        providers=('build','runtime') if args.provider == 'all' else (args.provider,),
        linkages=('static','dynamic') if args.linkage == 'both' else (args.linkage,),
        firmwares=('bios','uefi') if args.firmware == 'both' else (args.firmware,),
        transports=('modern','legacy') if args.transport == 'both' else (args.transport,),
        storage=args.storage)
    report = verify(args.directory.resolve(),args.output.resolve(),source_root=args.source_root,**selectors)
    if args.negative_controls is not None:
        report['negative_controls'] = controls(args.directory.resolve(),args.negative_controls.resolve(),selectors,report)
        import json
        (args.output / 'receipt.json').write_text(json.dumps(report,indent=2)+'\n')
    print('HTTP_NORMAL_ACTUAL_EVIDENCE_PASS profiles='+str(report['provider_profiles']))


if __name__ == '__main__':
    main()
