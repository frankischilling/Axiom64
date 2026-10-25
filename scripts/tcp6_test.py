#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Compare IPv6 TCP active/passive loss recovery on Linux and Axiom64."""
import argparse
import json
from pathlib import Path
import subprocess
import sys
from fetch import ROOT
from tcp6.inputs import freeze, program, write
from tcp6.native import child, client


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--native', action='store_true')
    parser.add_argument('--profile', choices=('native', 'static', 'dynamic', 'all'), default='all')
    parser.add_argument('--child', choices=('native', 'static', 'dynamic'))
    parser.add_argument('--client', choices=('native', 'static', 'dynamic'))
    parser.add_argument('--parent-namespace', type=int)
    parser.add_argument('--firmware', choices=('bios', 'uefi', 'both'), default='both')
    parser.add_argument('--transport', choices=('modern', 'legacy', 'both'), default='both')
    parser.add_argument('--output-directory', type=Path)
    args = parser.parse_args()
    if args.client:
        return client(args.output_directory.resolve(), args.client)
    if args.child:
        return child(args.output_directory.resolve(), args.child, args.parent_namespace)
    directory = (args.output_directory or ROOT / ('build/tcp6-native-wire' if args.native
                                                else 'build/tcp6-guest-wire')).resolve()
    directory.mkdir(parents=True, exist_ok=False)
    profiles = (('native', 'static', 'dynamic') if args.native else ('static', 'dynamic')) if args.profile == 'all' else (args.profile,)
    if not args.native and 'native' in profiles:
        parser.error('guest requires a pinned musl static or dynamic program')
    subprocess.run(['make', '-s', '-j2', *('build/tcp6-fault-' + name for name in profiles),
                    *([] if args.native else ['build/axiom64.elf', 'build/init', 'busybox'])],
                   cwd=ROOT, check=True)
    for profile in profiles:
        case = directory / profile
        case.mkdir()
        program(case, profile)
    source = freeze(directory)
    rows = []
    for profile in profiles:
        if not args.native:
            from tcp6.guest import prepare, run
            case = directory / profile
            image = prepare(case, profile)
            firmwares = ('bios', 'uefi') if args.firmware == 'both' else (args.firmware,)
            transports = ('modern', 'legacy') if args.transport == 'both' else (args.transport,)
            for firmware in firmwares:
                for transport in transports:
                    passed = run(case, profile, firmware, transport, image)
                    rows.append(dict(profile=profile, firmware=firmware, transport=transport,
                                     passed=passed))
                    write(directory / 'receipt.json', dict(source=source, results=rows,
                        complete=len(rows) == len(profiles) * len(firmwares) * len(transports),
                        passed=all(row['passed'] for row in rows), independent_capture_audited=True))
                    if not passed:
                        return 1
            continue
        invocation = ['unshare', '--net', sys.executable, '-B', 'scripts/tcp6_test.py',
                      '--child', profile, '--parent-namespace',
                      str(Path('/proc/self/ns/net').stat().st_ino),
                      '--output-directory', str(directory / profile)]
        result = subprocess.run(invocation, cwd=ROOT)
        case_receipt = json.loads((directory / profile / 'receipt.json').read_text()) if (directory / profile / 'receipt.json').is_file() else {}
        rows.append(dict(profile=profile, returncode=result.returncode,
                         independently_audited=case_receipt.get('independent_capture_audited') is True))
        write(directory / 'receipt.json', dict(source=source, results=rows,
            passed=all(not row['returncode'] and row['independently_audited'] for row in rows),
            complete=len(rows) == len(profiles),
            independent_capture_audited=all(row['independently_audited'] for row in rows)))
        if result.returncode:
            return 1
    from tcp6.evidence import audit
    expected = [(profile, None, None) for profile in profiles] if args.native else [
        (profile, firmware, transport) for profile in profiles for firmware in firmwares for transport in transports]
    audit(directory, expected=expected)
    return 0


if __name__ == '__main__':
    sys.exit(main())
