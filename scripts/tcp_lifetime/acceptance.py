# SPDX-License-Identifier: GPL-3.0-or-later
"""Run full TCP lifetimes with isolated outputs and bounded parallel observations."""
import argparse
from concurrent.futures import ThreadPoolExecutor
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from fetch import ROOT
from tcp_fault_peer import check
from tcp_fault_test import fixture, run
from tcp_fault_native import namespace


def native_one(linkage):
    original = os.readlink('/proc/self/ns/net')
    with tempfile.TemporaryDirectory(prefix=f'axiom64-tcp-lifetime-{linkage}-') as temporary:
        scratch = Path(temporary)
        (scratch / 'parent-netns').write_text(original)
        completed = subprocess.run(['unshare', '--net', sys.executable, '-u', __file__,
                                    '--namespace', str(scratch), linkage], timeout=1700)
    check(os.readlink('/proc/self/ns/net') == original and completed.returncode == 0,
          'full native lifetime comparison preserves the original network namespace')
    rows = json.loads((ROOT / 'build' / f'tcp-lifetime-native-{linkage}-results.json').read_text())
    check(len(rows) == 1 and rows[0]['linkage'] == linkage and rows[0]['passed'],
          'one complete unshortened native lifetime comparison')
    return rows[0]


def main():
    if len(sys.argv) == 4 and sys.argv[1] == '--namespace':
        namespace(Path(sys.argv[2]), 'lifetime', (sys.argv[3],))
        return
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('mode', choices=('native', 'guest'))
    parser.add_argument('--firmware', choices=('bios', 'uefi', 'both'), default='both')
    parser.add_argument('--transport', choices=('modern', 'legacy', 'both'), default='both')
    args = parser.parse_args()
    if args.mode == 'native':
        check(os.geteuid() == 0, 'disposable raw network namespaces require root')
        subprocess.run(['make', '-s', '-j2', *(f'build/tcp-lifetime-{linkage}' for linkage in
                                            ('native', 'static', 'dynamic'))], cwd=ROOT, check=True)
        with ThreadPoolExecutor(max_workers=3) as executor:
            rows = list(executor.map(native_one, ('native', 'static', 'dynamic')))
        (ROOT / 'build/tcp-lifetime-native-results.json').write_text(json.dumps(rows, indent=2) + '\n')
    else:
        original = ROOT / 'build/rootfs-network.cpio'
        previous = original.read_bytes() if original.exists() else None
        try:
            # Fixture construction shares the existing build inputs and is sequential.
            # Only independent QEMU observations overlap, with at most two 512 MiB guests.
            images = {linkage: fixture(linkage, 'lifetime') for linkage in ('static', 'dynamic')}
            combinations = [(linkage, firmware, transport) for firmware in
                            (('bios', 'uefi') if args.firmware == 'both' else (args.firmware,))
                            for transport in (('modern', 'legacy') if args.transport == 'both' else (args.transport,))
                            for linkage in ('static', 'dynamic')]
            def observe(combination):
                linkage, firmware, transport = combination
                return run(linkage, firmware, transport, images[linkage], 1600, 'lifetime')
            with ThreadPoolExecutor(max_workers=2) as executor:
                rows = list(executor.map(observe, combinations))
            for firmware, transport in sorted({(row['firmware'], row['transport']) for row in rows}):
                scope = [row for row in rows if (row['firmware'], row['transport']) == (firmware, transport)]
                check(len(scope) == 2 and {row['linkage'] for row in scope} == {'static', 'dynamic'},
                      'each firmware/device report contains both actual guest linkages')
                (ROOT / 'build' / f'tcp-lifetime-{firmware}-{transport}-results.json').write_text(
                    json.dumps(scope, indent=2) + '\n')
        finally:
            if previous is None:
                original.unlink(missing_ok=True)
            else:
                original.write_bytes(previous)
    check(all(row['passed'] for row in rows), 'every complete default lifetime observation passes')


if __name__ == '__main__':
    main()
