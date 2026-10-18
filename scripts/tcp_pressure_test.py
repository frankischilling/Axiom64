# SPDX-License-Identifier: GPL-3.0-or-later
"""Overlap complete pressure observations with isolated peers and unique products."""
import argparse
from concurrent.futures import ProcessPoolExecutor, as_completed
from contextlib import ExitStack
import json
import multiprocessing
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import traceback
from fetch import ROOT
from tcp_fault_test import fixture, run

LINKAGES = ('native', 'static', 'dynamic')
GUESTS = tuple((linkage, firmware, transport) for linkage in ('static', 'dynamic')
               for firmware in ('bios', 'uefi') for transport in ('modern', 'legacy'))


def guest_profile(profile, image, timeout):
    os.chdir(ROOT)
    try:
        return run(*profile, Path(image), timeout, 'pressure')
    except Exception as error:
        path = ROOT / 'build' / ('tcp-pressure-' + '-'.join(profile) + '-producer.log')
        path.write_text(traceback.format_exc())
        return dict(wire='pressure', linkage=profile[0], firmware=profile[1], transport=profile[2],
                    passed=False, error=str(error), producer_log=path.name)


def native_profile(linkage, timeout):
    os.chdir(ROOT)
    log = ROOT / 'build' / f'tcp-pressure-native-{linkage}-producer.log'
    try:
        parent = os.readlink('/proc/self/ns/net')
        with tempfile.TemporaryDirectory(prefix=f'axiom64-pressure-native-{linkage}-') as directory:
            scratch = Path(directory)
            (scratch / 'parent-netns').write_text(parent)
            command = ['unshare', '--net', sys.executable, str(ROOT / 'scripts/tcp_fault_native.py'),
                       '--namespace', str(scratch), 'pressure', linkage]
            with log.open('wb') as output:
                actual = subprocess.run(command, cwd=ROOT, stdout=output, stderr=subprocess.STDOUT,
                                        timeout=timeout + 30)
            if os.readlink('/proc/self/ns/net') != parent:
                raise ValueError('native pressure producer changed its parent namespace')
        report = ROOT / 'build' / f'tcp-pressure-native-{linkage}-results.json'
        rows = json.loads(report.read_text())
        if len(rows) != 1 or rows[0]['linkage'] != linkage:
            raise ValueError('one complete result is required for each native pressure producer')
        row = rows[0]
        row['producer_log'] = log.name
        row['producer_returncode'] = actual.returncode
        if actual.returncode:
            row['passed'] = False
            row['error'] = row.get('error') or f'native producer exited {actual.returncode}'
        return row
    except Exception as error:
        with log.open('a') as output:
            output.write('\n' + traceback.format_exc())
        return dict(wire='pressure', linkage=linkage, passed=False, error=str(error), producer_log=log.name)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    group = parser.add_mutually_exclusive_group()
    group.add_argument('--native', action='store_true', help='observe all three native linkages')
    group.add_argument('--guest', action='store_true', help='observe all eight guest configurations')
    parser.add_argument('--workers', type=int, default=4, help='maximum simultaneous guest VMs (1 through 4)')
    parser.add_argument('--timeout', type=float, default=300)
    args = parser.parse_args()
    if args.workers not in range(1, 5) or args.timeout <= 120:
        parser.error('one to four VMs and a budget longer than the complete 120-second observation are required')
    selected_native, selected_guest = not args.guest, not args.native
    os.chdir(ROOT)
    subprocess.run(['make', '-s', '-j2', *(f'build/tcp-pressure-{linkage}' for linkage in LINKAGES)],
                   cwd=ROOT, check=True)
    images = {}
    if selected_guest:
        original = ROOT / 'build/rootfs-network.cpio'
        previous = original.read_bytes() if original.exists() else None
        try:
            # Fixture construction writes the shared temporary archive; each
            # completed ISO and input manifest is immutable during observation.
            for linkage in ('static', 'dynamic'):
                images[linkage] = str(fixture(linkage, 'pressure'))
        finally:
            if previous is None:
                original.unlink(missing_ok=True)
            else:
                original.write_bytes(previous)
    native, guest = {}, {}
    context = multiprocessing.get_context('spawn')
    with ExitStack() as stack:
        futures = {}
        if selected_native:
            pool = stack.enter_context(ProcessPoolExecutor(max_workers=3, mp_context=context))
            for linkage in LINKAGES:
                futures[pool.submit(native_profile, linkage, args.timeout)] = ('native', linkage)
        if selected_guest:
            pool = stack.enter_context(ProcessPoolExecutor(max_workers=args.workers, mp_context=context))
            for profile in GUESTS:
                futures[pool.submit(guest_profile, profile, images[profile[0]], args.timeout)] = ('guest', profile)
        for future in as_completed(futures):
            kind, key = futures[future]
            try:
                result = future.result()
            except Exception as error:
                result = dict(wire='pressure', passed=False, error=str(error))
            (native if kind == 'native' else guest)[key] = result
            for values, order, name in ((native, LINKAGES, 'tcp-pressure-native-results.json'),
                                        (guest, GUESTS, 'tcp-pressure-results.json')):
                if values:
                    rows = [values[key] for key in order if key in values]
                    (ROOT / 'build' / name).write_text(json.dumps(rows, indent=2) + '\n')
            print(json.dumps(dict(kind=kind, profile=key, passed=result['passed'], error=result.get('error'),
                                  completed_native=len(native), completed_guests=len(guest))), flush=True)
    complete = (not selected_native or set(native) == set(LINKAGES)) and (not selected_guest or set(guest) == set(GUESTS))
    passed = complete and all(row['passed'] for row in [*native.values(), *guest.values()])
    print(json.dumps(dict(passed=passed, native=len(native), guests=len(guest),
                          complete120second_observations_required=True)), flush=True)
    raise SystemExit(0 if passed else 1)


if __name__ == '__main__':
    main()
