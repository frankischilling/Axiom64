# SPDX-License-Identifier: GPL-3.0-or-later
"""Run all real PMTU expiry profiles with isolated native and guest observers."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import time
from fetch import ROOT


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--output-directory', type=Path, default=ROOT / 'build/ipv6-expiry')
    args = parser.parse_args()
    directory = args.output_directory.resolve()
    directory.mkdir(parents=True, exist_ok=False)
    # Both drivers use the same compiled clients. Finish that shared preparation
    # before either driver can start its independent network namespaces or VMs.
    subprocess.run(['make', '-j2', *('build/ipv6-expiry-' + profile
                                   for profile in ('native', 'static', 'dynamic'))], cwd=ROOT, check=True)
    commands = {
        'native': [sys.executable, '-B', 'scripts/ipv6_host_native.py', '--suite', 'expiry',
                   '--workers', '3', '--output-directory', str(directory / 'native')],
        'guest': [sys.executable, '-B', 'scripts/ipv6_host_test.py', '--suite', 'expiry',
                  '--workers', '4', '--output-directory', str(directory / 'guest')],
    }
    sources = {name: digest(ROOT / name) for name in (
        'Makefile', 'userspace/tests/net/ipv6_expiry.c', 'userspace/tests/net/ipv6_fixture.h',
        'scripts/ipv6_expiry_test.py', 'scripts/ipv6_expiry_peer.py',
        'scripts/ipv6_expiry_capture.py', 'scripts/ipv6_host_native.py',
        'scripts/ipv6_host_test.py', 'scripts/tcp_capture_clock.py')}
    (directory / 'inputs.json').write_text(json.dumps(dict(commands=commands, source_sha256=sources), indent=2) + '\n')
    processes, logs, error = {}, [], None
    began = time.monotonic()
    def interrupted(signum, _frame):
        raise InterruptedError(f'expiry campaign received signal {signum}')
    previous_handler = signal.signal(signal.SIGTERM, interrupted)
    try:
        for name, command in commands.items():
            output = (directory / (name + '.log')).open('wb')
            logs.append(output)
            processes[name] = subprocess.Popen(command, cwd=ROOT, stdin=subprocess.DEVNULL,
                stdout=output, stderr=subprocess.STDOUT, start_new_session=True)
        while any(process.poll() is None for process in processes.values()):
            if time.monotonic() - began > 1500:
                raise TimeoutError('complete IPv6 expiry campaign exceeded its real-time deadline')
            time.sleep(.2)
    except BaseException as failure:
        error = f'{type(failure).__name__}: {failure}'
    finally:
        # Stop only the process groups created by this campaign, including each
        # namespace client and VM, if the coordinator is interrupted.
        for process in processes.values():
            if error or process.poll() not in (0,):
                try:
                    os.killpg(process.pid, signal.SIGTERM)
                except ProcessLookupError:
                    pass
        for process in processes.values():
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                os.killpg(process.pid, signal.SIGKILL)
                process.wait()
            if error or process.returncode:
                try:
                    os.killpg(process.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
        for output in logs:
            output.close()
        signal.signal(signal.SIGTERM, previous_handler)
    results, native, guests = {}, [], []
    try:
        for name, filename in (('native', 'receipt.json'), ('guest', 'results.json')):
            path = directory / name / filename
            results[name] = dict(sha256=digest(path), returncode=processes[name].returncode)
            rows = json.loads(path.read_text())
            if name == 'native':
                native = rows
            else:
                guests = rows
        if {row['profile'] for row in native} != {'native', 'static', 'dynamic'} or len(native) != 3:
            raise ValueError('all three distinct native linkages are required')
        expected = {(linkage, firmware, transport) for linkage in ('static', 'dynamic')
                    for firmware in ('bios', 'uefi') for transport in ('modern', 'legacy')}
        if {(row['linkage'], row['firmware'], row['transport']) for row in guests} != expected or len(guests) != 8:
            raise ValueError('all eight distinct guest profiles are required')
        if any(row['returncode'] for row in native) or any(not row['passed'] for row in guests):
            raise ValueError('an actual native or guest expiry profile failed')
    except Exception as failure:
        error = error or f'{type(failure).__name__}: {failure}'
    unchanged = all(digest(ROOT / name) == value for name, value in sources.items())
    passed = not error and unchanged and len(results) == 2 and all(
        not row['returncode'] for row in results.values())
    result = dict(passed=passed, error=error, seconds=time.monotonic() - began,
                  sources_unchanged=unchanged, profiles=11, results=results, full_F12_complete=False)
    (directory / 'result.json').write_text(json.dumps(result, indent=2) + '\n')
    print(json.dumps(result), flush=True)
    return 0 if passed else 1


if __name__ == '__main__':
    sys.exit(main())
