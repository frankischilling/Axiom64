# SPDX-License-Identifier: GPL-3.0-or-later
"""Overlap complete routing qualification with the existing source-filter cohort."""
import argparse
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import threading
import time

from ci.paired_network import capture, stop
from fetch import ROOT
from ipv4_source_route.controls import require
from tcp6.inputs import digest, write


def routing(directory):
    commands = [
        ['make', 'test-ipv4-source-controls'],
        [sys.executable, '-B', '-m', 'ipv4_source_route.matrix', 'build/ipv4-source-route-wire', '--produce'],
        [sys.executable, '-B', '-m', 'ipv4_source_route.protected', 'build/ipv4-source-route-wire',
         '--output', 'build/ipv4-source-route-audit', '--controls', 'build/ipv4-source-controls']]
    records = []
    for number, command in enumerate(commands):
        began = time.monotonic_ns()
        process = subprocess.Popen(command, cwd=ROOT, stdin=subprocess.DEVNULL, start_new_session=True)
        try:
            process.wait()
        finally:
            stop(process)
        records.append(dict(command=command, pid=process.pid, returncode=process.returncode,
                            elapsed_ns=time.monotonic_ns() - began))
        write(directory / 'routing-commands.json', records)
        require(process.returncode == 0, 'complete routing qualification command failed')


def run(directory, commands=None):
    directory = Path(directory).resolve()
    require(directory.is_relative_to((ROOT / 'build').resolve()), 'designated ignored source cohort window')
    directory.mkdir(parents=True, exist_ok=False)
    if commands is None:
        commands = dict(
            filters=[sys.executable, '-B', '-m', 'ipv4_multicast.source_matrix', 'build/ipv4-source-evidence', '--produce'],
            routing=[sys.executable, '-B', '-m', 'ipv4_source_route.window', '--directory', str(directory), '--routing-only'])
    require(set(commands) == {'filters', 'routing'}, 'both complete source cohort workers')
    source = {name: digest(ROOT / name) for name in ('scripts/ipv4_source_route/window.py', '.github/workflows/build.yml')}
    records, processes, threads, failures = {}, {}, [], []
    lock = threading.Lock()
    def observe(name, process):
        capture(process, directory / (name + '.log'), name, failures)
        process.wait()
        with lock:
            records[name].update(status='completed', returncode=process.returncode, end_ns=time.monotonic_ns())
            write(directory / 'processes.json', records)
    began = time.monotonic_ns()
    try:
        for name, command in commands.items():
            process = subprocess.Popen(command, cwd=ROOT, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT, start_new_session=True, env=dict(os.environ, PYTHONPATH=str(ROOT / 'scripts')))
            processes[name] = process
            with lock:
                records[name] = dict(pid=process.pid, command=command, status='running', start_ns=time.monotonic_ns())
                write(directory / 'processes.json', records)
            thread = threading.Thread(target=observe, args=(name, process))
            threads.append(thread)
            thread.start()
        # A failed worker does not cancel the other cohort's required cases.
        for process in processes.values():
            process.wait()
    finally:
        for process in processes.values():
            stop(process)
        for thread in threads:
            thread.join()
        for process in processes.values():
            process.stdout.close()
        for name, process in processes.items():
            records[name].update(status='completed', returncode=process.returncode,
                                 log_sha256=digest(directory / (name + '.log')))
        write(directory / 'processes.json', records)
    require(not failures and all(process.returncode == 0 for process in processes.values()),
            'both complete source cohorts and retained output readers must succeed')
    require(source == {name: digest(ROOT / name) for name in source}, 'unchanged cohort orchestration and workflow')
    proof = dict(passed=True, workers=records, source=source, elapsed_ns=time.monotonic_ns() - began,
                 source_filter_cases_removed=0, routing_campaign_workers=2, observations_rescaled=False)
    write(directory / 'verified.json', proof)
    return proof


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--directory', type=Path, default=ROOT / 'build/ipv4-source-route-window')
    parser.add_argument('--routing-only', action='store_true')
    args = parser.parse_args()
    def interrupted(signum, frame):
        raise KeyboardInterrupt('source cohort window interrupted')
    signal.signal(signal.SIGTERM, interrupted)
    if args.routing_only:
        routing(args.directory)
    else:
        print(json.dumps(run(args.directory)), flush=True)


if __name__ == '__main__':
    main()
