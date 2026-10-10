# SPDX-License-Identifier: GPL-3.0-or-later
"""Run both musl linkages concurrently with independent generated files."""
import argparse
import json
import os
from pathlib import Path
import re
import shutil
import signal
import subprocess
import sys
import tempfile
import threading
import time


ROOT = Path(__file__).resolve().parents[2]
SUITE = re.compile(r'(protocol|link)-(bios|uefi)-(modern|legacy)-lane([01])')


def parameters(suite):
    match = SUITE.fullmatch(suite)
    if match is None:
        raise ValueError(f'unsupported paired network suite: {suite}')
    kind, firmware, transport, affected = match.groups()
    return kind, ['--firmware', firmware, '--transport', transport, '--affected', affected]


def capture(process, destination, linkage, failures):
    try:
        with destination.open('wb') as output:
            for line in process.stdout:
                output.write(line)
                output.flush()
                print(f'{linkage}: {line.decode("utf-8", errors="replace").rstrip()}', flush=True)
    except Exception as failure:
        failures.append(f'{linkage}: {type(failure).__name__}: {failure}')


def stop(process):
    # A worker may have exited while leaving a QEMU descendant in its session.
    try:
        os.killpg(process.pid, signal.SIGTERM)
    except ProcessLookupError:
        pass
    try:
        process.wait(timeout=5)
    except subprocess.TimeoutExpired:
        pass
    # Reap descendants too, including those that ignored TERM after their parent exited.
    try:
        os.killpg(process.pid, signal.SIGKILL)
    except ProcessLookupError:
        pass
    process.wait()


def run_pair(root, archive, temporary_parent, suite):
    kind, arguments = parameters(suite)
    root, archive = Path(root).resolve(), Path(archive).resolve()
    if not archive.is_file():
        raise ValueError(f'test input archive is missing: {archive}')
    evidence = root / 'build' / 'paired-network' / suite
    evidence.mkdir(parents=True, exist_ok=True)
    workers, readers, records = {}, {}, {}
    capture_failures = []
    error = None
    began = time.monotonic()
    with tempfile.TemporaryDirectory(prefix=f'{suite}-', dir=temporary_parent) as temporary:
        dynamic = Path(temporary)
        try:
            subprocess.run(['tar', '-xzf', str(archive), '-C', str(dynamic)], check=True)
            for linkage, workspace in (('static', root), ('dynamic', dynamic)):
                output = evidence / linkage
                output.mkdir(exist_ok=True)
                command = [sys.executable, '-u', str(workspace / 'scripts' / f'manager_{kind}_test.py'),
                           *arguments, '--linkage', linkage]
                records[linkage] = dict(workspace=str(workspace), command=command,
                                        evidence=str(output.relative_to(root)), returncode=None)
                print(f'Starting {suite} {linkage} in {workspace}', flush=True)
                process = subprocess.Popen(command, cwd=workspace, stdout=subprocess.PIPE,
                                           stderr=subprocess.STDOUT, start_new_session=True)
                workers[linkage] = process
                reader = threading.Thread(target=capture,
                                          args=(process, output / 'worker.log', linkage, capture_failures))
                reader.start()
                readers[linkage] = reader
            for linkage, process in workers.items():
                records[linkage]['returncode'] = process.wait()
        except BaseException as failure:
            error = f'{type(failure).__name__}: {failure}'
            print(error, file=sys.stderr, flush=True)
        finally:
            for process in workers.values():
                stop(process)
            for linkage, process in workers.items():
                readers[linkage].join()
                process.stdout.close()
                records[linkage]['returncode'] = process.returncode
            for linkage, record in records.items():
                destination = root / record['evidence']
                build = Path(record['workspace']) / 'build'
                for source in build.glob(f'manager-{kind}-*'):
                    if source.is_file() and source.suffix in ('.json', '.log', '.png', '.pcap'):
                        shutil.copy2(source, destination / source.name)
            success = error is None and not capture_failures and set(records) == {'static', 'dynamic'} and all(
                record['returncode'] == 0 for record in records.values())
            report = dict(suite=suite, success=success, error=error, capture_failures=capture_failures,
                          elapsed_seconds=round(time.monotonic() - began, 3), workers=records)
            (evidence / 'results.json').write_text(json.dumps(report, indent=2) + '\n')
    return 0 if success else 1


def interrupted(signum, frame):
    raise InterruptedError(f'received signal {signum}')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--suite', required=True)
    parser.add_argument('--archive', required=True, type=Path)
    parser.add_argument('--temporary-parent', type=Path)
    args = parser.parse_args()
    signal.signal(signal.SIGTERM, interrupted)
    signal.signal(signal.SIGINT, interrupted)
    try:
        return run_pair(ROOT, args.archive, args.temporary_parent, args.suite)
    except ValueError as failure:
        parser.error(str(failure))


if __name__ == '__main__':
    raise SystemExit(main())
