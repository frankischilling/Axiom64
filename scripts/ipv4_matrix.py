#!/usr/bin/env python3
"""Run complete IPv4 profiles in isolated processes sharing immutable images."""
import argparse
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import sys
import time
from ci.paired_network import stop
from fetch import ROOT
from network_test import fixture
from ipv4_test import run


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def phase(fault, workers, results, destination):
    name = 'fault' if fault else 'normal'
    image = ROOT / f'build/axiom64-ipv4-{name}.iso'
    expected_image = digest(image)
    expected_kernel = digest(ROOT / 'build/axiom64.elf')
    pending = [(firmware, transport) for transport in ['modern', 'legacy']
               for firmware in ['bios', 'uefi']]
    prior, completed, active, observations = list(results), {}, [], []
    receipt = ROOT / f'build/ipv4-{name}-worker-results.json'
    started = time.monotonic_ns()

    def save():
        results[:] = prior + [completed[n] for n in sorted(completed)]
        destination.write_text(json.dumps(results, indent=2) + '\n')
        receipt.write_text(json.dumps(dict(workers=workers, image=str(image),
            image_sha256=expected_image, kernel_elf_sha256=expected_kernel,
            started_monotonic_ns=started, observed_monotonic_ns=time.monotonic_ns(),
            cases=observations), indent=2) + '\n')

    try:
        while pending or active:
            while pending and len(active) < workers:
                firmware, transport = pending.pop(0)
                label = f'ipv4-{firmware}-{transport}' + ('-fault' if fault else '')
                output = ROOT / f'build/{label}-worker-case-results.json'
                output.write_text('[]\n')
                timeout = 120 if fault else 780
                command = [sys.executable, '-u', __file__, '--worker', firmware, transport,
                           '--prepared-image', str(image), '--image-sha256', expected_image,
                           '--result-file', str(output), '--timeout', str(timeout)]
                if fault:
                    command.append('--fault')
                with (ROOT / f'build/{label}-worker.log').open('wb') as log:
                    process = subprocess.Popen(command, cwd=ROOT, stdout=log,
                        stderr=subprocess.STDOUT, stdin=subprocess.DEVNULL, start_new_session=True)
                row = dict(firmware=firmware, transport=transport, fault=fault, pid=process.pid,
                           command=command, started_monotonic_ns=time.monotonic_ns(),
                           result_file=output.name, terminal=False)
                observations.append(row)
                active.append((process, row, output, timeout, len(observations) - 1))
                save()
            for item in list(active):
                process, row, output, timeout, order = item
                overdue = time.monotonic_ns() - row['started_monotonic_ns'] > (timeout + 45) * 1000000000
                if process.poll() is None and not overdue:
                    continue
                stop(process)
                rows = json.loads(output.read_text())
                valid = (len(rows) == 1 and all(rows[0].get(key) == row[key]
                         for key in ('firmware', 'transport', 'fault')))
                result = rows[0] if valid else dict(firmware=row['firmware'],
                    transport=row['transport'], fault=fault, passed=False,
                    error='worker did not retain its exact profile result')
                if process.returncode or overdue:
                    result['passed'] = False
                    result['worker_error'] = ('worker exceeded its outer bound' if overdue else
                                              f'worker exited {process.returncode}')
                completed[order] = result
                row.update(terminal=True, finished_monotonic_ns=time.monotonic_ns(),
                           returncode=process.returncode, passed=result['passed'])
                active.remove(item)
                save()
                print(f'IPV4_PROFILE firmware={row["firmware"]} transport={row["transport"]} '
                      f'fault={int(fault)} passed={int(result["passed"])}', flush=True)
            if active:
                time.sleep(.05)
        if digest(image) != expected_image or digest(ROOT / 'build/axiom64.elf') != expected_kernel:
            for result in completed.values():
                result.update(passed=False, worker_error='shared image or debugger kernel changed')
            raise ValueError('shared IPv4 image or matching debugger kernel changed during execution')
        if len(completed) != 4 or not all(row['passed'] for row in completed.values()):
            raise RuntimeError(f'IPv4 {name} profiles failed; see {receipt}')
    finally:
        for process, row, _, _, _ in active:
            stop(process)
            row.update(terminal=True, finished_monotonic_ns=time.monotonic_ns(),
                       returncode=process.returncode, passed=False)
        save()


def main(workers=2):
    subprocess.run([sys.executable, 'scripts/tests/ipv4_matrix_test.py'], cwd=ROOT, check=True)
    results = []
    destination = ROOT / 'build/ipv4-results.json'
    try:
        for fault in [False, True]:
            fixture(program='ipv4-tests', script='userspace/tests/net/ipv4.sh',
                    environment={'AXIOM64_IP_FAULT': '1'} if fault else None)
            subprocess.run([sys.executable, 'scripts/image.py', '--test', '--suite', 'network',
                            '--output-name', 'ipv4-test.iso'], cwd=ROOT, check=True)
            name = 'fault' if fault else 'normal'
            shutil.copyfile(ROOT / 'build/ipv4-test.iso', ROOT / f'build/axiom64-ipv4-{name}.iso')
            phase(fault, workers, results, destination)
    finally:
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_text(json.dumps(results, indent=2) + '\n')
    print(f'IPV4_MATRIX_PASS boots={len(results)} workers={workers}', flush=True)


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--workers', type=int, choices=(1, 2, 4), default=2)
    parser.add_argument('--worker', nargs=2, metavar=('FIRMWARE', 'TRANSPORT'))
    parser.add_argument('--prepared-image', type=Path)
    parser.add_argument('--image-sha256')
    parser.add_argument('--result-file', type=Path)
    parser.add_argument('--timeout', type=int)
    parser.add_argument('--fault', action='store_true')
    args = parser.parse_args()
    if args.worker:
        if (args.worker[0] not in ('bios', 'uefi') or args.worker[1] not in ('modern', 'legacy') or
                not args.prepared_image or not args.result_file or not args.timeout or
                digest(args.prepared_image) != args.image_sha256):
            parser.error('worker needs an exact prepared image, valid profile, result file and timeout')
        result = run(*args.worker, args.timeout, args.fault, image=args.prepared_image, gdb_port=0)
        args.result_file.write_text(json.dumps([result], indent=2) + '\n')
        raise SystemExit(0 if result['passed'] else 1)
    if any((args.prepared_image, args.image_sha256, args.result_file, args.timeout, args.fault)):
        parser.error('prepared-image options apply only to an internal worker')
    main(args.workers)
