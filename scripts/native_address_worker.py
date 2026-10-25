# SPDX-License-Identifier: GPL-3.0-or-later
"""Run a dedicated native reference with packet and address work on one CPU."""
import argparse
import fcntl
import hashlib
import json
import os
from pathlib import Path
import platform
import signal
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
WORKER_MASK = Path('/sys/devices/virtual/workqueue/cpumask')
LOCK = Path('/run/lock/axiom64-native-address-worker.lock')


def bits(text):
    return int(text.strip().replace(',', ''), 16)


def cpu_mask(cpu):
    text = format(1 << cpu, 'x')
    groups = []
    while text:
        groups.append(text[-8:])
        text = text[:-8]
    return ','.join(reversed(groups))+'\n'


def run(command, receipt_path):
    if os.geteuid():
        raise ValueError('native worker scheduling requires root on a dedicated reference host')
    receipt_path = receipt_path.resolve()
    if not receipt_path.is_relative_to(ROOT/'build') or receipt_path.exists():
        raise ValueError('native worker receipt needs a fresh path under this checkout build directory')
    receipt_path.parent.mkdir(parents=True, exist_ok=True)
    receipt = dict(command=command, kernel=platform.uname()._asdict(), CPUs=os.cpu_count(),
        wrapper_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
        clocks_packets_flags_and_acceptance_deadlines_unchanged=True)
    previous_affinity = os.sched_getaffinity(0)
    previous_mask = None
    selected_mask = None
    lock = None
    process = None
    requested_signal = None
    previous_handlers = {number:signal.getsignal(number) for number in (signal.SIGTERM, signal.SIGINT)}
    def interrupted(number, frame):
        nonlocal requested_signal
        requested_signal = number
        raise InterruptedError('native reference interrupted by signal '+str(number))
    for number in previous_handlers:
        signal.signal(number, interrupted)
    errors = []
    try:
        descriptor = os.open(LOCK, os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
        lock = os.fdopen(descriptor, 'a')
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        previous_mask = WORKER_MASK.read_text()
        choices = sorted(cpu for cpu in previous_affinity if bits(previous_mask) & (1 << cpu))
        if not choices:
            raise ValueError('native process and unbound workers have no shared available CPU')
        cpu = choices[0]
        selected_mask = 1 << cpu
        os.sched_setaffinity(0, {cpu})
        WORKER_MASK.write_text(cpu_mask(cpu))
        actual_mask = WORKER_MASK.read_text()
        if bits(actual_mask) != selected_mask:
            raise ValueError('unbound worker CPU readback differs from the selected packet CPU')
        receipt.update(selected_CPU=cpu, previous_worker_mask=previous_mask.strip(),
            actual_worker_mask=actual_mask.strip(), previous_process_affinity=sorted(previous_affinity),
            actual_process_affinity=sorted(os.sched_getaffinity(0)))
        process = subprocess.Popen(command, cwd=ROOT, start_new_session=True)
        receipt['child_pid'] = process.pid
        try:
            receipt['child_process_affinity'] = sorted(os.sched_getaffinity(process.pid))
        except ProcessLookupError:
            receipt['child_process_affinity'] = None
        receipt['command_returncode'] = process.wait()
    except BaseException as error:
        errors.append(type(error).__name__+': '+str(error))
    finally:
        for number in previous_handlers:
            signal.signal(number, signal.SIG_IGN)
        if process is not None and process.poll() is None:
            try:
                os.killpg(process.pid, signal.SIGTERM)
                try:
                    process.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    os.killpg(process.pid, signal.SIGKILL)
                    process.wait()
                receipt['interrupted_child_returncode'] = process.returncode
            except BaseException as error:
                errors.append('owned child retirement: '+str(error))
        if previous_mask is not None:
            try:
                current = WORKER_MASK.read_text()
                if selected_mask is not None and bits(current) != selected_mask:
                    # Preserve another owner's newly selected global value.
                    raise ValueError('unbound worker mask changed outside this native reference')
                WORKER_MASK.write_text(previous_mask)
                receipt['original_worker_mask_restored'] = WORKER_MASK.read_text() == previous_mask
                if not receipt['original_worker_mask_restored']:
                    raise ValueError('original unbound worker mask was not restored')
            except BaseException as error:
                errors.append('worker mask restoration: '+str(error))
        try:
            os.sched_setaffinity(0, previous_affinity)
            receipt['original_process_affinity_restored'] = os.sched_getaffinity(0) == previous_affinity
            if not receipt['original_process_affinity_restored']:
                raise ValueError('original process affinity was not restored')
        except BaseException as error:
            errors.append('process affinity restoration: '+str(error))
        if lock is not None:
            lock.close()
        for number, handler in previous_handlers.items():
            signal.signal(number, handler)
        receipt['errors'] = errors
        receipt['passed'] = not errors and receipt.get('command_returncode') == 0
        with receipt_path.open('x') as output:
            output.write(json.dumps(receipt, indent=2)+'\n')
    print('NATIVE_ADDRESS_WORKER '+json.dumps(receipt), flush=True)
    if requested_signal is not None:
        return 128 + requested_signal
    if errors:
        return 1
    status = receipt['command_returncode']
    return status if status >= 0 else 128-status


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--receipt', type=Path, required=True)
    parser.add_argument('command', nargs=argparse.REMAINDER)
    args = parser.parse_args()
    command = args.command[1:] if args.command[:1] == ['--'] else args.command
    if not command:
        parser.error('one explicit native reference command is required')
    return run(command, args.receipt)


if __name__ == '__main__':
    raise SystemExit(main())
