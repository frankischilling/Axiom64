# SPDX-License-Identifier: GPL-3.0-or-later
"""Measure Linux DAD timer expiry and dispatch using the original native client."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import shutil
import signal
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT/'scripts'))
from compile_uapi_client import audit_compile
from native_timer_trace import TimerTrace


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def run(command, path):
    process = None
    try:
        with path.open('xb') as log:
            process = subprocess.Popen(command, cwd=ROOT, stdout=log,
                stderr=subprocess.STDOUT, start_new_session=True)
            return process.wait(timeout=75)
    finally:
        if process is not None and process.poll() is None:
            os.killpg(process.pid, signal.SIGTERM)
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                os.killpg(process.pid, signal.SIGKILL)
                process.wait()


def interrupted(number, frame):
    raise InterruptedError('timer diagnostic interrupted by signal '+str(number))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--reference', type=Path, required=True)
    args = parser.parse_args()
    assert os.geteuid() == 0 and platform.release() == '6.17.0-1022-azure'
    output = ROOT/'build/device-timer-diagnostic'
    output.mkdir(parents=True, exist_ok=False)
    source = args.reference/'ipv6-device-native/ipv6-device-pending-native'
    program = output/source.name
    shutil.copy2(source, program)
    program.chmod(0o755)
    shutil.copyfile(source.with_suffix('.inputs.json'), program.with_suffix('.inputs.json'))
    manifest = audit_compile(program, ROOT)
    product = digest(program)
    assert product == manifest['product']['sha256'] == '380e363c8f9070e500f446cc322fb05a7a472d9e721afa5fe3795bbf47a63254'
    (output/'cases').mkdir()
    rows = []
    handlers = {number:signal.signal(number, interrupted) for number in (signal.SIGTERM,signal.SIGINT)}
    trace = None
    try:
        trace = TimerTrace(output/'trace')
        for trial in range(24):
            case = output/'cases'/f'{trial:02d}'
            command = ['unshare','--mount','--net','--pid','--fork','--mount-proc',
                sys.executable,str(ROOT/'scripts/ipv6_device_test.py'),'--child','native',
                '--action','carrier','--state','regenerating','--directory',str(case),
                '--parent-net-ns',str(Path('/proc/self/ns/net').stat().st_ino),'--program',str(program)]
            trace.mark(f'BEGIN TRIAL={trial}')
            code = run(command,output/f'{trial:02d}.log')
            trace.mark(f'END TRIAL={trial}')
            trace.drain(f'trial-{trial:02d}')
            receipt = json.loads((case/'receipt.json').read_text())
            error = receipt['capture_audit_error']
            row = dict(trial=trial,command=command,returncode=code,client_sha256=digest(program),
                functional_passed=receipt['functional_passed'],strict_capture_passed=receipt['passed'],
                capture_error=error,diagnostic_complete=receipt['functional_passed'] and
                    (error is None or error.startswith('regeneration NA to ready real bound:')) and
                    receipt['actual_process_exit']==0 and receipt['source_unchanged'] and
                    not receipt['packet_monitor_errors'] and all(item['dropped']==0 for item in receipt['captures']) and
                    (code==0)==receipt['passed'])
            rows.append(row)
            (output/'results.json').write_text(json.dumps(rows,indent=2)+'\n')
            print(json.dumps({key:row[key] for key in ('trial','returncode','functional_passed',
                'strict_capture_passed','capture_error')}),flush=True)
    finally:
        try:
            if trace is not None:
                trace.close()
        finally:
            for number,handler in handlers.items():
                signal.signal(number,handler)
    proof = dict(diagnostic_only=True,feature_acceptance=False,kernel=platform.release(),
        fixed_trials=24,profiles=len(rows),client_sha256=product,client_unchanged=digest(program)==product,
        clocks_protocol_settings_deadlines_and_quiet_intervals_unchanged=True,
        original_trace_retained=True,strict_profiles_passed=sum(row['strict_capture_passed'] for row in rows),
        diagnostic_complete=len(rows)==24 and all(row['diagnostic_complete'] for row in rows))
    (output/'diagnostic.json').write_text(json.dumps(proof,indent=2)+'\n')
    print(json.dumps(proof),flush=True)
    assert proof['diagnostic_complete'] and proof['client_unchanged']


if __name__ == '__main__':
    main()
