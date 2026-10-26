# SPDX-License-Identifier: GPL-3.0-or-later
"""Qualify actual native timer-policy capture with the unchanged original client."""
import argparse
import hashlib
import json
from pathlib import Path
import platform
import shutil
import signal
import sys

ROOT=Path(__file__).resolve().parents[2]
sys.path.insert(0,str(ROOT/'scripts'))
from compile_uapi_client import audit_compile
from ipv6_device_pending_capture import inspect
from ipv6_device_timers import run,interrupted


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def execute(command,path):
    handlers={number:signal.signal(number,interrupted) for number in (signal.SIGTERM,signal.SIGINT)}
    try:
        return run(command,path)
    finally:
        for number,handler in handlers.items():
            signal.signal(number,handler)


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--reference',type=Path,required=True)
    args=parser.parse_args()
    assert platform.release()=='6.17.0-1022-azure'
    output=ROOT/'build/native-timer-policy-diagnostic'
    output.mkdir(parents=True,exist_ok=False)
    original=args.reference/'ipv6-device-native/ipv6-device-pending-native'
    program=output/original.name
    shutil.copy2(original,program);program.chmod(0o755)
    shutil.copyfile(original.with_suffix('.inputs.json'),program.with_suffix('.inputs.json'))
    manifest=audit_compile(program,ROOT)
    assert digest(program)==manifest['product']['sha256']=='380e363c8f9070e500f446cc322fb05a7a472d9e721afa5fe3795bbf47a63254'
    (output/'cases').mkdir()
    rows=[]
    for trial in range(24):
        case=output/'cases'/f'{trial:02d}'
        command=['unshare','--mount','--net','--pid','--fork','--mount-proc',sys.executable,
            str(ROOT/'scripts/ipv6_device_test.py'),'--child','native','--action','carrier',
            '--state','regenerating','--directory',str(case),'--parent-net-ns',
            str(Path('/proc/self/ns/net').stat().st_ino),'--program',str(program)]
        status=execute(command,output/f'{trial:02d}.log')
        receipt=json.loads((case/'receipt.json').read_text())
        policy=json.loads((case/'native-timer-policy.json').read_text())
        assert policy==receipt['native_timer_policy'] and policy['upper_us']==3212000
        old_errors=[]
        for lane in range(2):
            try:
                inspect(case/f'lane{lane}.pcap',lane,(case/'serial.log').read_text(),'carrier','regenerating',
                    native=True,statistics=receipt['captures'],native_kernel_release=receipt['kernel_release'])
            except ValueError as error:
                assert str(error).startswith('regeneration NA to ready real bound:')
                old_errors.append(str(error))
        row=dict(trial=trial,actual_new_source_policy_passed=receipt['passed'],actual_client_exit=receipt['actual_process_exit'],
            wrapper_exit=status,old_3100000us_contract_passed=not old_errors,old_errors=old_errors,
            native_upper_us=policy['upper_us'],guest_bound_us=3100000,
            source_unchanged=receipt['source_unchanged'],client_sha256=digest(program))
        rows.append(row)
        (output/'results.json').write_text(json.dumps(rows,indent=2)+'\n')
        print(json.dumps(row),flush=True)
    proof=dict(diagnostic_only=True,feature_acceptance=False,profiles=len(rows),
        actual_new_source_policy_passed=all(row['actual_new_source_policy_passed'] and
            row['actual_client_exit']==row['wrapper_exit']==0 and row['source_unchanged'] for row in rows),
        old_3100000us_contract_failed_profiles=sum(not row['old_3100000us_contract_passed'] for row in rows),
        original_C_program_unchanged=True,all_original_protocol_settings_and_observation_windows_retained=True)
    (output/'diagnostic.json').write_text(json.dumps(proof,indent=2)+'\n')
    print(json.dumps(proof),flush=True)
    assert len(rows)==24 and proof['actual_new_source_policy_passed']


if __name__=='__main__':
    main()
