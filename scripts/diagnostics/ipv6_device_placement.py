# SPDX-License-Identifier: GPL-3.0-or-later
"""Compare owned worker placement using the unchanged original native client."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import shutil
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'scripts'))
from compile_uapi_client import audit_compile


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--reference', type=Path, required=True)
    args = parser.parse_args()
    assert os.geteuid() == 0 and platform.release() == '6.17.0-1022-azure'
    output = ROOT / 'build/device-placement-diagnostic'
    output.mkdir(parents=True, exist_ok=False)
    source = args.reference / 'ipv6-device-native/ipv6-device-pending-native'
    program = output / source.name
    shutil.copy2(source, program)
    program.chmod(0o755)
    shutil.copyfile(source.with_suffix('.inputs.json'), program.with_suffix('.inputs.json'))
    manifest = audit_compile(program, ROOT)
    product = digest(program)
    assert product == manifest['product']['sha256'] == '380e363c8f9070e500f446cc322fb05a7a472d9e721afa5fe3795bbf47a63254'
    wrapper = ROOT / 'scripts/native_address_worker.py'
    initial_affinity = sorted(os.sched_getaffinity(0))
    mask = Path('/sys/devices/virtual/workqueue/cpumask')
    initial_mask = mask.read_text()
    (output / 'cases').mkdir()
    rows = []
    for trial in range(8):
        # Alternate which placement runs first; all sixteen results are retained.
        order = ('ordinary', 'owned') if trial % 2 == 0 else ('owned', 'ordinary')
        for placement in order:
            case = output / 'cases' / f'{trial:02d}-{placement}'
            command = ['unshare', '--mount', '--net', '--pid', '--fork', '--mount-proc',
                sys.executable, str(ROOT / 'scripts/ipv6_device_test.py'), '--child', 'native',
                '--action', 'carrier', '--state', 'regenerating', '--directory', str(case),
                '--parent-net-ns', str(Path('/proc/self/ns/net').stat().st_ino), '--program', str(program)]
            worker_path = output / f'{trial:02d}-worker.json'
            launch = command if placement == 'ordinary' else [sys.executable, str(wrapper),
                '--receipt', str(worker_path), '--', *command]
            with (output / f'{trial:02d}-{placement}.log').open('xb') as log:
                result = subprocess.run(launch, cwd=ROOT, stdout=log, stderr=subprocess.STDOUT)
            receipt = json.loads((case / 'receipt.json').read_text())
            error = receipt['capture_audit_error']
            worker = json.loads(worker_path.read_text()) if placement == 'owned' else None
            restored = (sorted(os.sched_getaffinity(0)) == initial_affinity and mask.read_text() == initial_mask)
            worker_valid = worker is None or (not worker['errors'] and
                worker['original_worker_mask_restored'] and worker['original_process_affinity_restored'] and
                worker['command_returncode'] == result.returncode and
                worker['wrapper_sha256'] == digest(wrapper) and
                worker['actual_process_affinity'] == worker['child_process_affinity'] == [worker['selected_CPU']])
            row = dict(trial=trial, placement=placement, command=launch, returncode=result.returncode,
                client_sha256=digest(program), functional_passed=receipt['functional_passed'],
                strict_capture_passed=receipt['passed'], capture_error=error,
                placement_restored=restored, worker_receipt_verified=worker_valid,
                diagnostic_complete=receipt['functional_passed'] and
                    (error is None or error.startswith('regeneration NA to ready real bound:')) and
                    receipt['actual_process_exit'] == 0 and receipt['source_unchanged'] and
                    not receipt['packet_monitor_errors'] and restored and worker_valid and
                    all(item['dropped'] == 0 for item in receipt['captures']) and
                    (result.returncode == 0) == receipt['passed'])
            rows.append(row)
            (output / 'results.json').write_text(json.dumps(rows, indent=2) + '\n')
            print(json.dumps(row), flush=True)
    proof = dict(diagnostic_only=True, feature_acceptance=False, kernel=platform.release(),
        profiles=len(rows), fixed_trials=8, original_client_sha256=product,
        client_unchanged=digest(program) == product, wrapper_sha256=digest(wrapper),
        initial_process_affinity=initial_affinity, initial_worker_mask=initial_mask,
        original_clocks_protocol_settings_deadlines_and_quiet_intervals_unchanged=True,
        diagnostic_complete=len(rows) == 16 and all(row['diagnostic_complete'] for row in rows))
    (output / 'diagnostic.json').write_text(json.dumps(proof, indent=2) + '\n')
    print(json.dumps(proof), flush=True)
    assert proof['diagnostic_complete'] and proof['client_unchanged']


if __name__ == '__main__':
    main()
