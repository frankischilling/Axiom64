# SPDX-License-Identifier: GPL-3.0-or-later
"""Measure first-ready observation latency; this experiment is not feature acceptance."""
import argparse
import hashlib
import json
from pathlib import Path
import platform
import shutil
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'scripts'))
import ipv6_device_test as device
from compile_uapi_client import audit_compile


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def instrument(original, fast):
    source = original.replace('#include "ipv6_device_fixture.h"',
                              '#include "../../userspace/tests/net/ipv6_device_fixture.h"')
    old = '''static void unavailable_window(unsigned subject) {
    uint64_t began = now();'''
    new = '''static void unavailable_window(unsigned subject) {
    uint64_t began = now(), previous_begin = 0, previous_addresses = 0, previous_end = 0;'''
    assert source.count(old) == 1
    source = source.replace(old, new)
    old = '''            struct inventory values = snapshot(subject);
            struct address_record value = {0};
            if (first_unavailable_ready(&values, &value))
                control(subject, READY, 1, &value);'''
    new = '''            uint64_t query_begin = now();
            struct inventory values = {0};
            dump(subject, RTM_GETADDR, &values);
            uint64_t query_addresses = now();
            dump(subject, RTM_GETROUTE, &values);
            uint64_t query_end = now();
            struct address_record value = {0};
            if (first_unavailable_ready(&values, &value)) {
                control(subject, READY, 1, &value);
                printf("[DEBUG-1018] subject=%u previous_begin=%llu previous_addresses=%llu previous_end=%llu ready_begin=%llu ready_addresses=%llu ready_end=%llu\\n", subject,
                       (unsigned long long)previous_begin, (unsigned long long)previous_addresses,
                       (unsigned long long)previous_end, (unsigned long long)query_begin,
                       (unsigned long long)query_addresses, (unsigned long long)query_end);
            }
            previous_begin = query_begin;
            previous_addresses = query_addresses;
            previous_end = query_end;'''
    assert source.count(old) == 1
    source = source.replace(old, new)
    if fast:
        begin = source.index('static void unavailable_window(')
        end = source.index('\nint main(', begin)
        body = source[begin:end]
        assert body.count('        pause_poll();') == 1
        body = body.replace('        pause_poll();', '''        struct timespec observation_delay = {0, 1000000};
        check(!nanosleep(&observation_delay, NULL), "diagnostic address observation polling");''')
        source = source[:begin] + body + source[end:]
    return source


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--reference', type=Path, required=True)
    parser.add_argument('--directory', type=Path, required=True)
    args = parser.parse_args()
    output = args.directory.resolve()
    assert output.is_relative_to(ROOT / 'build')
    output.mkdir(parents=True, exist_ok=False)
    assert platform.release() == '6.17.0-1022-azure', 'compare the actual failing hosted kernel'
    original = (ROOT / device.PENDING_SOURCE).read_text()
    assert hashlib.sha256(original.encode()).hexdigest() == 'aac1f5a1e9acbf2707de2263e4a1e24c188182693c15392318a61b69096890bd'
    programs = {}
    reference = args.reference / 'ipv6-device-native/ipv6-device-pending-native'
    reference_manifest = json.loads(reference.with_suffix('.inputs.json').read_text())
    assert digest(reference) == reference_manifest['product']['sha256']
    folder = output / 'reference'
    folder.mkdir()
    retained = folder / reference.name
    shutil.copy2(reference, retained)
    retained.chmod(0o755)
    shutil.copyfile(reference.with_suffix('.inputs.json'), retained.with_suffix('.inputs.json'))
    audit_compile(retained, ROOT)
    programs['reference'] = retained
    for name, fast in (('observed', False), ('fast-observer', True)):
        path = output / (name + '.c')
        path.write_text(instrument(original, fast))
        device.PENDING_SOURCE = path.relative_to(ROOT).as_posix()
        folder = output / name
        folder.mkdir()
        programs[name], _ = device.build('native', folder, 'regenerating')
    before = {name: digest(program) for name, program in programs.items()}
    rows = []
    (output / 'cases').mkdir()
    for trial in range(8):
        # Fixed, interleaved trials retain every result, including timing failures.
        for name, program in programs.items():
            case = output / 'cases' / f'{trial:02d}-{name}'
            command = ['unshare', '--mount', '--net', '--pid', '--fork', '--mount-proc',
                sys.executable, str(ROOT / 'scripts/ipv6_device_test.py'), '--child', 'native',
                '--action', 'carrier', '--state', 'regenerating', '--directory', str(case),
                '--parent-net-ns', str(Path('/proc/self/ns/net').stat().st_ino), '--program', str(program)]
            with (output / f'{trial:02d}-{name}.log').open('xb') as log:
                result = subprocess.run(command, cwd=ROOT, stdout=log, stderr=subprocess.STDOUT)
            receipt = json.loads((case / 'receipt.json').read_text())
            error = receipt['capture_audit_error']
            expected_error = error is None or error.startswith('regeneration NA to ready real bound:')
            row = dict(trial=trial, variant=name, command=command, returncode=result.returncode,
                client_sha256=digest(program), functional_passed=receipt['functional_passed'],
                strict_capture_passed=receipt['passed'], capture_error=error,
                diagnostic_complete=receipt['functional_passed'] and expected_error and
                    receipt['actual_process_exit'] == 0 and receipt['source_unchanged'] and
                    not receipt['packet_monitor_errors'] and
                    all(item['dropped'] == 0 for item in receipt['captures']) and
                    (result.returncode == 0) == receipt['passed'],
                observations=[line for line in (case / 'serial.log').read_text().splitlines()
                              if '[DEBUG-1018]' in line])
            rows.append(row)
            (output / 'results.json').write_text(json.dumps(rows, indent=2) + '\n')
            print(json.dumps({key: row[key] for key in ('trial', 'variant', 'functional_passed',
                'strict_capture_passed', 'capture_error', 'observations')}), flush=True)
    proof = dict(diagnostic_only=True, feature_acceptance=False, kernel=platform.release(),
        fixed_trials=8, variants=list(programs), profiles=len(rows),
        original_C_reference_retained=True, source_timing_bounds_unchanged=True,
        observation_only_difference_ns=dict(observed=20000000, fast_observer=1000000),
        program_hashes=before, binaries_unchanged=all(digest(program) == before[name]
            for name, program in programs.items()),
        diagnostic_complete=len(rows) == 24 and all(row['diagnostic_complete'] for row in rows))
    (output / 'diagnostic.json').write_text(json.dumps(proof, indent=2) + '\n')
    print(json.dumps(proof), flush=True)
    assert proof['diagnostic_complete'] and proof['binaries_unchanged']


if __name__ == '__main__':
    main()
