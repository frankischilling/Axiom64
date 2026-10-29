# SPDX-License-Identifier: GPL-3.0-or-later
"""Overlap the complete native expiry comparison with isolated Ethernet guests."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import threading
import time

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'scripts'))
from ci.paired_network import capture, interrupted

PRODUCTS = ('ipv4-native', 'ipv4-tests', 'ipv4-dynamic', 'native-icmp-budget')


def digest(path):
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def stop(process):
    def send(number):
        try:
            os.killpg(process.pid, number)
        except ProcessLookupError:
            pass
        except PermissionError:
            # The native make process runs under sudo in CI. This process group
            # belongs to the Popen instance created below, including descendants.
            subprocess.run(['sudo', '-n', 'kill', '-' + signal.Signals(number).name.removeprefix('SIG'),
                            '--', '-' + str(process.pid)], check=False,
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    send(signal.SIGTERM)
    try:
        process.wait(timeout=5)
    except subprocess.TimeoutExpired:
        pass
    send(signal.SIGKILL)
    process.wait()


def run_window(root, commands=None, products=None):
    root = Path(root).resolve()
    output = root / 'build/network-window'
    output.mkdir(parents=True, exist_ok=False)
    original = commands is None
    if original:
        with (output / 'prepare.log').open('wb') as log:
            subprocess.run(['make', '-j2', *('build/' + name for name in PRODUCTS)], cwd=root,
                           stdout=log, stderr=subprocess.STDOUT, check=True)
        commands = {'native': ['sudo', '-n', 'make', '-j1', 'test-native-icmp-budget',
                               'test-ipv4-fragments-native'], 'guest': ['make', 'test-network']}
        products = [root / 'build' / name for name in PRODUCTS]
    if set(commands) != {'native', 'guest'}:
        raise ValueError('the network window requires both complete workers')
    before = {str(path.relative_to(root)): digest(path) for path in products or []}
    sources = {name: digest(root / name) for name in ('scripts/ci/network_window.py',
               'scripts/ci/paired_network.py', 'scripts/network_matrix.py',
               'scripts/ipv4_fragment_native.py', 'scripts/native_icmp_budget_test.py', 'Makefile')
               if (root / name).is_file()}
    workers, readers, records = {}, {}, {}
    waiters = []
    failures = []
    error = None
    started = time.monotonic_ns()
    try:
        for name, command in commands.items():
            records[name] = dict(command=command, start_monotonic_ns=time.monotonic_ns())
            process = subprocess.Popen(command, cwd=root, stdin=subprocess.DEVNULL,
                                       stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                       start_new_session=True)
            workers[name] = process
            records[name]['pid'] = process.pid
            reader = threading.Thread(target=capture,
                args=(process, output / (name + '.log'), name, failures))
            reader.start()
            readers[name] = reader
        # Waiters observe each completion independently; a slow native window
        # must not inflate the recorded guest duration.
        def wait(name, process):
            records[name].update(returncode=process.wait(), end_monotonic_ns=time.monotonic_ns())
        waiters = [threading.Thread(target=wait, args=(name, process)) for name, process in workers.items()]
        for waiter in waiters:
            waiter.start()
        for waiter in waiters:
            waiter.join()
    except BaseException as failure:
        error = f'{type(failure).__name__}: {failure}'
    finally:
        for process in workers.values():
            stop(process)
        for waiter in waiters:
            waiter.join()
        for name, process in workers.items():
            readers[name].join()
            process.stdout.close()
            records[name].update(returncode=process.returncode)
            records[name].setdefault('end_monotonic_ns', time.monotonic_ns())
        for record in records.values():
            record.setdefault('returncode', None)
            record.setdefault('end_monotonic_ns', time.monotonic_ns())
        unchanged = all((root / name).is_file() and digest(root / name) == value
                        for name, value in before.items())
        unchanged = unchanged and all(digest(root / name) == value for name, value in sources.items())
        passed = (error is None and not failures and unchanged and set(records) == {'native', 'guest'}
                  and all(row['returncode'] == 0 for row in records.values()))
        overlap = (min(row['end_monotonic_ns'] for row in records.values()) -
                   max(row['start_monotonic_ns'] for row in records.values())) if len(records) == 2 else 0
        report = dict(passed=passed, error=error, capture_failures=failures,
                      original_complete_commands=original, immutable_products=before,
                      source_sha256=sources, inputs_unchanged=unchanged, workers=records,
                      start_monotonic_ns=started, end_monotonic_ns=time.monotonic_ns(),
                      overlap_ns=max(0, overlap), original_clocks_and_deadlines_preserved=True)
        (output / 'results.json').write_text(json.dumps(report, indent=2) + '\n')
    return 0 if passed else 1


def validate_window(root, report):
    from network_matrix import cases
    root = Path(root)
    expected_commands = {'native': ['sudo', '-n', 'make', '-j1', 'test-native-icmp-budget',
                                   'test-ipv4-fragments-native'], 'guest': ['make', 'test-network']}
    expected_sources = {'scripts/ci/network_window.py', 'scripts/ci/paired_network.py',
                        'scripts/network_matrix.py', 'scripts/ipv4_fragment_native.py',
                        'scripts/native_icmp_budget_test.py', 'Makefile'}
    if not (report['passed'] and report['original_complete_commands'] and report['inputs_unchanged']
            and report['original_clocks_and_deadlines_preserved'] and
            set(report['workers']) == set(expected_commands) and
            set(report['immutable_products']) == {'build/' + name for name in PRODUCTS} and
            set(report['source_sha256']) == expected_sources):
        raise ValueError('both original workers and complete immutable input inventories are required')
    for name, worker in report['workers'].items():
        if not (worker['command'] == expected_commands[name] and worker['returncode'] == 0 and
                type(worker['pid']) is int and worker['pid'] > 0 and
                report['start_monotonic_ns'] <= worker['start_monotonic_ns'] <
                worker['end_monotonic_ns'] <= report['end_monotonic_ns']):
            raise ValueError('every original worker command, actual successful status and interval are required')
    overlap = min(w['end_monotonic_ns'] for w in report['workers'].values()) - \
              max(w['start_monotonic_ns'] for w in report['workers'].values())
    if overlap <= 0 or report['overlap_ns'] != overlap:
        raise ValueError('recorded overlap must match the actual worker intervals')
    if not all(digest(root / name) == value for name, value in
               {**report['immutable_products'], **report['source_sha256']}.items()):
        raise ValueError('original compiler products and observer source bytes must remain unchanged')
    rows = json.loads((root / 'build/network-results.json').read_text())
    expected = {(c['firmware'], c['transport'], tuple(c['models']), c['queue'], c.get('wrap', False),
                 c.get('fault'), c.get('pressure', False), c.get('status', True), c.get('mtu', 0)) for c in cases()}
    actual = [(r['firmware'], r['transport'], tuple(r['models']), r['rx_queue'], r['wrap'],
               r['fault'], r['pressure'], r['status_feature'], r['host_mtu']) for r in rows]
    if not (len(actual) == len(expected) and set(actual) == expected and
            all(r['passed'] and r['returncode'] == 1 and not r['timed_out'] and
                r['error'] is None and not r['missing'] for r in rows)):
        raise ValueError('every original Ethernet guest cell must complete exactly once')
    return len(rows)


def audit_window(root):
    from ipv4_fragment_native import verify_capture, verify_path_mtu, verify_path_lifetime, verify_preflight
    from ipv4_query_model import query_model
    root = Path(root)
    directory = root / 'build/network-window'
    report = json.loads((directory / 'results.json').read_text())
    guest_cells = validate_window(root, report)
    native = root / 'build/ipv4-fragments-native'
    receipt = json.loads((native / 'receipt.json').read_text())
    if not (receipt['passed'] and not receipt['pmtu_only'] and not receipt['lifetime_only'] and
            receipt['profiles'] == [dict(profile=name, returncode=0) for name in ('native', 'static', 'dynamic')]):
        raise ValueError('all three complete native profiles remain required')
    if not json.loads((root / 'build/native-icmp-budget-evidence/receipt.json').read_text())['passed']:
        raise ValueError('the original actual ICMP budget controls must pass')
    observations, preflights = [], []
    for profile in ('native', 'static', 'dynamic'):
        case = native / profile
        actual = json.loads((case / 'receipt.json').read_text())
        before = json.loads((case / 'preexecution.json').read_text())
        if not actual['passed'] or before['requested_fragment_timeout_seconds'] != 60 or \
                before['requested_path_mtu_lifetime_seconds'] != 600:
            raise ValueError('original complete native clocks and acceptance are required')
        preflight = verify_preflight(case, actual['capture_statistics'])
        preflights.append(dict(profile=profile, audit=preflight))
        for lane in range(2):
            capture_path, log = case / f'lane{lane}.pcap', case / 'client.log'
            observations.append(dict(profile=profile, lane=lane,
                expiry=verify_capture(capture_path, lane, log, native=True),
                path=verify_path_mtu(capture_path, lane, log, native=True,
                                     query_model=query_model(before['kernel'])),
                lifetime=verify_path_lifetime(capture_path, lane, log, native=True)))
    result = dict(passed=True, complete_native_profiles=3, captures=6, observations=observations,
                  preflight_audits=preflights,
                  original_complete_guest_command=True, original_guest_cells=guest_cells,
                  original_clocks_and_deadlines_preserved=True)
    (directory / 'audit.json').write_text(json.dumps(result, indent=2) + '\n')
    print(json.dumps({k: v for k, v in result.items() if k not in ('observations', 'preflight_audits')}), flush=True)
    return 0


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('mode', choices=('run', 'audit'))
    args = parser.parse_args()
    signal.signal(signal.SIGTERM, interrupted)
    signal.signal(signal.SIGINT, interrupted)
    return run_window(ROOT) if args.mode == 'run' else audit_window(ROOT)


if __name__ == '__main__':
    raise SystemExit(main())
