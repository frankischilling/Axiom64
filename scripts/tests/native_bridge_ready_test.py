# SPDX-License-Identifier: GPL-3.0-or-later
"""Exercise actual isolated bridge startup, delayed forwarding and rejection."""
import argparse
import json
import os
from pathlib import Path
import subprocess
import sys
import threading
import time
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'scripts'))
from native_bridge_ready import prepare


def ip(*arguments):
    subprocess.run(['ip', *arguments], check=True, stdout=subprocess.DEVNULL, timeout=5)


def child(directory, parent):
    assert Path('/proc/self/ns/net').stat().st_ino != parent
    for scope in ('all', 'default'):
        Path(f'/proc/sys/net/ipv6/conf/{scope}/disable_ipv6').write_text('1\n')
    for lane in range(2):
        ip('link', 'add', f'eth{lane}', 'type', 'veth', 'peer', 'name', f'peer{lane}')
        ip('link', 'add', f'bridge{lane}', 'type', 'bridge', 'stp_state', '0', 'mcast_snooping', '0')
        ip('link', 'set', f'bridge{lane}', 'up')
        ip('link', 'set', f'peer{lane}', 'master', f'bridge{lane}', 'up')
    results = []

    def case(name):
        path = directory / name
        path.mkdir()
        return path

    fresh = prepare(case('fresh'))
    assert fresh['passed'] and all(value == '1' for value in fresh['disable_ipv6'].values())
    results.append('fresh')
    restored = []
    observed = threading.Event()
    original_dump = subprocess.check_output
    holding = False

    def observe_dump(*arguments, **options):
        nonlocal holding
        if not holding:
            # Hold the real port after the setup's UP notifications, before
            # its first kernel dump. No fabricated link state reaches prepare.
            ip('link', 'set', 'peer1', 'down')
            holding = True
        # Return the untouched kernel dump, then release the fixture's delay.
        value = original_dump(*arguments, **options)
        observed.set()
        return value

    def restore():
        assert observed.wait(5)
        time.sleep(.25)
        ip('link', 'set', 'peer1', 'up')
        restored.append(time.monotonic_ns())

    worker = threading.Thread(target=restore)
    worker.start()
    try:
        with patch('native_bridge_ready.subprocess.check_output', side_effect=observe_dump):
            delayed = prepare(case('delayed'))
    finally:
        worker.join(timeout=5)
    assert not worker.is_alive() and restored
    assert delayed['passed'] and delayed['polls'] > 1
    assert delayed['initial_links']['peer1']['linkinfo']['info_slave_data']['state'] != 'forwarding'
    assert delayed['end_monotonic_ns'] - delayed['begin_monotonic_ns'] >= 200000000
    results.append('delayed')
    holding = False
    blocked = case('blocked')
    try:
        with patch('native_bridge_ready.subprocess.check_output', side_effect=observe_dump):
            prepare(blocked)
    except ValueError as error:
        assert 'setup deadline' in str(error)
    else:
        raise AssertionError('an unavailable bridge must prevent client launch')
    receipt = json.loads((blocked / 'native-link-ready.json').read_text())
    assert not receipt['passed'] and not receipt['workload_started']
    assert receipt['end_monotonic_ns'] - receipt['begin_monotonic_ns'] >= 2000000000
    results.append('blocked')
    Path('/proc/sys/net/ipv6/conf/eth0/disable_ipv6').write_text('0\n')
    enabled = case('enabled')
    try:
        prepare(enabled)
    except ValueError as error:
        assert 'IPv6 disabled' in str(error)
    else:
        raise AssertionError('premature IPv6 activation must prevent client launch')
    receipt = json.loads((enabled / 'native-link-ready.json').read_text())
    assert not receipt['passed'] and receipt['polls'] == 0 and not receipt['workload_started']
    results.append('enabled')
    (directory / 'receipt.json').write_text(json.dumps(dict(passed=True, cases=results,
        kernel=os.uname().release, real_bridge_and_veth=True, workload_reexecuted=False), indent=2)+'\n')
    print('NATIVE_BRIDGE_READY_CONTROLS_PASS cases=4 actual_forwarding_delay_and_rejection')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--directory', type=Path, default=ROOT / 'build/native-bridge-ready-tests')
    parser.add_argument('--child', type=int)
    args = parser.parse_args()
    directory = args.directory.resolve()
    if not directory.is_relative_to(ROOT / 'build'):
        raise ValueError('native startup controls require bounded build output')
    if os.geteuid():
        raise ValueError('actual isolated bridge controls require root')
    if args.child is not None:
        child(directory, args.child)
        return
    directory.mkdir(parents=True, exist_ok=False)
    subprocess.run(['unshare', '--mount', '--net', '--pid', '--fork', '--mount-proc',
        sys.executable, '-B', str(Path(__file__).resolve()), '--directory', str(directory),
        '--child', str(Path('/proc/self/ns/net').stat().st_ino)], check=True, timeout=30)


if __name__ == '__main__':
    main()
