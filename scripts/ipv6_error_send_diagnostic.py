# SPDX-License-Identifier: GPL-3.0-or-later
"""Bounded diagnosis with retained binaries; never a merge-acceptance producer."""
import argparse
from concurrent.futures import ThreadPoolExecutor
import fcntl
import hashlib
import json
import os
from pathlib import Path
import platform
import selectors
import signal
import socket
import struct
import subprocess
import sys
import time

from fetch import ROOT
from ipv6_errors_peer import Peer
from ipv6_host_native import reserve_error_destination
from tcp_fault_native import Capture

PROFILES = ('native', 'static', 'dynamic')
PROGRAMS = {
    'native': 'a8ccc7ad65a5d0d31ad4051f0c725d5d7ea27a500047e85ebfc8acf685ffab3e',
    'static': '0eafb9314071c945c94ba548ab55a6b5e9f1356a474ae131ab6b5d2fa1d342cb',
    'dynamic': '818bac3c74212972184027a02c359beb41c00c326d8bec287bd3393bb402a1f6',
}
LOADER = 'e75d8845e08d11d43b798cd1435efc1ffdb707bcd17a4b68155c5cddfee4c730'


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def write(path, value):
    path.write_text(json.dumps(value, indent=2) + '\n')


def neighbor_state():
    """Read shared table capacity and namespace entries without changing policy."""
    result = dict(observed_ns=time.time_ns(), monotonic_ns=time.monotonic_ns(),
                  network_namespace=Path('/proc/self/ns/net').stat().st_ino,
                  kernel=platform.uname()._asdict(), files={}, commands={})
    paths = ['/proc/net/stat/ndisc_cache']
    paths.extend('/proc/sys/net/ipv6/neigh/default/' + name
                 for name in ('gc_thresh1', 'gc_thresh2', 'gc_thresh3', 'gc_interval'))
    for name in paths:
        try:
            result['files'][name] = dict(text=Path(name).read_text())
        except OSError as error:
            result['files'][name] = dict(error=str(error))
    for label, command in (
            ('tables', ['ip', '-j', '-s', 'ntable', 'show']),
            ('neighbors', ['ip', '-j', '-s', '-6', 'neighbor', 'show']),
            ('kernel_log', ['dmesg', '--color=never'])):
        try:
            observed = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                      text=True, timeout=5)
        except (OSError, subprocess.TimeoutExpired) as error:
            result['commands'][label] = dict(command=command, error=str(error))
            continue
        output = observed.stdout
        if label == 'kernel_log':
            output = '\n'.join(line for line in output.splitlines()
                               if any(word in line.lower()
                                      for word in ('neigh', 'ndisc', 'table overflow')))
        result['commands'][label] = dict(command=command, returncode=observed.returncode,
                                         stdout=output, stderr=observed.stderr)
    return result


def inputs(retained, profile):
    directory = retained / 'ipv6-errors-native-wire' / profile
    before = json.loads((directory / 'preexecution.json').read_text())
    for name, expected in before['source_sha256'].items():
        if sha(ROOT / name) != expected:
            raise ValueError('diagnostic source differs from retained execution: ' + name)
    program = directory / 'products' / (
        '1-ipv6-errors-dynamic' if profile == 'dynamic' else '0-ipv6-errors-' + profile)
    if sha(program) != PROGRAMS[profile] or PROGRAMS[profile] not in before['product_sha256'].values():
        raise ValueError('retained client bytes differ')
    command = [str(program)]
    if profile == 'dynamic':
        loader = directory / 'products/0-ld-musl-x86_64.so.1'
        if sha(loader) != LOADER or LOADER not in before['product_sha256'].values():
            raise ValueError('retained loader bytes differ')
        loader.chmod(0o555)
        command.insert(0, str(loader))
    program.chmod(0o555)
    return before, command


def child(args):
    before, command = inputs(args.retained, args.profile)
    if args.client != 'original':
        command[-1] = str(ROOT / 'build' / ('diagnostic-' + args.client))
    directory = args.output / args.label
    directory.mkdir(parents=True, exist_ok=False)
    namespace = Path('/proc/self/ns/net').stat().st_ino
    if namespace == args.parent_namespace:
        raise ValueError('diagnostic requires a separate network namespace')
    affinity = sorted(os.sched_getaffinity(0))
    cpu = affinity[PROFILES.index(args.profile) % len(affinity)]
    os.sched_setaffinity(0, {cpu})
    for name, value in before['settings'].items():
        subprocess.run(['sysctl', '-q', '-w', f'{name}={value}'], check=True)
    reservation = reserve_error_destination(args.parent_namespace)
    subprocess.run(['ip', 'link', 'set', 'lo', 'up'], check=True)
    write(directory / 'preexecution.json', dict(kernel=platform.uname()._asdict(),
        profile=args.profile, label=args.label, packet_cpu=cpu, previous_affinity=affinity,
        network_namespace=namespace, parent_network_namespace=args.parent_namespace,
        original_source_sha256=before['source_sha256'], command=command,
        original_product_sha256=before['product_sha256'], settings=before['settings'],
        error_destination=reservation, traced=args.trace, client=args.client,
        actual_command_sha256={name: sha(Path(name)) for name in command}, acceptance=False))
    if args.trace:
        command = ['strace', '-f', '-qq', '-s', '160', '-ttt', '-T', '-o',
            str(directory / 'syscalls.log'), '-e',
            'trace=sendto,sendmsg,recvmsg,recvfrom,connect,bind,setsockopt,getsockopt,close,dup',
            *command]
    peers = [Peer(lane, native=True) for lane in range(2)]
    taps, captures, statistics = [], [], []
    selector = selectors.DefaultSelector()
    process, error = None, None
    began = time.monotonic()
    try:
        for lane in range(2):
            tap = os.open('/dev/net/tun', os.O_RDWR | os.O_NONBLOCK)
            taps.append(tap)
            name = f'eth{lane}'
            fcntl.ioctl(tap, 0x400454ca, struct.pack('16sH', name.encode(), 0x1002))
            subprocess.run(['ip', 'link', 'set', 'dev', name, 'address',
                peers[lane].guest.hex(':'), 'mtu', '1500', 'up'], check=True)
            selector.register(tap, selectors.EVENT_READ, lane)
            captures.append(Capture(name, directory / f'lane{lane}.pcap'))
            peers[lane].observe_input = captures[-1].watch
        write(directory / 'neighbor-before-client.json', neighbor_state())
        with (directory / 'client.log').open('xb') as stream:
            environment = {key: value for key, value in os.environ.items()
                           if key in ('PATH', 'LANG', 'LC_ALL')}
            process = subprocess.Popen(command, stdin=subprocess.DEVNULL, stdout=stream,
                stderr=subprocess.STDOUT, start_new_session=True, env=environment)
            while process.poll() is None:
                if time.monotonic() - began > 120:
                    raise TimeoutError('original 120-second overall limit')
                for key, _ in selector.select(.02):
                    peers[key.data].receive(os.read(key.fd, 65535))
                for lane, peer in enumerate(peers):
                    peer.tick()
                    while peer.outgoing:
                        packet = peer.outgoing.pop(0)
                        if os.write(taps[lane], packet) != len(packet):
                            raise OSError('short native Ethernet injection')
    except Exception as failure:
        error = type(failure).__name__ + ': ' + str(failure)
    finally:
        if process is not None and process.poll() is None:
            os.killpg(process.pid, signal.SIGTERM)
            try:
                process.wait(timeout=2)
            except subprocess.TimeoutExpired:
                os.killpg(process.pid, signal.SIGKILL)
                process.wait()
        # The transient TAP links disappear when their last fd closes. Preserve
        # real namespace state while those links and their routes still exist.
        write(directory / 'neighbor-after-client.json', neighbor_state())
        for label, arguments in (('addresses', ['address', 'show']), ('routes', ['-6', 'route', 'show', 'table', 'all']),
                                 ('neighbors', ['-6', 'neigh', 'show'])):
            result = subprocess.run(['ip', '-j', *arguments], stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
            (directory / (label + '.json')).write_bytes(result.stdout)
        for capture in captures:
            statistics.append(capture.close())
        selector.close()
        for tap in taps:
            os.close(tap)
    text = (directory / 'client.log').read_text() if (directory / 'client.log').exists() else ''
    result = dict(profile=args.profile, label=args.label, returncode=process.returncode if process else None,
        observer_error=error, seconds=time.monotonic() - began, peers=[peer.result() for peer in peers],
        capture_statistics=statistics, observed_target_failure='actual original error input errno=22' in text,
        original_client_completed=process is not None and process.returncode == 0 and
            'IPV6_ERRORS_PASS adapters=2' in text and all(peer.passed for peer in peers),
        minimum_client_completed=process is not None and process.returncode == 0 and
            'IPV6_ERRORS_METADATA_ONLY_COMPLETE' in text and
            all(peer.metadata.passed and peer.extensions.passed for peer in peers),
        client=args.client,
        original_source_products_unchanged=inputs(args.retained, args.profile)[0] == before,
        diagnostic_only=True, acceptance=False)
    write(directory / 'receipt.json', result)
    print(json.dumps({key: result[key] for key in ('label', 'returncode', 'observer_error',
        'observed_target_failure', 'original_client_completed')}), flush=True)
    return 0


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--retained', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--child', action='store_true')
    parser.add_argument('--profile', choices=PROFILES)
    parser.add_argument('--label')
    parser.add_argument('--parent-namespace', type=int)
    parser.add_argument('--trace', action='store_true')
    parser.add_argument('--client', choices=('original', 'rebuilt', 'minimum', 'wire', 'local', 'wire0', 'wire1', 'delayed'), default='original')
    args = parser.parse_args()
    args.retained, args.output = args.retained.resolve(), args.output.resolve()
    if args.child:
        return child(args)
    args.output.mkdir(parents=True, exist_ok=False)
    for profile in PROFILES:
        inputs(args.retained, profile)
    plans = [dict(label='full-wire', profiles=['dynamic'] * 4, trace=False, client='wire'),
             dict(label='original-cohort', profiles=list(PROFILES), trace=False, client='original')]
    write(args.output / 'plan.json', dict(plans=plans, stop_on_pass=False,
        original_packet_clocks_and_deadlines=True, acceptance=False))
    results = []
    parent = Path('/proc/self/ns/net').stat().st_ino
    for plan in plans:
        write(args.output / (plan['label'] + '-neighbor-before.json'), neighbor_state())
        def run(item):
            number, profile = item
            label = plan['label'] + '-' + str(number) + '-' + profile
            command = ['unshare', '--net', sys.executable, '-B', str(Path(__file__).resolve()),
                '--child', '--retained', str(args.retained), '--output', str(args.output),
                '--profile', profile, '--label', label, '--parent-namespace', str(parent)]
            command.extend(['--client', plan['client']])
            if plan['trace']:
                command.append('--trace')
            with (args.output / (label + '.log')).open('xb') as stream:
                process = subprocess.run(command, stdout=stream, stderr=subprocess.STDOUT, timeout=135)
            receipt = args.output / label / 'receipt.json'
            return dict(label=label, harness_returncode=process.returncode,
                receipt=json.loads(receipt.read_text()) if receipt.exists() else None)
        with ThreadPoolExecutor(max_workers=len(plan['profiles'])) as pool:
            results.extend(pool.map(run, enumerate(plan['profiles'])))
        write(args.output / (plan['label'] + '-neighbor-after.json'), neighbor_state())
    write(args.output / 'receipt.json', dict(executions=results, diagnostic_only=True,
        original_required_run=43831112405, original_required_head='319f9697de8070997a051a8b6e72363b0112bfa5',
        original_host_failure_resolved=False, acceptance=False))
    print(json.dumps([dict(label=row['label'], harness_code=row['harness_returncode'],
        target_failure=(row['receipt'] or {}).get('observed_target_failure'),
        client_completed=(row['receipt'] or {}).get('original_client_completed')) for row in results]))
    return 0 if all(row['harness_returncode'] == 0 and row['receipt'] is not None for row in results) else 1


if __name__ == '__main__':
    raise SystemExit(main())
