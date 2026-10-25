# SPDX-License-Identifier: GPL-3.0-or-later
"""Collect native-only scheduling diagnostics; never qualifies guest behavior."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import socket
import subprocess
import sys
import time
import traceback

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'scripts'))
from ipv6_router_peer import Peer
from tcp_fault_native import Capture


def digest(path):
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def trace_command(path, value):
    # Trace control files interpret writes as commands. Never truncate or append.
    descriptor = os.open(path, os.O_WRONLY)
    try:
        payload = value.encode()
        if os.write(descriptor, payload) != len(payload):
            raise OSError('incomplete trace control command')
    finally:
        os.close(descriptor)


def child(args):
    if Path('/proc/self/ns/net').stat().st_ino == args.parent_net_ns:
        raise ValueError('diagnostic requires a separate network namespace')
    directory = args.directory / 'namespace'
    directory.mkdir()
    for scope in ('all', 'default'):
        Path(f'/proc/sys/net/ipv6/conf/{scope}/disable_ipv6').write_text('1\n')
    peer = Peer(0, native=True)
    for command in (
        ['ip', 'link', 'add', 'eth0', 'type', 'veth', 'peer', 'name', 'peer0'],
        ['ip', 'link', 'set', 'eth0', 'address', peer.guest.hex(':')],
        ['ip', 'link', 'set', 'peer0', 'address', peer.mac.hex(':'), 'up']):
        subprocess.run(command, check=True)
    # This is the original complete zero-lifetime, four-prefix advertisement.
    frame = peer.advertisement(lifetime=0, valid=0, preferred=0, hops=41,
        pio_flags=((5, 0xc0), (6, 0x40), (7, 0xc0), (8, 0x40)))
    expected = 'deacfb0ca27f1fbad75f0d68c350183dde5d4abc1d7ca932891a5334032b3da9'
    if hashlib.sha256(frame).hexdigest() != expected:
        raise ValueError('diagnostic advertisement differs from original failed packet')
    packet = directory / 'original-advertisement.bin'
    packet.write_bytes(frame)
    capture = Capture('peer0', directory/'lane0.pcap')
    command = [str(args.directory/'program'), str(packet), '3000']
    receipt = dict(diagnostic_only=True, feature_acceptance=False, command=command,
                   original_one_second_assertion_unchanged=True,
                   post_failure_observation_is_not_qualification=True)
    began = time.monotonic()
    try:
        with (directory/'serial.log').open('xb') as log:
            process = subprocess.Popen(command, stdout=log, stderr=subprocess.STDOUT)
            try:
                receipt['returncode'] = process.wait(timeout=600)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait()
                receipt.update(timed_out=True, returncode=process.returncode)
    finally:
        receipt['capture'] = capture.close()
    text = (directory/'serial.log').read_text()
    receipt.update(seconds=time.monotonic()-began,
        completed_cases=len(re.findall(r'^PIO_RACE_CASE ', text, re.M)),
        original_assertion_failure_reproduced=('PIO_RACE_REPRODUCED ' in text and
            'IPV6_ROUTER_FIRST_PIO_REJECT ' in text and 'metadata=1' in text),
        serial_sha256=digest(directory/'serial.log'), packet_sha256=digest(packet))
    receipt['collection_completed'] = (
        receipt['returncode'] == 0 and not receipt.get('timed_out') and
        text.splitlines().count('PIO_RACE_NOT_REPRODUCED cases=3000') == 1
    ) or (receipt['returncode'] == 1 and receipt['original_assertion_failure_reproduced'])
    (directory/'receipt.json').write_text(json.dumps(receipt, indent=2)+'\n')
    return 0 if receipt['collection_completed'] else 1


def collect(args):
    if os.geteuid() != 0:
        raise ValueError('native namespace and kernel tracing require root')
    args.directory.mkdir(parents=True, exist_ok=False)
    directory = args.directory
    command = ['gcc', '-std=gnu11', '-O2', '-g', '-Wall', '-Wextra', '-Werror',
        'scripts/diagnostics/ipv6_deprecation.c', '-o', str(directory/'program')]
    names = ['scripts/diagnostics/ipv6_deprecation.c',
             'scripts/diagnostics/ipv6_deprecation.py',
             'userspace/tests/net/ipv6_router.c', 'userspace/tests/net/ipv6_fixture.h',
             'scripts/ipv6_router_peer.py', 'scripts/tcp_fault_native.py']
    inputs = {name:digest(ROOT/name) for name in names}
    subprocess.run(command, cwd=ROOT, check=True)
    if any(digest(ROOT/name) != value for name,value in inputs.items()):
        raise ValueError('diagnostic inputs changed during compilation')
    receipt = dict(diagnostic_only=True, feature_acceptance=False,
        actual_kernel=platform.uname()._asdict(), CPUs=os.cpu_count(),
        workflow_commit=os.environ.get('GITHUB_SHA'),
        affinity=sorted(os.sched_getaffinity(0)),
        clocksource=Path('/sys/devices/system/clocksource/clocksource0/current_clocksource').read_text().strip(),
        source_sha256=inputs, compiler_command=command,
        compiler_version=subprocess.check_output(['gcc', '--version'], text=True),
        program_sha256=digest(directory/'program'),
        clocks_and_public_acceptance_bounds_unchanged=True)
    trace = Path('/sys/kernel/tracing')
    if not (trace/'kprobe_events').exists():
        subprocess.run(['mount', '-t', 'tracefs', 'tracefs', str(trace)], check=True)
    group = 'axiom64_pio_' + str(os.getpid())
    instance = trace/'instances'/group
    probes = {
        'verify': 'p:{g}/verify addrconf_verify_rtnl net=%di:x64',
        'verify_return': 'r:{g}/verify_return addrconf_verify_rtnl',
        'prefix': 'p:{g}/prefix addrconf_prefix_rcv_add_addr net=%di:x64',
        'prefix_return': 'r:{g}/prefix_return addrconf_prefix_rcv_add_addr result=$retval:s32',
        'schedule': 'p:{g}/schedule mod_delayed_work_on cpu=%di:s32 wq=%si:x64 work=%dx:x64 delay=%cx:u64',
        'cancel': 'p:{g}/cancel cancel_delayed_work work=%di:x64',
    }
    added = []
    previous_affinity = os.sched_getaffinity(0)
    worker_mask = Path('/sys/devices/virtual/workqueue/cpumask')
    previous_worker_mask = worker_mask.read_text() if args.serialize_worker else None
    try:
        if args.serialize_worker:
            cpu = min(previous_affinity)
            os.sched_setaffinity(0, {cpu})
            worker_mask.write_text(format(1 << cpu, 'x')+'\n')
            effective = worker_mask.read_text()
            if int(effective.strip().replace(',', ''), 16) != 1 << cpu:
                raise ValueError('actual unbound worker mask differs from selected packet CPU')
            receipt['worker_affinity_experiment'] = dict(
                CPU=cpu, actual_mask=effective.strip(), previous_mask=previous_worker_mask.strip(),
                original_SMP_kernel_unchanged=True,
                clocks_packets_final_flags_and_deadlines_unchanged=True)
        instance.mkdir()
        (instance/'buffer_size_kb').write_text('16384\n')
        (instance/'trace_clock').write_text('mono\n')
        (directory/'available-functions.txt').write_text((trace/'available_filter_functions').read_text())
        for name, definition in probes.items():
            trace_command(trace/'kprobe_events', definition.format(g=group)+'\n')
            added.append(name)
        (instance/'events'/group/'schedule/filter').write_text('delay != 2\n')
        (instance/'events'/group/'enable').write_text('1\n')
        (instance/'tracing_on').write_text('1\n')
        command = ['unshare', '--net', sys.executable, '-B', str(Path(__file__).resolve()),
            '--child', '--directory', str(directory), '--parent-net-ns',
            str(Path('/proc/self/ns/net').stat().st_ino)]
        with (directory/'driver.log').open('xb') as log:
            completed = subprocess.run(command, stdout=log, stderr=subprocess.STDOUT, timeout=650)
        receipt.update(child_returncode=completed.returncode,
                       collection_completed=completed.returncode == 0)
    except BaseException as error:
        receipt['error'] = type(error).__name__ + ': ' + str(error)
        (directory/'error.log').write_text(traceback.format_exc())
    finally:
        cleanup_errors = []
        if instance.exists():
            try:
                (instance/'tracing_on').write_text('0\n')
                (directory/'kernel-trace.log').write_text((instance/'trace').read_text())
                (directory/'trace-buffer-statistics.json').write_text(json.dumps({
                    file.parent.name:file.read_text() for file in (instance/'per_cpu').glob('cpu*/stats')},
                    indent=2)+'\n')
                if added:
                    (instance/'events'/group/'enable').write_text('0\n')
            except BaseException as error:
                cleanup_errors.append('trace retention: '+str(error))
            try:
                instance.rmdir()
            except BaseException as error:
                cleanup_errors.append('trace instance removal: '+str(error))
        for name in reversed(added):
            try:
                trace_command(trace/'kprobe_events', '-:'+group+'/'+name+'\n')
            except BaseException as error:
                cleanup_errors.append('probe removal '+name+': '+str(error))
        if previous_worker_mask is not None:
            try:
                worker_mask.write_text(previous_worker_mask)
            except BaseException as error:
                cleanup_errors.append('worker mask restoration: '+str(error))
            try:
                os.sched_setaffinity(0, previous_affinity)
            except BaseException as error:
                cleanup_errors.append('process affinity restoration: '+str(error))
            receipt['original_worker_mask_restored'] = worker_mask.read_text() == previous_worker_mask
            receipt['original_process_affinity_restored'] = os.sched_getaffinity(0) == previous_affinity
            if not receipt['original_worker_mask_restored'] or not receipt['original_process_affinity_restored']:
                cleanup_errors.append('diagnostic affinity restoration incomplete')
        if cleanup_errors:
            receipt.update(cleanup_errors=cleanup_errors, collection_completed=False)
        receipt['source_unchanged'] = all(digest(ROOT/name) == value for name,value in inputs.items())
        (directory/'receipt.json').write_text(json.dumps(receipt, indent=2)+'\n')
    print(json.dumps(receipt, indent=2))
    return 0 if receipt.get('collection_completed') and receipt['source_unchanged'] else 1


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--directory', type=Path, required=True)
    parser.add_argument('--serialize-worker', action='store_true',
        help='diagnostic only: use one packet/worker CPU on an expendable host, then restore masks')
    parser.add_argument('--child', action='store_true')
    parser.add_argument('--parent-net-ns', type=int)
    args = parser.parse_args()
    args.directory = args.directory.resolve()
    if not args.directory.is_relative_to(ROOT/'build'):
        raise ValueError('diagnostic output must remain under this checkout build directory')
    raise SystemExit(child(args) if args.child else collect(args))
