# SPDX-License-Identifier: GPL-3.0-or-later
"""Check actual native packet-socket barriers and profile CPU ownership."""
import argparse
import fcntl
import hashlib
import json
import os
from pathlib import Path
import selectors
import shutil
import struct
import subprocess
import sys
import time
import zipfile

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'scripts'))
from ipv4_expiry_capture import encode_capture, read_capture
from ipv6_host_native import packet_profile_cpu
from tcp_capture_clock import bind_native_clock
from tcp_fault_native import Capture

CASES = 8192


def require(condition, reason):
    if not condition:
        raise ValueError(reason)


def inspect(rows):
    require(len(rows) == 2 * CASES, 'all original barrier frames')
    original = bytes.fromhex('02495036000052540012341088f14158434f') + bytes(42)
    for index, row in enumerate(rows):
        sequence, reply = divmod(index, 2)
        expected = bytearray(original)
        expected[20:24] = sequence.to_bytes(4, 'big')
        if reply:
            expected[:6], expected[6:12] = original[6:12], original[:6]
            expected[18] = 1
        require(row['frame'] == expected, 'exact ordered request and acknowledgment bytes')


def child(profile, directory, parent_namespace):
    ownership = packet_profile_cpu(profile, parent_namespace)
    directory.mkdir(exist_ok=False)
    (directory / 'ownership.json').write_text(json.dumps(ownership, indent=2) + '\n')
    # This Ethernet-only probe must not create unrelated IPv6 discovery traffic.
    subprocess.run(['sysctl', '-qw', 'net.ipv6.conf.all.disable_ipv6=1',
                    'net.ipv6.conf.default.disable_ipv6=1'], check=True)
    tap = os.open('/dev/net/tun', os.O_RDWR | os.O_NONBLOCK)
    selector = selectors.DefaultSelector()
    capture, process = None, None
    try:
        fcntl.ioctl(tap, 0x400454ca, struct.pack('16sH', b'eth0', 0x1002))
        subprocess.run(['ip', 'link', 'set', 'eth0', 'address', '52:54:00:12:34:10', 'up'], check=True)
        capture = Capture('eth0', directory / 'wire.pcap')
        selector.register(tap, selectors.EVENT_READ)
        count = 0
        began = time.monotonic()
        with (directory / 'client.log').open('xb') as log:
            process = subprocess.Popen([str(directory.parent / 'client.elf'), str(CASES)],
                stdout=log, stderr=subprocess.STDOUT)
            while process.poll() is None:
                require(time.monotonic() - began < 30, 'bounded actual barrier workload')
                for key, _ in selector.select(.01):
                    frame = os.read(key.fd, 65535)
                    require(len(frame) == 60 and frame[12:18] == b'\x88\xf1AXCO' and
                            frame[18] == 0 and int.from_bytes(frame[20:24], 'big') == count,
                            'actual ordered original request')
                    response = bytearray(frame)
                    response[:6], response[6:12] = frame[6:12], frame[:6]
                    response[18] = 1
                    if (count + 1) % 64 == 0:
                        capture.observe_injection(bytes(response), lambda packet: os.write(tap, packet))
                    else:
                        require(os.write(tap, response) == 60, 'whole actual acknowledgment injection')
                    count += 1
        require(process.returncode == 0 and count == CASES and
                (directory / 'client.log').read_text() == f'BARRIER_CLIENT_PASS cases={CASES} cpu_count=1\n',
                'complete actual client and inherited CPU affinity')
    finally:
        if process is not None and process.poll() is None:
            process.kill()
            process.wait()
        statistics = capture.close() if capture is not None else None
        selector.close()
        os.close(tap)
    (directory / 'statistics.json').write_text(json.dumps(statistics, indent=2) + '\n')
    rows = read_capture(directory / 'wire.pcap')
    inspect(rows)
    for row in rows:
        row['stamp'] = row['ns'] // 1000
    clock = bind_native_clock(directory / 'wire.pcap', rows, statistics)
    rejected = []
    with zipfile.ZipFile(directory / 'damaged.zip', 'x', zipfile.ZIP_DEFLATED) as archive:
        for name in ('reordered-acknowledgment', 'missing-acknowledgment', 'changed-request'):
            changed = [dict(row) for row in rows]
            if name == 'reordered-acknowledgment':
                changed[1], changed[2] = changed[2], changed[1]
            elif name == 'missing-acknowledgment':
                del changed[1]
            else:
                damaged = bytearray(changed[0]['frame'])
                damaged[25] = 1
                changed[0]['frame'] = bytes(damaged)
            encoded = encode_capture(changed)
            archive.writestr(name + '.pcap', encoded)
            scratch = directory / (name + '.pcap')
            scratch.write_bytes(encoded)
            try:
                inspect(read_capture(scratch))
            except ValueError:
                rejected.append(name)
            else:
                raise ValueError('altered original capture was accepted: ' + name)
            finally:
                scratch.unlink()
    result = dict(passed=True, profile_cpu_selector=profile, client_linkage='host-native',
                  cases=CASES, frames=2 * CASES,
                  ownership=ownership, clock=clock, serialized_controls_rejected=rejected)
    (directory / 'result.json').write_text(json.dumps(result, indent=2) + '\n')
    print(json.dumps(result), flush=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--directory', type=Path, default=ROOT / 'build/ipv6-capture-order')
    parser.add_argument('--child', choices=('native', 'static', 'dynamic'))
    parser.add_argument('--parent-network-namespace', type=int)
    args = parser.parse_args()
    if args.child:
        child(args.child, args.directory, args.parent_network_namespace)
        return 0
    parent_namespace = Path('/proc/self/ns/net').stat().st_ino
    previous = sorted(os.sched_getaffinity(0))
    try:
        packet_profile_cpu('native', parent_namespace)
    except ValueError:
        pass
    else:
        raise ValueError('parent namespace scheduling was accepted')
    require(sorted(os.sched_getaffinity(0)) == previous, 'parent CPU ownership remains unchanged')
    directory = args.directory.resolve()
    require(directory.is_relative_to((ROOT / 'build').resolve()), 'designated fresh evidence output')
    directory.mkdir(parents=True, exist_ok=False)
    source = ROOT / 'scripts/tests/native_ipv6_barrier.c'
    command = ['cc', '-std=c11', '-O2', '-Wall', '-Wextra', '-Werror', str(source), '-o', str(directory / 'client.elf')]
    subprocess.run(command, check=True)
    shutil.copy2(source, directory / 'client.c')
    (directory / 'compile.json').write_text(json.dumps(dict(command=command,
        source_sha256=hashlib.sha256(source.read_bytes()).hexdigest(),
        program_sha256=hashlib.sha256((directory / 'client.elf').read_bytes()).hexdigest()), indent=2) + '\n')
    for profile in ('native', 'static', 'dynamic'):
        subprocess.run(['unshare', '--net', sys.executable, '-B', __file__, '--child', profile,
            '--parent-network-namespace', str(parent_namespace), '--directory', str(directory / profile)], check=True)
    require(sorted(os.sched_getaffinity(0)) == previous, 'all child scheduling stays private')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
