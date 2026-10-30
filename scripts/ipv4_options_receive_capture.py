# SPDX-License-Identifier: GPL-3.0-or-later
"""Capture option-bearing loopback packets in an isolated Linux network namespace."""
from pathlib import Path
from datetime import datetime, timezone
import argparse
import hashlib
import json
import os
import platform
import select
import socket
import struct
import subprocess
import sys
import time

from fetch import ROOT

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('--output', type=Path, default=ROOT / 'build/ipv4-options-receive-native.json')
parser.add_argument('--namespace-parent', help=argparse.SUPPRESS)
args = parser.parse_args()
if os.geteuid() != 0:
    raise ValueError('native raw packet observation requires root')
target = args.output.resolve()
if target.exists():
    raise ValueError('refusing to overwrite native packet observations')
target.parent.mkdir(parents=True, exist_ok=True)

def host_settings():
    return {f'{device}.{name}': (Path('/proc/sys/net/ipv4/conf') / device / name).read_text()
            for device in ('all', 'default', 'lo')
            for name in ('accept_source_route', 'rp_filter', 'forwarding')}

if args.namespace_parent is None:
    original = host_settings()
    namespace = os.readlink('/proc/self/ns/net')
    subprocess.run(['unshare', '--net', sys.executable, '-B', str(Path(__file__).resolve()),
                    '--namespace-parent', namespace, '--output', str(target)],
                   stdin=subprocess.DEVNULL, check=True, timeout=30)
    if original != host_settings():
        raise ValueError('parent network settings changed during the isolated capture')
    record = json.loads(target.read_text())
    record['host_sysctls_unchanged'] = True
    record['parent_namespace'] = namespace
    target.write_text(json.dumps(record, indent=2))
    print(json.dumps(dict(output=str(target), rows=len(record['rows']),
                          sha256=hashlib.sha256(target.read_bytes()).hexdigest(),
                          host_sysctls_unchanged=True)))
    raise SystemExit(0)
parent = os.readlink(f'/proc/{os.getppid()}/ns/net')
if parent != args.namespace_parent or os.readlink('/proc/self/ns/net') == parent:
    raise ValueError('capture configuration requires a different namespace from its parent')
subprocess.run(['ip', 'link', 'set', 'lo', 'up'], check=True)
for device in ('all', 'lo'):
    for name, value in [('accept_source_route', '1'), ('rp_filter', '0'), ('forwarding', '0')]:
        (Path('/proc/sys/net/ipv4/conf') / device / name).write_text(value)
vectors = []
def add(name, value):
    value = bytes(value)
    assert len(value) <= 40
    vectors.append((name, value + b'\0' * (-len(value) % 4)))

add('empty', b'')
add('nops', [1] * 4)
add('end-clears-tail', [0, 255, 255, 255])
for kind in (2, 7, 68, 130, 131, 134, 136, 137, 148, 255):
    for length in (2, 3, 4, 7, 8, 12):
        value = [kind, length] + [0] * (length - 2)
        if kind in (7, 131, 137) and length >= 3:
            value[2] = 4
        if kind == 68 and length >= 3:
            value[2] = 5
        add(f'type-{kind}-{length}', value)
for length in (3, 7, 8, 11, 15):
    for pointer in (0, 3, 4, 5, length + 1, 255):
        add(f'rr-{length}-{pointer}', [7, length, pointer] + [0xa5] * (length - 3))
for length in (4, 8, 12, 16):
    for pointer in (4, 5, 6, length + 1):
        for flag in (0, 1, 2, 3, 15, 0xf0, 0xf3):
            add(f'ts-{length}-{pointer}-{flag}', [68, length, pointer, flag] + [0xa5] * (length - 4))
for address in (0, 0x7f000001, 0x7f000002, 0xe0000001, 0xffffffff, 0xc0000201, 0xf0000001):
    add(f'prespecified-{address:08x}', [68, 12, 5, 3] + list(address.to_bytes(4, 'big')) + [0xa5] * 4)
for kind in (131, 137):
    for pointer in (3, 4, 8, 12, 255):
        add(f'route-{kind}-{pointer}', [kind, 11, pointer, 127, 0, 0, 1, 127, 0, 0, 2])
for option in ([7, 7, 4, 0, 0, 0, 0], [68, 8, 5, 0, 0, 0, 0, 0], [148, 4, 0, 0]):
    add('duplicate-' + str(option[0]), option + option)
add('rr-ts-order', [68, 8, 5, 0, 0, 0, 0, 0, 7, 7, 4, 0, 0, 0, 0])
add('duplicate-rr-short', [7, 7, 4, 0, 0, 0, 0, 7, 2])
add('duplicate-rr-pointer', [7, 7, 4, 0, 0, 0, 0, 7, 3, 3])
add('rr-room', [7, 15, 4] + [0] * 12)
add('ts-room', [68, 16, 5, 0] + [0] * 12)

receiver = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
receiver.bind(('0.0.0.0', 0))
port = receiver.getsockname()[1]
raw = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_UDP)
raw.bind(('0.0.0.0', 0))
sender = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_UDP)
sender.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
icmp = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
icmp.bind(('127.0.0.2', 0))
for descriptor in (receiver, raw):
    for option in (6, 7, 8, 12, 13):
        descriptor.setsockopt(socket.IPPROTO_IP, option, 1)
for descriptor in (receiver, raw, icmp):
    descriptor.setblocking(False)

def take(descriptor):
    packet, control, flags, address = descriptor.recvmsg(65536, 512)
    return dict(data=packet.hex(), control=[dict(level=level, type=kind, data=data.hex())
        for level, kind, data in control], flags=flags, address=address)

rows = []
began = time.monotonic()
for number, (name, options) in enumerate(vectors):
    for descriptor in (receiver, raw, icmp):
        while True:
            try:
                take(descriptor)
            except BlockingIOError:
                break
    marker = b'IPOPT_RX' + number.to_bytes(4, 'big')
    udp = struct.pack('!HHHH', 49157, port, 8 + len(marker), 0) + marker
    header = struct.pack('!BBHHHBBH4s4s', 0x45 + len(options) // 4, 34,
        20 + len(options) + len(udp), number + 1, 0x4000, 63, 17, 0,
        socket.inet_aton('127.0.0.2'), socket.inet_aton('127.0.0.1'))
    before = time.time_ns()
    assert sender.sendto(header + options + udp, ('127.0.0.1', port)) == 20 + len(options) + len(udp)
    found = {}
    deadline = time.monotonic() + 0.03
    descriptors = {receiver: 'udp', raw: 'raw', icmp: 'icmp'}
    while time.monotonic() < deadline:
        ready, _, _ = select.select(list(descriptors), [], [], max(0, deadline - time.monotonic()))
        for descriptor in ready:
            value = take(descriptor)
            # A separate serial payload identifies the datagram in both receive paths.
            if descriptors[descriptor] == 'icmp' or marker.hex() in value['data']:
                found[descriptors[descriptor]] = value
        if 'udp' in found and 'raw' in found:
            break
    rows.append(dict(name=name, input=options.hex(), before_ns=before, after_ns=time.time_ns(), **found))

settings = {}
for device in ('all', 'default', 'lo'):
    for name in ('accept_source_route', 'rp_filter', 'forwarding'):
        path = Path('/proc/sys/net/ipv4/conf') / device / name
        settings[f'{device}.{name}'] = path.read_text().strip()
record = dict(observed_at=datetime.now(timezone.utc).isoformat(), kernel=platform.release(),
    settings=settings, source_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
    loopback_packets_only=True, isolated_namespace_configured=True,
    network_namespace=os.readlink('/proc/self/ns/net'), elapsed_seconds=time.monotonic() - began,
    rows=rows, native_diagnostic_only=True)
with target.open('x') as stream:
    json.dump(record, stream, indent=2)
print(json.dumps(dict(rows=len(rows), raw=sum('raw' in row for row in rows),
    udp=sum('udp' in row for row in rows), icmp=sum('icmp' in row for row in rows),
    path=str(target), sha256=hashlib.sha256(target.read_bytes()).hexdigest(), settings=settings)))
