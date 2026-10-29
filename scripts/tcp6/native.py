# SPDX-License-Identifier: GPL-3.0-or-later
"""Execute exact IPv6 TCP clients on two TAP interfaces in a private namespace."""
import fcntl
import json
import os
from pathlib import Path
import platform
import signal
import socket
import struct
import subprocess
import sys
import time
from fetch import ROOT
from tcp6.observation import Capture
from tcp_fault_test import exercise
from tcp_fault_peer import check
from tcp6.inputs import digest, write
from tcp6.peer import Peer
from tcp6.capture import verify


class Tap:
    def __init__(self, name):
        self.fd = os.open('/dev/net/tun', os.O_RDWR | os.O_NONBLOCK)
        fcntl.ioctl(self.fd, 0x400454ca, struct.pack('16sH', name.encode(), 0x1002))

    def fileno(self):
        return self.fd

    def setblocking(self, enabled):
        os.set_blocking(self.fd, enabled)

    def recvfrom(self, size):
        return os.read(self.fd, size), ('tap', 0, socket.PACKET_HOST)

    def send(self, frame):
        return os.write(self.fd, frame)

    def close(self):
        os.close(self.fd)


def client(directory, profile):
    command = [str(directory / 'program'), '--native']
    if profile == 'dynamic':
        command.insert(0, str(directory / 'loader'))
    began = time.monotonic_ns()
    process = subprocess.Popen(command, cwd=ROOT, stdin=subprocess.DEVNULL)
    record = dict(pid=process.pid, owner_pid=os.getpid(), command=command,
                  actual=sorted(os.sched_getaffinity(process.pid)),
                  namespace=Path('/proc/self/ns/net').stat().st_ino,
                  kernel=platform.release(), start_monotonic_ns=began)
    write(directory / 'client-execution.json', record)
    returncode = process.wait()
    record.update(returncode=returncode, end_monotonic_ns=time.monotonic_ns())
    write(directory / 'client-execution.json', record)
    print(f'TCP_FAULT_NATIVE_DONE status={returncode}', flush=True)
    return returncode


def child(directory, profile, parent_namespace, suite='loss'):
    from tcp6.profiles import definition
    config = definition(suite)
    own_namespace = Path('/proc/self/ns/net').stat().st_ino
    check(own_namespace != parent_namespace, 'native TCP6 runs in a new network namespace')
    packet_cpu = None
    if suite == 'errors':
        from ipv6_host_native import packet_profile_cpu
        # Error phases require causal request/reply ordering. Enqueue TAP input
        # and client requests on the same CPU while retaining original captures.
        packet_cpu = packet_profile_cpu(profile, parent_namespace)
    settings = {}
    accept_ra = int(config.get('router_hop_control', False))
    def command(*args):
        return subprocess.check_output(args, text=True, stderr=subprocess.STDOUT).strip()
    for key, value in (
        ('net.ipv6.conf.all.disable_ipv6', 0), ('net.ipv6.conf.default.disable_ipv6', 0),
        ('net.ipv6.conf.default.addr_gen_mode', 1),
        ('net.ipv6.conf.all.accept_ra', accept_ra), ('net.ipv6.conf.default.accept_ra', accept_ra),
        ('net.ipv6.conf.all.autoconf', 0), ('net.ipv6.conf.default.autoconf', 0),
        ('net.ipv6.conf.all.enhanced_dad', 0), ('net.ipv6.conf.default.enhanced_dad', 0),
        ('net.ipv6.auto_flowlabels', 0)):
        command('sysctl', '-qw', f'{key}={value}')
        settings[key] = command('sysctl', '-n', key)
        check(settings[key] == str(value), 'actual native namespace setting')
    taps, captures, statistics, interfaces = [], [], [], []
    peers = [config['peer'](lane, minimum_fin_ms=180, native=True) for lane in range(2)]
    products = json.loads((directory / 'products.json').read_text())
    check(all(digest(directory / name) == fingerprint for name, fingerprint in products.items()),
          'exact frozen native executable inputs')
    process, error, text, results, returncode = None, None, '', [], None
    began = time.monotonic_ns()
    try:
        for lane, peer in enumerate(peers):
            name = f'eth{lane}'
            taps.append(Tap(name))
            command('ip', 'link', 'set', 'dev', name, 'address', peer.guest.hex(':'), 'mtu', '1500')
            command('ip', 'link', 'set', 'dev', name, 'up')
            captures.append(Capture(name, directory / f'lane{lane}.pcap'))
            if hasattr(peer, 'observe_input'):
                peer.observe_input = captures[-1].watch
            interfaces.append(json.loads(command('ip', '-j', '-d', 'link', 'show', 'dev', name))[0])
        write(directory / 'interfaces.json', interfaces)
        invocation = [sys.executable, '-B', 'scripts/tcp6_test.py', '--client', profile,
                      '--output-directory', str(directory), '--suite', suite]
        process = subprocess.Popen(invocation, cwd=ROOT, stdin=subprocess.DEVNULL,
                                   stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                   start_new_session=True)
        if packet_cpu is not None:
            packet_cpu['tasks'] = [dict(tid=int(task.name), actual=sorted(os.sched_getaffinity(int(task.name))))
                                   for task in sorted(Path('/proc/self/task').iterdir())]
            packet_cpu['wrapper'] = dict(pid=process.pid, actual=sorted(os.sched_getaffinity(process.pid)))
        write(directory / 'preexecution.json', dict(profile=profile, kernel=platform.release(),
            namespace=own_namespace, parent_namespace=parent_namespace, settings=settings,
            command=invocation, deadline_seconds=150, products=products, packet_cpu=packet_cpu,
            start_monotonic_ns=began))
        with (directory / 'client.log').open('xb') as log:
            text, results, error, returncode = exercise(process, peers, taps, 150, log, raw=True)
        process.wait(timeout=2)
    except Exception as failure:
        error = f'{type(failure).__name__}: {failure}'
    finally:
        if process is not None and process.poll() is None:
            os.killpg(process.pid, signal.SIGKILL)
            process.wait()
        for capture in captures:
            try:
                statistics.append(capture.close())
            except Exception as failure:
                error = error or f'capture: {failure}'
        for tap in taps:
            tap.close()
    write(directory / 'peers.json', [dict(lane=peer.lane, frames=peer.frames) for peer in peers])
    audits = []
    if not error:
        try:
            audits = [config['verify'](directory / f'lane{lane}.pcap', lane, text, native=True,
                             statistics=statistics[lane]) for lane in range(2)]
        except Exception as failure:
            error = f'independent capture: {failure}'
    passed = (not error and returncode == 0 and len(results) == 2 and
              text.splitlines().count(config['marker']) == 1 and
              all(digest(directory / name) == fingerprint for name, fingerprint in products.items()))
    receipt = dict(passed=passed, profile=profile, native=True, suite=suite, error=error, returncode=returncode,
        results=[{key: value for key, value in row.items() if key != 'frames'} for row in results],
        capture_statistics=statistics, start_monotonic_ns=began, end_monotonic_ns=time.monotonic_ns(),
        independent_capture_audited=len(audits) == 2, capture_audits=audits)
    write(directory / 'receipt.json', receipt)
    print(json.dumps({key: value for key, value in receipt.items()
                      if key not in ('results', 'capture_statistics', 'capture_audits')}), flush=True)
    return 0 if passed else 1
