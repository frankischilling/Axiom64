# SPDX-License-Identifier: GPL-3.0-or-later
"""Compare controlled TCP loss with Linux in nested private network namespaces."""
import json
import errno
import os
from pathlib import Path
import socket
import struct
import subprocess
import sys
import tempfile
import threading
import time
from fetch import ROOT
from tcp_fault_peer import Peer, check
from tcp_fault_test import exercise


class Capture:
    def __init__(self, interface, path):
        self.socket = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(3))
        self.socket.bind((interface, 0))
        self.socket.settimeout(.05)
        self.output = path.open('wb')
        self.output.write(struct.pack('<IHHIIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1))
        self.stopping = threading.Event()
        self.error = None
        self.thread = threading.Thread(target=self.collect, daemon=True)
        self.thread.start()

    def collect(self):
        try:
            while not self.stopping.is_set():
                try:
                    frame = self.socket.recv(65535)
                except socket.timeout:
                    continue
                timestamp = time.time_ns()
                self.output.write(struct.pack('<IIII', timestamp // 1000000000,
                                              timestamp // 1000 % 1000000, len(frame), len(frame)) + frame)
        except Exception as exception:
            self.error = exception

    def close(self, removed=False):
        self.stopping.set()
        self.thread.join(timeout=1)
        self.socket.close()
        self.output.close()
        ended = (removed and isinstance(self.error, OSError) and
                 self.error.errno in (errno.ENETDOWN, errno.ENODEV))
        check(not self.thread.is_alive() and (self.error is None or ended),
              f'independent packet monitor completes: {self.error}')


def command(*args):
    subprocess.run(list(args), check=True, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)


def client(scratch, linkage):
    (scratch / 'client-ready').write_text(os.readlink('/proc/self/ns/net'))
    began = time.monotonic()
    while not (scratch / 'client-go').exists():
        check(time.monotonic() - began < 10, 'private client namespace setup deadline')
        time.sleep(.005)
    binary = ROOT / 'build' / f'tcp-fault-{linkage}'
    os.execv(str(binary), [str(binary), '--native'])


def namespace(scratch):
    parent = (scratch / 'parent-netns').read_text()
    fixture_namespace = os.readlink('/proc/self/ns/net')
    check(parent != fixture_namespace, 'raw peer requires an isolated network namespace')
    rows = []
    for linkage in ('native', 'static', 'dynamic'):
        for name in ('client-ready', 'client-go'):
            (scratch / name).unlink(missing_ok=True)
        process = subprocess.Popen(['unshare', '--net', sys.executable, __file__, '--client', str(scratch), linkage],
                                   stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        channels, monitors, result = [], [], None
        peers = [Peer(lane, minimum_fin_ms=180) for lane in range(2)]
        label = f'tcp-fault-linux-{linkage}'
        began = time.monotonic()
        try:
            while not (scratch / 'client-ready').exists():
                check(process.poll() is None and time.monotonic() - began < 5,
                      'nested Linux client namespace becomes available')
                time.sleep(.005)
            client_namespace = (scratch / 'client-ready').read_text()
            check(client_namespace not in (parent, fixture_namespace), 'Linux client has a separate network stack')
            command('nsenter', '-t', str(process.pid), '-n', 'ip', 'link', 'set', 'lo', 'up')
            for lane, peer in enumerate(peers):
                interface, guest = f'peer{lane}', f'eth{lane}'
                command('ip', 'link', 'add', interface, 'type', 'veth', 'peer', 'name', guest)
                command('ip', 'link', 'set', guest, 'netns', str(process.pid))
                command('ip', 'link', 'set', interface, 'address', peer.mac.hex(':'))
                command('ip', 'link', 'set', interface, 'up')
                command('ethtool', '-K', interface, 'tx', 'off', 'tso', 'off', 'gso', 'off', 'gro', 'off')
                prefix = ('nsenter', '-t', str(process.pid), '-n')
                command(*prefix, 'ip', 'link', 'set', guest, 'address', peer.guest.hex(':'))
                command(*prefix, 'ethtool', '-K', guest, 'tx', 'off', 'tso', 'off', 'gso', 'off', 'gro', 'off')
                command(*prefix, 'ip', 'addr', 'add', f'10.23.{lane + 1}.2/24', 'dev', guest)
                command(*prefix, 'ip', 'link', 'set', guest, 'up')
                channel = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(3))
                channel.bind((interface, 0))
                channels.append(channel)
                monitors.append(Capture(interface, ROOT / 'build' / f'{label}-lane{lane}.pcap'))
            (scratch / 'client-go').write_text('go\n')
            log_path = ROOT / 'build' / f'{label}.log'
            with log_path.open('wb') as log:
                text, results, error = exercise(process, peers, channels, 150, log, raw=True)
            required = ['TCP_FAULT_PASS flows=4 bytes_each=65536']
            required += [f'TCP_FAULT_FLOW_PASS lane={lane} role={role} bytes_each=65536'
                         for lane in range(2) for role in range(2)]
            missing = [marker for marker in required if marker not in text]
            peer_path = ROOT / 'build' / f'{label}-peer.json'
            peer_path.write_text(json.dumps([dict(lane=peer.lane, frames=peer.frames) for peer in peers], indent=2) + '\n')
            result = dict(linkage=linkage, returncode=process.returncode, error=error, missing=missing,
                          parent_namespace=parent, peer_namespace=fixture_namespace, client_namespace=client_namespace,
                          peers=[{key: value for key, value in peer.items() if key != 'frames'} for peer in results],
                          peer=peer_path.name, captures=[f'{label}-lane{lane}.pcap' for lane in range(2)],
                          log=log_path.name, seconds=round(time.monotonic() - began, 3),
                          passed=not error and not missing and process.returncode == 0 and 'TCP_FAULT_FAIL' not in text)
        finally:
            if process.poll() is None:
                process.kill()
            process.wait()
            for channel in channels:
                channel.close()
            for monitor in monitors:
                monitor.close(removed=result is not None and result['passed'])
        rows.append(result)
        (ROOT / 'build/tcp-fault-native-results.json').write_text(json.dumps(rows, indent=2) + '\n')
        print(json.dumps(result), flush=True)
        if not result['passed']:
            print(text[-5000:], flush=True)
            raise SystemExit('Native controlled TCP loss comparison failed')


def main():
    if len(sys.argv) == 4 and sys.argv[1] == '--client':
        client(Path(sys.argv[2]), sys.argv[3])
        return
    if len(sys.argv) == 3 and sys.argv[1] == '--namespace':
        namespace(Path(sys.argv[2]))
        return
    check(len(sys.argv) == 1, 'known native controlled TCP arguments')
    subprocess.run(['make', '-s', '-j2', 'build/tcp-fault-native', 'build/tcp-fault-static',
                    'build/tcp-fault-dynamic'], cwd=ROOT, check=True)
    original = os.readlink('/proc/self/ns/net')
    with tempfile.TemporaryDirectory(prefix='axiom64-tcp-loss-') as temporary:
        scratch = Path(temporary)
        (scratch / 'parent-netns').write_text(original)
        completed = subprocess.run(['unshare', '--net', sys.executable, __file__, '--namespace', str(scratch)],
                                   capture_output=True, text=True, timeout=480)
    check(os.readlink('/proc/self/ns/net') == original, 'native loss comparison preserves the host network namespace')
    print(completed.stdout, end='', flush=True)
    if completed.returncode:
        print(completed.stderr, end='', flush=True)
    check(completed.returncode == 0, 'all isolated Linux controlled TCP comparisons pass')


if __name__ == '__main__':
    main()
