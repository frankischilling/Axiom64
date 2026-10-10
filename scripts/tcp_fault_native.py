# SPDX-License-Identifier: GPL-3.0-or-later
"""Compare controlled TCP faults with Linux in nested private network namespaces."""
import argparse
import json
import os
from pathlib import Path
import socket
import signal
import struct
import subprocess
import sys
import tempfile
import threading
import time
from fetch import ROOT
from tcp_fault_peer import check
from tcp_fault_test import exercise, wire_configuration


class Capture:
    def __init__(self, interface, path):
        self.socket = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(3))
        # Linux SO_RCVBUFFORCE reserves a per-socket burst budget without
        # changing host sysctls. This isolated fixture already requires root.
        self.socket.setsockopt(socket.SOL_SOCKET, 33, 4 * 1024 * 1024)
        self.buffer_bytes = self.socket.getsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF)
        check(self.buffer_bytes >= 4 * 1024 * 1024, 'independent capture reserves its packet burst budget')
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
            while True:
                try:
                    frame = self.socket.recv(65535)
                except socket.timeout:
                    if self.stopping.is_set():
                        break
                    continue
                timestamp = time.time_ns()
                self.output.write(struct.pack('<IIII', timestamp // 1000000000,
                                              timestamp // 1000 % 1000000, len(frame), len(frame)) + frame)
        except Exception as exception:
            self.error = exception

    def close(self):
        self.stopping.set()
        self.thread.join(timeout=1)
        try:
            check(not self.thread.is_alive() and self.error is None,
                  f'independent packet monitor completes: {self.error}')
            # Linux SOL_PACKET/PACKET_STATISTICS counts kernel receive drops.
            packets, dropped = struct.unpack('II', self.socket.getsockopt(263, 6, 8))
            check(dropped == 0, f'independent packet monitor loses no actual frames: dropped={dropped}')
            return dict(packets=packets, dropped=dropped, buffer_bytes=self.buffer_bytes)
        finally:
            self.socket.close()
            self.output.close()


def command(*args):
    subprocess.run(list(args), check=True, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)


def client(scratch, linkage):
    (scratch / 'client-ready').write_text(os.readlink('/proc/self/ns/net'))
    began = time.monotonic()
    while not (scratch / 'client-go').exists():
        check(time.monotonic() - began < 10, 'private client namespace setup deadline')
        time.sleep(.005)
    binary = ROOT / 'build' / f'tcp-fault-{linkage}'
    completed = subprocess.run([str(binary), '--native'])
    print(f'TCP_FAULT_NATIVE_DONE status={completed.returncode}', flush=True)
    began = time.monotonic()
    while not (scratch / 'client-release').exists():
        check(time.monotonic() - began < 10, 'independent peer/capture completion deadline')
        time.sleep(.005)
    raise SystemExit(completed.returncode)


def namespace(scratch, wire='loss'):
    peer_type, wire_prefix = wire_configuration(wire)
    parent = (scratch / 'parent-netns').read_text()
    fixture_namespace = os.readlink('/proc/self/ns/net')
    check(parent != fixture_namespace, 'raw peer requires an isolated network namespace')
    rows = []
    for linkage in ('native', 'static', 'dynamic'):
        for name in ('client-ready', 'client-go', 'client-release'):
            (scratch / name).unlink(missing_ok=True)
        process = subprocess.Popen(['unshare', '--net', sys.executable, __file__, '--client', str(scratch), linkage],
                                   stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                   start_new_session=True)
        channels, monitors, result = [], [], None
        peers = [peer_type(lane, minimum_fin_ms=180) for lane in range(2)]
        label = f'{wire_prefix}-linux-{linkage}'
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
                text, results, error, returncode = exercise(process, peers, channels, 150, log, raw=True)
            required = ['TCP_FAULT_PASS flows=4 bytes_each=65536']
            required += [f'TCP_FAULT_FLOW_PASS lane={lane} role={role} bytes_each=65536'
                         for lane in range(2) for role in range(2)]
            missing = [marker for marker in required if marker not in text]
            peer_path = ROOT / 'build' / f'{label}-peer.json'
            peer_path.write_text(json.dumps([dict(lane=peer.lane, frames=peer.frames) for peer in peers], indent=2) + '\n')
            result = dict(wire=wire, linkage=linkage, returncode=returncode, error=error, missing=missing,
                          parent_namespace=parent, peer_namespace=fixture_namespace, client_namespace=client_namespace,
                          peers=[{key: value for key, value in peer.items() if key != 'frames'} for peer in results],
                          peer=peer_path.name, captures=[f'{label}-lane{lane}.pcap' for lane in range(2)],
                          log=log_path.name, seconds=round(time.monotonic() - began, 3),
                          passed=not error and not missing and returncode == 0 and 'TCP_FAULT_FAIL' not in text)
        finally:
            try:
                statistics, failures = [], []
                for monitor in monitors:
                    try:
                        statistics.append(monitor.close())
                    except Exception as exception:
                        failures.append(str(exception))
                if result is not None:
                    result['capture_statistics'] = statistics
                if failures:
                    if result is None:
                        raise ValueError('; '.join(failures))
                    result['passed'] = False
                    result['error'] = result['error'] or '; '.join(failures)
            finally:
                for channel in channels:
                    channel.close()
                if result is not None and result['passed']:
                    (scratch / 'client-release').write_text('complete\n')
                    try:
                        check(process.wait(timeout=5) == result['returncode'], 'private namespace wrapper matches actual client status')
                    except Exception:
                        try:
                            os.killpg(process.pid, signal.SIGKILL)
                        except ProcessLookupError:
                            pass
                        process.wait()
                        raise
                else:
                    try:
                        os.killpg(process.pid, signal.SIGKILL)
                    except ProcessLookupError:
                        pass
                    process.wait()
        rows.append(result)
        (ROOT / 'build' / f'{wire_prefix}-native-results.json').write_text(json.dumps(rows, indent=2) + '\n')
        print(json.dumps(result), flush=True)
        if not result['passed']:
            print(text[-5000:], flush=True)
            raise SystemExit('Native controlled TCP loss comparison failed')


def main():
    if len(sys.argv) == 4 and sys.argv[1] == '--client':
        client(Path(sys.argv[2]), sys.argv[3])
        return
    if len(sys.argv) in (3, 4) and sys.argv[1] == '--namespace':
        namespace(Path(sys.argv[2]), sys.argv[3] if len(sys.argv) == 4 else 'loss')
        return
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--wire', choices=('loss', 'reordering'), default='loss')
    args = parser.parse_args()
    subprocess.run(['make', '-s', '-j2', 'build/tcp-fault-native', 'build/tcp-fault-static',
                    'build/tcp-fault-dynamic'], cwd=ROOT, check=True)
    original = os.readlink('/proc/self/ns/net')
    with tempfile.TemporaryDirectory(prefix=f'axiom64-tcp-{args.wire}-') as temporary:
        scratch = Path(temporary)
        (scratch / 'parent-netns').write_text(original)
        completed = subprocess.run(['unshare', '--net', sys.executable, __file__, '--namespace', str(scratch), args.wire],
                                   capture_output=True, text=True, timeout=480)
    check(os.readlink('/proc/self/ns/net') == original, 'native loss comparison preserves the host network namespace')
    print(completed.stdout, end='', flush=True)
    if completed.returncode:
        print(completed.stderr, end='', flush=True)
    check(completed.returncode == 0, 'all isolated Linux controlled TCP comparisons pass')


if __name__ == '__main__':
    main()
