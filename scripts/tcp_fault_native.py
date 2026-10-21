# SPDX-License-Identifier: GPL-3.0-or-later
"""Compare controlled TCP faults with Linux in nested private network namespaces."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
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
from tcp_fault_test import exercise, wire_configuration, application_configuration


def clock_pair():
    before = time.monotonic_ns()
    realtime = time.time_ns()
    return dict(receipt_monotonic_ns=before, receipt_realtime_ns=realtime,
                receipt_monotonic_after_ns=time.monotonic_ns())


class Capture:
    def __init__(self, interface, path):
        self.clock_start = clock_pair()
        self.socket = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(3))
        # Linux SO_RCVBUFFORCE reserves a per-socket burst budget without
        # changing host sysctls. This isolated fixture already requires root.
        self.socket.setsockopt(socket.SOL_SOCKET, 33, 4 * 1024 * 1024)
        self.buffer_bytes = self.socket.getsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF)
        check(self.buffer_bytes >= 4 * 1024 * 1024, 'independent capture reserves its packet burst budget')
        self.socket.bind((interface, 0))
        # Linux SO_TIMESTAMPNS_NEW returns two signed 64-bit values in system
        # realtime, which can jump. Preserve it and record monotonic read time
        # separately so elapsed protocol checks do not mix clock domains.
        self.socket.setsockopt(socket.SOL_SOCKET, 64, 1)
        self.socket.settimeout(.05)
        self.output = path.open('wb')
        self.output.write(struct.pack('<IHHIIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1))
        self.clocks_path = path.with_suffix('.clocks.jsonl')
        self.clocks = self.clocks_path.open('w')
        self.frame_count = 0
        self.stopping = threading.Event()
        self.error = None
        self.injection = None
        self.injection_lock = threading.Lock()
        self.thread = threading.Thread(target=self.collect, daemon=True)
        self.thread.start()

    def collect(self):
        try:
            while True:
                try:
                    frame, ancillary, flags, _ = self.socket.recvmsg(65535, socket.CMSG_SPACE(16))
                    observed = clock_pair()
                except socket.timeout:
                    if self.stopping.is_set():
                        break
                    continue
                check(not flags & (socket.MSG_TRUNC | socket.MSG_CTRUNC),
                      'independent capture receives complete frame and receipt timestamp')
                stamps = [value for level, kind, value in ancillary
                          if level == socket.SOL_SOCKET and kind == 64]
                check(len(stamps) == 1 and len(stamps[0]) == 16, 'one actual kernel packet receipt timestamp')
                seconds, nanoseconds = struct.unpack('=qq', stamps[0])
                check(seconds >= 0 and 0 <= nanoseconds < 1000000000, 'kernel receipt timestamp bounds')
                timestamp = seconds * 1000000000 + nanoseconds
                self.output.write(struct.pack('<IIII', timestamp // 1000000000,
                                              timestamp // 1000 % 1000000, len(frame), len(frame)) + frame)
                # Both files stay buffered during bursts. The original PCAP
                # timestamp and frame remain unchanged; each record binds them
                # to an independently observed monotonic receipt.
                self.clocks.write(json.dumps(dict(frame=self.frame_count,
                    sha256=hashlib.sha256(frame).hexdigest(), kernel_realtime_ns=timestamp,
                    **observed)) + '\n')
                self.frame_count += 1
                if self.injection is not None:
                    with self.injection_lock:
                        waiting = self.injection
                        if waiting is not None and waiting['frame'] == frame and not waiting['ready'].is_set():
                            waiting['monotonic_ns'] = observed['receipt_monotonic_ns']
                            waiting['ready'].set()
        except Exception as exception:
            self.error = exception

    def watch(self, frame):
        """Return a pollable receipt for one future actual packet injection."""
        waiting = dict(frame=bytes(frame), ready=threading.Event(), monotonic_ns=None)
        with self.injection_lock:
            check(self.injection is None, 'one outstanding independently observed injection')
            self.injection = waiting
        def observed():
            check(self.error is None, 'independent input monitor remains healthy')
            with self.injection_lock:
                if not waiting['ready'].is_set():
                    return None
                if self.injection is waiting:
                    self.injection = None
                return waiting['monotonic_ns'] / 1e9
        return observed

    def observe_injection(self, frame, send, timeout=2):
        """Send one exact frame and wait for its independent monotonic receipt."""
        waiting = dict(frame=frame, ready=threading.Event(), monotonic_ns=None)
        with self.injection_lock:
            check(self.injection is None, 'one outstanding independently observed injection')
            self.injection = waiting
        try:
            check(send(frame) == len(frame), 'complete independently observed injection')
            check(waiting['ready'].wait(timeout) and self.error is None,
                  'independent capture observes the injected frame within its deadline')
            return waiting['monotonic_ns'] / 1e9
        finally:
            with self.injection_lock:
                self.injection = None

    def close(self):
        self.stopping.set()
        self.thread.join(timeout=1)
        try:
            check(not self.thread.is_alive() and self.error is None,
                  f'independent packet monitor completes: {self.error}')
            # Linux SOL_PACKET/PACKET_STATISTICS counts kernel receive drops.
            packets, dropped = struct.unpack('II', self.socket.getsockopt(263, 6, 8))
            check(dropped == 0, f'independent packet monitor loses no actual frames: dropped={dropped}')
            check(packets == self.frame_count, 'every captured frame has one independent clock record')
            self.output.flush()
            self.clocks.flush()
            return dict(packets=packets, dropped=dropped, buffer_bytes=self.buffer_bytes,
                        monotonic_receipts=self.clocks_path.name,
                        monotonic_receipts_sha256=hashlib.sha256(self.clocks_path.read_bytes()).hexdigest(),
                        receipt_frames=self.frame_count, original_packet_times_not_rescaled=True,
                        clock_start=self.clock_start, clock_end=clock_pair())
        finally:
            self.socket.close()
            self.output.close()
            self.clocks.close()


def command(*args):
    subprocess.run(list(args), check=True, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)


def client(scratch, linkage, wire='loss'):
    (scratch / 'client-ready').write_text(os.readlink('/proc/self/ns/net'))
    began = time.monotonic()
    while not (scratch / 'client-go').exists():
        check(time.monotonic() - began < 10, 'private client namespace setup deadline')
        time.sleep(.005)
    program, _ = application_configuration(wire)
    binary = ROOT / 'build' / f'{program}-{linkage}'
    command_line = [str(binary), '--native']
    if linkage == 'dynamic':
        from build_musl import loader
        command_line.insert(0, str(loader('build')))
    if wire == 'icmp':
        from tcp_icmp_inputs import record
        record(linkage, native=True)
    elif wire == 'pmtu':
        from tcp_pmtu_inputs import record
        record(linkage, native=True)
    elif wire == 'pressure':
        from tcp_pressure_inputs import record
        record(linkage, native=True)
    elif wire == 'reconnect':
        from tcp_reconnect_inputs import record
        record(linkage, native=True)
    elif wire == 'recovery':
        from tcp_recovery_inputs import record
        record(linkage, native=True)
    elif wire == 'malformed':
        from tcp_malformed.inputs import record
        record(linkage, native=True)
    elif wire in ('window', 'fast'):
        from tcp_congestion.inputs import record
        record(linkage, wire, native=True)
    else:
        from tcp_native_inputs import record
        record(wire, linkage)
    completed = subprocess.run(command_line)
    print(f'TCP_FAULT_NATIVE_DONE status={completed.returncode}', flush=True)
    began = time.monotonic()
    while not (scratch / 'client-release').exists():
        check(time.monotonic() - began < 10, 'independent peer/capture completion deadline')
        time.sleep(.005)
    raise SystemExit(completed.returncode)


def namespace(scratch, wire='loss', linkages=('native', 'static', 'dynamic')):
    check(linkages and len(set(linkages)) == len(linkages) and
          set(linkages) <= {'native', 'static', 'dynamic'}, 'known independent native linkages')
    peer_type, wire_prefix = wire_configuration(wire)
    parent = (scratch / 'parent-netns').read_text()
    fixture_namespace = os.readlink('/proc/self/ns/net')
    check(parent != fixture_namespace, 'raw peer requires an isolated network namespace')
    rows = []
    for linkage in linkages:
        for name in ('client-ready', 'client-go', 'client-release'):
            (scratch / name).unlink(missing_ok=True)
        process = subprocess.Popen(['unshare', '--net', sys.executable, __file__, '--client', str(scratch), linkage, wire],
                                   stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                   start_new_session=True)
        channels, monitors, bridges, result = [], [], [], None
        peers = [peer_type(lane, minimum_fin_ms=180) for lane in range(2)]
        label = f'{wire_prefix}-linux-{linkage}'
        if wire == 'recovery':
            from tcp_recovery_carrier import Carrier
            Carrier(peers, label, native_pid=process.pid)
        elif wire == 'reconnect':
            from tcp_reconnect_fault import QueuedOutput
            QueuedOutput(peers, label, ROOT / 'build', native_pid=process.pid)
        for peer in peers:
            if wire == 'recovery':
                peer.native_profile(process.pid, label)
            elif hasattr(peer, 'native_profile'):
                peer.native_profile()
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
                observer = interface
                if wire == 'recovery':
                    observer = f'bridge{lane}'
                    # This isolated TCP fixture has no multicast workload.
                    # Disable bridge snooping before UP so its own IGMP
                    # membership reports do not enter the workload capture.
                    command('ip', 'link', 'add', observer, 'type', 'bridge', 'mcast_snooping', '0')
                    bridges.append(observer)
                    command('ip', 'link', 'set', observer, 'address', peer.mac.hex(':'))
                    command('ip', 'link', 'set', interface, 'master', observer)
                    command('ip', 'link', 'set', observer, 'up')
                command('ethtool', '-K', interface, 'tx', 'off', 'tso', 'off', 'gso', 'off', 'gro', 'off')
                prefix = ('nsenter', '-t', str(process.pid), '-n')
                command(*prefix, 'ip', 'link', 'set', guest, 'address', peer.guest.hex(':'))
                command(*prefix, 'ethtool', '-K', guest, 'tx', 'off', 'tso', 'off', 'gso', 'off', 'gro', 'off')
                command(*prefix, 'ip', 'addr', 'add', f'10.23.{lane + 1}.2/24', 'dev', guest)
                command(*prefix, 'ip', 'link', 'set', guest, 'up')
                channel = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(3))
                channel.bind((observer, 0))
                channels.append(channel)
                monitors.append(Capture(observer, ROOT / 'build' / f'{label}-lane{lane}.pcap'))
            (scratch / 'client-go').write_text('go\n')
            log_path = ROOT / 'build' / f'{label}.log'
            with log_path.open('wb') as log:
                budget = 1600 if wire == 'lifetime' else 300 if wire == 'pressure' else 150
                text, results, error, returncode = exercise(process, peers, channels, budget, log, raw=True)
            _, required = application_configuration(wire)
            missing = [marker for marker in required if marker not in text]
            peer_path = ROOT / 'build' / f'{label}-peer.json'
            peer_path.write_text(json.dumps([dict(lane=peer.lane, frames=peer.frames) for peer in peers], indent=2) + '\n')
            result = dict(wire=wire, linkage=linkage, returncode=returncode, error=error, missing=missing,
                          parent_namespace=parent, peer_namespace=fixture_namespace, client_namespace=client_namespace,
                          peers=[{key: value for key, value in peer.items() if key != 'frames'} for peer in results],
                          peer=peer_path.name, captures=[f'{label}-lane{lane}.pcap' for lane in range(2)],
                          log=log_path.name, seconds=round(time.monotonic() - began, 3),
                          passed=not error and not missing and returncode == 0 and
                          not any(marker in text for marker in ('TCP_FAULT_FAIL', 'TCP_TIMEOUT_FAIL', 'TCP_LIFETIME_FAIL', 'TCP_ICMP_FAIL')))
            if wire == 'lifetime':
                result['defaults'] = {name: int(subprocess.check_output(
                    ['nsenter', '-t', str(process.pid), '-n', '/usr/sbin/sysctl', '-n', f'net.ipv4.{name}']))
                    for name in ('tcp_retries1', 'tcp_retries2', 'tcp_syn_retries', 'tcp_synack_retries')}
                result['host_configuration_changed'] = False
            result['kernel'] = platform.release()
            result['inputs'] = f'{wire_prefix}-linux-{linkage}-inputs.json'
        finally:
            if wire in ('recovery', 'reconnect'):
                for peer in peers:
                    peer.close()
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
                for bridge in bridges:
                    command('ip', 'link', 'del', bridge)
        rows.append(result)
        result_suffix = f'-{linkages[0]}' if len(linkages) == 1 else ''
        (ROOT / 'build' / f'{wire_prefix}-native{result_suffix}-results.json').write_text(json.dumps(rows, indent=2) + '\n')
        print(json.dumps(result), flush=True)
        if not result['passed']:
            print(text[-5000:], flush=True)
            raise SystemExit('Native controlled TCP loss comparison failed')


def main():
    if len(sys.argv) in (4, 5) and sys.argv[1] == '--client':
        client(Path(sys.argv[2]), sys.argv[3], sys.argv[4] if len(sys.argv) == 5 else 'loss')
        return
    if len(sys.argv) in (3, 4, 5) and sys.argv[1] == '--namespace':
        namespace(Path(sys.argv[2]), sys.argv[3] if len(sys.argv) >= 4 else 'loss',
                  (sys.argv[4],) if len(sys.argv) == 5 else ('native', 'static', 'dynamic'))
        return
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--wire', choices=('loss', 'reordering', 'persist', 'timeout', 'old-ack', 'challenge', 'icmp', 'pmtu', 'pressure', 'reconnect', 'recovery', 'malformed', 'window', 'fast'), default='loss')
    args = parser.parse_args()
    program, _ = application_configuration(args.wire)
    subprocess.run(['make', '-s', '-j2', *(f'build/{program}-{linkage}' for linkage in
                                        ('native', 'static', 'dynamic'))], cwd=ROOT, check=True)
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
