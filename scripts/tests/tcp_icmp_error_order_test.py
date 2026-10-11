# SPDX-License-Identifier: GPL-3.0-or-later
"""Require actual native ICMP error delivery after an earlier error-queue wakeup."""
import hashlib
from collections import Counter
import json
import os
from pathlib import Path
import re
import signal
import socket
import struct
import subprocess
import sys
import tempfile
import time

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from fetch import ROOT
from build_musl import loader
from tcp_fault_native import Capture, command
from tcp_fault_peer import packet, check
from tcp_fault_test import exercise
from tcp_icmp_peer import Peer, Flow, CASES
from tcp_icmp_capture import packets, audit_inputs
from tcp_icmp_inputs import record


class ErrorOrderPeer(Peer):
    def line(self, line):
        if b'ICMP_ERROR_ORDER_PASS ' in line:
            for flow in self.flows:
                flow.done = True

    def receive(self, frame):
        if frame[12:14] == b'\x08\x06':
            return super().receive(frame)
        self.frames.append(dict(direction='receive', ms=self.ms(), frame=bytes(frame).hex()))
        if len(frame) < 54 or frame[12:14] != b'\x08\x00' or frame[23] != 6:
            return
        segment = packet(frame)
        check(segment['source_ip'] == self.address and segment['target_ip'] == self.ip and
              segment['source'] == 41000 and segment['target'] == 49000,
              'actual native error-order connection tuple')
        if not self.flows:
            check(segment['flags'] == 2, 'actual error-order SYN precedes application data')
            ordinal = next(index for index, case in enumerate(CASES)
                           if case['mode'] == 'SOFT' and case['type'] == 3 and case['code'] == 3)
            self.flows.append(Flow(self, ordinal, 49000, 41000))
        self.flows[0].input(segment, frame)

    def result(self):
        check(len(self.flows) == 1 and self.flows[0].done and self.flows[0].data == b'one',
              'actual error-order socket completes after sending its application bytes')
        return dict(lane=0, frames=self.frames, flows=[self.flows[0].result()])


def audit(directory, row, source_root=ROOT, native_libraries=None):
    check(row['passed'] and row['returncode'] == 0 and not row['error'], 'error-order client success')
    text = (directory / row['log']).read_text()
    match = re.search(r'^ICMP_ERROR_ORDER_PASS empty_reads=(\d+) error=111 cleared=0 elapsed_ms=(\d+)\r?$',
                      text, re.M)
    check(match and text.count('ICMP_ERROR_ORDER_PASS ') == 1 and int(match[1]) > 0 and
          15 <= int(match[2]) < 3000 and 'TCP_ICMP_FAIL' not in text,
          'early empty SO_ERROR reads precede the bounded owned error and its consumption')
    capture = packets(directory / row['capture'])
    quotes = [item for item in capture if item['protocol'] == 1]
    data = [item for item in capture if item['protocol'] == 6 and item['ip'][12:16] == bytes([10, 23, 1, 2]) and
            item['body'][(item['body'][12] >> 4) * 4:] == b'one']
    check(len(quotes) == len(data) == 1 and quotes[0]['body'][:2] == bytes([3, 3]) and
          quotes[0]['body'][8:] == data[0]['ip'][:28] and quotes[0]['stamp'] - data[0]['stamp'] >= 15000,
          'one delayed captured ICMP quote owns the earlier emitted TCP data')
    from tcp_icmp_capture import checksum
    check(checksum(quotes[0]['body']) == 0, 'actual error-order ICMP checksum')
    peer = json.loads((directory / row['peer']).read_text())
    check(Counter(bytes.fromhex(item['frame']) for item in peer['frames'] if item['frame'][24:28] == '0800') ==
          Counter(item['frame'] for item in capture), 'independent error-order peer and PCAP bytes')
    check(len({row[key] for key in ('parent_namespace', 'peer_namespace', 'client_namespace')}) == 3,
          'three actual independent error-order network namespaces')
    inputs = json.loads((directory / row['inputs']).read_text())
    check(inputs['native'] and inputs['linkage'] == row['linkage'], 'actual error-order input linkage')
    audit_inputs(inputs, source_root, native_libraries)
    statistics = row['capture_statistics']
    raw, at, count = (directory / row['capture']).read_bytes(), 24, 0
    while at < len(raw):
        size = struct.unpack_from('<IIII', raw, at)[2]
        at += 16 + size
        count += 1
    check(at == len(raw) and statistics['dropped'] == 0 and statistics['packets'] == count,
          'complete zero-drop error-order packet capture')
    return dict(linkage=row['linkage'], empty_reads=int(match[1]), elapsed_ms=int(match[2]),
                capture_sha256=hashlib.sha256((directory / row['capture']).read_bytes()).hexdigest())


def client(scratch, linkage):
    (scratch / 'ready').write_text(os.readlink('/proc/self/ns/net'))
    began = time.monotonic()
    while not (scratch / 'go').exists():
        check(time.monotonic() - began < 10, 'native error-order setup deadline')
        time.sleep(.001)
    record(linkage, native=True, label=f'tcp-icmp-error-order-{linkage}')
    arguments = [str(ROOT / 'build' / f'tcp-icmp-{linkage}'), '--native-error-order-check']
    if linkage == 'dynamic':
        arguments.insert(0, str(loader('build')))
    completed = subprocess.run(arguments)
    print(f'TCP_FAULT_NATIVE_DONE status={completed.returncode}', flush=True)
    began = time.monotonic()
    while not (scratch / 'release').exists():
        check(time.monotonic() - began < 10, 'native error-order evidence completion deadline')
        time.sleep(.001)
    raise SystemExit(completed.returncode)


def namespace(scratch):
    parent = (scratch / 'parent').read_text()
    check(os.readlink('/proc/self/ns/net') != parent, 'isolated native error-order peer namespace')
    rows = []
    for linkage in ('native', 'static', 'dynamic'):
        for name in ('ready', 'go', 'release'):
            (scratch / name).unlink(missing_ok=True)
        process = subprocess.Popen(['unshare', '--net', sys.executable, __file__, '--client', str(scratch), linkage],
                                   stdout=subprocess.PIPE, stderr=subprocess.STDOUT, start_new_session=True)
        channel = monitor = None
        label = f'tcp-icmp-error-order-{linkage}'
        row = dict(linkage=linkage, inputs=label + '-inputs.json', peer=label + '-peer.json',
                   log=label + '.log', capture=label + '.pcap', parent_namespace=parent,
                   peer_namespace=os.readlink('/proc/self/ns/net'))
        began = time.monotonic()
        try:
            while not (scratch / 'ready').exists():
                check(process.poll() is None and time.monotonic() - began < 5, 'native error-order client starts')
                time.sleep(.001)
            row['client_namespace'] = (scratch / 'ready').read_text()
            check(row['client_namespace'] not in (parent, row['peer_namespace']), 'separate native TCP stack')
            peer = ErrorOrderPeer(0)
            command('ip', 'link', 'add', 'peer0', 'type', 'veth', 'peer', 'name', 'eth0')
            command('ip', 'link', 'set', 'eth0', 'netns', str(process.pid))
            command('ip', 'link', 'set', 'peer0', 'address', peer.mac.hex(':'))
            command('ip', 'link', 'set', 'peer0', 'up')
            command('ethtool', '-K', 'peer0', 'tx', 'off', 'tso', 'off', 'gso', 'off', 'gro', 'off')
            prefix = ('nsenter', '-t', str(process.pid), '-n')
            command(*prefix, 'ip', 'link', 'set', 'eth0', 'address', peer.guest.hex(':'))
            command(*prefix, 'ethtool', '-K', 'eth0', 'tx', 'off', 'tso', 'off', 'gso', 'off', 'gro', 'off')
            command(*prefix, 'ip', 'addr', 'add', '10.23.1.2/24', 'dev', 'eth0')
            command(*prefix, 'ip', 'link', 'set', 'eth0', 'up')
            channel = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(3))
            channel.bind(('peer0', 0))
            monitor = Capture('peer0', ROOT / 'build' / row['capture'])
            (scratch / 'go').write_text('go')
            with (ROOT / 'build' / row['log']).open('wb') as output:
                text, results, error, code = exercise(process, [peer], [channel], 10, output, raw=True)
            row.update(returncode=code, error=error, passed=not error and code == 0 and
                       'ICMP_ERROR_ORDER_PASS ' in text and 'TCP_ICMP_FAIL' not in text)
            until = time.monotonic() + .05
            while time.monotonic() < until:
                try:
                    frame, address = channel.recvfrom(65536)
                    if address[2] != socket.PACKET_OUTGOING:
                        peer.receive(frame)
                except BlockingIOError:
                    time.sleep(.001)
                while peer.outgoing:
                    frame = peer.outgoing.pop(0)
                    check(channel.send(frame) == len(frame), 'complete error-order peer frame')
            (ROOT / 'build' / row['peer']).write_text(json.dumps(dict(frames=peer.frames), indent=2) + '\n')
            row['capture_statistics'] = monitor.close()
            monitor = None
            (scratch / 'release').write_text('complete')
            check(process.wait(timeout=5) == code, 'native error-order wrapper preserves exit status')
            audit(ROOT / 'build', row)
        finally:
            if monitor:
                monitor.close()
            if channel:
                channel.close()
            if process.poll() is None:
                os.killpg(process.pid, signal.SIGKILL)
            process.wait()
            rows.append(row)
            (ROOT / 'build/tcp-icmp-error-order-results.json').write_text(json.dumps(rows, indent=2) + '\n')
        print(f'ICMP_ERROR_ORDER_NATIVE_PASS linkage={linkage}', flush=True)


if __name__ == '__main__':
    if len(sys.argv) == 4 and sys.argv[1] == '--client':
        client(Path(sys.argv[2]), sys.argv[3])
    elif len(sys.argv) == 3 and sys.argv[1] == '--namespace':
        namespace(Path(sys.argv[2]))
    else:
        parent = os.readlink('/proc/self/ns/net')
        with tempfile.TemporaryDirectory(prefix='axiom64-icmp-error-order-') as temporary:
            scratch = Path(temporary)
            (scratch / 'parent').write_text(parent)
            subprocess.run(['unshare', '--net', sys.executable, __file__, '--namespace', str(scratch)],
                           check=True, timeout=60)
        check(os.readlink('/proc/self/ns/net') == parent, 'native error-order test preserves the host namespace')
