# SPDX-License-Identifier: GPL-3.0-or-later
"""Delete an actual private Linux netdevice with TCP output queued in netem."""
import json
import os
from pathlib import Path
import platform
import re
import signal
import socket
import subprocess
import sys
import tempfile
import time
import traceback

from fetch import ROOT
from tcp_fault_native import Capture, command
from tcp_fault_peer import check
from tcp_fault_test import exercise
from tcp_device.inputs import record
from tcp_device.peer import Peer
from tcp_device.run import save

ENTRY = ROOT / 'scripts/tcp_device/run.py'


class Controller:
    def __init__(self, pid, peers, affected, output):
        self.pid, self.peers, self.affected, self.output = pid, peers, affected, output
        self.stage, self.events = 'warm', []

    def command(self, arguments):
        actual_command = ['nsenter', '-t', str(self.pid), '-n', *arguments]
        actual = subprocess.run(actual_command, capture_output=True)
        self.events.append(dict(command=actual_command, returncode=actual.returncode,
            stdout=actual.stdout.decode(), stderr=actual.stderr.decode(), monotonic_ns=time.monotonic_ns()))
        save(self.output / 'actual-device-operations.json', self.events)
        check(actual.returncode == 0, 'actual isolated native interface operation succeeds')
        return actual.stdout

    def line(self, line):
        line = line.rstrip(b'\r')
        lane, healthy = self.affected, 1 - self.affected
        interface = f'eth{lane}'
        if line == f'TCP_DEVICE_ARM lane={lane}'.encode():
            check(self.stage == 'warm', 'native queue follows both original warm TCP streams')
            self.command(['tc', 'qdisc', 'add', 'dev', interface, 'root', 'netem', 'delay', '10000ms'])
            self.peers[lane].flows[0].gate()
            self.stage = 'armed'
        elif line == f'TCP_DEVICE_HELD lane={lane} queued=512'.encode():
            check(self.stage == 'armed', 'native pending write follows the actual queue arm')
            rows = json.loads(self.command(['tc', '-j', '-s', 'qdisc', 'show', 'dev', interface]))
            check(any(row.get('kind') == 'netem' and row.get('backlog', 0) >= 512 and row.get('qlen', 0) >= 1
                      for row in rows), 'actual native queue contains the pending TCP output')
            self.stage = 'held'
        elif line == f'TCP_DEVICE_HEALTHY_LIVE lane={healthy} bytes=48'.encode():
            check(self.stage == 'held' and len(self.peers[healthy].flows[0].received) == 48,
                  'native original other-NIC stream progresses while old bytes remain held')
            before = json.loads(self.command(['ip', '-j', 'link', 'show']))
            check({'eth0', 'eth1'} <= {row['ifname'] for row in before}, 'both actual native interfaces exist before removal')
            self.command(['ip', 'link', 'delete', 'dev', interface])
            after = json.loads(self.command(['ip', '-j', 'link', 'show']))
            check(interface not in {row['ifname'] for row in after} and
                  f'eth{healthy}' in {row['ifname'] for row in after},
                  'selected native netdevice vanishes while the other stays present')
            self.stage = 'removed'
        elif line.startswith(f'TCP_DEVICE_FAILED lane={lane} '.encode()):
            check(self.stage == 'removed', 'actual native error follows real interface deletion')
            match = re.fullmatch(rb'TCP_DEVICE_FAILED lane=\d revents=(\d+) read_errno=101 send_errno=32 cleared_error=101', line)
            check(match and int(match[1]) & 8, 'actual native permanent socket error and clear/error progression')
            self.events.append(dict(operation='actual_native_error', line=line.decode(), monotonic_ns=time.monotonic_ns()))
            self.peers[lane].flows[0].done = True
            self.stage = 'failed'
        elif line.startswith(f'TCP_DEVICE_HEALTHY_PASS lane={healthy} '.encode()):
            check(self.stage == 'failed' and int(line.rsplit(b'=', 1)[1]) >= 5000,
                  'native original healthy tuple outlives the full pending-copy lifetime')
            self.events.append(dict(operation='healthy_complete', line=line.decode(), monotonic_ns=time.monotonic_ns()))
            self.stage = 'complete'
        save(self.output / 'actual-device-operations.json', self.events)


def client(scratch, linkage, affected, output):
    (scratch / 'client-ready').write_text(os.readlink('/proc/self/ns/net'))
    began = time.monotonic()
    while not (scratch / 'client-go').exists():
        check(time.monotonic() - began < 10, 'private device client namespace setup deadline')
        time.sleep(.005)
    # Record the actual executable and its loaders before executing it.
    name = record(linkage, affected, native=True)
    (output / 'inputs.json').write_bytes((ROOT / 'build' / name).read_bytes())
    actual = [str(ROOT / 'build' / f'tcp-device-{linkage}'), '--native', str(affected)]
    if linkage == 'dynamic':
        from build_musl import loader
        actual.insert(0, str(loader('build')))
    save(output / 'client-command.json', actual)
    completed = subprocess.run(actual)
    print(f'TCP_FAULT_NATIVE_DONE status={completed.returncode}', flush=True)
    began = time.monotonic()
    while not (scratch / 'client-release').exists():
        check(time.monotonic() - began < 10, 'independent device peer/capture completion deadline')
        time.sleep(.005)
    raise SystemExit(completed.returncode)


def namespace(scratch, linkage, affected, output):
    parent, current = (scratch / 'parent-netns').read_text(), os.readlink('/proc/self/ns/net')
    check(parent != current, 'native removal fixture owns a separate peer namespace')
    process = subprocess.Popen(['unshare', '--net', sys.executable, str(ENTRY), '--client',
        str(scratch), linkage, str(affected), str(output)], stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT, start_new_session=True)
    channels, monitors, peers = [], [], []
    controller = Controller(process.pid, peers, affected, output)
    peers.extend(Peer(lane, controller) for lane in range(2))
    result = dict(passed=False, native=True, linkage=linkage, affected=affected,
                  directory=output.name, kernel_release=platform.release())
    try:
        began = time.monotonic()
        while not (scratch / 'client-ready').exists():
            check(process.poll() is None and time.monotonic() - began < 10, 'actual native client namespace becomes available')
            time.sleep(.005)
        client_namespace = (scratch / 'client-ready').read_text()
        check(client_namespace not in (parent, current), 'native client and peer stacks are separately owned')
        command('nsenter', '-t', str(process.pid), '-n', 'ip', 'link', 'set', 'lo', 'up')
        for lane, peer in enumerate(peers):
            interface, guest, bridge = f'peer{lane}', f'eth{lane}', f'bridge{lane}'
            command('ip', 'link', 'add', interface, 'type', 'veth', 'peer', 'name', guest)
            command('ip', 'link', 'set', guest, 'netns', str(process.pid))
            command('ip', 'link', 'add', bridge, 'type', 'bridge', 'mcast_snooping', '0')
            command('ip', 'link', 'set', bridge, 'address', peer.mac.hex(':'))
            command('ip', 'link', 'set', bridge, 'up')
            command('ip', 'link', 'set', interface, 'master', bridge)
            command('ip', 'link', 'set', interface, 'up')
            command('ethtool', '-K', interface, 'tx', 'off', 'tso', 'off', 'gso', 'off', 'gro', 'off')
            prefix = ['nsenter', '-t', str(process.pid), '-n']
            command(*prefix, 'ip', 'link', 'set', guest, 'address', peer.guest.hex(':'))
            command(*prefix, 'ethtool', '-K', guest, 'tx', 'off', 'tso', 'off', 'gso', 'off', 'gro', 'off')
            command(*prefix, 'ip', 'addr', 'add', f'10.23.{lane + 1}.2/24', 'dev', guest)
            command(*prefix, 'ip', 'link', 'set', guest, 'up')
            channel = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(3))
            channel.bind((bridge, 0))
            channels.append(channel)
            monitors.append(Capture(bridge, output / f'lane{lane}.pcap'))
        (scratch / 'client-go').write_text('go\n')
        with (output / 'client.log').open('wb') as log:
            text, results, error, status = exercise(process, peers, channels, 45, log, raw=True)
        save(output / 'peer-frames.json', [dict(lane=peer.lane, frames=peer.frames) for peer in peers])
        result.update(returncode=status, error=error, peers=results, parent_namespace=parent,
            peer_namespace=current, client_namespace=client_namespace, controller_stage=controller.stage,
            passed=status == 0 and error is None and controller.stage == 'complete' and
                   f'TCP_DEVICE_PASS affected={affected} queued=512' in text and 'TCP_DEVICE_FAIL line=' not in text,
            configured_TCP_USER_TIMEOUT_ms=3000, no_global_settings_changed=True)
    except BaseException:
        result['failure'] = traceback.format_exc()
        print(result['failure'], flush=True)
    finally:
        result['capture_statistics'] = []
        for monitor in monitors:
            try:
                result['capture_statistics'].append(monitor.close())
            except Exception:
                result.update(passed=False, capture_failure=traceback.format_exc())
        (scratch / 'client-release').write_text('release\n')
        try:
            if result['passed']:
                status = process.wait(timeout=5)
                if status != result['returncode']:
                    result.update(passed=False, release_failure='native namespace wrapper changed the actual client status')
        except subprocess.TimeoutExpired:
            result.update(passed=False, release_failure='owned native namespace client did not exit')
        finally:
            if not result['passed']:
                # The wrapper owns a fresh session and can still have a live C
                # child even after the wrapper itself has exited.
                try:
                    os.killpg(process.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
            process.wait()
        for channel in channels:
            channel.close()
        save(output / 'producer-result.json', result)
    raise SystemExit(0 if result['passed'] else 1)


def run():
    subprocess.run(['make', *(f'build/tcp-device-{linkage}' for linkage in ('native', 'static', 'dynamic'))],
                   cwd=ROOT, check=True)
    rows = []
    for linkage in ('native', 'static', 'dynamic'):
        for affected in (0, 1):
            output = ROOT / 'build/tcp-device' / f'linux-{linkage}-{affected}'
            output.mkdir(parents=True, exist_ok=True)
            with tempfile.TemporaryDirectory(prefix='axiom64-native-device-') as temporary:
                scratch = Path(temporary)
                (scratch / 'parent-netns').write_text(os.readlink('/proc/self/ns/net'))
                with (output / 'namespace.log').open('wb') as log:
                    actual = subprocess.run(['unshare', '--net', sys.executable, str(ENTRY), '--namespace',
                        str(scratch), linkage, str(affected), str(output)], stdout=log, stderr=subprocess.STDOUT, timeout=60)
            row = json.loads((output / 'producer-result.json').read_text())
            row['passed'] &= actual.returncode == 0
            row['directory'] = output.name
            rows.append(row)
            print(json.dumps({key: row[key] for key in ('linkage', 'affected', 'passed')}), flush=True)
    return rows
