# SPDX-License-Identifier: GPL-3.0-or-later
"""Change one real link while preserving its administratively up observers."""
import hashlib
import json
from pathlib import Path
import subprocess
import time
from fetch import ROOT
from qmp import Qmp
from tcp_fault_peer import check


class Carrier:
    def __init__(self, peers, label, native_pid=None, monitor_path=None):
        check(len(peers) == 2 and [peer.lane for peer in peers] == [0, 1], 'both owned carrier peers')
        check((native_pid is None) != (monitor_path is None), 'one actual native or QMP carrier controller')
        check(Path(label).name == label, 'bounded carrier observation label')
        self.peers, self.native_pid, self.monitor_path = peers, native_pid, monitor_path
        self.path = ROOT / 'build' / f'{label}-carrier.json'
        self.monitor = self.pending = None
        self.events, self.down, self.restored = [], [False, False], [False, False]
        self.held = [None, None]
        for peer in peers:
            check(peer.carrier is None, 'one carrier controller per observation')
            peer.carrier = self
        self.save()

    def save(self):
        self.path.write_text(json.dumps(dict(native=self.native_pid is not None,
            native_pid=self.native_pid, events=self.events, pending=self.pending,
            down_confirmed=self.down, held=self.held, restored=self.restored), indent=2) + '\n')

    def reply_limit(self, lane, permitted):
        # Four earlier Q/H control bytes precede these new application bytes.
        # The companion may send before its stdout request is processed, but
        # its echo cannot acknowledge a carrier transition that has not happened.
        if lane == 1 and not self.down[0]:
            return min(permitted, 5204)
        if lane == 0 and not self.down[1]:
            return min(permitted, 5716)
        return permitted

    def command(self, arguments):
        actual = subprocess.run(arguments, capture_output=True, timeout=5)
        self.pending['commands'].append(dict(command=arguments, returncode=actual.returncode,
            stdout=actual.stdout.decode(), stderr=actual.stderr.decode()))
        self.save()
        check(actual.returncode == 0, 'actual isolated native carrier command succeeds')
        return actual.stdout

    def native_state(self, lane, up):
        until = time.monotonic() + 2
        while True:
            commands = {
                'port': ['ip', '-j', 'link', 'show', 'dev', f'peer{lane}'],
                'observer': ['ip', '-j', 'link', 'show', 'dev', f'bridge{lane}'],
                'client': ['nsenter', '-t', str(self.native_pid), '-n', 'ip', '-j',
                           'link', 'show', 'dev', f'eth{lane}']}
            state = {}
            for name, command in commands.items():
                rows = json.loads(self.command(command))
                check(len(rows) == 1, 'one actual native carrier interface state')
                state[name] = rows[0]
            check('UP' in state['observer']['flags'] and 'UP' in state['client']['flags'],
                  'carrier loss preserves observer and client administrative state')
            if ('UP' in state['port']['flags']) == up and ('LOWER_UP' in state['client']['flags']) == up:
                return state
            check(time.monotonic() < until, 'actual selected native carrier state propagates')
            time.sleep(.01)

    def confirm(self, lane, error, available, flags):
        check(len(self.events) == lane * 2 + 1 and self.down[lane] and not self.restored[lane] and
              self.held[lane] is None, 'one held observation while the selected carrier is absent')
        check(error == available == 0 and flags & 1, 'held stream remains administratively up without delivery or error')
        check(self.peers[1 - lane].flows[0].sent >= 5716 + lane * 512 and
              len(self.peers[lane].flows[0].received) == 5200 + lane * 512,
              'healthy companion completes while every selected fault byte remains undelivered')
        self.held[lane] = dict(error=error, available=available, flags=flags,
                               monotonic_ns=time.monotonic_ns())
        self.save()

    def change(self, lane, up):
        expected = [(0, False), (0, True), (1, False), (1, True)]
        check(len(self.events) < 4 and (lane, up) == expected[len(self.events)],
              'each physical carrier is lowered and restored once in order')
        check(not up or self.held[lane] is not None, 'actual held-byte observation precedes carrier restoration')
        flow = self.peers[lane].flows[0]
        check(flow.commands == 4 and len(flow.received) == 5200 + lane * 512,
              'selected carrier fault bytes remain outside the peer until restoration')
        self.pending = dict(lane=lane, up=up, start_monotonic_ns=time.monotonic_ns(), commands=[])
        self.save()
        if self.native_pid is not None:
            self.command(['ip', 'link', 'set', f'peer{lane}', 'up' if up else 'down'])
            self.pending['state'] = self.native_state(lane, up)
        else:
            if self.monitor is None:
                self.monitor = Qmp(self.monitor_path)
            result = self.monitor.command('set_link', dict(name=f'carrier{lane}', up=up))
            check(result == {}, 'actual selected QEMU carrier change succeeds')
            self.pending['qmp'] = dict(command='set_link', name=f'carrier{lane}', up=up, result=result)
        self.pending['end_monotonic_ns'] = time.monotonic_ns()
        self.events.append(self.pending)
        self.pending = None
        if up:
            self.restored[lane] = True
        else:
            self.down[lane] = True
        self.save()
        if not up:
            self.peers[1 - lane].flows[0].flush()

    def result(self):
        check(len(self.events) == 4 and all(self.down) and all(self.held) and all(self.restored) and self.pending is None,
              'both actual physical carrier transitions complete')
        return dict(metadata=self.path.name, sha256=hashlib.sha256(self.path.read_bytes()).hexdigest(),
                    native=self.native_pid is not None, transitions=4, restored=True)

    def close(self):
        if self.monitor is not None:
            self.monitor.close()
            self.monitor = None
