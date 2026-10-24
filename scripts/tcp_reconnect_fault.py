# SPDX-License-Identifier: GPL-3.0-or-later
"""Keep old output copies separate from a successor using the same description."""
import hashlib
import json
from pathlib import Path
import re
import subprocess
import time
from tcp_fault_peer import check


class OutputHold:
    def __init__(self, controller, lane):
        self.controller, self.lane = controller, lane
        self.base = controller.root / f'{controller.label}-queued-copy-{lane}'
        self.process = self.stream = None
        self.events = []

    def tc(self, arguments):
        command = ['nsenter', '-t', str(self.controller.pid), '-n', 'tc', *arguments]
        actual = subprocess.run(command, capture_output=True, timeout=5)
        self.events.append(dict(command=command, returncode=actual.returncode,
                               stdout=actual.stdout.decode(), stderr=actual.stderr.decode()))
        self.controller.save()
        check(actual.returncode == 0, 'actual isolated selective output-queue command succeeds')
        return actual.stdout

    def arm(self):
        lane = self.lane
        if self.controller.pid is not None:
            self.tc(['qdisc', 'add', 'dev', f'eth{lane}', 'root', 'handle', '1:', 'prio',
                     'bands', '3', 'priomap', *(['0'] * 16)])
            self.tc(['qdisc', 'add', 'dev', f'eth{lane}', 'parent', '1:3', 'handle', '30:',
                     'netem', 'delay', '10000ms'])
            self.tc(['filter', 'add', 'dev', f'eth{lane}', 'protocol', 'ip', 'parent', '1:',
                     'pref', '10', 'u32', 'match', 'ip', 'protocol', '6', '0xff',
                     'match', 'ip', 'dport', str(self.controller.peers[lane].flows[-1].local_port), '0xffff', 'flowid', '1:3'])
            return
        port = self.controller.peers[lane].flows[-1].local_port
        core = Path(__file__).resolve().parents[1] / 'kernel/net/ipv4/core.cpp'
        lines = core.read_text().splitlines()
        expiry_line = next(i + 1 for i, line in enumerate(lines)
                           if 'clear(item, item.ethernet_ready ? 105 : 113)' in line)
        armed = self.base.with_suffix('.armed')
        armed.unlink(missing_ok=True)
        script = self.base.with_suffix('.gdb')
        script.write_text('\n'.join([
            'set pagination off', 'set confirm off',
            f'file {self.controller.kernel_path}',
            f'target remote 127.0.0.1:{self.controller.debug_port}',
            'set $held = 0', 'set $old_seq = 0',
            f'break *ax::net_send if $rdi == {lane + 1} && $rdx == 566 && '
            '((unsigned char*)$rsi)[12] == 8 && ((unsigned char*)$rsi)[13] == 0 && '
            '((unsigned char*)$rsi)[23] == 6 && '
            f'((unsigned char*)$rsi)[36] == {port >> 8} && ((unsigned char*)$rsi)[37] == {port & 255}',
            'commands', 'silent',
            'set $seq = (((unsigned char*)$rsi)[38] << 24) | (((unsigned char*)$rsi)[39] << 16) | '
            '(((unsigned char*)$rsi)[40] << 8) | ((unsigned char*)$rsi)[41]',
            'if !$held', 'set $old_seq = $seq',
            f'printf "TCP_RECONNECT_QUEUED_PHYSICAL_HELD index={lane + 1} sequence=%u length=566\\n", $old_seq',
            'python print("TCP_RECONNECT_QUEUED_HELD_MONOTONIC_NS " + str(__import__("time").monotonic_ns()))',
            'python print("TCP_RECONNECT_QUEUED_HELD_FRAME " + bytes(gdb.selected_inferior().read_memory(int(gdb.parse_and_eval("$rsi")) & ((1 << 64) - 1), 566)).hex())',
            'end', 'if $seq == $old_seq', 'set $held = $held + 1', 'return (int)-11', 'end',
            'continue', 'end',
            f'break kernel/net/ipv4/core.cpp:{expiry_line} if $held && item.index == {lane + 1} && item.length == 566 && '
            f'item.bytes[36] == {port >> 8} && item.bytes[37] == {port & 255}',
            'commands', 'silent',
            f'printf "TCP_RECONNECT_QUEUED_OLD_COPY_EXPIRED index={lane + 1} owner=%#lx held=%u length=%lu\\n", (unsigned long)item.owner, $held, item.length',
            'python print("TCP_RECONNECT_QUEUED_EXPIRED_MONOTONIC_NS " + str(__import__("time").monotonic_ns()))',
            'python print("TCP_RECONNECT_QUEUED_EXPIRED_FRAME " + bytes(gdb.selected_inferior().read_memory(int(gdb.parse_and_eval("item.bytes")) & ((1 << 64) - 1), 566)).hex())',
            'detach', 'quit', 'end',
            f'python open({str(armed)!r}, "w").write("armed")', 'continue', '']))
        self.stream = self.base.with_suffix('.log').open('wb')
        self.process = subprocess.Popen(['gdb', '-q', '-batch', '-x', str(script)],
                                        stdout=self.stream, stderr=subprocess.STDOUT)
        began = time.monotonic()
        while not armed.exists():
            check(self.process.poll() is None and time.monotonic() - began < 5,
                  'owned queued-copy observer arms at the real driver boundary')
            time.sleep(.005)
        self.events.append(dict(stage='armed', debugger_pid=self.process.pid))
        self.controller.save()

    def confirm(self, stage):
        if self.controller.pid is not None:
            rows = json.loads(self.tc(['-j', '-s', 'qdisc', 'show', 'dev', f'eth{self.lane}']))
            check(any(row.get('kind') == 'netem' and row.get('backlog', 0) >= 512 and
                      row.get('qlen', 0) >= 1 for row in rows),
                  'actual old payload remains queued through description cancellation')
        else:
            began = time.monotonic()
            while True:
                self.stream.flush()
                text = self.base.with_suffix('.log').read_text()
                if f'TCP_RECONNECT_QUEUED_PHYSICAL_HELD index={self.lane + 1}' in text:
                    break
                check(self.process.poll() is None and time.monotonic() - began < 2,
                      'actual old payload reached the held transmit boundary')
                time.sleep(.005)
        self.events.append(dict(stage=stage, monotonic_ns=time.monotonic_ns()))
        self.controller.save()

    def permit_successor(self):
        self.confirm('cancelled_with_old_copy_pending')
        if self.controller.pid is not None:
            # Existing packets stay in netem; only future packets lose the old
            # classifier. The successor can use the exact original tuple.
            self.tc(['filter', 'del', 'dev', f'eth{self.lane}', 'parent', '1:',
                     'protocol', 'ip', 'pref', '10'])

    def finish(self):
        flow = self.controller.peers[self.lane].flows[-1]
        if self.controller.pid is not None:
            rows = json.loads(self.tc(['-j', '-s', 'qdisc', 'show', 'dev', f'eth{self.lane}']))
            check(all(row.get('backlog', 0) == 0 for row in rows if row.get('kind') == 'netem') and
                  len(flow.late_bytes) == 512, 'actual old native bytes arrive after the successor opens')
            self.tc(['qdisc', 'del', 'dev', f'eth{self.lane}', 'root'])
        else:
            check(self.process.wait(timeout=5) == 0, 'old-copy observer detaches after actual expiry')
            self.stream.flush()
            text = self.base.with_suffix('.log').read_text()
            check(re.search(rf'TCP_RECONNECT_QUEUED_OLD_COPY_EXPIRED index={self.lane + 1} owner=0(?:x0)? held=\d+ length=566', text),
                  'the expired old copy has no successor callback owner')
            held = re.findall(r'TCP_RECONNECT_QUEUED_HELD_FRAME ([0-9a-f]+)', text)
            expired = re.findall(r'TCP_RECONNECT_QUEUED_EXPIRED_FRAME ([0-9a-f]+)', text)
            check(len(held) == len(expired) == 1 and held == expired and len(flow.late_bytes) == 0,
                  'the exact held guest frame expires without reaching the new stream')
        self.events.append(dict(stage='completed', monotonic_ns=time.monotonic_ns()))
        self.controller.save()

    def close(self):
        if self.process is not None and self.process.poll() is None:
            self.process.kill()
            self.process.wait()
        if self.stream is not None:
            self.stream.close()


class QueuedOutput:
    def __init__(self, peers, label, directory, native_pid=None, debug_port=None, kernel_path=None):
        check(len(peers) == 2 and [peer.lane for peer in peers] == [0, 1], 'both owned queued-copy peers')
        check((native_pid is None) != (debug_port is None), 'one native or guest queued-copy controller')
        check(Path(label).name == label and '/' not in label and '\\' not in label, 'bounded queued-copy label')
        check(native_pid is not None or kernel_path is not None, 'guest observer has its actual kernel symbols')
        self.peers, self.label = peers, label
        self.root = Path(directory)
        check(self.root.is_dir(), 'existing owned queued-copy output directory')
        self.metadata = self.root / (label + '-queued-copy.json')
        self.kernel_path = Path(kernel_path) if kernel_path is not None else None
        self.pid, self.debug_port = native_pid, debug_port
        self.stages = ['warm', 'warm']
        self.successors = [None, None]
        self.companion_bases = [None, None]
        self.holds = [OutputHold(self, lane) for lane in range(2)]
        self.events = []
        for peer in peers:
            check(peer.queued_copy is None, 'one queued-copy controller per observation')
            peer.queued_copy = self
        self.save()

    def save(self):
        self.metadata.write_text(json.dumps(dict(native=self.pid is not None, native_pid=self.pid,
            stages=self.stages, successors=self.successors, events=self.events,
            holds=[hold.events for hold in self.holds]), indent=2) + '\n')

    def successor(self, lane, frame):
        check(self.stages[lane] == 'unbound' and self.successors[lane] is None,
              'one actual successor SYN follows confirmed description cancellation')
        self.successors[lane] = dict(monotonic_ns=time.monotonic_ns(),
                                     syn_sha256=hashlib.sha256(frame).hexdigest())
        self.save()

    def limit(self, lane, wanted):
        other = 1 - lane
        if self.stages[other] in ('armed', 'held'):
            return min(wanted, self.companion_bases[other] + (16 if self.stages[other] == 'held' else 0))
        return wanted

    def line(self, line):
        match = re.fullmatch(rb'TCP_RECONNECT_QUEUED_(ARM|HELD|UNSPEC|DONE) lane=([01])(?: .*)?', line.rstrip(b'\r'))
        if not match:
            return
        stage, lane = match[1].decode(), int(match[2])
        flow = self.peers[lane].flows[-1]
        if stage == 'ARM':
            prefix = int(line.rsplit(b'=', 1)[1])
            check(all(prior.done for peer in self.peers for prior in peer.flows[:-1]),
                  'every earlier reconnect case completes before queued-copy cancellation')
            check(self.stages[lane] == 'warm' and len(flow.phases) == 1 and
                  len(flow.phases[0].received) == prefix, 'actual complete old prefix precedes queued fault')
            flow.old_prefix = prefix
            companion = self.peers[1 - lane].flows[-1].phases[-1]
            self.companion_bases[lane] = companion.app_sent
            self.stages[lane] = 'armed'
            self.holds[lane].arm()
            self.events.append(dict(stage=stage, lane=lane, monotonic_ns=time.monotonic_ns()))
            flow.phases[0].control()
        elif stage == 'HELD':
            check(self.stages[lane] == 'armed' and len(flow.phases[0].received) == flow.old_prefix,
                  'actual old fault bytes remain outside the peer')
            self.holds[lane].confirm('held_before_cancel')
            self.stages[lane] = 'held'
        elif stage == 'UNSPEC':
            check(self.stages[lane] == 'held', 'actual disconnect follows confirmed output ownership')
            self.holds[lane].permit_successor()
            flow.future = True
            self.stages[lane] = 'unbound'
        else:
            observed = re.fullmatch(rb'TCP_RECONNECT_QUEUED_DONE lane=[01] elapsed_ms=(\d+) successor=528\r?', line)
            check(observed and int(observed[1]) >= 11000, 'complete actual queued-copy lifetime wait')
            check(self.stages[lane] == 'unbound' and len(flow.phases) == 2 and
                  len(flow.phases[1].received) >= 528, 'actual successor survives the old copy lifetime')
            self.holds[lane].finish()
            self.stages[lane] = 'completed'
        if stage != 'ARM':
            self.events.append(dict(stage=stage, lane=lane, monotonic_ns=time.monotonic_ns()))
        self.save()
        for peer in self.peers:
            peer.flows[-1].flush()


    def result(self):
        check(self.stages == ['completed', 'completed'] and len(self.events) == 8 and all(self.successors),
              'both physical queued-copy cancellation observations complete')
        traces = []
        if self.pid is None:
            for hold in self.holds:
                names = {kind: hold.base.with_suffix(suffix) for kind, suffix in
                         [('log', '.log'), ('script', '.gdb')]}
                traces.append(dict(lane=hold.lane, **{kind: path.name for kind, path in names.items()},
                                   **{kind + '_sha256': hashlib.sha256(path.read_bytes()).hexdigest()
                                      for kind, path in names.items()}))
        return dict(metadata=self.metadata.name,
                    sha256=hashlib.sha256(self.metadata.read_bytes()).hexdigest(),
                    native=self.pid is not None, complete=True, queued_each=512,
                    debugger_timing_excluded=self.pid is None, traces=traces)

    def close(self):
        for hold in self.holds:
            hold.close()
