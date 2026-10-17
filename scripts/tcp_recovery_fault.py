# SPDX-License-Identifier: GPL-3.0-or-later
"""Hold real native or guest output without changing TCP state or clocks."""
import json
import subprocess
import time
from fetch import ROOT
from tcp_fault_peer import check


class OutputHold:
    def __init__(self, lane, label, native_pid=None, gdb_port=None, expiry=False):
        self.lane, self.native_pid, self.gdb_port = lane, native_pid, gdb_port
        self.expiry = expiry
        self.base = ROOT / 'build' / f'{label}-queue-{lane}'
        self.armed = self.base.with_suffix('.armed')
        self.released = self.base.with_suffix('.released')
        self.log = self.base.with_suffix('.log')
        self.metadata = self.base.with_suffix('.json')
        self.process = self.stream = None
        self.confirmed = self.restored = False
        self.events = []

    def save(self):
        self.metadata.write_text(json.dumps(dict(lane=self.lane, native=self.native_pid is not None,
            confirmed=self.confirmed, restored=self.restored, expiry=self.expiry, events=self.events), indent=2) + '\n')

    def native_command(self, arguments):
        command = ['nsenter', '-t', str(self.native_pid), '-n', 'tc', *arguments]
        actual = subprocess.run(command, capture_output=True, timeout=5)
        self.events.append(dict(command=command, returncode=actual.returncode,
            stdout=actual.stdout.decode(), stderr=actual.stderr.decode()))
        self.save()
        check(actual.returncode == 0, 'actual private native queue command succeeds')
        return actual.stdout

    def arm(self):
        check(not self.events and self.process is None, 'one output hold per interface')
        self.armed.unlink(missing_ok=True)
        self.released.unlink(missing_ok=True)
        if self.native_pid is not None:
            self.native_command(['qdisc', 'add', 'dev', f'eth{self.lane}', 'root', 'netem', 'delay',
                                 '10000ms' if self.expiry else '1000ms'])
            return
        check(self.gdb_port is not None, 'guest has an owned debugger endpoint')
        script = self.base.with_suffix('.gdb')
        expiry_break = [
            'break ax::inet_failed if error == 105', 'commands', 'silent',
            'set $expired = $expired + 1', 'if $expired == 1',
            'printf "TCP_OUTPUT_EXPIRED index=%u\\n", socket->stream_index', 'end',
            'continue', 'end'] if self.expiry else []
        release = (f'printf "TCP_OUTPUT_RELEASED index={self.lane + 1} held=%u expired=%u\\n", $held, $expired'
                   if self.expiry else f'printf "TCP_OUTPUT_RELEASED index={self.lane + 1} held=%u\\n", $held')
        script.write_text('\n'.join([
            'set pagination off', 'set confirm off', f'file {ROOT / "build/axiom64.elf"}',
            f'target remote 127.0.0.1:{self.gdb_port}', 'set $held = 0', 'set $expired = 0',
            f'break *ax::net_send if $rdi == {self.lane + 1} && $rdx == 566 && '
            '((unsigned char*)$rsi)[12] == 8 && ((unsigned char*)$rsi)[13] == 0 && '
            '((unsigned char*)$rsi)[23] == 6',
            'commands', 'silent',
            f'python gdb.set_convenience_variable("hold", int(not __import__("os").path.exists({str(self.released)!r})))',
            'if $hold', 'if !$held',
            f'printf "TCP_OUTPUT_HELD index={self.lane + 1}\\n"', 'end',
            'set $held = $held + 1', 'return (int)-11', 'continue', 'end',
            release,
            'detach', 'quit', 'end',
            *expiry_break,
            f'python open({str(self.armed)!r}, "w").write("armed")', 'continue', '']))
        self.stream = self.log.open('wb')
        self.process = subprocess.Popen(['gdb', '-q', '-batch', '-x', str(script)],
                                        stdout=self.stream, stderr=subprocess.STDOUT)
        began = time.monotonic()
        while not self.armed.exists():
            check(self.process.poll() is None and time.monotonic() - began < 5, 'guest output boundary arms')
            time.sleep(.005)
        self.events.append(dict(stage='armed', debugger_pid=self.process.pid))
        self.save()

    def confirm(self):
        check(not self.confirmed, 'one queue confirmation')
        if self.native_pid is not None:
            rows = json.loads(self.native_command(['-j', '-s', 'qdisc', 'show', 'dev', f'eth{self.lane}']))
            check(any(row.get('kind') == 'netem' and row.get('backlog', 0) >= 512 and
                      row.get('qlen', 0) >= 1 for row in rows), 'native output contains the actual held payload')
        else:
            self.stream.flush()
            check(f'TCP_OUTPUT_HELD index={self.lane + 1}' in self.log.read_text(),
                  'guest actually reached the held Ethernet transmit boundary')
        self.confirmed = True
        self.save()

    def release(self):
        check(self.confirmed and not self.restored, 'restore a confirmed queued interface once')
        if self.native_pid is not None:
            self.native_command(['qdisc', 'del', 'dev', f'eth{self.lane}', 'root'])
        else:
            if self.expiry:
                self.stream.flush()
                check(f'TCP_OUTPUT_EXPIRED index={self.lane + 1}' in self.log.read_text(),
                      'actual owned IPv4 copy expired before guest output is released')
            self.released.write_text('released\n')
        self.restored = True
        self.save()

    def result(self):
        check(self.confirmed and self.restored, 'actual output hold and interface restoration completed')
        if self.process is not None:
            check(self.process.wait(timeout=5) == 0, 'guest output observer detaches after recovery')
            self.stream.flush()
            check(f'TCP_OUTPUT_RELEASED index={self.lane + 1} held=' in self.log.read_text(),
                  'recovered TCP output crosses the original Ethernet boundary')
        self.save()
        return dict(confirmed=True, restored=True, metadata=self.metadata.name,
                    debugger_timing_excluded=self.native_pid is None)

    def close(self):
        if self.process is not None and self.process.poll() is None:
            self.process.kill()
            self.process.wait()
        if self.stream is not None:
            self.stream.close()
        self.save()
