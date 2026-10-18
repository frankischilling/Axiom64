# SPDX-License-Identifier: GPL-3.0-or-later
"""Own a held IPv4 copy, physical PCI removal, and independent queue observations."""
from pathlib import Path
import hashlib
import json
import re
import subprocess
import time

from manager_link_hardware import Hardware
from qmp import Qmp
from tcp_fault_peer import check


class Monitor(Qmp):
    def __init__(self, path):
        self.records = []
        self.defer_cont = False
        super().__init__(path)

    def command(self, name, arguments=None):
        record = dict(command=name, arguments=arguments, monotonic_ns=time.monotonic_ns())
        if name == 'cont' and self.defer_cont:
            record['deferred_until_debugger_returns_held_send'] = True
            result = None
        else:
            result = super().command(name, arguments)
            record['result'] = result
        self.records.append(record)
        return result

    def resume(self):
        self.defer_cont = False
        self.command('cont')


class Controller:
    def __init__(self, task, output, affected, debug_port, monitor_path, test_path, transport):
        self.task, self.output, self.affected, self.debug_port = task, output, affected, debug_port
        self.monitor_path, self.test_path = monitor_path, test_path
        self.transport = transport
        self.peers = None
        self.monitor = self.hardware = self.process = self.stream = None
        self.events = []
        self.base = output / 'device-copy'
        self.log = self.base.with_suffix('.log')
        self.script = self.base.with_suffix('.gdb')
        self.request = self.base.with_suffix('.remove')
        self.released = self.base.with_suffix('.released')
        self.armed = self.base.with_suffix('.armed')
        self.stage = 'warm'

    def save(self):
        value = dict(affected=self.affected, stage=self.stage, events=self.events,
                     observer_returncode=self.process.poll() if self.process is not None else None,
                     monitor=self.monitor.records if self.monitor is not None else [],
                     hardware=self.hardware.records if self.hardware is not None else [],
                     debugger_timing_excluded=True, no_clock_advance_operations=True)
        if self.script.exists():
            value['script_sha256'] = hashlib.sha256(self.script.read_bytes()).hexdigest()
        if self.log.exists():
            value['log_sha256'] = hashlib.sha256(self.log.read_bytes()).hexdigest()
        (self.output / 'physical-device-observations.json').write_text(json.dumps(value, indent=2) + '\n')

    def wait_marker(self, marker):
        began = time.monotonic()
        while True:
            if self.stream is not None:
                self.stream.flush()
            if self.log.exists() and marker in self.log.read_text():
                return
            check(self.process is not None and self.process.poll() is None and time.monotonic() - began < 10,
                  'owned debugger reaches actual device-copy observation: ' + marker)
            time.sleep(.005)

    def arm(self):
        lane = self.affected
        for path in (self.request, self.released, self.armed):
            path.unlink(missing_ok=True)
        lines = (self.task / 'kernel/net/ipv4/core.cpp').read_text().splitlines()
        pending = next(index + 1 for index, line in enumerate(lines)
                       if 'if (!info || !info->live || !info->administrative || !info->carrier)' in line)
        array = "'kernel/net/ipv4/core.cpp'::'ax::(anonymous namespace)::output'"
        python_code = [
            'python', 'import gdb, os, time',
            'copy_cleared = False',
            'def reclaimed():',
            '    global copy_cleared',
            '    if int(gdb.parse_and_eval("$cleared")): return',
            '    item = gdb.parse_and_eval("$queueptr").dereference()',
            '    owner = gdb.parse_and_eval("$ownerptr").dereference()',
            f'    table = gdb.parse_and_eval({array!r})',
            '    remaining = sum(int(table[i]["bytes"]) != 0 and table[i]["owner"] == gdb.parse_and_eval("$ownerptr") for i in range(32))',
            '    if not copy_cleared and not int(item["bytes"]):',
            '        if int(item["owner"]) or int(item["length"]):',
            '            raise gdb.GdbError("actual saved copy fields must be fully cleared before reuse")',
            '        print("TCP_DEVICE_COPY_CLEARED owner=%s bytes=%s length=%s" % (item["owner"], item["bytes"], item["length"]))',
            '        copy_cleared = True',
            '    if copy_cleared and not int(owner["transmitted"]) and not remaining:',
            '        print("TCP_DEVICE_QUEUE_CLEARED transmitted=%s remaining=%d" % (owner["transmitted"], remaining))',
            '        gdb.set_convenience_variable("cleared", 1)',
            'end']
        self.script.write_text('\n'.join([
            'set pagination off', 'set confirm off',
            f'file {self.task / "build/axiom64.elf"}', f'target remote 127.0.0.1:{self.debug_port}',
            'set $held = 0', 'set $queued = 0', 'set $failed = 0', 'set $cleared = 0', 'set $paused_for_remove = 0',
            *python_code,
            f'break *ax::net_send if $rdi == {lane + 1} && $rdx == 566 && '
            '((unsigned char*)$rsi)[12] == 8 && ((unsigned char*)$rsi)[13] == 0 && '
            '((unsigned char*)$rsi)[23] == 6 && '
            f'((unsigned char*)$rsi)[36] == {(49600 + lane) >> 8} && ((unsigned char*)$rsi)[37] == {(49600 + lane) & 255}',
            'commands', 'silent', 'if !$held',
            f'printf "TCP_DEVICE_PHYSICAL_HELD index={lane + 1} length=566\\n"',
            'python print("TCP_DEVICE_HELD_FRAME " + bytes(gdb.selected_inferior().read_memory(int(gdb.parse_and_eval("$rsi")) & ((1 << 64) - 1), 566)).hex())',
            'end', 'set $held = $held + 1',
            f'python gdb.set_convenience_variable("remove_requested", int(os.path.exists({str(self.request)!r})))',
            'if $queued && $remove_requested && !$paused_for_remove',
            'set $paused_for_remove = 1',
            'printf "TCP_DEVICE_PAUSED_FOR_PCI_REMOVAL\\n"',
            'python', 'began = time.monotonic()',
            f'while not os.path.exists({str(self.released)!r}):',
            '    if time.monotonic() - began > 10: raise RuntimeError("bounded owned PCI-removal handshake expired")',
            '    time.sleep(.005)', 'end', 'end',
            'return (int)-11', 'if $paused_for_remove',
            'printf "TCP_DEVICE_REMOVAL_RESUMING_AFTER_HELD_RETURN\\n"', 'end', 'continue', 'end',
            f'break kernel/net/ipv4/core.cpp:{pending} if $held && !$queued && item.index == {lane + 1} && item.length == 566',
            'commands', 'silent', 'set $queued = 1', 'set $queueptr = &item', 'set $ownerptr = item.owner',
            f'printf "TCP_DEVICE_QUEUE_PENDING index={lane + 1} owner=%#lx transmitted=%lu length=%lu\\n", (unsigned long)item.owner, item.owner->transmitted, item.length',
            'python print("TCP_DEVICE_QUEUED_FRAME " + bytes(gdb.selected_inferior().read_memory(int(gdb.parse_and_eval("item.bytes")) & ((1 << 64) - 1), 566)).hex())',
            'disable 2', 'continue', 'end',
            # Entry registers and saved addresses remain valid across optimized
            # cleanup paths and interrupted frames. Observe the real error here;
            # inspect completed reclamation before a later allocation can reuse
            # the vacant slot. Both ARP and IPv4 allocate before filling a slot.
            'break *ax::inet_failed if $queued && $rdi == (unsigned long)$ownerptr && $esi == 5',
            'commands', 'silent',
            'printf "TCP_DEVICE_QUEUE_FAILURE error=%d owner=%#lx length=%lu\\n", $esi, (unsigned long)$queueptr->owner, $queueptr->length',
            'set $failed = 1', 'disable 3', 'continue', 'end',
            'break *ax::alloc if $failed && !$cleared',
            'commands', 'silent', 'python reclaimed()', 'if $cleared', 'disable 4', 'end', 'continue', 'end',
            f'break *ax::net_send if $failed && $rdi == {2 - lane} && $rdx >= 54 && '
            '((unsigned char*)$rsi)[12] == 8 && ((unsigned char*)$rsi)[13] == 0 && '
            '((unsigned char*)$rsi)[23] == 6 && (((unsigned char*)$rsi)[47] & 1)',
            'commands', 'silent', 'python reclaimed()',
            'python\nif not int(gdb.parse_and_eval("$cleared")): raise gdb.GdbError("actual owned copies must be reclaimed before surviving FIN")\nend',
            'printf "TCP_DEVICE_HEALTHY_FIN_AFTER_RECLAMATION\\n"',
            'detach', 'quit', 'end',
            f'python open({str(self.armed)!r}, "w").write("armed")', 'continue', '']))
        self.stream = self.log.open('wb')
        self.process = subprocess.Popen(['gdb', '-q', '-batch', '-x', str(self.script)],
                                        stdout=self.stream, stderr=subprocess.STDOUT)
        began = time.monotonic()
        while not self.armed.exists():
            check(self.process.poll() is None and time.monotonic() - began < 10, 'fresh device-copy observer arms')
            time.sleep(.005)
        self.monitor = Monitor(self.monitor_path)
        self.hardware = Hardware(self.monitor, self.test_path, self.affected, self.transport)
        self.events.append(dict(stage='armed', monotonic_ns=time.monotonic_ns()))

    def line(self, line):
        line = line.rstrip(b'\r')
        if line == f'TCP_DEVICE_ARM lane={self.affected}'.encode():
            check(self.stage == 'warm', 'one physical removal after both TCP opens')
            self.arm()
            self.stage = 'armed'
            self.peers[self.affected].flows[0].gate()
        elif line == f'TCP_DEVICE_HELD lane={self.affected} queued=512'.encode():
            check(self.stage == 'armed', 'pending copy follows observer readiness')
            self.wait_marker('TCP_DEVICE_QUEUE_PENDING')
            self.stage = 'held'
        elif line.startswith(b'TCP_DEVICE_HEALTHY_LIVE '):
            check(self.stage == 'held' and len(self.peers[1 - self.affected].flows[0].received) == 48,
                  'healthy original tuple progresses while the failed tuple remains queued')
            self.request.write_text('remove selected owned emulator adapter\n')
            self.wait_marker('TCP_DEVICE_PAUSED_FOR_PCI_REMOVAL')
            # Keep the debugger stopped at its held send during the shared PCI
            # selector sequence. Resume only after its forced EAGAIN return.
            self.monitor.defer_cont = True
            self.hardware.remove()
            self.events.append(dict(stage='physically_removed', monotonic_ns=time.monotonic_ns()))
            self.released.write_text('physical PCI removal complete\n')
            self.wait_marker('TCP_DEVICE_REMOVAL_RESUMING_AFTER_HELD_RETURN')
            self.monitor.resume()
            self.stage = 'removed'
        elif line.startswith(f'TCP_DEVICE_FAILED lane={self.affected} '.encode()):
            check(self.stage == 'removed' and b'read_errno=5 send_errno=32 cleared_error=0' in line,
                  'actual guest observes EIO once, EOF, EPIPE and cleared SO_ERROR')
            self.stage = 'failed'
            self.peers[self.affected].flows[0].done = True
            self.events.append(dict(stage='actual_guest_failure', line=line.decode(), monotonic_ns=time.monotonic_ns()))
        elif line.startswith(b'TCP_DEVICE_HEALTHY_PASS '):
            check(self.stage == 'failed', 'healthy original tuple outlives the permanent device error')
            elapsed = int(line.rsplit(b'=', 1)[1])
            check(elapsed >= 5000, 'healthy stream remains active beyond the full old-copy lifetime')
            self.events.append(dict(stage='healthy_complete', line=line.decode(), monotonic_ns=time.monotonic_ns()))
            self.stage = 'complete'
        self.save()

    def finish(self):
        check(self.stage == 'complete' and self.process.wait(timeout=5) == 0,
              'actual physical-failure observer detaches after the surviving FIN')
        text = self.log.read_text()
        held = re.findall(r'TCP_DEVICE_HELD_FRAME ([0-9a-f]+)', text)
        queued = re.findall(r'TCP_DEVICE_QUEUED_FRAME ([0-9a-f]+)', text)
        check(len(held) == len(queued) == 1 and held == queued,
              'pending owned output is the exact original held TCP frame')
        check('TCP_DEVICE_QUEUE_FAILURE error=5 ' in text and
              'TCP_DEVICE_COPY_CLEARED owner=0x0 bytes=0x0 length=0' in text and
              'TCP_DEVICE_QUEUE_CLEARED transmitted=0 remaining=0' in text and
              'TCP_DEVICE_HEALTHY_FIN_AFTER_RECLAMATION' in text,
              'physical device failure reclaims the actual copy and transmitted accounting')
        self.save()

    def close(self):
        if self.process is not None and self.process.poll() is None:
            self.process.kill()
            self.process.wait()
        if self.stream is not None:
            self.stream.close()
        if self.hardware is not None:
            self.hardware.close()
        if self.monitor is not None:
            self.monitor.close()
        self.save()
