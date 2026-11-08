# SPDX-License-Identifier: GPL-3.0-or-later
"""Keep a real QEMU stopped while the device controller releases its debugger hold."""
import argparse
import json
from pathlib import Path
import re
import socket
import subprocess
import sys
import tempfile
import time
from types import SimpleNamespace

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from fetch import ROOT
from tcp_device.physical import Controller, Monitor


def wait_file(path, process):
    deadline = time.monotonic() + 5
    while not path.exists():
        if process.poll() is not None or time.monotonic() >= deadline:
            raise RuntimeError('debugger did not reach controlled resume boundary: ' + path.name)
        time.sleep(.001)


def run(directory, forced_cont=False):
    directory.mkdir(parents=True, exist_ok=False)
    assembly = directory / 'counter.asm'
    assembly.write_text('''bits 16
org 0x7c00
jmp 0x0000:start
start:
    cli
    xor ax, ax
    mov ds, ax
    mov ss, ax
    mov sp, 0x7c00
    mov dword [0x7000], 0
times 0x40-($-$$) db 0x90
counter:
    inc dword [0x7000]
    jmp counter
times 510-($-$$) db 0
dw 0xaa55
''')
    image = directory / 'counter.img'
    subprocess.run(['nasm', '-f', 'bin', str(assembly), '-o', str(image)], check=True)
    qemu = controller = None
    with tempfile.TemporaryDirectory(prefix='axiom-device-resume-') as temporary:
        monitor_path = Path(temporary) / 'qmp.sock'
        with socket.socket() as reserve:
            reserve.bind(('127.0.0.1', 0))
            debug_port = reserve.getsockname()[1]
        armed, paused = directory / 'armed', directory / 'paused'
        controller = Controller(directory, directory, 0, debug_port, monitor_path, None, 'modern')
        controller.stage = 'held'
        controller.peers = [SimpleNamespace(flows=[SimpleNamespace(received=bytes(48))]) for _ in range(2)]

        class GatedMonitor(Monitor):
            def resume(self):
                # Force the host scheduling order that races with the next stop.
                wait_file(paused, controller.process)
                result = super().resume()
                if forced_cont:
                    self.command('cont')
                return result

        class PauseHardware:
            records = []

            def remove(self):
                # Exercise the real QMP pause/deferred-resume path. PCI payload
                # checks belong to the separate complete device-loss cohort.
                controller.monitor.command('stop')
                controller.monitor.command('cont')

            def close(self):
                pass

        controller.script.write_text('\n'.join([
            'set pagination off', 'set confirm off',
            f'target remote 127.0.0.1:{debug_port}', 'set $stops = 0',
            'break *0x7c40', 'commands', 'silent', 'set $stops = $stops + 1',
            'if $stops == 1', 'python', 'import os, time, gdb',
            f'open({str(armed)!r}, "w").write("armed")',
            'deadline = time.monotonic() + 5',
            f'while not os.path.exists({str(controller.request)!r}):',
            '    if time.monotonic() >= deadline: raise RuntimeError("held resume was not requested")',
            '    time.sleep(.001)', 'end',
            'printf "TCP_DEVICE_PAUSED_FOR_PCI_REMOVAL\\n"', 'python',
            'deadline = time.monotonic() + 5',
            f'while not os.path.exists({str(controller.released)!r}):',
            '    if time.monotonic() >= deadline: raise RuntimeError("held resume was not released")',
            '    time.sleep(.001)', 'end',
            'printf "TCP_DEVICE_REMOVAL_RESUMING_AFTER_HELD_RETURN\\n"', 'continue', 'end',
            'disable 1', 'python',
            'before = int(gdb.parse_and_eval("*(unsigned int*)0x7000"))',
            f'open({str(paused)!r}, "w").write("paused")',
            'time.sleep(.3)',
            'after = int(gdb.parse_and_eval("*(unsigned int*)0x7000"))',
            'print("TCP_DEVICE_RESUME_COUNTER before=%d after=%d" % (before, after))',
            'if before != after: raise gdb.GdbError("QMP resumed the guest during a debugger observation")',
            'print("TCP_DEVICE_RESUME_PASS debugger_observation_stayed_stopped=1")',
            'end', 'detach', 'quit', 'end', 'continue', '']))
        try:
            with (directory / 'qemu.log').open('wb') as qemu_log:
                qemu = subprocess.Popen([
                    'qemu-system-x86_64', '-machine', 'pc', '-m', '32M', '-nic', 'none',
                    '-drive', f'file={image},format=raw,if=floppy', '-boot', 'a',
                    '-display', 'none', '-serial', 'none', '-monitor', 'none', '-no-reboot',
                    '-S', '-gdb', f'tcp:127.0.0.1:{debug_port}',
                    '-qmp', f'unix:{monitor_path},server=on,wait=off'],
                    stdin=subprocess.DEVNULL, stdout=qemu_log, stderr=subprocess.STDOUT)
                wait_file(monitor_path, qemu)
                controller.monitor = GatedMonitor(monitor_path)
                controller.hardware = PauseHardware()
                controller.stream = controller.log.open('wb')
                controller.process = subprocess.Popen(['gdb', '-q', '-batch', '-x', str(controller.script)],
                    stdin=subprocess.DEVNULL, stdout=controller.stream, stderr=subprocess.STDOUT)
                wait_file(armed, controller.process)
                controller.line(b'TCP_DEVICE_HEALTHY_LIVE controlled-resume\n')
                status = controller.process.wait(timeout=10)
                controller.stream.flush()
                text = controller.log.read_text()
                values = re.findall(r'^TCP_DEVICE_RESUME_COUNTER before=(\d+) after=(\d+)$', text, re.M)
                if len(values) != 1:
                    raise RuntimeError('missing actual debugger counter observation:\n' + text)
                before, after = map(int, values[0])
                if forced_cont:
                    accepted = (status != 0 and before != after and
                                'QMP resumed the guest during a debugger observation' in text)
                else:
                    accepted = (status == 0 and before == after and
                                text.count('TCP_DEVICE_RESUME_PASS debugger_observation_stayed_stopped=1') == 1)
                if not accepted:
                    raise RuntimeError('actual debugger/QMP resume race:\n' + text)
                result = dict(passed=True, debugger_exit=status, actual_qemu_counter=True,
                              forced_cont=forced_cont, counter_before=before, counter_after=after,
                              physical_device_acceptance=False, monitor=controller.monitor.records)
                (directory / 'resume-results.json').write_text(json.dumps(result, indent=2) + '\n')
        finally:
            if controller is not None:
                controller.close()
            if qemu is not None and qemu.poll() is None:
                qemu.kill()
                qemu.wait()
    return result


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--directory', type=Path, default=ROOT / 'build/tcp-device/resume-control')
    directory = parser.parse_args().directory.resolve()
    directory.mkdir(parents=True, exist_ok=False)
    rows = [run(directory / name, forced_cont) for name, forced_cont in
            [('debugger-owned', False), ('forced-qmp-cont', True)]]
    (directory / 'results.json').write_text(json.dumps(dict(passed=True, cases=rows,
        forced_cont_rejected=True, physical_device_acceptance=False), indent=2) + '\n')
    print('TCP_DEVICE_RESUME_PASS actual_cases=2 forced_cont_rejected=1')
