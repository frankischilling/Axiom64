#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Compare actual restored random streams with unchanged and changed VM IDs."""
import argparse
import json
from pathlib import Path
import re
import shutil
import socket
import subprocess
import tempfile
import time

from fetch import ROOT
from random_administration_test import fingerprint, fixture, snapshot

GUID = 'ab21c785-812e-4523-91fb-fb81c51d61e3'
CLONE_GUID = 'f9d8eba7-2d42-4d2e-b8d6-2b569a9a09f4'
TAG = 'random-checkpoint'


class QMP:
    def __init__(self, path, process, logfile, timeout):
        self.socket = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.stream = None
        self.log = logfile.open('w')
        self.timeout = timeout
        self.sequence = 0
        self.buffer = b''
        deadline = time.monotonic() + timeout
        try:
            while True:
                try:
                    self.socket.connect(str(path))
                    break
                except (FileNotFoundError, ConnectionRefusedError):
                    if process.poll() is not None or time.monotonic() >= deadline:
                        raise RuntimeError('QEMU did not open its QMP socket')
                    time.sleep(0.02)
            greeting = self.receive(deadline)
            if 'QMP' not in greeting:
                raise RuntimeError('QMP greeting is missing')
            self.command('qmp_capabilities')
        except BaseException:
            self.close()
            raise

    def record(self, direction, value):
        self.log.write(json.dumps(dict(direction=direction, monotonic_ns=time.monotonic_ns(),
                                       value=value)) + '\n')
        self.log.flush()

    def receive(self, deadline):
        while b'\n' not in self.buffer:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise TimeoutError('QMP response deadline expired')
            self.socket.settimeout(remaining)
            data = self.socket.recv(65536)
            if not data:
                raise RuntimeError('QMP closed before its response')
            self.buffer += data
            if len(self.buffer) > 4 * 1024 * 1024:
                raise RuntimeError('QMP response exceeded its bound')
        line, self.buffer = self.buffer.split(b'\n', 1)
        value = json.loads(line)
        self.record('receive', value)
        return value

    def command(self, name, arguments=None):
        self.sequence += 1
        value = dict(execute=name, id=self.sequence)
        if arguments is not None:
            value['arguments'] = arguments
        self.record('send', value)
        self.socket.sendall(json.dumps(value).encode() + b'\n')
        deadline = time.monotonic() + self.timeout
        while True:
            response = self.receive(deadline)
            if 'event' in response:
                continue
            if response.get('id') != self.sequence:
                raise RuntimeError('QMP response has an unexpected identifier')
            if 'error' in response:
                raise RuntimeError('QMP rejected ' + name + ': ' + json.dumps(response['error']))
            if 'return' not in response:
                raise RuntimeError('QMP response has neither a result nor an error')
            return response['return']

    def monitor(self, command):
        result = self.command('human-monitor-command', {'command-line': command})
        if result.strip():
            raise RuntimeError('monitor command failed: ' + command + ': ' + result)

    def close(self):
        self.socket.close()
        self.log.close()


class VM:
    def __init__(self, directory, label, image, disk, variables, guid, timeout, paused=False):
        self.directory = directory
        self.label = label
        self.timeout = timeout
        self.logfile = directory / (label + '.log')
        self.qmpfile = directory / (label + '-qmp.jsonl')
        self.temporary = tempfile.TemporaryDirectory(prefix='axiom64-snapshot-')
        self.output = self.logfile.open('wb')
        self.started = time.monotonic_ns()
        self.qmp = None
        path = Path(self.temporary.name) / 'qmp.sock'
        self.command = ['qemu-system-x86_64', '-machine', 'pc', '-cpu', 'max', '-m', '256M',
                        '-nic', 'none', '-cdrom', str(image), '-display', 'none', '-serial', 'stdio',
                        '-monitor', 'none', '-qmp', f'unix:{path},server=on,wait=off', '-no-reboot',
                        '-device', 'isa-debug-exit,iobase=0xf4,iosize=0x04',
                        '-device', 'vmgenid,guid=' + guid,
                        '-drive', f'if=none,format=qcow2,file={disk},id=checkpoint',
                        '-device', 'virtio-blk-pci,drive=checkpoint,disable-legacy=on']
        if variables:
            self.command += ['-drive', 'if=pflash,format=raw,readonly=on,file=/usr/share/OVMF/OVMF_CODE_4M.fd',
                             '-drive', 'if=pflash,format=qcow2,file=' + str(variables)]
        if paused:
            self.command.append('-S')
        self.process = subprocess.Popen(self.command, cwd=ROOT, stdin=subprocess.PIPE,
                                        stdout=self.output, stderr=subprocess.STDOUT)
        try:
            self.qmp = QMP(path, self.process, self.qmpfile, timeout)
        except BaseException:
            self.close()
            raise

    def text(self):
        return self.logfile.read_text(errors='replace')

    def wait(self, expression, offset=0):
        deadline = time.monotonic() + self.timeout
        while True:
            text = self.text()[offset:]
            match = re.search(expression, text)
            if match:
                return match
            if any(marker in text for marker in ('RANDOM_SNAPSHOT_FAIL ', 'PANIC:', 'FAULT pid=')):
                raise RuntimeError('guest failed before the expected observation: ' + self.label)
            if self.process.poll() is not None:
                raise RuntimeError('QEMU exited before the expected observation: ' + self.label)
            if time.monotonic() >= deadline:
                raise TimeoutError('guest observation deadline expired: ' + self.label)
            time.sleep(0.02)

    def sample(self, mode):
        offset = len(self.text())
        sent = time.monotonic_ns()
        self.process.stdin.write(b'R')
        self.process.stdin.flush()
        if mode == 'ready':
            expression = r'RANDOM_SNAPSHOT_SAMPLE index=1 value=([0-9a-f]{64})\r?\n'
            value = self.wait(expression, offset)[1]
        else:
            expression = r'RANDOM_SNAPSHOT_UNREADY index=1 result=EAGAIN entropy_bits=0\r?\n'
            self.wait(expression, offset)
            value = None
        return dict(value=value, serial_offset=offset, command_sent_ns=sent,
                    observed_ns=time.monotonic_ns())

    def finish(self, linkage, mode):
        self.process.stdin.write(b'Q')
        self.process.stdin.flush()
        self.wait(r'AXIOM64_EXIT status=0')
        self.process.wait(timeout=self.timeout)
        text = self.text()
        expected = f'RANDOM_SNAPSHOT_PASS linkage={linkage} mode={mode} samples=1 entropy_bits=' + (
            '256' if mode == 'ready' else '0')
        if self.process.returncode != 1 or expected not in text or 'AXIOM64_TESTS_PASS' not in text:
            raise RuntimeError('restored guest did not complete: ' + self.label)
        if any(marker in text for marker in ('RANDOM_SNAPSHOT_FAIL ', 'PANIC:', 'FAULT pid=',
                                             'RANDOM_RESEEDED source=rdseed')):
            raise RuntimeError('guest failed or another source reseeded during snapshot comparison')
        return dict(command=self.command, returncode=self.process.returncode,
                    elapsed_ns=time.monotonic_ns() - self.started, log=self.logfile.name,
                    log_input=fingerprint(self.logfile), qmp=self.qmpfile.name)

    def close(self):
        if self.process.poll() is None:
            self.process.kill()
            self.process.wait()
        if self.qmp:
            self.qmp.close()
        self.process.stdin.close()
        self.output.close()
        self.temporary.cleanup()

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.close()


def disk_info(path, output):
    result = subprocess.check_output(['qemu-img', 'info', '--output=json', str(path)], text=True)
    output.write_text(result)
    info = json.loads(result)
    states = [item for item in info.get('snapshots', ()) if item['name'] == TAG]
    if info['format'] != 'qcow2' or len(states) != 1:
        raise RuntimeError('the actual disk does not contain exactly one named checkpoint')
    return info, states[0]


def cell(directory, image, linkage, firmware, mode, timeout):
    directory.mkdir()
    disk = directory / 'original.qcow2'
    subprocess.run(['qemu-img', 'create', '-q', '-f', 'qcow2', str(disk), '16M'], check=True)
    variables = None
    firmware_inputs = {}
    if firmware == 'uefi':
        variables = directory / 'original-VARS.qcow2'
        firmware_inputs = {name: fingerprint(Path('/usr/share/OVMF') / name) for name in
                           ('OVMF_CODE_4M.fd', 'OVMF_VARS_4M.fd')}
        subprocess.run(['qemu-img', 'convert', '-f', 'raw', '-O', 'qcow2',
                        '/usr/share/OVMF/OVMF_VARS_4M.fd', str(variables)], check=True)
    record = dict(linkage=linkage, firmware=firmware, mode=mode, image=fingerprint(image),
                  guid=GUID, clone_guid=CLONE_GUID, firmware_inputs=firmware_inputs,
                  processes=[], observations=[], passed=False)
    try:
        with VM(directory, 'original', image, disk, variables, GUID, timeout) as vm:
            vm.wait(r'RANDOM_SNAPSHOT_WAIT')
            text = vm.text()
            if ('RANDOM_VMGENID_INIT transport=fw_cfg credited_bits=0' not in text or
                    f'Firmware: {firmware.upper()}' not in text):
                raise RuntimeError('the cold guest did not discover its generation source')
            if mode == 'ready':
                if 'RANDOM_READY source=rdseed bits=256' not in text:
                    raise RuntimeError('the source guest was not initialized by trusted RDSEED')
            elif 'RANDOM_READY ' in text or 'RANDOM_SOURCE rdseed=1 trust_cpu=0' not in text:
                raise RuntimeError('the source guest unexpectedly initialized')
            vm.qmp.command('stop')
            vm.qmp.monitor('savevm ' + TAG)
            vm.qmp.command('cont')
            original = vm.sample(mode)
            original['phase'] = 'before-restore'
            record['observations'].append(original)
            offset = len(vm.text())
            vm.qmp.monitor('loadvm ' + TAG)
            vm.qmp.command('cont')
            restored = vm.sample(mode)
            restored['phase'] = 'same-instance'
            record['observations'].append(restored)
            if restored['value'] != original['value'] or 'RANDOM_VMGENID_CHANGED ' in vm.text():
                raise RuntimeError('the same-instance control did not reproduce the original state')
            restored['restore_log_offset'] = offset
            record['processes'].append(vm.finish(linkage, mode))
        info, state = disk_info(disk, directory / 'original-image-info.json')
        states = [state]
        if variables:
            _, variable_state = disk_info(variables, directory / 'original-vars-info.json')
            states.append(variable_state)
        if sum(item['vm-state-size'] for item in states) <= 0:
            raise RuntimeError('the checkpoint contains no actual VM memory and device state')
        record['checkpoint'] = dict(disk=fingerprint(disk), state=state,
                                    variables=fingerprint(variables) if variables else None)
        for label, guid, changed in (('same-id-instance', GUID, False),
                                     ('changed-id-instance', CLONE_GUID, True)):
            cloned = directory / (label + '.qcow2')
            shutil.copyfile(disk, cloned)
            cloned_vars = None
            if variables:
                cloned_vars = directory / (label + '-VARS.qcow2')
                shutil.copyfile(variables, cloned_vars)
            clone_before = dict(disk=fingerprint(cloned),
                                variables=fingerprint(cloned_vars) if cloned_vars else None)
            if clone_before['disk'] != record['checkpoint']['disk'] or (
                    clone_before['variables'] != record['checkpoint']['variables']):
                raise RuntimeError('the clone does not contain the exact saved VM state')
            with VM(directory, label, image, cloned, cloned_vars, guid, timeout, paused=True) as vm:
                vm.qmp.monitor('loadvm ' + TAG)
                vm.qmp.command('cont')
                observed = vm.sample(mode)
                observed.update(phase=label, restored_disk=clone_before)
                text = vm.text()
                marker = 'RANDOM_VMGENID_CHANGED initialized=' + str(int(mode == 'ready')) + ' credited_bits=0'
                if (marker in text) != changed:
                    raise RuntimeError('the restored guest did not observe the expected generation ID')
                if text.count('RANDOM_VMGENID_CHANGED ') != int(changed):
                    raise RuntimeError('the restored guest reported an unexpected generation transition')
                if 'RANDOM_VMGENID_INIT ' in text or 'RANDOM_SNAPSHOT_WAIT' in text:
                    raise RuntimeError('the incoming instance cold-booted instead of restoring its checkpoint')
                if mode == 'ready' and (observed['value'] != original['value']) != changed:
                    raise RuntimeError('the restored stream does not reflect the generation transition')
                record['observations'].append(observed)
                record['processes'].append(vm.finish(linkage, mode))
        record.update(passed=True, vm_processes=3, cold_boots=1, memory_restores=3)
    except BaseException as error:
        record['error'] = repr(error)
        raise
    finally:
        for process in record['processes']:
            process['qmp_input'] = fingerprint(directory / process['qmp'])
        (directory / 'result.json').write_text(json.dumps(record, indent=2) + '\n')
    print(json.dumps(dict(case=directory.name, passed=True, processes=3,
                          cold_boots=1, memory_restores=3)), flush=True)
    return record


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--linkage', choices=('static', 'dynamic', 'both'), default='both')
    parser.add_argument('--firmware', choices=('bios', 'uefi', 'both'), default='both')
    parser.add_argument('--mode', choices=('ready', 'unready'), nargs='+', default=['ready', 'unready'])
    parser.add_argument('--output', type=Path, default=ROOT / 'build/random-snapshot-results')
    parser.add_argument('--timeout', type=float, default=90)
    args = parser.parse_args()
    if args.timeout <= 0:
        parser.error('the observation timeout must be positive')
    directory = args.output.resolve()
    directory.mkdir(parents=True, exist_ok=False)
    linkages = ('static', 'dynamic') if args.linkage == 'both' else (args.linkage,)
    subprocess.run(['make', '-s', '-j2', 'build/axiom64.elf', 'build/init', 'busybox',
                    *(f'build/random-snapshot-{linkage}' for linkage in linkages)], cwd=ROOT, check=True)
    inputs = snapshot(directory)
    for name in ('userspace/tests/random/snapshot.c', 'scripts/random_snapshot_test.py',
                 'scripts/image.py', 'scripts/disk_root.py', 'userspace/init/main.c',
                 'userspace/init/console.c', 'userspace/init/console.h'):
        inputs[name] = fingerprint(ROOT / name)
    (directory / 'source-inputs.json').write_text(json.dumps(inputs, indent=2) + '\n')
    tools = {}
    for name in ('qemu-system-x86_64', 'qemu-img'):
        binary = Path(shutil.which(name)).resolve()
        tools[name] = dict(path=str(binary), input=fingerprint(binary),
                           version=subprocess.check_output([name, '--version'], text=True))
    (directory / 'tools.json').write_text(json.dumps(tools, indent=2) + '\n')
    results = []
    for linkage in linkages:
        for mode in args.mode:
            image_directory = directory / (linkage + '-' + mode)
            image_directory.mkdir()
            archive = ROOT / 'build/rootfs-network.cpio'
            saved = archive.read_bytes() if archive.exists() else None
            try:
                image = fixture(image_directory, linkage, mode, program='random-snapshot')
            finally:
                if saved is None:
                    archive.unlink(missing_ok=True)
                else:
                    archive.write_bytes(saved)
            for firmware in ('bios', 'uefi') if args.firmware == 'both' else (args.firmware,):
                case = directory / (linkage + '-' + mode + '-' + firmware)
                results.append(cell(case, image, linkage, firmware, mode, args.timeout))
                (directory / 'results.json').write_text(json.dumps(results, indent=2) + '\n')
    if inputs != {name: fingerprint(ROOT / name) for name in inputs}:
        raise RuntimeError('source changed during restored-VM comparisons')


if __name__ == '__main__':
    main()
