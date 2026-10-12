#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Fault the generation adapter and verify actual failed exec ownership and recovery."""
import argparse
import json
from pathlib import Path
import re
import shutil
import socket
import subprocess
import time

from fetch import ROOT
from random_administration_test import fingerprint, fixture, snapshot


def mutate(directory, port, slot):
    commands = ['set pagination off', 'set confirm off', 'target remote 127.0.0.1:' + str(port),
                'print ax::generation.live', 'print ax::generation.slot']
    if slot is not None:
        commands += ['set variable ax::generation.slot = ' + str(slot), 'print ax::generation.slot']
    commands += ['detach', 'quit']
    script = directory / ('failure.gdb' if slot == 256 else 'recovery.gdb')
    script.write_text('\n'.join(commands)+'\n')
    result = subprocess.run(['gdb', '-nx', '-q', '-batch', '-x', str(script), str(ROOT / 'build/axiom64.elf')],
                            capture_output=True, text=True, timeout=20)
    log = script.with_suffix('.log')
    log.write_text(result.stdout+result.stderr)
    if result.returncode or not re.search(r'\$1 = true\n', result.stdout):
        raise RuntimeError('the initialized generation adapter was not inspected')
    values = re.findall(r'\$\d+ = (\d+)\n', result.stdout)
    if len(values) != (1 if slot is None else 2) or (slot is not None and int(values[-1]) != slot):
        raise RuntimeError('the actual bounded generation slot mutation differs')
    return int(values[0]), dict(command_input=fingerprint(script), log=fingerprint(log), returncode=0)


def boot(directory, iso, linkage, firmware):
    directory.mkdir()
    with socket.socket() as reserve:
        reserve.bind(('127.0.0.1', 0))
        port = reserve.getsockname()[1]
    command = ['qemu-system-x86_64', '-machine', 'pc', '-cpu', 'max', '-m', '256M', '-nic', 'none',
               '-cdrom', str(iso), '-display', 'none', '-serial', 'stdio', '-monitor', 'none', '-no-reboot',
               '-device', 'isa-debug-exit,iobase=0xf4,iosize=0x04', '-gdb', 'tcp:127.0.0.1:' + str(port),
               '-device', 'vmgenid,guid=6fcf8c8d-47d6-4b44-8c36-439427c1939c']
    if firmware == 'uefi':
        variables = directory / 'VARS.fd'
        shutil.copyfile('/usr/share/OVMF/OVMF_VARS_4M.fd', variables)
        command += ['-drive', 'if=pflash,format=raw,readonly=on,file=/usr/share/OVMF/OVMF_CODE_4M.fd',
                    '-drive', 'if=pflash,format=raw,file=' + str(variables)]
    log = directory / 'guest.log'
    row = dict(linkage=linkage, firmware=firmware, image=fingerprint(iso), command=command, passed=False)
    process = None
    start = time.monotonic_ns()
    try:
        with log.open('wb') as stream:
            process = subprocess.Popen(command, stdin=subprocess.PIPE, stdout=stream, stderr=subprocess.STDOUT)
            deadline = time.monotonic()+60

            def wait(marker):
                while time.monotonic() < deadline:
                    data = log.read_text()
                    if '\n' + marker + '\n' in data:
                        return
                    if process.poll() is not None or 'GENERATION_EXEC_FAIL ' in data:
                        raise RuntimeError('generation exec did not reach ' + marker)
                    time.sleep(.01)
                raise TimeoutError('generation exec barrier expired: ' + marker)

            wait('GENERATION_EXEC_READY')
            original, row['failure'] = mutate(directory, port, 256)
            if not 0 <= original < 256:
                raise RuntimeError('the original generation slot is outside discovery bounds')
            row['original_slot'] = original
            process.stdin.write(b'F')
            process.stdin.flush()
            wait('GENERATION_EXEC_DENIED errors=16 memory=preserved')
            old, row['recovery'] = mutate(directory, port, original)
            if old != 256:
                raise RuntimeError('the failed adapter state did not remain active')
            process.stdin.write(b'R')
            process.stdin.flush()
            process.wait(timeout=max(.01, deadline-time.monotonic()))
        text = log.read_text()
        required = ['GENERATION_EXEC_SOURCE_ERROR error=5\n', 'GENERATION_RECOVERED_EXEC\n',
                    'GENERATION_EXEC_PASS denied=16 recovered=1\n', 'AXIOM64_TESTS_PASS\n',
                    'AXIOM64_EXIT status=0\n', f'Firmware: {firmware.upper()}\n']
        if process.returncode != 1 or any(marker not in text for marker in required) or 'GENERATION_UNEXPECTED_EXEC' in text:
            raise RuntimeError('the actual exec error or recovery result differs')
        row['passed'] = True
    except BaseException as error:
        row['error'] = repr(error)
        raise
    finally:
        if process is not None and process.poll() is None:
            process.kill()
            process.wait()
        if process is not None:
            process.stdin.close()
        row.update(returncode=process.returncode if process else None, elapsed_ns=time.monotonic_ns()-start,
                   log=fingerprint(log))
        (directory / 'result.json').write_text(json.dumps(row, indent=2)+'\n')
    print(json.dumps(dict(case=directory.name, passed=True)), flush=True)
    return row


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--linkage', choices=('static', 'dynamic', 'both'), default='both')
    parser.add_argument('--firmware', choices=('bios', 'uefi', 'both'), default='both')
    parser.add_argument('--output', type=Path, default=ROOT / 'build/random-generation-exec-results')
    args = parser.parse_args()
    out = args.output.resolve()
    out.mkdir(parents=True, exist_ok=False)
    subprocess.run(['make', '-s', '-j2', 'build/axiom64.elf', 'build/init', 'busybox',
                    'build/generation-exec-static', 'build/generation-exec-dynamic'], cwd=ROOT, check=True)
    inputs = snapshot(out)
    for name in ('userspace/tests/random/generation_exec.c', 'scripts/random_generation_exec_test.py'):
        inputs[name] = fingerprint(ROOT / name)
    (out / 'source-inputs.json').write_text(json.dumps(inputs, indent=2)+'\n')
    results = []
    for linkage in ('static', 'dynamic') if args.linkage == 'both' else (args.linkage,):
        folder = out / (linkage+'-image')
        folder.mkdir()
        iso = fixture(folder, linkage, 'ready', program='generation-exec')
        for firmware in ('bios', 'uefi') if args.firmware == 'both' else (args.firmware,):
            results.append(boot(out / (linkage+'-'+firmware), iso, linkage, firmware))
            (out / 'results.json').write_text(json.dumps(results, indent=2)+'\n')
    if inputs != {name: fingerprint(ROOT / name) for name in inputs}:
        raise RuntimeError('the actual generation exec source changed')


if __name__ == '__main__':
    main()
