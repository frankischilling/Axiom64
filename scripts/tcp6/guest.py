# SPDX-License-Identifier: GPL-3.0-or-later
"""Boot exact native-comparable TCP6 clients with two physical guest NIC drivers."""
import json
from pathlib import Path
import shutil
import socket
import subprocess
import time
import account_store_guest
from fetch import ROOT, LOCK
from build_musl import loader
from tcp_fault_test import exercise
from tcp_fixture_inputs import audit_fixture
from tcp6.capture import verify
from tcp6.inputs import digest, write
from tcp6.peer import Peer


def prepare(directory, profile):
    compiled = json.loads((directory / 'program.inputs.json').read_text())
    image = account_store_guest.fixture(directory, 'build', profile,
        program_builder=lambda *args: (directory / 'program', compiled),
        filename='tcp6-fault', command='/bin/tcp6-fault',
        extra_products={'source/program.inputs.json': directory / 'program.inputs.json'})
    script = b'#!/bin/sh\nset -e\n/bin/tcp6-fault\necho AXIOM64_TESTS_PASS\n'
    executables = {'sbin/init': digest(ROOT / 'build/init'),
        'bin/tcp6-fault': digest(directory / 'program'),
        'bin/busybox': digest(ROOT / ('build/busybox-' + LOCK['busybox']['version']) / 'busybox'),
        'lib/ld-musl-x86_64.so.1': digest(loader('build')),
        'source/program.inputs.json': digest(directory / 'program.inputs.json')}
    audit = audit_fixture(image, digest(directory / 'kernel.elf'), executables, script)
    write(directory / 'image-audit.json', dict(audit=audit, executables=executables,
        kernel_sha256=digest(directory / 'kernel.elf'), script=script.decode()))
    return image


def run(directory, profile, firmware, transport, image):
    output = directory / (firmware + '-' + transport)
    output.mkdir()
    peers = [Peer(lane) for lane in range(2)]
    servers = []
    command = ['qemu-system-x86_64', '-machine', 'pc', '-cpu', 'max', '-m', '512M',
        '-cdrom', str(image), '-nic', 'none', '-display', 'none', '-serial', 'stdio',
        '-monitor', 'none', '-no-reboot', '-device', 'isa-debug-exit,iobase=0xf4,iosize=0x04']
    for lane, peer in enumerate(peers):
        server = socket.socket()
        server.bind(('127.0.0.1', 0))
        server.listen(1)
        servers.append(server)
        command += ['-netdev', f'socket,id=peer{lane},connect=127.0.0.1:{server.getsockname()[1]}']
        device = ('virtio-net-pci,' + ('disable-legacy=on' if transport == 'modern'
                                     else 'disable-modern=on')) if lane == 0 else 'e1000'
        command += ['-device', f'{device},netdev=peer{lane},addr={lane + 4:x},mac={peer.guest.hex(":")}',
                    '-object', f'filter-dump,id=cap{lane},netdev=peer{lane},file={output / ("lane" + str(lane) + ".pcap")}']
    firmware_inputs = {}
    if firmware == 'uefi':
        variables = output / 'OVMF_VARS.fd'
        shutil.copy2('/usr/share/OVMF/OVMF_VARS_4M.fd', variables)
        code = '/usr/share/OVMF/OVMF_CODE_4M.fd'
        firmware_inputs = {code: digest(Path(code)), 'variables_before_sha256': digest(variables)}
        command += ['-drive', 'if=pflash,format=raw,readonly=on,file=' + code,
                    '-drive', f'if=pflash,format=raw,file={variables}']
    products = dict(image_sha256=digest(image), kernel_sha256=digest(directory / 'kernel.elf'),
                    program_sha256=digest(directory / 'program'))
    began = time.monotonic_ns()
    write(output / 'preexecution.json', dict(command=command, profile=profile,
        firmware=firmware, transport=transport, products=products, firmware_inputs=firmware_inputs,
        start_monotonic_ns=began, deadline_seconds=150))
    process, error, text, results, returncode = None, None, '', [], None
    try:
        process = subprocess.Popen(command, cwd=ROOT, stdin=subprocess.DEVNULL,
                                   stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        with (output / 'guest.log').open('xb') as log:
            text, results, error, returncode = exercise(process, peers, servers, 150, log)
    except Exception as failure:
        error = f'{type(failure).__name__}: {failure}'
    finally:
        if process is not None and process.poll() is None:
            process.kill()
            process.wait()
        for server in servers:
            server.close()
    write(output / 'peers.json', [dict(lane=peer.lane, frames=peer.frames) for peer in peers])
    audits = []
    if not error:
        try:
            audits = [verify(output / f'lane{lane}.pcap', lane, text) for lane in range(2)]
        except Exception as failure:
            error = f'independent capture: {failure}'
    lines = text.splitlines()
    passed = (not error and returncode == 1 and len(audits) == 2 and
              lines.count('TCP6_FAULT_PASS flows=4 bytes_each=65536') == 1 and
              lines.count('AXIOM64_TESTS_PASS') == 1 and 'Firmware: ' + firmware.upper() in text and
              not any(marker in text for marker in ('PANIC:', 'FAULT pid=', 'TCP_FAULT_FAIL')) and
              products == dict(image_sha256=digest(image), kernel_sha256=digest(directory / 'kernel.elf'),
                               program_sha256=digest(directory / 'program')))
    receipt = dict(passed=passed, profile=profile, native=False, firmware=firmware,
        transport=transport, returncode=returncode, error=error, products=products,
        start_monotonic_ns=began, end_monotonic_ns=time.monotonic_ns(), capture_audits=audits,
        independent_capture_audited=len(audits) == 2,
        results=[{key: value for key, value in row.items() if key != 'frames'} for row in results])
    write(output / 'receipt.json', receipt)
    print(json.dumps({key: value for key, value in receipt.items()
                      if key not in ('results', 'capture_audits')}), flush=True)
    return passed
