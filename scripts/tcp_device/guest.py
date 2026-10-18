# SPDX-License-Identifier: GPL-3.0-or-later
"""Build four immutable images, then observe both PCI removals in all guest profiles."""
from concurrent.futures import ThreadPoolExecutor, as_completed
import json
from pathlib import Path
import shutil
import socket
import subprocess
import sys
import tempfile
import traceback

from build_musl import loader
from fetch import ROOT, LOCK
from normal_manager_test import write_archive
from tcp_device.inputs import record
from tcp_device.peer import Peer
from tcp_device.physical import Controller
from tcp_device.run import save
from tcp_fault_test import exercise


def fixture(linkage, affected):
    subprocess.run(['make', '-s', '-j2', 'build/axiom64.elf', 'build/init',
                    f'build/tcp-device-{linkage}', 'busybox'], cwd=ROOT, check=True)
    files = {name: (0o40755, b'') for name in ('bin', 'sbin', 'lib', 'etc', 'dev', 'proc', 'tmp', 'run')}
    for name, source in (('sbin/init', ROOT / 'build/init'),
                         ('bin/tcp-device', ROOT / 'build' / f'tcp-device-{linkage}'),
                         ('bin/busybox', ROOT / 'build' / f"busybox-{LOCK['busybox']['version']}" / 'busybox'),
                         ('lib/ld-musl-x86_64.so.1', loader('build'))):
        files[name] = (0o100755, source.read_bytes())
    files['etc/net-test.sh'] = (0o100755,
        f'#!/bin/sh\nset -e\n/bin/tcp-device {affected}\necho AXIOM64_TESTS_PASS\n'.encode())
    archive = ROOT / 'build/rootfs-network.cpio'
    write_archive(archive, files)
    image = ROOT / 'build' / f'axiom64-tcp-device-{affected}-{linkage}.iso'
    subprocess.run([sys.executable, 'scripts/image.py', '--test', '--suite', 'network',
                    '--output-name', image.name], cwd=ROOT, check=True, stdout=subprocess.DEVNULL)
    name = record(linkage, affected, image=image)
    return image, (ROOT / 'build' / name).read_bytes()


def profile(linkage, firmware, transport, affected, fixture_inputs):
    image, inputs = fixture_inputs
    output = ROOT / 'build/tcp-device' / f'{linkage}-{firmware}-{transport}-{affected}'
    output.mkdir(parents=True, exist_ok=True)
    (output / 'inputs.json').write_bytes(inputs)
    servers, process, controller = [], None, None
    row = dict(native=False, linkage=linkage, firmware=firmware, transport=transport,
               affected=affected, directory=output.name, passed=False)
    try:
        with tempfile.TemporaryDirectory(prefix='axiom64-tcp-device-') as temporary:
            control = Path(temporary)
            monitor_path, test_path = control / 'qmp.sock', control / 'qtest.sock'
            with socket.socket() as reserve:
                reserve.bind(('127.0.0.1', 0))
                debug_port = reserve.getsockname()[1]
            controller = Controller(ROOT, output, affected, debug_port, monitor_path, test_path, transport)
            peers = [Peer(lane, controller) for lane in range(2)]
            controller.peers = peers
            command = ['qemu-system-x86_64', '-machine', 'pc', '-cpu', 'max', '-m', '512M', '-nic', 'none',
                '-cdrom', str(image), '-display', 'none', '-serial', 'stdio', '-monitor', 'none',
                '-no-reboot', '-device', 'isa-debug-exit,iobase=0xf4,iosize=0x04',
                '-gdb', f'tcp:127.0.0.1:{debug_port}', '-qmp', f'unix:{monitor_path},server=on,wait=off',
                '-qtest', f'unix:{test_path},server=on,wait=off',
                '-qtest-log', str(output / 'qtest.log')]
            for lane, model in enumerate(('virtio-net-pci', 'e1000')):
                server = socket.socket()
                server.bind(('127.0.0.1', 0))
                server.listen(1)
                servers.append(server)
                nic = f'{model},netdev=peer{lane},id=nic{lane},addr={lane + 4:x},mac={peers[lane].guest.hex(":")}'
                if lane == 0:
                    nic += ',disable-legacy=on' if transport == 'modern' else ',disable-modern=on'
                command += ['-netdev', f'socket,id=peer{lane},connect=127.0.0.1:{server.getsockname()[1]}',
                            '-device', nic, '-object',
                            f'filter-dump,id=capture{lane},netdev=peer{lane},file={output / f"lane{lane}.pcap"}']
            if firmware == 'uefi':
                variables = output / 'OVMF_VARS.fd'
                shutil.copyfile('/usr/share/OVMF/OVMF_VARS_4M.fd', variables)
                command += ['-drive', 'if=pflash,format=raw,readonly=on,file=/usr/share/OVMF/OVMF_CODE_4M.fd',
                            '-drive', f'if=pflash,format=raw,file={variables}']
            save(output / 'command.json', command)
            with (output / 'guest.log').open('wb') as log:
                process = subprocess.Popen(command, stdin=subprocess.DEVNULL,
                                           stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
                text, results, error, returncode = exercise(process, peers, servers, 90, log)
            save(output / 'peer-frames.json', [dict(lane=peer.lane, frames=peer.frames) for peer in peers])
            row.update(returncode=returncode, error=error, peers=results,
                passed=error is None and returncode == 1 and
                all(marker in text for marker in (f'TCP_DEVICE_PASS affected={affected} queued=512',
                    'AXIOM64_TESTS_PASS', 'AXIOM64_EXIT status=0', f'Firmware: {firmware.upper()}',
                    f'virtio-net: index=1 transport={transport}', 'e1000: index=2 model=82540EM')) and
                not any(marker in text for marker in ('TCP_DEVICE_FAIL line=', 'PANIC:', 'FAULT pid=')))
            if row['passed']:
                controller.finish()
                row['physical_observer_passed'] = True
    except Exception:
        row.update(passed=False, failure=traceback.format_exc())
        (output / 'failure.txt').write_text(row['failure'])
    finally:
        if process is not None and process.poll() is None:
            process.kill()
            process.wait()
        if controller is not None:
            controller.close()
        for server in servers:
            server.close()
        save(output / 'producer-result.json', row)
    print(json.dumps({key: row[key] for key in ('linkage', 'firmware', 'transport', 'affected', 'passed')}), flush=True)
    return row


def run(workers=2):
    original = ROOT / 'build/rootfs-network.cpio'
    previous = original.read_bytes() if original.exists() else None
    try:
        images = {(linkage, affected): fixture(linkage, affected)
                  for linkage in ('static', 'dynamic') for affected in (0, 1)}
    finally:
        if previous is None:
            original.unlink(missing_ok=True)
        else:
            original.write_bytes(previous)
    rows = []
    with ThreadPoolExecutor(max_workers=workers) as executor:
        pending = [executor.submit(profile, linkage, firmware, transport, affected, images[linkage, affected])
                   for linkage in ('static', 'dynamic') for firmware in ('bios', 'uefi')
                   for transport in ('modern', 'legacy') for affected in (0, 1)]
        for future in as_completed(pending):
            rows.append(future.result())
    return rows
