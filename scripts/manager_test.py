"""Exercise the foreground network manager through actual processes and Ethernet."""
import argparse
import json
from pathlib import Path
import selectors
import shutil
import socket
import subprocess
import time
from fetch import ROOT, LOCK
from manager_peer import ManagerPeer

SCENARIOS = ('concurrent', 'missing', 'static', 'conflict', 'defense', 'disabled', 'unsafe', 'manual', 'restart',
             'hint-sync', 'resolver', 'hint-remove', 'close')


def fixture(linkage, scenario, root='/tmp', build_image=True):
    subprocess.run(['make', '-j2', 'build/axiom64.elf', 'build/init', 'busybox',
                    'build/manager-tests', 'build/network-manager',
                    'build/network-manager-dynamic', 'build/network-manager-faults',
                    'build/network-manager-dynamic-faults'], cwd=ROOT, check=True)
    expected = json.loads((ROOT / 'sources.lock.json').read_text())['build_musl']['version']
    version = subprocess.check_output(['dpkg-query', '-W', '-f=${Version}', 'musl-dev'], text=True)
    if version != expected:
        raise RuntimeError('fixture musl differs from the pinned build version')
    files = {name: (0o40755, b'') for name in
             ['bin', 'sbin', 'etc', 'dev', 'proc', 'sys', 'tmp', 'run', 'root', 'lib']}
    for name, source in [('sbin/init', ROOT / 'build/init'),
                         ('bin/busybox', ROOT / 'build' / f"busybox-{LOCK['busybox']['version']}" / 'busybox'),
                         ('bin/manager-tests', ROOT / 'build/manager-tests'),
                         ('sbin/network-manager', ROOT / 'build/network-manager'),
                         ('sbin/network-manager-dynamic', ROOT / 'build/network-manager-dynamic'),
                         ('sbin/network-manager-faults', ROOT / 'build/network-manager-faults'),
                         ('sbin/network-manager-dynamic-faults', ROOT / 'build/network-manager-dynamic-faults'),
                         ('lib/ld-musl-x86_64.so.1', Path('/lib/ld-musl-x86_64.so.1').resolve())]:
        files[name] = (0o100755, Path(source).read_bytes())
    binary = 'network-manager-dynamic' if linkage == 'dynamic' else 'network-manager'
    script = f'#!/bin/sh\nset -e\n/bin/manager-tests /sbin/{binary} {scenario} {root}\necho AXIOM64_TESTS_PASS\n'
    files['etc/net-test.sh'] = (0o100755, script.encode())
    with (ROOT / 'build/rootfs-network.cpio').open('wb') as output:
        for inode, (name, (mode, data)) in enumerate([*sorted(files.items()), ('TRAILER!!!', (0, b''))], 1):
            encoded = name.encode() + b'\0'
            fields = [inode, mode, 0, 0, 1, 0, len(data), 0, 0, 0, 0, len(encoded), 0]
            output.write(b'070701' + b''.join(f'{value:08x}'.encode() for value in fields) + encoded)
            output.write(bytes(-output.tell() % 4))
            output.write(data)
            output.write(bytes(-output.tell() % 4))
    if build_image:
        subprocess.run(['python3', 'scripts/image.py', '--test', '--suite', 'network',
                        '--output-name', f'axiom64-manager-{linkage}.iso'], cwd=ROOT, check=True)


def run(linkage, scenario, firmware, transport, timeout, repetition=0, root_disk=None, image=None):
    label = f'manager-{scenario}-{linkage}-{firmware}-{transport}' + (f'-repeat{repetition}' if repetition else '')
    log = ROOT / 'build' / (label + '.log')
    selector = selectors.DefaultSelector()
    servers, peers = [], [ManagerPeer(0, scenario), ManagerPeer(1, scenario)]
    command = ['qemu-system-x86_64', '-machine', 'pc', '-cpu', 'max', '-m', '512M',
               '-cdrom', str(image or ROOT / 'build' / f'axiom64-manager-{linkage}.iso'), '-nic', 'none',
               '-display', 'none', '-serial', 'stdio', '-monitor', 'none', '-no-reboot',
               '-device', 'isa-debug-exit,iobase=0xf4,iosize=0x04']
    if root_disk:
        mode = 'disable-legacy=on' if transport == 'modern' else 'disable-modern=on'
        command += ['-drive', f'if=none,id=root,format=raw,cache=writeback,file={root_disk}',
                    '-device', f'virtio-blk-pci,drive=root,{mode},rerror=report,werror=report,addr=6']
    for lane, model in enumerate(['virtio-net-pci', 'e1000']):
        server = socket.socket()
        server.bind(('127.0.0.1', 0))
        server.listen(1)
        server.setblocking(False)
        servers.append(server)
        selector.register(server, selectors.EVENT_READ, ('server', lane))
        nic = f'{model},netdev=peer{lane},addr={lane + 4:x},mac={peers[lane].guest.hex(":")}'
        if lane == 0:
            nic += ',disable-legacy=on' if transport == 'modern' else ',disable-modern=on'
        command += ['-netdev', f'socket,id=peer{lane},connect=127.0.0.1:{server.getsockname()[1]}',
                    '-device', nic]
    if firmware == 'uefi':
        variables = ROOT / 'build' / (label + '-OVMF_VARS.fd')
        shutil.copyfile('/usr/share/OVMF/OVMF_VARS_4M.fd', variables)
        command += ['-drive', 'if=pflash,format=raw,readonly=on,file=/usr/share/OVMF/OVMF_CODE_4M.fd',
                    '-drive', f'if=pflash,format=raw,file={variables}']
    started = time.monotonic()
    error = None
    exit_at = None
    with log.open('wb') as output:
        process = subprocess.Popen(command, stdout=output, stderr=subprocess.STDOUT,
                                   stdin=subprocess.DEVNULL)
        try:
            while True:
                now = time.monotonic()
                if process.poll() is not None:
                    if exit_at is None:
                        exit_at = now
                    if now - exit_at > .2:
                        break
                if now - started > timeout:
                    raise RuntimeError('network manager deadline exceeded')
                for key, events in selector.select(.01):
                    kind, lane = key.data
                    peer = peers[lane]
                    if kind == 'server':
                        connection, _ = key.fileobj.accept()
                        connection.setblocking(False)
                        connection.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
                        peer.connection = connection
                        selector.unregister(key.fileobj)
                        selector.register(connection, selectors.EVENT_READ, ('peer', lane))
                        continue
                    connection = key.fileobj
                    if events & selectors.EVENT_READ:
                        data = connection.recv(65536)
                        if not data:
                            selector.unregister(connection)
                            continue
                        peer.input.extend(data)
                        while len(peer.input) >= 4:
                            size = int.from_bytes(peer.input[:4], 'big')
                            if not 14 <= size <= 1518:
                                raise RuntimeError('QEMU packet length outside Ethernet bounds')
                            if len(peer.input) < size + 4:
                                break
                            if b'MANAGER_TEST_READY' in log.read_bytes():
                                peer.packet(bytes(peer.input[4:size + 4]))
                            del peer.input[:size + 4]
                    if peer.output:
                        try:
                            sent = connection.send(peer.output)
                            del peer.output[:sent]
                        except BlockingIOError:
                            pass
                    selector.modify(connection, selectors.EVENT_READ | (
                        selectors.EVENT_WRITE if peer.output else 0), ('peer', lane))
        except Exception as exception:
            error = str(exception)
        finally:
            if process.poll() is None:
                process.kill()
            returncode = process.wait()
            selector.close()
            for server in servers:
                server.close()
            for peer in peers:
                if peer.connection:
                    peer.connection.close()
    text = log.read_text(errors='replace')
    required = [f'MANAGER_TEST_PASS scenario={scenario} processes=checked resolver=merged manual=preserved',
                'AXIOM64_TESTS_PASS', 'AXIOM64_EXIT status=0',
                f'Firmware: {firmware.upper()}']
    if scenario != 'persist-prime':
        required.append('NETWORK_MANAGER_EXIT status=0')
    if root_disk:
        required += ['VFS_ROOT_PASS filesystem=ext2 device=/dev/vda readonly=0',
                     'MANAGER_PERSIST_PRIME_PASS' if scenario == 'persist-prime' else 'MANAGER_PERSIST_REBOOT_PASS']
    missing = [marker for marker in required if marker not in text]
    counts = [peer.counts() for peer in peers]
    if error is None and returncode == 1 and not missing:
        try:
            counts = [peer.verify() for peer in peers]
        except Exception as exception:
            error = str(exception)
    result = dict(linkage=linkage, scenario=scenario, firmware=firmware, transport=transport, returncode=returncode,
                  error=error, missing=missing, counts=counts, log=log.name,
                  seconds=round(time.monotonic() - started, 3),
                  passed=returncode == 1 and error is None and not missing and
                  not any(marker in text for marker in ['PANIC:', 'MANAGER_TEST_FAIL ', 'FAULT pid=']))
    print(json.dumps(result), flush=True)
    if not result['passed']:
        print(text[-4500:], flush=True)
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--linkage', choices=['static', 'dynamic', 'both'], default='both')
    parser.add_argument('--scenario', choices=SCENARIOS, nargs='+', default=list(SCENARIOS))
    parser.add_argument('--firmware', choices=['bios', 'uefi', 'both'], default='both')
    parser.add_argument('--transport', choices=['modern', 'legacy', 'both'], default='both')
    parser.add_argument('--timeout', type=float, default=110)
    parser.add_argument('--repeat', type=int, default=1)
    args = parser.parse_args()
    if args.timeout <= 0:
        parser.error('timeout must be positive')
    if args.repeat <= 0:
        parser.error('repeat must be positive')
    results = []
    report = 'manager-results.json' if args.firmware == 'both' or args.transport == 'both' else (
        f'manager-{args.firmware}-{args.transport}-results.json')
    for linkage in ['static', 'dynamic'] if args.linkage == 'both' else [args.linkage]:
        for scenario in args.scenario:
            fixture(linkage, scenario)
            for firmware in ['bios', 'uefi'] if args.firmware == 'both' else [args.firmware]:
                for transport in ['modern', 'legacy'] if args.transport == 'both' else [args.transport]:
                    for repetition in range(args.repeat):
                        result = run(linkage, scenario, firmware, transport, args.timeout,
                                     repetition + 1 if args.repeat > 1 else 0)
                        results.append(result)
                        (ROOT / 'build' / report).write_text(json.dumps(results, indent=2) + '\n')
                        if not result['passed']:
                            raise SystemExit('Guest concurrent network manager failed')


if __name__ == '__main__':
    main()
