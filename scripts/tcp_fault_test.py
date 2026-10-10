# SPDX-License-Identifier: GPL-3.0-or-later
"""Exercise real Linux TCP sockets against independently constructed loss peers."""
import argparse
import json
from pathlib import Path
import selectors
import shutil
import socket
import struct
import subprocess
import time
from fetch import ROOT, LOCK
from tcp_fault_peer import Peer, check


def fixture(linkage):
    subprocess.run(['make', '-s', '-j2', 'build/axiom64.elf', 'build/init',
                    f'build/tcp-fault-{linkage}', 'busybox'], cwd=ROOT, check=True)
    actual = subprocess.check_output(['dpkg-query', '-W', '-f=${Version}', 'musl-dev'], text=True)
    expected = json.loads((ROOT / 'sources.lock.json').read_text())['build_musl']['version']
    check(actual == expected, 'controlled TCP fixture uses locked musl')
    files = {name: (0o40755, b'') for name in ('bin', 'sbin', 'lib', 'etc', 'dev', 'proc', 'tmp', 'run')}
    for name, source in (('sbin/init', ROOT / 'build/init'),
                         ('bin/tcp-fault', ROOT / 'build' / f'tcp-fault-{linkage}'),
                         ('bin/busybox', ROOT / 'build' / f"busybox-{LOCK['busybox']['version']}" / 'busybox'),
                         ('lib/ld-musl-x86_64.so.1', Path('/lib/ld-musl-x86_64.so.1').resolve())):
        files[name] = (0o100755, source.read_bytes())
    files['etc/net-test.sh'] = (0o100755, b'#!/bin/sh\nset -e\n/bin/tcp-fault\necho AXIOM64_TESTS_PASS\n')
    original = ROOT / 'build/rootfs-network.cpio'
    with original.open('wb') as output:
        for inode, (name, (mode, data)) in enumerate([*sorted(files.items()), ('TRAILER!!!', (0, b''))], 1):
            encoded = name.encode() + b'\0'
            fields = [inode, mode, 0, 0, 1, 0, len(data), 0, 0, 0, 0, len(encoded), 0]
            output.write(b'070701' + b''.join(f'{value:08x}'.encode() for value in fields) + encoded)
            output.write(bytes(-output.tell() % 4))
            output.write(data)
            output.write(bytes(-output.tell() % 4))
    image = ROOT / 'build' / f'axiom64-tcp-fault-{linkage}.iso'
    subprocess.run(['python3', 'scripts/image.py', '--test', '--suite', 'network', '--output-name', image.name],
                   cwd=ROOT, check=True, stdout=subprocess.DEVNULL)
    return image


def exercise(process, peers, servers, timeout, log, raw=False):
    selector = selectors.DefaultSelector()
    connections = [None, None]
    buffers, started_roles = [bytearray(), bytearray()], set()
    began, text, lines, error = time.monotonic(), bytearray(), bytearray(), None
    selector.register(process.stdout, selectors.EVENT_READ, ('serial', None))
    for lane, server in enumerate(servers):
        server.setblocking(False)
        selector.register(server, selectors.EVENT_READ, ('peer' if raw else 'server', lane))
        if raw:
            connections[lane] = server
    try:
        while True:
            check(time.monotonic() - began <= timeout, 'controlled TCP overall deadline')
            for key, _ in selector.select(.005):
                kind, lane = key.data
                if kind == 'serial':
                    data = key.fileobj.read1(65536)
                    if not data:
                        selector.unregister(key.fileobj)
                        continue
                    text.extend(data)
                    lines.extend(data)
                    log.write(data)
                    log.flush()
                    while b'\n' in lines:
                        line, _, rest = lines.partition(b'\n')
                        lines = bytearray(rest)
                        for index in range(2):
                            marker = f'TCP_FAULT_READY lane={index} role=1'.encode()
                            if marker in line and index not in started_roles:
                                check(connections[index] is not None, 'independent TCP peer connected before passive open')
                                peers[index].flows[1].start()
                                started_roles.add(index)
                    continue
                if kind == 'server':
                    channel, _ = key.fileobj.accept()
                    channel.setblocking(False)
                    channel.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
                    connections[lane] = channel
                    selector.unregister(key.fileobj)
                    selector.register(channel, selectors.EVENT_READ, ('peer', lane))
                    continue
                if raw:
                    frame, address = key.fileobj.recvfrom(65536)
                    if address[2] != socket.PACKET_OUTGOING:
                        peers[lane].receive(frame)
                    continue
                data = key.fileobj.recv(65536)
                if not data:
                    selector.unregister(key.fileobj)
                    continue
                buffers[lane].extend(data)
                while len(buffers[lane]) >= 4:
                    size = int.from_bytes(buffers[lane][:4], 'big')
                    check(14 <= size <= 1518, 'complete bounded Ethernet backend frame')
                    if len(buffers[lane]) < size + 4:
                        break
                    frame = bytes(buffers[lane][4:size + 4])
                    del buffers[lane][:size + 4]
                    peers[lane].receive(frame)
            for lane, peer in enumerate(peers):
                channel = connections[lane]
                if channel is None:
                    continue
                if raw:
                    while peer.outgoing:
                        frame = peer.outgoing.pop(0)
                        check(channel.send(frame) == len(frame), 'complete independent Ethernet packet send')
                else:
                    while peer.outgoing:
                        frame = peer.outgoing.pop(0)
                        peer.output.extend(struct.pack('!I', len(frame)) + frame)
                    if peer.output:
                        try:
                            count = channel.send(peer.output)
                            del peer.output[:count]
                        except BlockingIOError:
                            pass
            if process.poll() is not None and not selector.get_map().get(process.stdout.fileno()):
                break
        process.wait()
        results = [peer.result() for peer in peers]
    except Exception as exception:
        error, results = str(exception), []
    finally:
        if process.poll() is None:
            process.kill()
        process.wait()
        selector.close()
        for channel in connections:
            if channel is not None and not raw:
                channel.close()
    return text.decode(errors='replace'), results, error


def run(linkage, firmware, transport, image, timeout):
    label = f'tcp-fault-{linkage}-{firmware}-{transport}'
    log_path = ROOT / 'build' / f'{label}.log'
    peers, servers, captures = [Peer(lane) for lane in range(2)], [], []
    command = ['qemu-system-x86_64', '-machine', 'pc', '-cpu', 'max', '-m', '512M', '-nic', 'none',
               '-cdrom', str(image), '-display', 'none', '-serial', 'stdio', '-monitor', 'none',
               '-no-reboot', '-device', 'isa-debug-exit,iobase=0xf4,iosize=0x04']
    for lane, model in enumerate(('virtio-net-pci', 'e1000')):
        server = socket.socket()
        server.bind(('127.0.0.1', 0))
        server.listen(1)
        servers.append(server)
        nic = f'{model},netdev=peer{lane},addr={lane + 4:x},mac={peers[lane].guest.hex(":")}'
        if lane == 0:
            nic += ',disable-legacy=on' if transport == 'modern' else ',disable-modern=on'
        capture = ROOT / 'build' / f'{label}-lane{lane}.pcap'
        capture.unlink(missing_ok=True)
        captures.append(capture)
        command += ['-netdev', f'socket,id=peer{lane},connect=127.0.0.1:{server.getsockname()[1]}',
                    '-device', nic, '-object', f'filter-dump,id=capture{lane},netdev=peer{lane},file={capture}']
    if firmware == 'uefi':
        variables = ROOT / 'build' / f'{label}-OVMF_VARS.fd'
        shutil.copyfile('/usr/share/OVMF/OVMF_VARS_4M.fd', variables)
        command += ['-drive', 'if=pflash,format=raw,readonly=on,file=/usr/share/OVMF/OVMF_CODE_4M.fd',
                    '-drive', f'if=pflash,format=raw,file={variables}']
    began = time.monotonic()
    try:
        with log_path.open('wb') as log:
            process = subprocess.Popen(command, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
            text, results, error = exercise(process, peers, servers, timeout, log)
    finally:
        for server in servers:
            server.close()
    peer_path = ROOT / 'build' / f'{label}-peer.json'
    peer_path.write_text(json.dumps([dict(lane=peer.lane, frames=peer.frames) for peer in peers], indent=2) + '\n')
    required = ['TCP_FAULT_CONFIG_PASS nics=2', 'TCP_FAULT_PASS flows=4 bytes_each=65536',
                'AXIOM64_TESTS_PASS', 'AXIOM64_EXIT status=0', f'Firmware: {firmware.upper()}',
                f'virtio-net: index=1 transport={transport}', 'e1000: index=2 model=82540EM']
    required += [f'TCP_FAULT_FLOW_PASS lane={lane} role={role} bytes_each=65536'
                 for lane in range(2) for role in range(2)]
    missing = [marker for marker in required if marker not in text]
    result = dict(linkage=linkage, firmware=firmware, transport=transport, returncode=process.returncode,
                  error=error, missing=missing, peers=[{key: value for key, value in peer.items() if key != 'frames'}
                                                     for peer in results],
                  peer=peer_path.name, captures=[path.name for path in captures], log=log_path.name,
                  seconds=round(time.monotonic() - began, 3),
                  passed=not error and not missing and process.returncode == 1 and
                  not any(marker in text for marker in ('TCP_FAULT_FAIL', 'PANIC:', 'FAULT pid=')))
    print(json.dumps(result), flush=True)
    if not result['passed']:
        print(text[-5000:], flush=True)
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name, choices in (('linkage', ('static', 'dynamic')), ('firmware', ('bios', 'uefi')),
                          ('transport', ('modern', 'legacy'))):
        parser.add_argument(f'--{name}', choices=(*choices, 'both'), default='both')
    parser.add_argument('--timeout', type=float, default=150)
    args = parser.parse_args()
    if args.timeout <= 0:
        parser.error('timeout must be positive')
    original = ROOT / 'build/rootfs-network.cpio'
    previous = original.read_bytes() if original.exists() else None
    results = []
    try:
        for linkage in ('static', 'dynamic') if args.linkage == 'both' else (args.linkage,):
            image = fixture(linkage)
            for firmware in ('bios', 'uefi') if args.firmware == 'both' else (args.firmware,):
                for transport in ('modern', 'legacy') if args.transport == 'both' else (args.transport,):
                    result = run(linkage, firmware, transport, image, args.timeout)
                    results.append(result)
                    (ROOT / 'build/tcp-fault-results.json').write_text(json.dumps(results, indent=2) + '\n')
                    if not result['passed']:
                        raise SystemExit('Controlled guest TCP loss acceptance failed')
    finally:
        if previous is None:
            original.unlink(missing_ok=True)
        else:
            original.write_bytes(previous)


if __name__ == '__main__':
    main()
