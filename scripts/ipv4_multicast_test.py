#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Retain native Linux or guest multicast wire diagnostics over two real links."""
import argparse
import fcntl
import hashlib
import shutil
import json
import os
from pathlib import Path
import selectors
import socket
import struct
import subprocess
import sys
import time

from fetch import ROOT
from ipv4_multicast_peer import Peer
from tcp6.inputs import freeze
from compile_uapi_client import sources
from build_musl import loader


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--native', action='store_true')
    parser.add_argument('--profile', choices=('native', 'static', 'dynamic'), default='static')
    parser.add_argument('--firmware', choices=('bios', 'uefi'), default='bios')
    parser.add_argument('--transport', choices=('modern', 'legacy'), default='modern')
    parser.add_argument('--matrix', action='store_true')
    parser.add_argument('--isolated', action='store_true', help=argparse.SUPPRESS)
    parser.add_argument('--directory', type=Path, required=True)
    args = parser.parse_args()
    directory = args.directory.resolve()
    if args.matrix:
        directory.mkdir(parents=True, exist_ok=False)
        cases = [(True, profile, 'bios', 'modern') for profile in ('native', 'static', 'dynamic')]
        if not args.native:
            cases += [(False, profile, firmware, transport) for profile in ('static', 'dynamic')
                      for firmware in ('bios', 'uefi') for transport in ('modern', 'legacy')]
        results = []
        for native, profile, firmware, transport in cases:
            label = f'linux-{profile}' if native else f'guest-{profile}-{firmware}-{transport}'
            command = [sys.executable, '-B', __file__, '--profile', profile, '--firmware', firmware,
                       '--transport', transport, '--directory', str(directory / label)]
            if native:
                command.append('--native')
            with (directory / (label + '.log')).open('xb') as output:
                result = subprocess.run(command, cwd=ROOT, stdout=output, stderr=subprocess.STDOUT)
            results.append(dict(label=label, returncode=result.returncode))
            (directory / 'matrix-results.json').write_text(json.dumps(results, indent=2) + '\n')
            print(json.dumps(results[-1]), flush=True)
            if result.returncode:
                return result.returncode
        return 0
    if args.profile == 'native' and not args.native:
        parser.error('native host libc requires --native')
    if args.native and not args.isolated:
        return subprocess.call(['unshare', '--net', sys.executable, __file__, '--native',
                                '--isolated', '--profile', args.profile, '--directory', str(directory)], cwd=ROOT)
    directory.mkdir(parents=True, exist_ok=False)
    peers = [Peer(lane) for lane in range(2)]
    selector = selectors.DefaultSelector()
    handles = []
    captures = []
    capture_statistics = []
    frozen = freeze(directory)
    outgoing = [bytearray(), bytearray()]
    incoming = [bytearray(), bytearray()]
    serial = directory / 'client.log'
    program = f'ipv4-multicast-{args.profile}'
    if args.native:
        if args.profile == 'native':
            compile_command = ['gcc', '-std=c11', '-O2', '-g', '-Wall', '-Wextra', '-Werror',
                               'userspace/tests/net/ipv4_multicast.c', '-o', f'build/{program}']
            before = sources(compile_command, ROOT)
            subprocess.run(compile_command, cwd=ROOT, check=True)
            if before != sources(compile_command, ROOT):
                raise ValueError('native source changed during compile')
            binary = ROOT / 'build' / program
            (ROOT / 'build' / (program + '.inputs.json')).write_text(json.dumps(dict(command=compile_command,
                sources=before, product=dict(bytes=binary.stat().st_size,
                sha256=hashlib.sha256(binary.read_bytes()).hexdigest())), indent=2) + '\n')
        else:
            subprocess.run(['make', '-s', f'build/{program}'], cwd=ROOT, check=True)
        command = [str(ROOT / 'build' / program)]
        if args.profile == 'dynamic':
            command.insert(0, str(loader('build')))
        subprocess.run(['ip', 'link', 'set', 'lo', 'up'], check=True)
        for lane in range(2):
            fd = os.open('/dev/net/tun', os.O_RDWR | os.O_NONBLOCK)
            fcntl.ioctl(fd, 0x400454ca, struct.pack('16sH', f'eth{lane}'.encode(), 0x1002))
            subprocess.run(['ip', 'link', 'set', f'eth{lane}', 'address', peers[lane].guest.hex(':')], check=True)
            handles.append(fd)
            selector.register(fd, selectors.EVENT_READ, ('tap', lane))
            # A packet socket on a down TAP returns ENETDOWN immediately.
            # Bring up this isolated IPv4 link before starting its monitor.
            Path(f'/proc/sys/net/ipv6/conf/eth{lane}/disable_ipv6').write_text('1\n')
            subprocess.run(['ip', 'link', 'set', f'eth{lane}', 'up'], check=True)
            from tcp_fault_native import Capture
            captures.append(Capture(f'eth{lane}', directory / f'lane{lane}.pcap'))
    else:
        from network_test import fixture
        image_name = f'ipv4-multicast-{directory.name}.iso'
        fixture(program=program, script='userspace/tests/net/multicast-run.sh',
                environment={'AXIOM64_MULTICAST_CLIENT': '/bin/' + program},
                runtime_loader=loader('runtime') if args.profile == 'dynamic' else None)
        subprocess.run([sys.executable, 'scripts/image.py', '--test', '--suite', 'network',
                        '--output-name', image_name], cwd=ROOT, check=True)
        image = directory / 'guest.iso'
        os.replace(ROOT / 'build' / image_name, image)
        command = ['qemu-system-x86_64', '-machine', 'pc', '-cpu', 'max', '-m', '2G',
                   '-cdrom', str(image), '-nic', 'none', '-display', 'none',
                   '-serial', 'stdio', '-monitor', 'none', '-no-reboot',
                   '-device', 'isa-debug-exit,iobase=0xf4,iosize=0x04']
        for lane, model in enumerate(('virtio-net-pci', 'e1000')):
            server = socket.socket()
            server.bind(('127.0.0.1', 0))
            server.listen(1)
            server.setblocking(False)
            handles.append(server)
            selector.register(server, selectors.EVENT_READ, ('server', lane))
            command += ['-netdev', f'socket,id=peer{lane},connect=127.0.0.1:{server.getsockname()[1]}',
                        '-device', f'{model},netdev=peer{lane},addr={lane + 4:x},mac={peers[lane].guest.hex(":")}' + ((',disable-legacy=on' if args.transport == 'modern' else ',disable-modern=on') if lane == 0 else ''),
                        '-object', f'filter-dump,id=capture{lane},netdev=peer{lane},file={directory}/lane{lane}.pcap']
    if not args.native and args.firmware == 'uefi':
        variables = directory / 'OVMF_VARS.fd'
        shutil.copyfile('/usr/share/OVMF/OVMF_VARS_4M.fd', variables)
        command += ['-drive', 'if=pflash,format=raw,readonly=on,file=/usr/share/OVMF/OVMF_CODE_4M.fd',
                    '-drive', f'if=pflash,format=raw,file={variables}']
    retained_products = {}
    names = [program, program + '.inputs.json']
    if not args.native:
        names += ['axiom64.elf', 'init', 'rootfs-network.cpio']
    for name in names:
        shutil.copy2(ROOT / 'build' / name, directory / name)
        retained_products[name] = hashlib.sha256((directory / name).read_bytes()).hexdigest()
    if not args.native:
        retained_products['guest.iso'] = hashlib.sha256(image.read_bytes()).hexdigest()
    if args.profile == 'dynamic':
        for provider in ('build', 'runtime'):
            name = 'musl-' + provider + '-loader'
            shutil.copy2(loader(provider), directory / name)
            retained_products[name] = hashlib.sha256((directory / name).read_bytes()).hexdigest()
    if args.profile == 'native':
        for library in ('libc.so.6', 'ld-linux-x86-64.so.2'):
            path = Path(subprocess.check_output(['gcc', '-print-file-name=' + library], text=True).strip()).resolve()
            name = 'host-' + library
            shutil.copy2(path, directory / name)
            retained_products[name] = hashlib.sha256((directory / name).read_bytes()).hexdigest()
    (directory / 'inputs.json').write_text(json.dumps(dict(source=frozen, products=retained_products), indent=2) + '\n')
    (directory / 'command.json').write_text(json.dumps(command, indent=2) + '\n')
    links = [None, None]
    error = None
    process = None
    started = time.monotonic()
    def send(lane, frames):
        for frame in frames:
            peers[lane].frames.append(dict(monotonic=time.monotonic(), direction='peer', data=frame.hex()))
            if args.native:
                if os.write(handles[lane], frame) != len(frame):
                    raise RuntimeError('short native multicast injection')
            else:
                outgoing[lane].extend(len(frame).to_bytes(4, 'big') + frame)
    try:
        with serial.open('wb') as output:
            process = subprocess.Popen(command, cwd=ROOT, stdin=subprocess.DEVNULL, stdout=output, stderr=subprocess.STDOUT)
            while process.poll() is None:
                if time.monotonic() - started > 100:
                    raise TimeoutError('multicast client deadline')
                for lane in range(2):
                    send(lane, peers[lane].ready())
                    if not args.native and links[lane] is not None and links[lane].fileno() in selector.get_map():
                        selector.modify(links[lane], selectors.EVENT_READ | (selectors.EVENT_WRITE if outgoing[lane] else 0), ('peer', lane))
                for key, events in selector.select(.01):
                    kind, lane = key.data
                    if kind == 'server':
                        connection, _ = key.fileobj.accept()
                        connection.setblocking(False)
                        connection.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
                        links[lane] = connection
                        handles.append(connection)
                        selector.unregister(key.fileobj)
                        selector.register(connection, selectors.EVENT_READ, ('peer', lane))
                    elif kind == 'tap':
                        send(lane, peers[lane].receive(os.read(key.fd, 65535)))
                    else:
                        if events & selectors.EVENT_READ:
                            data = key.fileobj.recv(65536)
                            if not data:
                                selector.unregister(key.fileobj)
                                continue
                            incoming[lane].extend(data)
                            while len(incoming[lane]) >= 4:
                                size = int.from_bytes(incoming[lane][:4], 'big')
                                if size < 14 or size > 65553:
                                    raise ValueError('QEMU frame length')
                                if len(incoming[lane]) < 4 + size:
                                    break
                                frame = bytes(incoming[lane][4:4 + size])
                                del incoming[lane][:4 + size]
                                send(lane, peers[lane].receive(frame))
                        if events & selectors.EVENT_WRITE and outgoing[lane]:
                            count = key.fileobj.send(outgoing[lane])
                            del outgoing[lane][:count]
            # Read the final already-queued peer frames before deriving results.
            for key, _ in selector.select(0):
                kind, lane = key.data
                if kind == 'tap':
                    send(lane, peers[lane].receive(os.read(key.fd, 65535)))
    except Exception as exception:
        error = f'{type(exception).__name__}: {exception}'
    finally:
        if process is not None and process.poll() is None:
            process.terminate()
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=5)
        for capture in captures:
            try:
                capture_statistics.append(capture.close())
            except Exception as exception:
                failure = f'capture close: {type(exception).__name__}: {exception}'
                error = f'{error}; {failure}' if error else failure
        selector.close()
        for handle in handles:
            os.close(handle) if isinstance(handle, int) else handle.close()
    text = serial.read_text(errors='replace') if serial.exists() else ''
    results = [peer.result() for peer in peers]
    for peer in peers:
        (directory / f'lane{peer.lane}-frames.json').write_text(json.dumps(peer.frames, indent=2) + '\n')
    result = dict(passed=error is None and 'MULTICAST_TESTS_PASS' in text and all(row['passed'] for row in results) and
                  process is not None and process.returncode == (0 if args.native else 1),
                  native=args.native, profile=args.profile, firmware=args.firmware, transport=args.transport, source_root=str(ROOT), source=frozen, products=retained_products,
                  capture_statistics=capture_statistics, diagnostic_only=True,
                  strict_native_clock_and_independent_artifact_audit_pending=True,
                  returncode=process.returncode if process else None, error=error, peers=results)
    (directory / 'results.json').write_text(json.dumps(result, indent=2) + '\n')
    print(json.dumps(result, indent=2))
    return 0 if result['passed'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
