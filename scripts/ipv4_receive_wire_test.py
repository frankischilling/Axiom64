# SPDX-License-Identifier: GPL-3.0-or-later
"""Produce native or guest IPv4 metadata evidence over two actual Ethernet paths."""
import argparse
import fcntl
import json
import os
from pathlib import Path
import platform
import selectors
import shutil
import socket
import struct
import subprocess
import sys
import time

from fetch import ROOT
from account_store_guest import fixture
from build_musl import loader
from compile_uapi_client import audit_compile, sources
from ipv4_receive_wire_peer import ReceivePeer
from tcp6.inputs import digest, freeze


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--native', action='store_true')
    parser.add_argument('--isolated', action='store_true', help=argparse.SUPPRESS)
    parser.add_argument('--profile', choices=('native', 'static', 'dynamic'), default='static')
    parser.add_argument('--firmware', choices=('bios', 'uefi'), default='bios')
    parser.add_argument('--transport', choices=('modern', 'legacy'), default='modern')
    parser.add_argument('--directory', type=Path, required=True)
    args = parser.parse_args()
    directory = (ROOT / args.directory).resolve()
    if not directory.is_relative_to((ROOT / "build").resolve()):
        parser.error("use the designated ignored build output directory")
    if args.profile == 'native' and not args.native:
        parser.error('host libc requires native execution')
    if args.native and not args.isolated:
        return subprocess.call(['unshare', '--net', sys.executable, '-B', __file__, '--native', '--isolated',
            '--profile', args.profile, '--directory', str(directory)], cwd=ROOT)
    directory.mkdir(parents=True, exist_ok=False)
    source = freeze(directory)
    inputs = json.loads((directory / 'source-inputs.json').read_text())
    program = ROOT / ('build/ipv4-receive-wire-' + args.profile)
    if not program.is_file():
        raise ValueError('build the actual client before execution')
    if args.profile == 'native':
        command = ['gcc', '-std=c11', '-O2', '-g', '-Wall', '-Wextra', '-Werror',
            'userspace/tests/net/ipv4_receive_wire.c', 'userspace/tests/net/ipv4_receive_wire_fixture.c',
            '-o', str(program)]
        before = sources(command, ROOT)
        subprocess.run(command, cwd=ROOT, check=True)
        if sources(command, ROOT) != before:
            raise ValueError('native client sources changed during compilation')
        program.with_suffix('.inputs.json').write_text(json.dumps(dict(command=command, sources=before,
            product=dict(bytes=program.stat().st_size, sha256=digest(program)),
            compiler_version=subprocess.check_output(['gcc', '--version'], text=True).splitlines()[0]), indent=2) + '\n')
    compiler = audit_compile(program, ROOT)
    shutil.copy2(program.with_suffix('.inputs.json'), directory / 'program.inputs.json')
    shutil.copy2(program, directory / 'program.elf')
    peers = [ReceivePeer(lane) for lane in range(2)]
    selector = selectors.DefaultSelector()
    handles, captures, statistics = [], [], []
    links = [None, None]
    incoming, outgoing = [bytearray(), bytearray()], [bytearray(), bytearray()]
    configuration = None
    if args.native:
        if socket.if_nameindex() != [(1, 'lo')]:
            raise ValueError('fresh private native network namespace before any configuration')
        configuration = dict(namespace_inode=os.stat('/proc/self/ns/net').st_ino, sysctls=[])
        for interface in ('all', 'default'):
            path = Path('/proc/sys/net/ipv4/conf') / interface / 'rp_filter'
            before = path.read_text()
            path.write_text('0\n')
            configuration['sysctls'].append(dict(path=str(path), before=before, configured=path.read_text()))
        subprocess.run(['ip', 'link', 'set', 'lo', 'up'], check=True)
        for lane in range(2):
            fd = os.open('/dev/net/tun', os.O_RDWR | os.O_NONBLOCK)
            fcntl.ioctl(fd, 0x400454ca, struct.pack('16sH', ('eth' + str(lane)).encode(), 0x1002))
            subprocess.run(['ip', 'link', 'set', 'eth' + str(lane), 'address', peers[lane].guest.hex(':')], check=True)
            for family, setting, value in (('ipv6', 'disable_ipv6', '1\n'), ('ipv4', 'rp_filter', '0\n')):
                path = Path('/proc/sys/net') / family / 'conf' / ('eth' + str(lane)) / setting
                before = path.read_text()
                path.write_text(value)
                configuration['sysctls'].append(dict(path=str(path), before=before, configured=path.read_text()))
            subprocess.run(['ip', 'link', 'set', 'eth' + str(lane), 'up'], check=True)
            handles.append(fd)
            selector.register(fd, selectors.EVENT_READ, ('tap', lane))
            from tcp_fault_native import Capture
            captures.append(Capture('eth' + str(lane), directory / ('lane' + str(lane) + '.pcap')))
        configuration['interfaces'] = json.loads(subprocess.check_output(['ip', '-j', 'link', 'show']))
        configuration['initial_addresses'] = json.loads(subprocess.check_output(['ip', '-j', '-4', 'address', 'show']))
        configuration['initial_routes'] = json.loads(subprocess.check_output(['ip', '-j', '-4', 'route', 'show', 'table', 'all']))
        command = ([str(directory / 'loader.elf')] if args.profile == 'dynamic' else []) + [str(directory / 'program.elf')]
        if args.profile == 'native':
            for name in ('libc.so.6', 'ld-linux-x86-64.so.2'):
                path = Path(subprocess.check_output(['gcc', '-print-file-name=' + name], text=True).strip()).resolve()
                shutil.copy2(path, directory / ('host-' + name))
    else:
        image = fixture(directory, 'build', args.profile, program_builder=lambda *unused: (program, compiler),
            filename='ipv4-receive-wire', command='/bin/ipv4-receive-wire')
        command = ['qemu-system-x86_64', '-machine', 'pc', '-cpu', 'max', '-m', '512M',
            '-cdrom', str(image), '-nic', 'none', '-display', 'none', '-serial', 'stdio', '-monitor', 'none',
            '-no-reboot', '-device', 'isa-debug-exit,iobase=0xf4,iosize=0x04']
        for lane, model in enumerate(('virtio-net-pci', 'e1000')):
            server = socket.socket()
            server.bind(('127.0.0.1', 0))
            server.listen(1)
            server.setblocking(False)
            handles.append(server)
            selector.register(server, selectors.EVENT_READ, ('server', lane))
            command += ['-netdev', 'socket,id=peer' + str(lane) + ',connect=127.0.0.1:' + str(server.getsockname()[1]),
                '-device', model + ',netdev=peer' + str(lane) + ',addr=' + format(lane + 4, 'x') +
                ',mac=' + peers[lane].guest.hex(':') + ((',disable-legacy=on' if args.transport == 'modern' else ',disable-modern=on') if lane == 0 else ''),
                '-object', 'filter-dump,id=capture' + str(lane) + ',netdev=peer' + str(lane) + ',file=' + str(directory / ('lane' + str(lane) + '.pcap'))]
        if args.firmware == 'uefi':
            variables = directory / 'OVMF_VARS.fd'
            shutil.copy2('/usr/share/OVMF/OVMF_VARS_4M.fd', variables)
            command += ['-drive', 'if=pflash,format=raw,readonly=on,file=/usr/share/OVMF/OVMF_CODE_4M.fd',
                        '-drive', 'if=pflash,format=raw,file=' + str(variables)]
    if args.profile == 'dynamic':
        shutil.copy2(loader('build'), directory / 'loader.elf')
    (directory / 'command.json').write_text(json.dumps(command, indent=2) + '\n')
    process = None
    error = None
    began = time.monotonic()

    def send(lane, frames):
        for frame in frames:
            peers[lane].frames.append(dict(monotonic_ns=time.monotonic_ns(), direction='peer', data=frame.hex()))
            if args.native:
                if os.write(handles[lane], frame) != len(frame):
                    raise RuntimeError('complete native Ethernet injection')
            else:
                outgoing[lane].extend(len(frame).to_bytes(4, 'big') + frame)

    try:
        with (directory / 'client.log').open('xb') as log:
            process = subprocess.Popen(command, cwd=ROOT, stdin=subprocess.DEVNULL, stdout=log, stderr=subprocess.STDOUT)
            (directory / 'process.json').write_text(json.dumps(dict(pid=process.pid, status='running'), indent=2) + '\n')
            while process.poll() is None:
                if time.monotonic() - began > 180:
                    raise TimeoutError('finite metadata client execution')
                for lane in range(2):
                    if not args.native and links[lane] is not None and links[lane].fileno() in selector.get_map():
                        selector.modify(links[lane], selectors.EVENT_READ | (selectors.EVENT_WRITE if outgoing[lane] else 0), ('peer', lane))
                for key, events in selector.select(.01):
                    kind, lane = key.data
                    if kind == 'server':
                        link, _ = key.fileobj.accept()
                        link.setblocking(False)
                        link.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
                        links[lane] = link
                        handles.append(link)
                        selector.unregister(key.fileobj)
                        selector.register(link, selectors.EVENT_READ, ('peer', lane))
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
                                    raise ValueError('bounded actual QEMU frame')
                                if len(incoming[lane]) < size + 4:
                                    break
                                frame = bytes(incoming[lane][4:4 + size])
                                del incoming[lane][:4 + size]
                                send(lane, peers[lane].receive(frame))
                        if events & selectors.EVENT_WRITE and outgoing[lane]:
                            count = key.fileobj.send(outgoing[lane])
                            del outgoing[lane][:count]
    except Exception as failure:
        error = type(failure).__name__ + ': ' + str(failure)
    finally:
        if process is not None and process.poll() is None:
            process.kill()
            process.wait()
        for capture in captures:
            try:
                statistics.append(capture.close())
            except Exception as failure:
                error = (error + '; ' if error else '') + 'capture: ' + str(failure)
        selector.close()
        for handle in handles:
            os.close(handle) if isinstance(handle, int) else handle.close()
    if configuration is not None:
        configuration['final_addresses'] = json.loads(subprocess.check_output(['ip', '-j', '-4', 'address', 'show']))
        configuration['final_routes'] = json.loads(subprocess.check_output(['ip', '-j', '-4', 'route', 'show', 'table', 'all']))
        (directory / 'native-configuration.json').write_text(json.dumps(configuration, indent=2) + '\n')
    for peer in peers:
        (directory / ('lane' + str(peer.lane) + '-frames.json')).write_text(json.dumps(peer.frames, indent=2) + '\n')
    text = (directory / 'client.log').read_text(errors='replace')
    result = dict(passed=not error and process is not None and process.returncode == (0 if args.native else 1) and
        text.count('IPV4_RECEIVE_WIRE_DONE lanes=2 cases_each=78 observations=156') == 1 and
        all(peer.result()['passed'] for peer in peers), source=source, native=args.native, profile=args.profile,
        firmware=args.firmware, transport=args.transport, returncode=process.returncode if process else None,
        error=error, peers=[peer.result() for peer in peers], capture_statistics=statistics,
        source_unchanged=all(digest(ROOT / name) == value for name, value in inputs.items()),
        products={path.name: digest(path) for path in directory.iterdir() if path.is_file() and
            path.name in ('program.elf', 'program.inputs.json', 'kernel.elf', 'root.cpio', 'image.iso', 'loader.elf',
                          'host-libc.so.6', 'host-ld-linux-x86-64.so.2')},
        native_kernel_release=platform.release() if args.native else None,
        packet_semantics_and_independent_readback_pending=True, full_feature_acceptance=False)
    result['passed'] = result['passed'] and result['source_unchanged']
    (directory / 'results.json').write_text(json.dumps(result, indent=2) + '\n')
    (directory / 'process.json').write_text(json.dumps(dict(status='completed', returncode=result['returncode']), indent=2) + '\n')
    print(json.dumps({key: value for key, value in result.items() if key not in ('capture_statistics', 'peers')}, indent=2))
    return 0 if result['passed'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
