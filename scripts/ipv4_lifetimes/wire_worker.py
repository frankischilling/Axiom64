# SPDX-License-Identifier: GPL-3.0-or-later
"""Capture one real two-adapter lifetime wire campaign and controlled peer receipts."""
import argparse
import gzip
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

from account_store_guest import fixture
from build_musl import loader
from compile_uapi_client import audit_compile
from fetch import ROOT
from ipv4_lifetimes.reader import decode, require
from ipv4_lifetimes.wire_peer import Peer
from ipv4_source_route.runtime import capture as capture_runtime
from tcp6.inputs import digest, freeze, write
from tcp_fixture_inputs import audit_fixture

CLIENT = 'userspace/tests/net/ipv4/address_lifetime_wire.c'
SCRIPT = ('#!/bin/sh\nset -e\n/bin/busybox ifconfig eth0 up\n/bin/busybox ifconfig eth1 up\n'
          '/bin/ipv4-lifetime-wire eth0 eth1\necho AXIOM64_TESTS_PASS\n').encode()


def prepare(directory, profile, program, compiled):
    def builder(provider, linkage, destination):
        require(provider == 'build' and linkage == profile and destination == directory, 'fixed guest fixture products')
        return program, compiled
    return fixture(directory, 'build', profile, program_builder=builder, filename='ipv4-lifetime-wire',
                   command=SCRIPT.decode().split('set -e\n', 1)[1].rsplit('\necho ', 1)[0])


def audit_image(directory):
    products = decode((directory / 'products.json').read_text())
    for name in ('image.iso', 'root.cpio', 'kernel.elf'):
        require(digest(directory / name) == products[name]['sha256'] and
                (directory / name).stat().st_size == products[name]['bytes'], 'exact actual guest fixture products')
    executables = {name: value['sha256'] for name, value in products.items()
                   if name not in ('image.iso', 'root.cpio', 'kernel.elf')}
    audit_fixture(directory / 'image.iso', products['kernel.elf']['sha256'], executables, SCRIPT,
                  products['root.cpio']['sha256'])
    return directory / 'image.iso'


def offload(interface):
    before = subprocess.check_output(['ethtool', '-k', interface], text=True)
    subprocess.run(['ethtool', '-K', interface, 'tx', 'off', 'tso', 'off', 'gso', 'off', 'gro', 'off'],
                   check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    after = subprocess.check_output(['ethtool', '-k', interface], text=True)
    require(all(name + ': off' in after for name in ('tx-checksumming', 'tcp-segmentation-offload',
                                                   'generic-segmentation-offload', 'generic-receive-offload')),
            'actual complete-checksum native interface offloads')
    return dict(before=before, after=after)


def run(directory, mode, profile, firmware='bios', transport='modern', parent_namespace=None, shared=None):
    require(mode in ('native', 'guest') and profile in ('native', 'static', 'dynamic') and
            (mode == 'native' or profile != 'native') and firmware in ('bios', 'uefi') and
            transport in ('modern', 'legacy') and 'GH_TOKEN' not in os.environ, 'fixed credential-free worker inputs')
    directory = Path(directory).resolve()
    require(directory.is_relative_to((ROOT / 'build').resolve()), 'designated ignored wire output')
    if mode == 'native':
        require(os.geteuid() == 0 and parent_namespace is not None and
                Path('/proc/self/ns/net').stat().st_ino != parent_namespace,
                'actual root owns a fresh native network namespace')
    directory.mkdir(exist_ok=False)
    if shared is None:
        (directory / 'source').mkdir()
        source = freeze(directory / 'source')
    else:
        shared = Path(shared).resolve()
        require(shared.is_relative_to((ROOT / 'build').resolve()) and directory.parent == shared,
                'one owned shared matrix source and fixture root')
        source = decode((shared / 'inputs.json').read_text())['source']
    program = ROOT / 'build' / ('ipv4-lifetime-wire-' + profile)
    compiled = audit_compile(program, ROOT)
    shutil.copy2(program, directory / 'program')
    write(directory / 'program.inputs.json', compiled)
    selector = selectors.DefaultSelector()
    channels, monitors, buffers, listeners = {}, {}, {}, []
    environment = dict(os.environ)
    runtime_read = runtime_write = None
    if mode == 'native':
        configurations = {}
        for lane in (0, 1):
            interface, peer = 'eth' + str(lane), 'peer' + str(lane)
            subprocess.run(['ip', 'link', 'add', interface, 'type', 'veth', 'peer', 'name', peer], check=True)
            for name, mac in ((interface, f'02:00:00:00:00:0{lane + 1}'), (peer, f'02:00:00:00:01:0{lane + 1}')):
                subprocess.run(['ip', 'link', 'set', name, 'address', mac], check=True)
                subprocess.run(['ip', 'link', 'set', name, 'up'], check=True)
                configurations[name] = offload(name)
            Path('/proc/sys/net/ipv6/conf', peer, 'disable_ipv6').write_text('1\n')
            for name, collection, role in ((peer, channels, 'network'), (interface, monitors, 'ingress')):
                channel = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(3))
                channel.setsockopt(263, 8, 1)
                channel.setsockopt(socket.SOL_SOCKET, 35, 1)
                channel.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 4 * 1024 * 1024)
                channel.bind((name, 0))
                channel.setblocking(False)
                collection[lane] = channel
                selector.register(channel, selectors.EVENT_READ, (role, lane))
        write(directory / 'offloads.json', configurations)
        kernel = platform.release()
        config = Path('/boot/config-' + kernel)
        (directory / 'kernel.config').write_bytes(config.read_bytes() if config.is_file()
                                                else gzip.decompress(Path('/proc/config.gz').read_bytes()))
        write(directory / 'native.json', dict(kernel=kernel, kernel_config_sha256=digest(directory / 'kernel.config'),
              parent_namespace=parent_namespace, namespace=Path('/proc/self/ns/net').stat().st_ino))
        runtime_read, runtime_write = os.pipe()
        environment['LIFETIME_WIRE_RUNTIME_FD'] = str(runtime_read)
        executable = loader('build').resolve() if profile == 'dynamic' else program.resolve()
        command = ([str(executable)] if profile == 'dynamic' else []) + [str(program), 'eth0', 'eth1']
    else:
        base = directory if shared is None else shared / profile
        if shared is None:
            prepare(base, profile, program, compiled)
        image = audit_image(base)
        command = ['qemu-system-x86_64', '-machine', 'pc', '-cpu', 'max', '-m', '256M', '-cdrom', str(image),
                   '-display', 'none', '-serial', 'stdio', '-monitor', 'none', '-no-reboot',
                   '-device', 'isa-debug-exit,iobase=0xf4,iosize=0x04']
        if firmware == 'uefi':
            firmware_directory = directory if shared is None else shared
            if shared is None:
                shutil.copy2('/usr/share/OVMF/OVMF_CODE_4M.fd', directory / 'OVMF_CODE.fd')
                shutil.copy2('/usr/share/OVMF/OVMF_VARS_4M.fd', directory / 'OVMF_VARS.original.fd')
            shutil.copy2(firmware_directory / 'OVMF_VARS.original.fd', directory / 'OVMF_VARS.fd')
            command += ['-drive', 'if=pflash,format=raw,readonly=on,file=' + str(firmware_directory / 'OVMF_CODE.fd'),
                        '-drive', 'if=pflash,format=raw,file=' + str(directory / 'OVMF_VARS.fd')]
        virtio = 'virtio-net-pci,' + ('disable-legacy=on' if transport == 'modern' else 'disable-modern=on')
        for lane, device in enumerate((virtio, 'e1000')):
            listener = socket.socket()
            listener.bind(('127.0.0.1', 0))
            listener.listen(1)
            listener.settimeout(15)
            listeners.append(listener)
            command += ['-netdev', f'socket,id=net{lane},connect=127.0.0.1:{listener.getsockname()[1]}',
                        '-device', device + f',netdev=net{lane},mac=02:00:00:00:00:0{lane + 1}']
    write(directory / 'command.json', command)
    began = time.monotonic_ns()
    process = subprocess.Popen(command, cwd=ROOT, env=environment, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                               stderr=subprocess.STDOUT, pass_fds=() if runtime_read is None else (runtime_read,))
    write(directory / 'process.json', dict(pid=process.pid, status='running', mode=mode, profile=profile))
    if runtime_read is not None:
        os.close(runtime_read)
        runtime_read = None
    events, receipts, commands, serial = [], [], [], bytearray()
    pending_line = bytearray()
    stdout_closed = complete = False
    runtime_captured = False
    wire_stream = (directory / 'wire.jsonl').open('x')
    ingress_stream = (directory / 'ingress.jsonl').open('x')
    serial_stream = (directory / 'client.log').open('xb')

    def receipt(lane, frame, direction, packet_type=None, ancillary=(), flags=0):
        value = dict(index=lane, direction=direction, frame=frame.hex(), monotonic_ns=time.monotonic_ns(),
                     realtime_ns=time.time_ns(), packet_type=packet_type, flags=flags,
                     ancillary=[dict(level=level, kind=kind, data=data.hex()) for level, kind, data in ancillary])
        stream = ingress_stream if direction == 'ingress' else wire_stream
        stream.write(json.dumps(value) + '\n')
        stream.flush()
        receipts.append(value)

    def send(lane, frame):
        if mode == 'native':
            require(channels[lane].send(frame) == len(frame), 'complete native peer injection')
        else:
            channels[lane].sendall(len(frame).to_bytes(4, 'big') + frame)
        receipt(lane, frame, 'input')

    def command_byte(data, case):
        before = time.monotonic_ns()
        require(process.stdin.write(data) == len(data), 'complete original control byte')
        process.stdin.flush()
        commands.append(dict(case=case, bytes=data.hex(), before_ns=before, after_ns=time.monotonic_ns(), realtime_ns=time.time_ns()))
        write(directory / 'commands.json', commands)

    peer = Peer(send, command_byte)

    def consume(data):
        nonlocal complete, runtime_captured, runtime_write
        serial.extend(data)
        serial_stream.write(data)
        serial_stream.flush()
        pending_line.extend(data)
        while b'\n' in pending_line:
            end = pending_line.index(10)
            line = bytes(pending_line[:end]).decode(errors='replace').rstrip('\r')
            del pending_line[:end + 1]
            require('LIFETIME_WIRE_FAIL' not in line and 'PANIC:' not in line and 'FAULT pid=' not in line,
                    'actual client or kernel failure: ' + line[:240])
            if line == 'LIFETIME_WIRE_RUNTIME_READY':
                require(mode == 'native' and not runtime_captured, 'one native runtime readiness barrier')
                capture_runtime(process, program, executable, directory, profile, parent_namespace)
                os.write(runtime_write, b'\xa5')
                os.close(runtime_write)
                runtime_write = None
                runtime_captured = True
            elif line.startswith('LIFETIME_WIRE_EVENT '):
                value = decode(line.partition(' ')[2])
                events.append(dict(value, receipt_monotonic_ns=time.monotonic_ns(), receipt_realtime_ns=time.time_ns()))
                write(directory / 'events.json', events)
                peer.event(value)
            elif line == 'LIFETIME_WIRE_PASS cases=24 interfaces=2 transports=3 survival_states=4':
                require(not complete and len(peer.results) == 24, 'complete physical lifetime campaign')
                complete = True

    try:
        if mode == 'guest':
            for lane, listener in enumerate(listeners):
                channel, _ = listener.accept()
                channel.setblocking(False)
                channels[lane] = channel
                buffers[lane] = bytearray()
                selector.register(channel, selectors.EVENT_READ, ('network', lane))
        os.set_blocking(process.stdout.fileno(), False)
        selector.register(process.stdout, selectors.EVENT_READ, ('serial', 0))
        deadline = time.monotonic() + 300
        drain_deadline = None
        while True:
            if process.poll() is not None and stdout_closed:
                if drain_deadline is None:
                    drain_deadline = time.monotonic() + .1
                if time.monotonic() >= drain_deadline:
                    break
            require(time.monotonic() < deadline, 'original complete wire worker deadline')
            for key, _ in selector.select(.01):
                role, lane = key.data
                if role == 'serial':
                    data = os.read(process.stdout.fileno(), 65536)
                    if not data:
                        stdout_closed = True
                        selector.unregister(process.stdout)
                    else:
                        consume(data)
                elif mode == 'native':
                    data, ancillary, flags, address = key.fileobj.recvmsg(65535, 512)
                    receipt(lane, data, 'ingress' if role == 'ingress' else 'output', address[2], ancillary, flags)
                    require(not flags, 'complete untruncated native packet and auxiliary controls')
                    if role == 'network' and address[2] != 4 and not complete:
                        if data[12:14] == b'\x08\x00':
                            require(not any(level == 263 and kind == 8 and int.from_bytes(value[:4], 'little') & 8
                                            for level, kind, value in ancillary), 'native wire checksum is complete before observation')
                        peer.receive(lane, data)
                else:
                    data = key.fileobj.recv(65536)
                    if not data:
                        selector.unregister(key.fileobj)
                        continue
                    buffer = buffers[lane]
                    buffer.extend(data)
                    while len(buffer) >= 4:
                        length = int.from_bytes(buffer[:4], 'big')
                        require(14 <= length <= 9014, 'bounded actual QEMU Ethernet packet')
                        if len(buffer) < length + 4:
                            break
                        frame = bytes(buffer[4:length + 4])
                        del buffer[:length + 4]
                        receipt(lane, frame, 'output')
                        if not complete:
                            peer.receive(lane, frame)
            if not complete:
                peer.poll()
        process.wait(timeout=5)
        require(process.returncode == (0 if mode == 'native' else 1) and complete,
                'actual completed native or guest process and workload')
        if mode == 'guest':
            require(all(not buffer for buffer in buffers.values()), 'no incomplete final Ethernet frame')
        record = dict(protocol_passed=True, final_wire_acceptance=False, mode=mode, profile=profile, firmware=firmware,
                      transport=transport, returncode=process.returncode, elapsed_ns=time.monotonic_ns() - began,
                      cases=peer.results, source=source, shared_directory=str(shared) if shared else None,
                      original_directory=str(directory), client_log_sha256=digest(directory / 'client.log'),
                      command_sha256=digest(directory / 'command.json'), firmware_inputs={
                          name: dict(bytes=(firmware_directory / name).stat().st_size, sha256=digest(firmware_directory / name))
                          for name in ('OVMF_CODE.fd', 'OVMF_VARS.original.fd')} if mode == 'guest' and firmware == 'uefi' else {})
        write(directory / 'captured.json', record)
        return record
    finally:
        if process.poll() is None:
            process.terminate()
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait()
        write(directory / 'process.json', dict(pid=process.pid, status='completed', returncode=process.returncode))
        if mode == 'native':
            statistics = {}
            for role, collection in (('peer', channels), ('client', monitors)):
                for lane, channel in collection.items():
                    data = channel.getsockopt(263, 6, 12)
                    require(len(data) >= 8, 'actual native packet-statistics structure')
                    packets, drops = struct.unpack_from('II', data)
                    statistics[role + str(lane)] = dict(packets=packets, drops=drops)
            write(directory / 'packet-statistics.json', statistics)
        for channel in [*channels.values(), *monitors.values(), *listeners]:
            channel.close()
        for fd in (runtime_read, runtime_write):
            if fd is not None:
                os.close(fd)
        for stream in (wire_stream, ingress_stream, serial_stream):
            stream.close()
        selector.close()
        if complete and process.returncode == (0 if mode == 'native' else 1):
            record['artifacts'] = {path.relative_to(directory).as_posix(): digest(path)
                                   for path in sorted(directory.rglob('*'))
                                   if path.is_file() and path.name != 'captured.json'}
            write(directory / 'captured.json', record)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('directory', type=Path)
    parser.add_argument('--mode', choices=('native', 'guest'), required=True)
    parser.add_argument('--profile', choices=('native', 'static', 'dynamic'), required=True)
    parser.add_argument('--firmware', choices=('bios', 'uefi'), default='bios')
    parser.add_argument('--transport', choices=('modern', 'legacy'), default='modern')
    parser.add_argument('--parent-namespace', type=int)
    parser.add_argument('--shared', type=Path)
    args = parser.parse_args()
    print(json.dumps(run(args.directory, args.mode, args.profile, args.firmware, args.transport,
                         args.parent_namespace, args.shared)), flush=True)


if __name__ == '__main__':
    main()
