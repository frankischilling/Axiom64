#!/usr/bin/env python3
"""Exchange validated Ethernet frames with isolated loopback QEMU peers."""
import argparse
import json
import os
import re
from pathlib import Path
import selectors
import shutil
import shlex
import socket
import struct
import subprocess
import sys
import tempfile
import time
from fetch import ROOT
from qmp import Qmp
from network_fault import defer_tx, inject


def fixture(status=True, program='net-tests', script='userspace/tests/net/run.sh', environment=None,
            runtime_loader=None):
    subprocess.run(['make', 'build/axiom64.elf', 'build/init', f'build/{program}', 'busybox'],
                   cwd=ROOT, check=True)
    files = {name: (0o40755, b'') for name in ['bin', 'sbin', 'etc', 'dev', 'proc', 'sys', 'tmp', 'run', 'root']}
    if runtime_loader is not None:
        files['lib'] = (0o40755, b'')
        files['lib/ld-musl-x86_64.so.1'] = (0o100755, Path(runtime_loader).read_bytes())
    for name, source in [('sbin/init', ROOT / 'build/init'),
                         (f'bin/{program}', ROOT / 'build' / program),
                         ('bin/busybox', ROOT / 'build/busybox-1.37.0/busybox'),
                         ('etc/net-test.sh', ROOT / script)]:
        data = source.read_bytes()
        if name == 'etc/net-test.sh' and not status:
            data = b'export AXIOM64_LINK_TEST=0\n' + data
        if name == 'etc/net-test.sh' and environment:
            for key, value in environment.items():
                if not re.fullmatch(r'[A-Z][A-Z0-9_]*', key):
                    raise ValueError('invalid test environment key')
                data = f'export {key}={shlex.quote(value)}\n'.encode() + data
        files[name] = (0o100755, data)
    destination = ROOT / 'build/rootfs-network.cpio'
    # Completed ISO staging trees may still link the previous archive. Publish a
    # new inode only after the full newc stream is closed, preserving those bytes.
    with tempfile.TemporaryDirectory(prefix='.network-root-', dir=destination.parent) as staging:
        staged = Path(staging) / destination.name
        with staged.open('wb') as output:
            for inode, (name, (mode, data)) in enumerate([*sorted(files.items()), ('TRAILER!!!', (0, b''))], 1):
                encoded = name.encode() + b'\0'
                values = [inode, mode, 0, 0, 1, 0, len(data), 0, 0, 0, 0, len(encoded), 0]
                output.write(b'070701' + b''.join(f'{value:08x}'.encode() for value in values) + encoded)
                output.write(bytes(-output.tell() % 4))
                output.write(data)
                output.write(bytes(-output.tell() % 4))
        os.replace(staged, destination)


def reply(frame, lane):
    if len(frame) < 23 or len(frame) > 9014:
        raise RuntimeError('unexpected frame length')
    peer = bytes([2, 0x41, 0x58, 0x50, 0x4b, lane])
    guest = bytes([0x52, 0x54, 0, 0x12, 0x34, 0x10 + lane])
    if frame[:14] != peer + guest + bytes.fromhex('88b5') or frame[14:19] != b'AX64' + bytes([lane]):
        raise RuntimeError('unexpected interface, MAC, protocol, or marker')
    sequence = int.from_bytes(frame[19:23], 'big')
    expected = bytes((sequence + offset * 13 + lane * 7) & 255 for offset in range(23, len(frame)))
    if frame[23:] != expected:
        raise RuntimeError('packet payload differs from the host expectation')
    return guest + peer + frame[12:]


def packet_protocol_observations(text, indices):
    """Bind each protocol-listener query and pass to its actual selected interface."""
    events, observations, passes = [], [], []
    malformed = False
    for line in text.splitlines():
        if line.startswith('PACKET_PROTOCOL_OBSERVATION'):
            match = re.fullmatch(r'PACKET_PROTOCOL_OBSERVATION index=(\d+) type=(\d+) length=(\d+)', line)
            if match:
                index, kind, length = map(int, match.groups())
                observations.append(dict(index=index, type=kind, length=length))
                events.append(('observation', index, kind, length))
            else:
                malformed = True
        elif line.startswith('PACKET_PROTOCOL_PASS'):
            match = re.fullmatch(r'PACKET_PROTOCOL_PASS index=(\d+)', line)
            if match:
                index = int(match[1])
                passes.append(index)
                events.append(('pass', index))
            else:
                malformed = True
    expected = [event for index in indices for event in (('observation', index, 0, 64), ('pass', index))]
    return dict(passed=not malformed and events == expected, observations=observations, passes=passes)


def run(firmware, transport, models, queue, timeout, wrap, gdb=False, fault=None, status=True, mtu=0, pressure=False):
    label = f'network-{firmware}-{transport}-{"-".join(models)}-q{queue}{"-wrap" if wrap else ""}{"-fault-" + fault if fault else ""}{"-no-status" if not status else ""}{"-mtu" + str(mtu) if mtu else ""}{"-pressure" if pressure else ""}'
    log = ROOT / 'build' / (label + '.log')
    selector = selectors.DefaultSelector()
    control = Path('/tmp') / f'axiom64-network-{os.getpid()}.sock'
    control.unlink(missing_ok=True)
    link_events = set()
    debugger = debug_log = None
    armed = control.with_suffix('.armed')
    armed.unlink(missing_ok=True)
    released = control.with_suffix('.released')
    released.unlink(missing_ok=True)
    debug_port = 1235
    servers, peers = [], []
    command = ['qemu-system-x86_64', '-machine', 'pc', '-cpu', 'max', '-m', '2G',
               '-cdrom', str(ROOT / 'build/network-test.iso'), '-nic', 'none', '-display', 'none',
               '-serial', 'stdio', '-monitor', 'none', '-no-reboot',
               '-qmp', f'unix:{control},server=on,wait=off',
               '-device', 'isa-debug-exit,iobase=0xf4,iosize=0x04']
    if gdb or fault or pressure:
        command += ['-gdb', f'tcp:127.0.0.1:{debug_port}']
        if gdb:
            command += ['-S']
    for lane, model in enumerate(models):
        server = socket.socket()
        server.bind(('127.0.0.1', 0))
        server.listen(1)
        server.setblocking(False)
        servers.append(server)
        selector.register(server, selectors.EVENT_READ, ('server', lane))
        port = server.getsockname()[1]
        command += ['-netdev', f'socket,id=peer{lane},connect=127.0.0.1:{port}']
        nic = f'{"virtio-net-pci" if model == "virtio" else "e1000"},netdev=peer{lane},id=nic{lane},addr={lane + 4:x},mac=52:54:00:12:34:{0x10 + lane:02x}'
        if model == 'virtio':
            nic += f',rx_queue_size={queue},tx_queue_size=256,' + (
                'disable-legacy=on' if transport == 'modern' else 'disable-modern=on')
            nic += f',status={"on" if status else "off"},host_mtu={mtu}'
        command += ['-device', nic]
        peers.append(dict(input=bytearray(), output=bytearray(), frames=0, foreign=0, socket=None))
    if firmware == 'uefi':
        variables = ROOT / 'build' / (label + '-OVMF_VARS.fd')
        shutil.copyfile('/usr/share/OVMF/OVMF_VARS_4M.fd', variables)
        command += ['-drive', 'if=pflash,format=raw,readonly=on,file=/usr/share/OVMF/OVMF_CODE_4M.fd',
                    '-drive', f'if=pflash,format=raw,file={variables}']
    started = time.monotonic()
    timed_out = False
    error = None
    with log.open('w') as output:
        process = subprocess.Popen(command, stdin=subprocess.DEVNULL, stdout=output, stderr=subprocess.STDOUT)
        try:
            while process.poll() is None:
                if time.monotonic() - started > timeout:
                    timed_out = True
                    break
                tail = log.read_text(errors='replace')
                if fault and debugger is None and 'PACKET_FAULT_READY' in tail:
                    debugger, debug_log = inject(models[0], fault, debug_port, label, armed)
                if pressure and debugger is None and 'PACKET_PRESSURE_READY' in tail:
                    debugger, debug_log = defer_tx(models[0], debug_port, label, armed, released)
                if pressure and 'PACKET_PRESSURE_FULL' in tail:
                    released.touch()
                if debugger is not None and debugger.poll() not in [None, 0]:
                    raise RuntimeError('completion injection failed: ' + debug_log.read_text(errors='replace'))
                for lane in range(len(models)):
                    for stage, up in [('DOWN', False), ('UP', True)]:
                        event = f'PACKET_LINK_{stage} index={lane + 1}'
                        if event in tail and event not in link_events:
                            monitor = Qmp(control)
                            try:
                                monitor.command('set_link', {'name': f'nic{lane}', 'up': up})
                            finally:
                                monitor.close()
                            link_events.add(event)
                # Arming the breakpoint can happen after the sole request was
                # received. Re-enable its held reply without requiring another
                # incoming packet to generate a selector event.
                if (fault or pressure) and armed.exists():
                    for lane, state in enumerate(peers):
                        connection = state['socket']
                        if connection and state['output'] and connection.fileno() in selector.get_map():
                            selector.modify(connection, selectors.EVENT_READ | selectors.EVENT_WRITE,
                                            ('peer', lane))
                for key, events in selector.select(.01):
                    kind, lane = key.data
                    state = peers[lane]
                    if kind == 'server':
                        connection, _ = key.fileobj.accept()
                        connection.setblocking(False)
                        connection.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
                        state['socket'] = connection
                        selector.unregister(key.fileobj)
                        selector.register(connection, selectors.EVENT_READ, ('peer', lane))
                        continue
                    connection = key.fileobj
                    if events & selectors.EVENT_READ:
                        data = connection.recv(65536)
                        if not data:
                            selector.unregister(connection)
                            continue
                        state['input'].extend(data)
                        while len(state['input']) >= 4:
                            length = int.from_bytes(state['input'][:4], 'big')
                            if length < 14 or length > 9018:
                                raise RuntimeError('invalid QEMU frame prefix')
                            if len(state['input']) < length + 4:
                                break
                            frame = bytes(state['input'][4:length + 4])
                            del state['input'][:length + 4]
                            if frame[12:14] != bytes.fromhex('88b5'):
                                state['foreign'] += 1
                                continue
                            response = reply(frame, lane)
                            sequence = int.from_bytes(frame[19:23], 'big')
                            if sequence != state['frames']:
                                raise RuntimeError('packet sequence is duplicated, missing, or reordered')
                            capacity = 64 if models[lane] == 'virtio' else 63
                            if not pressure or sequence in [0, capacity + 1]:
                                state['output'].extend(struct.pack('!I', len(response)) + response)
                            state['frames'] += 1
                    if state['output'] and (not (fault or pressure) or armed.exists()):
                        try:
                            sent = connection.send(state['output'])
                            del state['output'][:sent]
                        except BlockingIOError:
                            pass
                    selector.modify(connection, selectors.EVENT_READ | (
                        selectors.EVENT_WRITE if state['output'] and (not (fault or pressure) or armed.exists()) else 0), ('peer', lane))
        except Exception as exception:
            error = str(exception)
        finally:
            if process.poll() is None:
                process.kill()
            returncode = process.wait()
            selector.close()
            control.unlink(missing_ok=True)
            armed.unlink(missing_ok=True)
            released.unlink(missing_ok=True)
            if debugger is not None and debugger.poll() is None:
                debugger.kill()
                debugger.wait()
            for server in servers:
                server.close()
            for state in peers:
                if state['socket']:
                    state['socket'].close()
    text = log.read_text(errors='replace')
    capacity = 64 if models[0] == 'virtio' else 63
    count = capacity + 2 if pressure else (1 if fault == 'id' else 2) if fault else 65621 if wrap else 67
    required = ['AXIOM64_TESTS_PASS', 'AXIOM64_EXIT status=0']
    if pressure:
        required += ['PACKET_PRESSURE_IPV6_DISABLED index=1',
                     f'PACKET_PRESSURE_PASS slots={capacity}']
        debug_text = debug_log.read_text(errors='replace') if debug_log else ''
        injected = f'PACKET_TX_DEFERRED model={models[0]}' in debug_text and \
                   f'PACKET_TX_RELEASED model={models[0]}' in debug_text
    elif fault:
        required += [f'PACKET_FAULT_PASS mode={fault}']
        injected = debug_log is not None and \
            f'PACKET_FAULT_INJECTED model={models[0]} kind={fault}' in debug_log.read_text(errors='replace')
    else:
        required += [f'PACKET_TESTS_PASS nics={len(models)}']
        required += [f'PACKET_NIC_PASS index={lane + 1} frames={count + (1 if mtu >= 9000 and model == "virtio" else 0)}'
                     for lane, model in enumerate(models)]
        required += [f'PACKET_ADMIN_FLAGS index={lane + 1} flags=1002' for lane in range(len(models))]
        if status:
            required += [f'PACKET_LINK_PASS index={lane + 1}' for lane in range(len(models))]
        injected = True
    required += [f'virtio-net: index={lane + 1} transport={transport} rx={queue} tx=256'
                 if model == 'virtio' else f'e1000: index={lane + 1} model=82540EM rx=64 tx=64'
                 for lane, model in enumerate(models)]
    if not fault and not pressure:
        required += [f'PACKET_PROTOCOL_PASS index={lane + 1}' for lane in range(len(models))]
    missing = [marker for marker in required if marker not in text]
    protocol = packet_protocol_observations(text, [] if fault or pressure else range(1, len(models) + 1))
    administrative_flags = [dict(index=int(index), flags=int(flags, 16)) for index, flags in re.findall(
        r'^PACKET_ADMIN_FLAGS index=(\d+) flags=([0-9a-f]+)\r?$', text, re.M)]
    administrative_flags_valid = (not administrative_flags if fault or pressure else
        administrative_flags == [dict(index=lane + 1, flags=0x1002) for lane in range(len(models))])
    timestamp_observations = [dict(zip(('index', 'begin_ns', 'end_ns', 'arrival_ns', 'dequeue_ns'),
                                       map(int, value))) for value in re.findall(
        r'^PACKET_TIMESTAMP_PASS index=(\d+) begin_ns=(\d+) end_ns=(\d+) arrival_ns=(\d+) '
        r'dequeue_ns=(\d+)\r?$', text, re.M)]
    lazy_observations = [dict(zip(('index', 'before_ns', 'stamp_ns', 'after_ns', 'arrival_ns'),
                                 map(int, value))) for value in re.findall(
        r'^PACKET_TIMESTAMP_LAZY index=(\d+) before_ns=(\d+) stamp_ns=(\d+) after_ns=(\d+) '
        r'arrival_ns=(\d+)\r?$', text, re.M)]
    timestamps_valid = fault or pressure or (
        len(timestamp_observations) == len(models) and
        {value['index'] for value in timestamp_observations} == set(range(1, len(models) + 1)) and
        all(value['begin_ns'] <= value['arrival_ns'] <= value['end_ns'] and
            value['dequeue_ns'] - value['arrival_ns'] >= 100000000 for value in timestamp_observations) and
        len(lazy_observations) == len(models) and
        {value['index'] for value in lazy_observations} == set(range(1, len(models) + 1)) and
        all(value['before_ns'] <= value['stamp_ns'] <= value['after_ns'] and
            value['stamp_ns'] - value['arrival_ns'] >= 100000000 and
            value['arrival_ns'] == next(stamp['arrival_ns'] for stamp in timestamp_observations
                                        if stamp['index'] == value['index']) for value in lazy_observations))
    features_valid = True
    for lane, model in enumerate(models):
        if model != 'virtio':
            continue
        match = re.search(rf'virtio-net: index={lane + 1} .*features=([0-9a-f]+)', text)
        features = int(match[1], 16) if match else 0
        expected = (1 << 5) | ((1 << 16) if status else 0) | (8 if mtu else 0) | (
            (1 << 32) if transport == 'modern' else 0)
        features_valid &= features == expected
    expected_counts = [count + (1 if not fault and mtu >= 9000 and model == 'virtio' else 0)
                       for model in models]
    result = dict(firmware=firmware, transport=transport, models=models,
                  rx_queue=queue, tx_queue=256, wrap=wrap,
                  fault=fault, pressure=pressure, injected=injected, status_feature=status, host_mtu=mtu,
                  features_valid=features_valid,
                  protocol_observations=protocol['observations'], protocol_passes=protocol['passes'],
                  protocol_selection_valid=protocol['passed'],
                  administrative_flags=administrative_flags, administrative_flags_valid=administrative_flags_valid,
                  timestamp_observations=timestamp_observations, timestamps_valid=bool(timestamps_valid),
                  lazy_timestamp_observations=lazy_observations,
                  passed=returncode == 1 and not timed_out and not error and not missing and injected and
                         features_valid and timestamps_valid and administrative_flags_valid and protocol['passed'] and
                         [state['frames'] for state in peers] == expected_counts,
                  returncode=returncode, timed_out=timed_out, error=error, missing=missing,
                  host_frames=[state['frames'] for state in peers],
                  host_foreign=[state['foreign'] for state in peers],
                  link_events=sorted(link_events),
                  seconds=round(time.monotonic() - started, 2), log=log.name)
    print(json.dumps(result), flush=True)
    if not result['passed']:
        print('\n'.join(text.splitlines()[-25:]), flush=True)
    return result


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--firmware', choices=['bios', 'uefi', 'both'], default='both')
    parser.add_argument('--transport', choices=['modern', 'legacy'], default='modern')
    parser.add_argument('--models', nargs='+', choices=['virtio', 'e1000'], default=['virtio', 'e1000'])
    parser.add_argument('--queue', type=int, default=256,
                        help='offered virtio RX size; QEMU TX size remains 256')
    parser.add_argument('--timeout', type=int, default=120)
    parser.add_argument('--wrap', action='store_true')
    parser.add_argument('--fault', choices=['length', 'id'], help='inject a real RX completion through GDB')
    parser.add_argument('--pressure', action='store_true', help='defer completion observation through GDB to fill TX buffers')
    parser.add_argument('--no-status', action='store_true', help='omit virtio carrier status and skip physical link tests')
    parser.add_argument('--mtu', type=int, choices=[0, 1500, 9000], default=0, help='offered virtio host MTU')
    parser.add_argument('--gdb', action='store_true', help='start paused with a local debugger on port 1235')
    args = parser.parse_args()
    if len(args.models) > 8 or args.queue not in [256, 512, 1024]:
        parser.error('one to eight NICs and a QEMU queue size of 256, 512, or 1024 are required')
    if args.fault and (len(args.models) != 1 or args.wrap or args.gdb or
                       (args.fault == 'id' and args.models[0] != 'virtio')):
        parser.error('--fault requires one NIC; ID injection uses virtio and cannot combine with wrap or manual GDB')
    if args.pressure and (len(args.models) != 1 or args.wrap or args.gdb or args.fault or args.mtu):
        parser.error('--pressure requires one NIC and cannot combine with wrap, fault, MTU, or manual GDB')
    fixture(not args.no_status)
    subprocess.run([sys.executable, str(ROOT / 'scripts/image.py'), '--test', '--suite', 'network',
                    '--phase', 'pressure' if args.pressure else 'invalid' if args.fault == 'id' else 'error' if args.fault else
                        'queue' if args.wrap else 'verify', '--output-name', 'network-test.iso'], check=True)
    results = [run(firmware, args.transport, args.models, args.queue, args.timeout, args.wrap,
                   args.gdb, args.fault, not args.no_status, args.mtu, args.pressure)
               for firmware in (['bios', 'uefi'] if args.firmware == 'both' else [args.firmware])]
    (ROOT / 'build/network-results.json').write_text(json.dumps(results, indent=2) + '\n')
    raise SystemExit(0 if all(result['passed'] for result in results) else 1)
