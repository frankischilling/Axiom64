#!/usr/bin/env python3
"""Run guest UDP exchanges over two isolated QEMU Ethernet adapters."""
import argparse
import json
import os
from pathlib import Path
import selectors
import shutil
import socket
import subprocess
import sys
import time
from fetch import ROOT
from network_test import fixture
from udp_peer import Peer
from qmp import Qmp
from network_fault import inject


def run(firmware, transport, timeout=90, fault=False, debugger_delay=0):
    label = f'udp-{firmware}-{transport}' + ('-fault' if fault else '')
    log = ROOT / 'build' / (label + '.log')
    selector = selectors.DefaultSelector()
    control = Path('/tmp') / f'axiom64-udp-{os.getpid()}.sock'
    control.unlink(missing_ok=True)
    link_events = set()
    armed = control.with_suffix('.armed')
    armed.unlink(missing_ok=True)
    debugger = debug_log = None
    servers, peers = [], [Peer(lane, fault) for lane in range(2)]
    command = ['qemu-system-x86_64', '-machine', 'pc', '-cpu', 'max', '-m', '2G',
               '-cdrom', str(ROOT / 'build/udp-test.iso'), '-nic', 'none', '-display', 'none',
               '-serial', 'stdio', '-monitor', 'none', '-no-reboot',
               '-qmp', f'unix:{control},server=on,wait=off',
               '-device', 'isa-debug-exit,iobase=0xf4,iosize=0x04']
    if fault:
        command += ['-gdb', 'tcp:127.0.0.1:1239']
    for lane, model in enumerate(['virtio-net-pci', 'e1000']):
        server = socket.socket()
        server.bind(('127.0.0.1', 0))
        server.listen(1)
        server.setblocking(False)
        servers.append(server)
        selector.register(server, selectors.EVENT_READ, ('server', lane))
        nic = f'{model},netdev=peer{lane},id=nic{lane},addr={lane + 4:x},mac={peers[lane].guest.hex(":")}'
        if lane == 0:
            nic += ',disable-legacy=on' if transport == 'modern' else ',disable-modern=on'
        command += ['-netdev', f'socket,id=peer{lane},connect=127.0.0.1:{server.getsockname()[1]}',
                    '-device', nic]
    if firmware == 'uefi':
        variables = ROOT / 'build' / (label + '-OVMF_VARS.fd')
        shutil.copyfile('/usr/share/OVMF/OVMF_VARS_4M.fd', variables)
        command += ['-drive', 'if=pflash,format=raw,readonly=on,file=/usr/share/OVMF/OVMF_CODE_4M.fd',
                    '-drive', f'if=pflash,format=raw,file={variables}']
    started, timed_out, error = time.monotonic(), False, None
    with log.open('wb') as output:
        process = subprocess.Popen(command, stdin=subprocess.DEVNULL, stdout=output, stderr=subprocess.STDOUT)
        try:
            while process.poll() is None:
                if time.monotonic() - started > timeout:
                    timed_out = True
                    break
                tail = log.read_text(errors='replace')
                if fault and debugger is None and 'UDP_FAULT_READY' in tail:
                    # Guest ARP deadlines must not include host debugger startup.
                    # GDB resumes the stopped VM after installing the breakpoint.
                    monitor = Qmp(control)
                    try:
                        monitor.command('stop')
                    finally:
                        monitor.close()
                    if debugger_delay:
                        time.sleep(debugger_delay)
                    debugger, debug_log = inject('virtio', 'id', 1239, label, armed)
                if debugger is not None and debugger.poll() not in [None, 0]:
                    raise RuntimeError('UDP completion injection failed: ' + debug_log.read_text(errors='replace'))
                sending = not fault or armed.exists()
                for lane in range(2):
                    for stage, up in [('DOWN', False), ('UP', True)]:
                        event = f'UDP_LINK_{stage} index={lane + 1}'
                        if event in tail and event not in link_events:
                            monitor = Qmp(control)
                            try:
                                monitor.command('set_link', {'name': f'nic{lane}', 'up': up})
                            finally:
                                monitor.close()
                            link_events.add(event)
                for peer in peers:
                    if f'UDP_PRESSURE_RELEASE index={peer.lane + 1}' in tail:
                        peer.release_pressure()
                    if peer.connection and peer.output and sending and peer.connection.fileno() in selector.get_map():
                        selector.modify(peer.connection, selectors.EVENT_READ | selectors.EVENT_WRITE,
                                        ('peer', peer.lane))
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
                            length = int.from_bytes(peer.input[:4], 'big')
                            if length < 14 or length > 65553:
                                raise RuntimeError('invalid QEMU Ethernet length prefix')
                            if len(peer.input) < length + 4:
                                break
                            peer.packet(bytes(peer.input[4:length + 4]))
                            del peer.input[:length + 4]
                    if peer.output and sending:
                        try:
                            sent = connection.send(peer.output)
                            del peer.output[:sent]
                        except BlockingIOError:
                            pass
                    selector.modify(connection, selectors.EVENT_READ | (
                        selectors.EVENT_WRITE if peer.output and sending else 0), ('peer', lane))
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
            control.unlink(missing_ok=True)
            armed.unlink(missing_ok=True)
            if debugger is not None and debugger.poll() is None:
                debugger.kill()
                debugger.wait()
    text = log.read_text(errors='replace')
    required = ['UDP_BINDINGS_PASS', 'UDP_ZERO_PEER_PASS', 'UDP_LOOPBACK_PASS', 'UDP_REUSE_PASS', 'UDP_SHUTDOWN_PASS',
                'UDP_ERRORS_PASS', 'UDP_RECEIVE_LIFETIME_PASS', 'UDP_CAPTURED_RECEIVE_PASS',
                'UDP_CONFIG_PASS', 'UDP_WIRE_PASS index=1', 'UDP_WIRE_PASS index=2',
                'UDP_TESTS_PASS', 'AXIOM64_TESTS_PASS', 'AXIOM64_EXIT status=0']
    required += ['UDP_INTERRUPT_PASS', 'UDP_RESTART_PASS', 'UDP_FORK_PASS', 'UDP_RESOURCE_CYCLES_PASS count=128']
    required += ['UDP_PAYLOAD_LIMIT_PASS bytes=65507', 'UDP_BUFFER_LIMIT_PASS bytes=2048 payload=2020']
    for lane in range(2):
        required += [f'UDP_ZERO_CHECKSUM_PASS index={lane + 1}',
                     f'UDP_MALFORMED_PASS index={lane + 1} frames=15',
                     f'UDP_CONNECTED_FILTER_PASS index={lane + 1}',
                     f'UDP_SERVER_PASS index={lane + 1}', f'UDP_WIRE_ERRORS_PASS index={lane + 1}']
        required += [f'UDP_BROADCAST_QUEUE_PASS index={lane + 1} ingress=48 retained=32',
                     f'UDP_LINK_PASS index={lane + 1}',
                     f'UDP_PRESSURE_PASS index={lane + 1} packets=33',
                     f'UDP_UNREACHABLE_PASS index={lane + 1}']
    injected = not fault or (debug_log is not None and debugger.returncode == 0 and
        'PACKET_FAULT_INJECTED model=virtio kind=id' in debug_log.read_text(errors='replace'))
    if fault:
        required = ['UDP_BINDINGS_PASS', 'UDP_ZERO_PEER_PASS', 'UDP_LOOPBACK_PASS', 'UDP_REUSE_PASS',
            'UDP_SHUTDOWN_PASS', 'UDP_ERRORS_PASS', 'UDP_RECEIVE_LIFETIME_PASS',
            'UDP_CAPTURED_RECEIVE_PASS', 'UDP_CONFIG_PASS', 'UDP_DEVICE_FAULT_PASS',
            'UDP_OTHER_NIC_PASS', 'UDP_TESTS_PASS', 'AXIOM64_TESTS_PASS', 'AXIOM64_EXIT status=0']
        required += ['UDP_INTERRUPT_PASS', 'UDP_RESTART_PASS', 'UDP_FORK_PASS', 'UDP_RESOURCE_CYCLES_PASS count=128']
        required += ['UDP_PAYLOAD_LIMIT_PASS bytes=65507', 'UDP_BUFFER_LIMIT_PASS bytes=2048 payload=2020']
    missing = [marker for marker in required if marker not in text]
    host_passed = (peers[0].arp == peers[1].arp == 1 and peers[0].frames == 0 and peers[1].frames == 1) if fault else (
        len(link_events) == 4 and all(p.arp == 1 and p.frames == 4 and p.zero == 1 and p.zero_checksum == 1 and
            p.malformed == 14 and p.filter_input == 3 and p.filter_errors == 1 and p.server_replies == 1 and
            p.reordered == 4 and p.closed == 1 and p.quote_errors == 7 and p.controls == set('VFSOCILR') and
            p.broadcast_requests == 3 and p.broadcast_ingress == 48 and p.broadcast_ack == 48 and
            p.pressure_frames == 33 and p.pressure_arp == 1 and p.unanswered == 3 for p in peers))
    result = dict(firmware=firmware, transport=transport, returncode=returncode, timed_out=timed_out,
                  fault=fault, injected=injected, debugger_delay=debugger_delay,
                  error=error, missing=missing, arp=[p.arp for p in peers],
                  wire_datagrams=[p.frames for p in peers], zero_payloads=[p.zero for p in peers],
                  firmware_frames=[p.foreign for p in peers],
                  zero_checksums=[p.zero_checksum for p in peers], malformed=[p.malformed for p in peers],
                  filter_inputs=[p.filter_input for p in peers], server_replies=[p.server_replies for p in peers],
                  filtered_tuple_errors=[p.filter_errors for p in peers],
                  reordered=[p.reordered for p in peers], port_errors=[p.closed for p in peers],
                  invalid_quotes=[p.quote_errors for p in peers],
                  broadcast_requests=[p.broadcast_requests for p in peers],
                  broadcast_ingress=[p.broadcast_ingress for p in peers],
                  broadcast_acknowledged=[p.broadcast_ack for p in peers], link_events=len(link_events),
                  pending_sends=[p.pressure_frames for p in peers],
                  pressure_arp=[p.pressure_arp for p in peers], unanswered_arp=[p.unanswered for p in peers],
                  seconds=round(time.monotonic() - started, 2), log=log.name,
                  passed=returncode == 1 and not timed_out and not error and not missing and injected and host_passed)
    print(json.dumps(result), flush=True)
    if not result['passed']:
        print('\n'.join(text.splitlines()[-25:]), flush=True)
    return result


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--firmware', choices=['bios', 'uefi'], default='bios')
    parser.add_argument('--transport', choices=['modern', 'legacy'], default='modern')
    parser.add_argument('--timeout', type=int, default=90)
    parser.add_argument('--fault', action='store_true')
    parser.add_argument('--debugger-delay', type=float, default=0,
                        help='simulate slow fault debugger setup while the guest is stopped')
    args = parser.parse_args()
    if args.debugger_delay < 0 or args.debugger_delay > 10 or (args.debugger_delay and not args.fault):
        parser.error('--debugger-delay must be from 0 to 10 seconds and requires --fault')
    fixture(program='udp-tests', script='userspace/tests/net/udp.sh',
            environment={'AXIOM64_UDP_FAULT': '1'} if args.fault else None)
    subprocess.run([sys.executable, 'scripts/image.py', '--test', '--suite', 'network',
                    '--output-name', 'udp-test.iso'], cwd=ROOT, check=True)
    result = run(args.firmware, args.transport, args.timeout, args.fault, args.debugger_delay)
    (ROOT / 'build/udp-results.json').write_text(json.dumps([result], indent=2) + '\n')
    raise SystemExit(0 if result['passed'] else 1)


if __name__ == '__main__':
    main()
