#!/usr/bin/env python3
"""Run guest UDP exchanges over two isolated QEMU Ethernet adapters."""
import argparse
import json
import os
from pathlib import Path
import re
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


def run(firmware, transport, timeout=90, fault=False, debugger_delay=0, *,
        capture_directory=None, image=None, expected_irq=None, machine='pc', no_vectors=False,
        force_pic=False, e1000e=False, intx=None):
    label = f'udp-{firmware}-{transport}' + ('-fault' if fault else '')
    if machine != 'pc':
        label += f'-{machine}'
    if no_vectors:
        label += '-no-vectors'
    if force_pic:
        label += '-pic'
    if e1000e:
        label += '-e1000e'
    if intx:
        label += f'-intx-{intx}'
    log = ROOT / 'build' / (label + '.log')
    selector = selectors.DefaultSelector()
    control = Path('/tmp') / f'axiom64-udp-{os.getpid()}.sock'
    control.unlink(missing_ok=True)
    link_events = set()
    armed = control.with_suffix('.armed')
    armed.unlink(missing_ok=True)
    debugger = debug_log = None
    servers, peers = [], [Peer(lane, fault) for lane in range(2)]
    command = ['qemu-system-x86_64', '-machine', machine, '-cpu', 'max', '-m', '2G',
               '-cdrom', str(image or ROOT / 'build/udp-test.iso'), '-nic', 'none', '-display', 'none',
               '-serial', 'stdio', '-monitor', 'none', '-no-reboot',
               '-qmp', f'unix:{control},server=on,wait=off',
               '-device', 'isa-debug-exit,iobase=0xf4,iosize=0x04']
    if fault:
        command += ['-gdb', 'tcp:127.0.0.1:1239']
    if intx == 'bridge':
        command += ['-device', 'pcie-root-port,id=upstream,bus=pcie.0,addr=6,slot=6',
                    '-device', 'pcie-pci-bridge,id=legacy,bus=upstream,addr=0']
    models = ['e1000', 'e1000'] if intx == 'shared' else [
        'virtio-net-pci', 'e1000e' if e1000e else 'e1000']
    slots = (4, 8) if intx == 'shared' else (4, 5)
    for lane, model in enumerate(models):
        server = socket.socket()
        server.bind(('127.0.0.1', 0))
        server.listen(1)
        server.setblocking(False)
        servers.append(server)
        selector.register(server, selectors.EVENT_READ, ('server', lane))
        nic = f'{model},netdev=peer{lane},id=nic{lane},addr={slots[lane]:x},mac={peers[lane].guest.hex(":")}'
        if intx == 'bridge' and lane == 1:
            nic += ',bus=legacy'
        if model == 'virtio-net-pci':
            nic += ',disable-legacy=on' if transport == 'modern' else ',disable-modern=on'
            if no_vectors:
                nic += ',vectors=0'
        command += ['-netdev', f'socket,id=peer{lane},connect=127.0.0.1:{server.getsockname()[1]}',
                    '-device', nic]
    if firmware == 'uefi':
        variables = ROOT / 'build' / (label + '-OVMF_VARS.fd')
        shutil.copyfile('/usr/share/OVMF/OVMF_VARS_4M.fd', variables)
        command += ['-drive', 'if=pflash,format=raw,readonly=on,file=/usr/share/OVMF/OVMF_CODE_4M.fd',
                    '-drive', f'if=pflash,format=raw,file={variables}']
    if capture_directory is not None:
        capture_directory = Path(capture_directory)
        capture_directory.mkdir(parents=True, exist_ok=False)
        for lane in range(2):
            command += ['-object', f'filter-dump,id=retained{lane},netdev=peer{lane},'
                        f'file={capture_directory}/lane{lane}.pcap']
        (capture_directory / 'command.json').write_text(json.dumps(command, indent=2) + '\n')
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
        required += [f'UDP_ADMIN_ROUTE index={lane + 1} before=552 after=1500',
                     f'UDP_BROADCAST_QUEUE_PASS index={lane + 1} ingress=48 retained=32',
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
    if expected_irq:
        route = f'virtio-net: index=1 transport={transport} irq={expected_irq} '
        if route not in text:
            missing.append(route.strip())
        completions = [f'virtio-net: MSI-X {direction} completion index=1'
                       for direction in ('RX', 'TX')]
        if expected_irq == 'msix':
            missing += [marker for marker in completions if marker not in text]
        elif any(marker in text for marker in completions):
            missing.append('polling boot emitted MSI-X completions')
    if force_pic and 'Interrupts: PIC/PIT selected by boot option' not in text:
        missing.append('forced PIC boot')
    if machine == 'q35' and 'PCI ECAM: segment=0 ' not in text:
        missing.append('Q35 PCI ECAM')
    if e1000e:
        mode = 'poll' if force_pic else 'msi'
        route = f'e1000: index=2 model=82574L rx=64 tx=64 irq={mode}'
        if route not in text:
            missing.append(route)
        completions = [f'e1000: MSI {direction} completion index=2'
                       for direction in ('RX', 'TX')]
        if mode == 'msi':
            missing += [marker for marker in completions if marker not in text]
        elif any(marker in text for marker in completions):
            missing.append('polling 82574L emitted MSI completions')
    intx_routes = re.findall(r'^e1000: INTx verified index=(\d+) gsi=(\d+)\r?$', text, re.M)
    if intx:
        indices = ('1', '2') if intx == 'shared' else ('2',)
        for index in indices:
            mode = 'poll' if intx == 'poll' else 'intx'
            route = f'e1000: index={index} model=82540EM rx=64 tx=64 irq={mode}'
            if route not in text:
                missing.append(route)
            markers = [f'e1000: INTx {direction} completion index={index}' for direction in ('RX', 'TX')]
            if intx != 'poll':
                missing += [marker for marker in markers if marker not in text]
            elif any(marker in text for marker in markers):
                missing.append('polling 82540EM emitted INTx completions')
        expected_devices = list(indices) if intx != 'poll' else []
        if [index for index, _ in intx_routes] != expected_devices:
            missing.append('verified INTx routes for the expected adapters')
        if intx == 'shared' and len({gsi for _, gsi in intx_routes}) != 1:
            missing.append('both INTx adapters on one firmware GSI')
        if intx == 'bridge' and intx_routes != [('2', '23')]:
            missing.append('swizzled Q35 bridge route on GSI 23')
        if 'masked unclaimed I/O APIC line' in text:
            missing.append('INTx line was masked during wire traffic')
    host_passed = (peers[0].arp == peers[1].arp == 1 and peers[0].frames == 0 and peers[1].frames == 1) if fault else (
        len(link_events) == 4 and all(p.arp == 2 and p.frames == 4 and p.zero == 1 and p.zero_checksum == 1 and
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
    if intx:
        result['intx_routes'] = [dict(index=int(index), gsi=int(gsi)) for index, gsi in intx_routes]
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
    parser.add_argument('--machine', choices=['pc', 'q35'], default='pc')
    parser.add_argument('--expected-irq', choices=['msix', 'poll'])
    parser.add_argument('--no-vectors', action='store_true')
    parser.add_argument('--force-pic', action='store_true')
    parser.add_argument('--e1000e', action='store_true')
    parser.add_argument('--intx', choices=['single', 'shared', 'bridge', 'poll'])
    parser.add_argument('--capture-directory', type=Path)
    parser.add_argument('--debugger-delay', type=float, default=0,
                        help='simulate slow fault debugger setup while the guest is stopped')
    args = parser.parse_args()
    if args.debugger_delay < 0 or args.debugger_delay > 10 or (args.debugger_delay and not args.fault):
        parser.error('--debugger-delay must be from 0 to 10 seconds and requires --fault')
    if args.intx and (args.e1000e or args.fault or (args.intx == 'shared' and args.expected_irq)):
        parser.error('--intx uses 82540EM and normal traffic, with two Intel devices in shared mode')
    if args.intx == 'bridge' and (args.machine != 'q35' or args.force_pic):
        parser.error('--intx bridge requires Q35 with APIC routing')
    fixture(program='udp-tests', script='userspace/tests/net/udp.sh',
            environment={'AXIOM64_UDP_FAULT': '1'} if args.fault else None)
    image = 'udp-test-pic.iso' if args.force_pic else 'udp-test.iso'
    command = [sys.executable, 'scripts/image.py', '--test', '--suite', 'network',
               '--output-name', image]
    if args.force_pic:
        command += ['--kernel-option', 'irq=pic']
    subprocess.run(command, cwd=ROOT, check=True)
    boot_image = ROOT / 'build' / image
    result = run(args.firmware, args.transport, args.timeout, args.fault, args.debugger_delay,
                 expected_irq=args.expected_irq, machine=args.machine, no_vectors=args.no_vectors,
                 force_pic=args.force_pic, e1000e=args.e1000e, image=boot_image, intx=args.intx,
                 capture_directory=args.capture_directory)
    receipt = 'udp-results.json'
    if args.expected_irq or args.e1000e or args.intx:
        receipt = result['log'].removesuffix('.log') + '.json'
    (ROOT / 'build' / receipt).write_text(json.dumps([result], indent=2) + '\n')
    if args.capture_directory:
        from udp_capture import audit_capture
        from udp_inputs import save_case
        case = args.capture_directory
        save_case(result, case)
        shutil.copyfile(boot_image, case / 'image.iso')
        if result['passed']:
            captures = [audit_capture(case / f'lane{lane}.pcap', lane, args.fault,
                                      route_retirement=True) for lane in range(2)]
            (case / 'capture-audit.json').write_text(json.dumps(captures, indent=2) + '\n')
    raise SystemExit(0 if result['passed'] else 1)


if __name__ == '__main__':
    main()
