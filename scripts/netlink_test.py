"""Boot IPv4 route-control tests with isolated peers for both Ethernet drivers."""
import argparse
import json
import os
import selectors
import shutil
import socket
import subprocess
import tempfile
import time
from fetch import ROOT
from network_test import fixture
from netlink_peer import Peer
from qmp import Qmp


def run(firmware, transport, timeout):
    label = f'netlink-{firmware}-{transport}'
    log = ROOT / 'build' / (label + '.log')
    selector = selectors.DefaultSelector()
    servers, peers = [], [Peer(0), Peer(1)]
    temporary = tempfile.TemporaryDirectory(prefix='axiom64-netlink-')
    control = temporary.name + '/qmp.sock'
    command = ['qemu-system-x86_64', '-machine', 'pc', '-cpu', 'max', '-m', '2G',
        '-cdrom', str(ROOT / 'build/axiom64-netlink.iso'), '-nic', 'none',
        '-display', 'none', '-serial', 'stdio', '-monitor', 'none', '-no-reboot', '-S',
        '-qmp', f'unix:{control},server=on,wait=off',
        '-device', 'isa-debug-exit,iobase=0xf4,iosize=0x04']
    for lane, model in enumerate(['virtio-net-pci', 'e1000']):
        server = socket.socket()
        server.bind(('127.0.0.1', 0))
        server.listen(1)
        server.setblocking(False)
        servers.append(server)
        selector.register(server, selectors.EVENT_READ, ('server', lane))
        device = f'{model},netdev=peer{lane},id=nic{lane},addr={lane + 4:x},mac={peers[lane].guest.hex(":")}'
        if lane == 0:
            device += ',disable-legacy=on' if transport == 'modern' else ',disable-modern=on'
        command += ['-netdev', f'socket,id=peer{lane},connect=127.0.0.1:{server.getsockname()[1]}',
                    '-device', device]
    if firmware == 'uefi':
        variables = ROOT / 'build' / (label + '-OVMF_VARS.fd')
        shutil.copyfile('/usr/share/OVMF/OVMF_VARS_4M.fd', variables)
        command += ['-drive', 'if=pflash,format=raw,readonly=on,file=/usr/share/OVMF/OVMF_CODE_4M.fd',
                    '-drive', f'if=pflash,format=raw,file={variables}']
    started = time.monotonic()
    error = None
    exited_at = None
    ready = False
    monitor = None
    carrier_restored = False
    with log.open('wb') as output:
        process = subprocess.Popen(command, stdout=output, stderr=subprocess.STDOUT,
                                   stdin=subprocess.DEVNULL)
        try:
            while not os.path.exists(control):
                if process.poll() is not None or time.monotonic() - started >= 5:
                    raise RuntimeError('route-control monitor startup failed')
                time.sleep(.01)
            monitor = Qmp(control)
            for lane in range(2):
                monitor.command('set_link', {'name': f'nic{lane}', 'up': False})
            monitor.command('cont')
            while True:
                now = time.monotonic()
                if process.poll() is not None:
                    if exited_at is None:
                        exited_at = now
                    if now - exited_at >= .2:
                        break
                if now - started >= timeout:
                    raise RuntimeError('route-control boot deadline exceeded')
                if not ready:
                    ready = b'NETLINK_READY' in log.read_bytes()
                if not carrier_restored and b'NETLINK_EARLY_ROUTES_PASS count=2' in log.read_bytes():
                    for lane in range(2):
                        monitor.command('set_link', {'name': f'nic{lane}', 'up': True})
                    carrier_restored = True
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
                                raise RuntimeError('QEMU frame length outside Ethernet bounds')
                            if len(peer.input) < size + 4:
                                break
                            # UEFI has its own network traffic before the Ring 3 marker.
                            if ready or b'NETLINK_READY' in log.read_bytes():
                                ready = True
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
            if monitor:
                monitor.close()
            temporary.cleanup()
    text = log.read_text(errors='replace')
    names = ['CARRIER_DOWN', 'EARLY_ROUTES', 'CARRIER_UP', 'LIFECYCLE', 'FORK_LIFETIME', 'MESSAGE_IO', 'UNCAPPED_REPLY', 'ROUTE_OWNERSHIP',
             'CONFIGURATION_ADAPTER', 'MALFORMED', 'ROUTE_LIMITS', 'BYTE_QUOTA', 'PRESSURE_LIFETIME',
             'SOCKET_LIMITS', 'ROUTED_PACKETS', 'TESTS']
    missing = [f'NETLINK_{name}_PASS' for name in names if f'NETLINK_{name}_PASS' not in text]
    missing += [value for value in ['AXIOM64_TESTS_PASS', 'AXIOM64_EXIT status=0'] if value not in text]
    counts = []
    if error is None and returncode == 1 and not missing:
        try:
            counts = [peer.verify() for peer in peers]
        except Exception as exception:
            error = str(exception)
    result = dict(firmware=firmware, transport=transport, returncode=returncode, error=error,
                  missing=missing, counts=counts, carrier_restored=carrier_restored,
                  seconds=round(time.monotonic() - started, 3),
                  passed=error is None and returncode == 1 and not missing)
    print(json.dumps(result), flush=True)
    if not result['passed']:
        print(text[-3500:], flush=True)
        raise RuntimeError('IPv4 route-control check failed')
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--firmware', choices=['bios', 'uefi', 'both'], default='both')
    parser.add_argument('--transport', choices=['modern', 'legacy', 'both'], default='both')
    parser.add_argument('--timeout', type=float, default=50)
    args = parser.parse_args()
    if args.timeout <= 0:
        parser.error('timeout must be positive')
    fixture(program='netlink-tests', script='userspace/tests/net/netlink.sh')
    subprocess.run(['python3', 'scripts/image.py', '--test', '--suite', 'network',
                    '--output-name', 'axiom64-netlink.iso'], cwd=ROOT, check=True)
    results = []
    for firmware in ['bios', 'uefi'] if args.firmware == 'both' else [args.firmware]:
        for transport in ['modern', 'legacy'] if args.transport == 'both' else [args.transport]:
            results.append(run(firmware, transport, args.timeout))
    (ROOT / 'build/netlink-results.json').write_text(json.dumps(results, indent=2) + '\n')


if __name__ == '__main__':
    main()
