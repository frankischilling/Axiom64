"""Validate the production DHCP/configuration modules with real Ethernet peers."""
import argparse
import json
import selectors
import shutil
import socket
import subprocess
import time
from fetch import ROOT
from network_test import fixture
from dhcp_peer import Peer


def run(firmware, transport, timeout):
    label = f'dhcp-transport-{firmware}-{transport}'
    log = ROOT / 'build' / (label + '.log')
    selector = selectors.DefaultSelector()
    servers, peers = [], [Peer(0), Peer(1)]
    command = ['qemu-system-x86_64', '-machine', 'pc', '-cpu', 'max', '-m', '2G',
        '-cdrom', str(ROOT / 'build/axiom64-dhcp-transport.iso'), '-nic', 'none',
        '-display', 'none', '-serial', 'stdio', '-monitor', 'none', '-no-reboot',
        '-device', 'isa-debug-exit,iobase=0xf4,iosize=0x04']
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
                    raise RuntimeError('DHCP transport deadline exceeded')
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
                            # Firmware emits traffic before the Ring 3 client starts.
                            if b'DHCP_TRANSPORT_READY' in log.read_bytes():
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
    required = [f'DHCP_TRANSPORT_BOUND index={index} generation={generation}'
                for index in [1, 2] for generation in [1, 2]]
    required += [f'DHCP_TRANSPORT_PASS index={index} renewals=1 rebindings=1' for index in [1, 2]]
    required += [f'DHCP_TRANSPORT_OWNERSHIP_PASS index={index}' for index in [1, 2]]
    required += ['DHCP_TRANSPORT_TESTS_PASS', 'AXIOM64_TESTS_PASS', 'AXIOM64_EXIT status=0']
    missing = [marker for marker in required if marker not in text]
    counts = []
    if error is None and returncode == 1 and not missing:
        try:
            counts = [peer.verify() for peer in peers]
        except Exception as exception:
            error = str(exception)
    result = dict(firmware=firmware, transport=transport, returncode=returncode,
                  error=error, missing=missing, counts=counts, log=log.name,
                  seconds=round(time.monotonic() - started, 3),
                  passed=returncode == 1 and error is None and not missing and
                  'PANIC:' not in text and 'Page fault' not in text)
    print(json.dumps(result), flush=True)
    if not result['passed']:
        print(text[-4500:], flush=True)
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--firmware', choices=['bios', 'uefi', 'both'], default='both')
    parser.add_argument('--transport', choices=['modern', 'legacy', 'both'], default='both')
    parser.add_argument('--timeout', type=float, default=110)
    args = parser.parse_args()
    if args.timeout <= 0:
        parser.error('timeout must be positive')
    fixture(program='dhcp-transport-tests', script='userspace/tests/net/dhcp-transport.sh')
    subprocess.run(['python3', 'scripts/image.py', '--test', '--suite', 'network',
                    '--output-name', 'axiom64-dhcp-transport.iso'], cwd=ROOT, check=True)
    results = []
    for firmware in ['bios', 'uefi'] if args.firmware == 'both' else [args.firmware]:
        for transport in ['modern', 'legacy'] if args.transport == 'both' else [args.transport]:
            result = run(firmware, transport, args.timeout)
            results.append(result)
            (ROOT / 'build/dhcp-transport-results.json').write_text(json.dumps(results, indent=2) + '\n')
            if not result['passed']:
                raise SystemExit('DHCP transport check failed')


if __name__ == '__main__':
    main()
