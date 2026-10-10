# SPDX-License-Identifier: GPL-3.0-or-later
"""Exchange native Linux TCP streams over both guest NICs and verify complete captures."""
import argparse
import json
from pathlib import Path
import shutil
import socket
import subprocess
import threading
import time
from fetch import ROOT
from tcp_test import fixture
from tcp_capture import BYTES, payload, verify


def receive(connection, expected):
    received = bytearray()
    while True:
        data = connection.recv(65536)
        if not data:
            break
        received.extend(data)
        if len(received) > len(expected):
            raise ValueError('native TCP peer received surplus bytes')
    if received != expected:
        raise ValueError('native TCP peer received different bytes or premature EOF')


class NativePeer:
    def __init__(self, lane):
        self.lane, self.error, self.result = lane, None, {}
        self.server = socket.socket()
        self.server.bind(('127.0.0.1', 0))
        self.server.listen(1)
        self.server.settimeout(20)
        reservation = socket.socket()
        reservation.bind(('127.0.0.1', 0))
        self.forward_port = reservation.getsockname()[1]
        reservation.close()
        self.connections, self.threads = [], []
        self.client_started = False

    @property
    def port(self):
        return self.server.getsockname()[1]

    def exchange(self, role):
        try:
            if role == 'server':
                connection, _ = self.server.accept()
                sending, receiving = 2, 1
            else:
                connection = socket.create_connection(('127.0.0.1', self.forward_port), timeout=5)
                sending, receiving = 3, 4
            self.connections.append(connection)
            with connection:
                connection.settimeout(20)
                if role == 'server':
                    receive(connection, payload(self.lane, receiving))
                connection.sendall(payload(self.lane, sending))
                connection.shutdown(socket.SHUT_WR)
                if role == 'client':
                    receive(connection, payload(self.lane, receiving))
            self.result[role] = dict(sent=BYTES, received=BYTES, passed=True)
        except Exception as exception:
            self.error = f'{role}: {exception}'

    def start(self, role):
        thread = threading.Thread(target=self.exchange, args=(role,), daemon=True)
        self.threads.append(thread)
        thread.start()

    def close(self):
        self.server.close()
        for connection in self.connections:
            try:
                connection.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            connection.close()
        for thread in self.threads:
            thread.join(timeout=1)


def run(linkage, firmware, transport, timeout):
    label = f'tcp-wire-{linkage}-{firmware}-{transport}'
    log = ROOT / 'build' / f'{label}.log'
    peers, captures = [NativePeer(lane) for lane in range(2)], []
    script = (f'#!/bin/sh\nset -e\n/bin/tcp-tests --wire {peers[0].port} {peers[1].port}\n'
              'echo AXIOM64_TESTS_PASS\n').encode()
    error, timed_out, evidence, process = None, False, [], None
    started = time.monotonic()
    try:
        image = fixture(linkage, script, f'axiom64-{label}.iso')
        command = ['qemu-system-x86_64', '-machine', 'pc', '-cpu', 'max', '-m', '512M', '-nic', 'none',
                   '-cdrom', str(image), '-display', 'none', '-serial', 'stdio', '-monitor', 'none',
                   '-no-reboot', '-device', 'isa-debug-exit,iobase=0xf4,iosize=0x04']
        for lane, model in enumerate(('virtio-net-pci', 'e1000')):
            peer = peers[lane]
            network = (f'user,id=peer{lane},net=10.23.{lane + 1}.0/24,host=10.23.{lane + 1}.1,'
                       f'hostfwd=tcp:127.0.0.1:{peer.forward_port}-10.23.{lane + 1}.2:{41000 + lane}')
            nic = f'{model},netdev=peer{lane},addr={lane + 4:x},mac=52:54:00:12:34:{0x10 + lane:02x}'
            if lane == 0:
                nic += ',disable-legacy=on' if transport == 'modern' else ',disable-modern=on'
            capture = ROOT / 'build' / f'{label}-lane{lane}.pcap'
            capture.unlink(missing_ok=True)
            captures.append(capture)
            command += ['-netdev', network, '-device', nic, '-object',
                        f'filter-dump,id=capture{lane},netdev=peer{lane},file={capture}']
            peer.start('server')
        if firmware == 'uefi':
            variables = ROOT / 'build' / f'{label}-OVMF_VARS.fd'
            shutil.copyfile('/usr/share/OVMF/OVMF_VARS_4M.fd', variables)
            command += ['-drive', 'if=pflash,format=raw,readonly=on,file=/usr/share/OVMF/OVMF_CODE_4M.fd',
                        '-drive', f'if=pflash,format=raw,file={variables}']
        booted = time.monotonic()
        with log.open('wb') as output:
            process = subprocess.Popen(command, stdin=subprocess.DEVNULL, stdout=output, stderr=subprocess.STDOUT)
            while process.poll() is None:
                if time.monotonic() - booted > timeout:
                    timed_out = True
                    break
                text = log.read_text(errors='replace')
                for lane, peer in enumerate(peers):
                    if not peer.client_started and f'TCP_SERVER_READY index={lane + 1}' in text:
                        peer.client_started = True
                        peer.start('client')
                    if peer.error:
                        raise ValueError(f'NIC {lane + 1} native peer failed: {peer.error}')
                time.sleep(.005)
            if process.poll() is None:
                process.kill()
            process.wait()
        for peer in peers:
            for thread in peer.threads:
                thread.join(timeout=2)
            if peer.error or set(peer.result) != {'client', 'server'}:
                raise ValueError(f'NIC {peer.lane + 1} native peer incomplete: {peer.error or peer.result}')
        evidence = [verify(capture, lane, peers[lane].port) for lane, capture in enumerate(captures)]
    except Exception as exception:
        error = str(exception)
    finally:
        if process is not None and process.poll() is None:
            process.kill()
            process.wait()
        for peer in peers:
            peer.close()
    text = log.read_text(errors='replace') if log.exists() else ''
    required = ['TCP_CONFIG_PASS nics=2', 'TCP_TEST_PASS', 'AXIOM64_TESTS_PASS', 'AXIOM64_EXIT status=0',
                f'Firmware: {firmware.upper()}', 'TCP_CREATE_PASS variants=8', 'TCP_OPTIONS_PASS ',
                'TCP_BINDINGS_PASS ', 'TCP_REFUSED_PASS ', 'TCP_VECTORS_PASS ',
                'TCP_WAITALL_PASS ', 'TCP_WAITALL_SIGNALS_PASS ', 'TCP_RETAINED_READ_PASS cases=2',
                'TCP_RESOURCE_CYCLES_PASS count=300', 'TCP_LOOPBACK_PASS bytes=262144',
                f'virtio-net: index=1 transport={transport}', 'e1000: index=2 model=82540EM']
    for lane in range(2):
        required += [f'TCP_NATIVE_SERVER_PASS index={lane + 1} bytes_each={BYTES}',
                     f'TCP_NATIVE_CLIENT_PASS index={lane + 1} bytes_each={BYTES}']
    missing = [marker for marker in required if marker not in text]
    result = dict(linkage=linkage, firmware=firmware, transport=transport,
                  returncode=process.returncode if process else None, timed_out=timed_out, error=error,
                  missing=missing, peers=[p.result for p in peers], captures=evidence,
                  seconds=round(time.monotonic() - started, 3), log=log.name,
                  passed=not timed_out and not error and not missing and len(evidence) == 2 and
                  process is not None and process.returncode == 1 and
                  not any(marker in text for marker in ('TCP_TEST_FAIL ', 'PANIC:', 'FAULT pid=')))
    print(json.dumps(result), flush=True)
    if not result['passed']:
        print(text[-5000:], flush=True)
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name, choices in (('linkage', ('static', 'dynamic')), ('firmware', ('bios', 'uefi')),
                          ('transport', ('modern', 'legacy'))):
        parser.add_argument(f'--{name}', choices=(*choices, 'both'), default='both')
    parser.add_argument('--timeout', type=float, default=90)
    args = parser.parse_args()
    if args.timeout <= 0:
        parser.error('timeout must be positive')
    results, original = [], ROOT / 'build/rootfs-network.cpio'
    previous = original.read_bytes() if original.exists() else None
    try:
        for linkage in ('static', 'dynamic') if args.linkage == 'both' else (args.linkage,):
            for firmware in ('bios', 'uefi') if args.firmware == 'both' else (args.firmware,):
                for transport in ('modern', 'legacy') if args.transport == 'both' else (args.transport,):
                    result = run(linkage, firmware, transport, args.timeout)
                    results.append(result)
                    (ROOT / 'build/tcp-wire-results.json').write_text(json.dumps(results, indent=2) + '\n')
                    if not result['passed']:
                        raise SystemExit('Guest/native TCP wire comparison failed')
    finally:
        if previous is None:
            original.unlink(missing_ok=True)
        else:
            original.write_bytes(previous)


if __name__ == '__main__':
    main()
