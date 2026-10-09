# SPDX-License-Identifier: GPL-3.0-or-later
"""Exercise DHCP failures and lease lifetimes through real foreground managers."""
import argparse
import json
from pathlib import Path
import re
import selectors
import shutil
import socket
import subprocess
import time
from fetch import ROOT
from manager_protocol_peer import ProtocolPeer, SCENARIOS, check
from manager_image import fixture


class Controller:
    def __init__(self, process, peers, affected):
        self.process, self.peers, self.affected = process, peers, affected
        self.ready = self.bound = self.recovered = self.steady = self.finished = False
        self.pending = None
        self.stages = []
        self.bound_host = None
        self.clock_checked = False

    def command(self, stage, approve=False):
        check(self.pending is None, 'one outstanding serial observation')
        self.pending = stage, approve
        self.process.stdin.write((stage + '\n').encode())
        self.process.stdin.flush()

    def line(self, line):
        if line.startswith('MANAGER_PROTOCOL_READY '):
            self.ready = True
        match = re.fullmatch(r'MANAGER_PROTOCOL_FRAME index=(\d+) length=(\d+) hash=([0-9a-f]{16}) packet_type=(\d+) monotonic_ms=(\d+)', line)
        if match:
            index, length, digest, packet_type, milliseconds = match.groups()
            check(int(index) in (1, 2), 'observer reports an actual Ethernet adapter')
            self.peers[int(index) - 1].receipt(int(length), digest, int(milliseconds), int(packet_type))
        match = re.fullmatch(r'MANAGER_PROTOCOL_PASS stage=(\S+) affected=(\d+) monotonic_ms=(\d+)', line)
        if not match:
            return
        stage, affected, milliseconds = match.groups()
        check(self.pending is not None and self.pending[0] == stage and int(affected) == self.affected,
              'serial completion corresponds to the outstanding independent observation')
        approve = self.pending[1]
        self.pending = None
        self.stages.append(dict(stage=stage, guest_ms=int(milliseconds)))
        target = self.peers[self.affected]
        if stage == 'bound':
            self.bound = True
            self.bound_host = time.monotonic()
            if target.scenario == 'dhcp-defense' and not target.conflicts:
                target.gate = 'defense-conflict'
                approve = True
        elif stage == 'recovered':
            self.recovered = True
        elif stage == 'steady':
            self.steady = True
        elif stage == 'finish':
            self.finished = True
        elif stage == 'clock':
            if target.scenario == 'expiry':
                origin = next(record for record in target.received if record.get('kind') == 3 and
                              bytes.fromhex(record['frame'])[54:58] == bytes(4))
                minimum = 36000
            else:
                origin = next(record for record in target.received if record.get('kind') == 4)
                minimum = 10000
            check(int(milliseconds) - origin['guest_ms'] >= minimum,
                  'actual guest expiry/DECLINE backoff has elapsed before fresh acquisition')
            self.clock_checked = True
        if approve:
            target.approve()

    def drive(self):
        if not self.ready or self.pending is not None or self.finished:
            return
        target, healthy = self.peers[self.affected], self.peers[1 - self.affected]
        healthy_ready = healthy.announcements >= 2
        target.tick(healthy_ready)
        if not healthy_ready:
            return
        gate = target.gate
        if gate in ('initial-offer', 'initial-ack'):
            target.approve()
            return
        if gate in ('reject-offer', 'reject-ack') and target.rejected_delivered():
            self.command('snapshot', approve=True)
        elif gate in ('renew-nak', 'rebind-nak') and target.rejected_delivered():
            self.command('bound', approve=True)
        elif gate == 'withdrawn' and all(record['delivered'] for record in target.sent):
            timed = target.scenario in ('expiry', 'conflict-probe', 'conflict-claim', 'dhcp-defense')
            if timed and not self.clock_checked:
                self.command('clock')
            else:
                initial = target.scenario in ('nak-request', 'nak-reboot', 'conflict-probe')
                self.command('snapshot' if initial else 'withdrawn', approve=True)
        elif gate == 'claim-conflict' and not self.bound:
            self.command('bound', approve=True)
        elif gate is None:
            complete_announcements = target.announcements >= getattr(target, 'ann_before_ack', 0) + 2
            extended = target.changed and target.acks == 2 and target.scenario in (
                'renew-ack', 'infinite-timers', 'default-timers', 'invalid-timers')
            if (target.reacquiring and target.acks >= 2 and
                    target.scenario not in ('nak-request', 'nak-reboot') and
                    complete_announcements or extended) and not self.recovered:
                self.command('recovered')
            elif complete_announcements and not self.bound and not self.recovered:
                self.command('bound')
            elif target.scenario == 'infinite' and self.bound and not self.steady:
                if time.monotonic() - self.bound_host >= 35.5:
                    self.command('steady')
            else:
                simple = target.scenario in ('reply-rejection', 'loss-reorder', 'options', 'manual-resolver',
                                             'nak-request', 'nak-reboot')
                done = simple and self.bound or self.recovered or target.scenario == 'infinite' and self.steady
                if done and all(record['delivered'] for peer in self.peers for record in peer.sent):
                    self.command('finish')


def run(linkage, scenario, affected, firmware, transport, timeout, image):
    label = f'manager-protocol-{scenario}-{linkage}-lane{affected}-{firmware}-{transport}'
    log = ROOT / 'build' / (label + '.log')
    evidence = ROOT / 'build' / (label + '-packets.json')
    selector = selectors.DefaultSelector()
    peers = [ProtocolPeer(lane, scenario, affected) for lane in (0, 1)]
    servers = []
    command = ['qemu-system-x86_64', '-machine', 'pc', '-cpu', 'max', '-m', '512M',
               '-cdrom', str(image), '-nic', 'none', '-display', 'none', '-serial', 'stdio',
               '-monitor', 'none', '-no-reboot', '-device', 'isa-debug-exit,iobase=0xf4,iosize=0x04']
    for lane, model in enumerate(('virtio-net-pci', 'e1000')):
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
    began, error, exit_at = time.monotonic(), None, None
    before_ready = [{}, {}]
    line_buffer = bytearray()
    with log.open('wb') as output:
        process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, stdin=subprocess.PIPE)
        selector.register(process.stdout, selectors.EVENT_READ, ('serial', None))
        controller = Controller(process, peers, affected)
        try:
            while True:
                now = time.monotonic()
                if process.poll() is not None:
                    exit_at = exit_at or now
                    if now - exit_at > .2:
                        break
                check(now - began <= timeout, 'actual manager protocol deadline')
                for key, events in selector.select(.01):
                    kind, lane = key.data
                    if kind == 'serial':
                        data = key.fileobj.read1(65536)
                        if not data:
                            selector.unregister(key.fileobj)
                            continue
                        output.write(data)
                        output.flush()
                        line_buffer.extend(data)
                        while b'\n' in line_buffer:
                            line, _, rest = line_buffer.partition(b'\n')
                            line_buffer = bytearray(rest)
                            controller.line(line.decode(errors='replace').strip())
                        continue
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
                            peer.disconnected = True
                            continue
                        peer.input.extend(data)
                        while len(peer.input) >= 4:
                            size = int.from_bytes(peer.input[:4], 'big')
                            check(14 <= size <= 1518, 'QEMU Ethernet packet boundary')
                            if len(peer.input) < size + 4:
                                break
                            frame = bytes(peer.input[4:size + 4])
                            if controller.ready:
                                peer.packet(frame)
                            else:
                                protocol = frame[12:14].hex()
                                before_ready[lane][protocol] = before_ready[lane].get(protocol, 0) + 1
                            del peer.input[:size + 4]
                controller.drive()
                for lane, peer in enumerate(peers):
                    if peer.connection is None or getattr(peer, 'disconnected', False):
                        continue
                    if peer.output:
                        try:
                            sent = peer.connection.send(peer.output)
                            del peer.output[:sent]
                        except BlockingIOError:
                            pass
                    selector.modify(peer.connection, selectors.EVENT_READ | (
                        selectors.EVENT_WRITE if peer.output else 0), ('peer', lane))
        except Exception as exception:
            error = str(exception)
        finally:
            if process.poll() is None:
                process.kill()
            returncode = process.wait()
            selector.close()
            process.stdin.close()
            process.stdout.close()
            for server in servers:
                server.close()
            for peer in peers:
                if peer.connection:
                    peer.connection.close()
    text = log.read_text(errors='replace')
    required = [f'MANAGER_PROTOCOL_COMPLETE scenario={scenario} affected={affected}',
                'NETWORK_MANAGER_EXIT status=0', 'AXIOM64_TESTS_PASS', 'AXIOM64_EXIT status=0',
                f'Firmware: {firmware.upper()}']
    missing = [marker for marker in required if marker not in text]
    counts = [peer.counts() for peer in peers]
    if error is None and returncode == 1 and not missing:
        try:
            counts = [peer.verify() for peer in peers]
        except Exception as exception:
            error = str(exception)
    evidence.write_text(json.dumps(dict(stages=controller.stages, before_ready=before_ready,
                                       peers=[dict(counts=peer.counts(), sent=peer.sent,
                                                   received=peer.received) for peer in peers]), indent=2) + '\n')
    result = dict(linkage=linkage, scenario=scenario, affected=affected, firmware=firmware,
                  transport=transport, returncode=returncode, error=error, missing=missing,
                  counts=counts, log=log.name, packets=evidence.name,
                  seconds=round(time.monotonic() - began, 3),
                  passed=returncode == 1 and error is None and not missing and controller.finished and
                  not any(marker in text for marker in ('PANIC:', 'MANAGER_TEST_FAIL ', 'FAULT pid=')))
    print(json.dumps(result), flush=True)
    if not result['passed']:
        print(text[-4500:], flush=True)
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--linkage', choices=('static', 'dynamic', 'both'), default='both')
    parser.add_argument('--scenario', choices=SCENARIOS, nargs='+', default=list(SCENARIOS))
    parser.add_argument('--affected', choices=('0', '1', 'both'), default='both')
    parser.add_argument('--firmware', choices=('bios', 'uefi', 'both'), default='both')
    parser.add_argument('--transport', choices=('modern', 'legacy', 'both'), default='both')
    parser.add_argument('--timeout', type=float, default=200)
    args = parser.parse_args()
    if args.timeout <= 0:
        parser.error('timeout must be positive')
    results = []
    report = ROOT / 'build' / f'manager-protocol-{args.firmware}-{args.transport}-lane{args.affected}-results.json'
    original = ROOT / 'build/rootfs-network.cpio'
    previous = original.read_bytes() if original.exists() else None
    try:
        for linkage in ('static', 'dynamic') if args.linkage == 'both' else (args.linkage,):
            for scenario in args.scenario:
                for affected in (0, 1) if args.affected == 'both' else (int(args.affected),):
                    image = fixture(linkage, scenario, affected)
                    for firmware in ('bios', 'uefi') if args.firmware == 'both' else (args.firmware,):
                        for transport in ('modern', 'legacy') if args.transport == 'both' else (args.transport,):
                            result = run(linkage, scenario, affected, firmware, transport, args.timeout, image)
                            results.append(result)
                            report.write_text(json.dumps(results, indent=2) + '\n')
                            if not result['passed']:
                                raise SystemExit('Actual concurrent manager protocol acceptance failed')
    finally:
        if previous is not None:
            replacement = ROOT / 'build/rootfs-manager-protocol-restore.cpio'
            replacement.write_bytes(previous)
            replacement.replace(original)
        elif original.exists():
            original.unlink()


if __name__ == '__main__':
    main()
