# SPDX-License-Identifier: GPL-3.0-or-later
"""Exercise actual foreground managers across carrier and adapter failures."""
import argparse
import json
from pathlib import Path
import re
import selectors
import shutil
import socket
import subprocess
import tempfile
import time
from fetch import ROOT
from manager_image import fixture
from manager_link_hardware import Hardware
from manager_link_peer import LinkPeer, SCENARIOS, check
from network_fault import inject
from qmp import Qmp
from qemu_acceleration import Acceleration


class Controller:
    def __init__(self, process, peers, affected, hardware, label, debug_port):
        self.process, self.peers, self.affected = process, peers, affected
        self.hardware, self.label, self.debug_port = hardware, label, debug_port
        self.target, self.healthy = peers[affected], peers[1 - affected]
        self.scenario = self.target.link_scenario
        self.ready = self.initial = self.down = self.progress = self.recovered = self.finished = False
        self.manual = self.returned = self.revalidating = False
        self.interrupted = self.scenario.endswith('initial')
        self.pending = self.down_ms = None
        self.stages, self.states, self.failures = [], [], []
        self.flaps = 0
        self.stale = None
        self.debugger = self.debug_log = self.armed = None
        self.fault = False
        self.initially_owned = not any(word in self.scenario for word in
                                       ('initial', 'selecting', 'probing')) and not self.target.disabled and \
            self.scenario != 'rx-length'
        self.target.offer_allowed = not self.interrupted
        self.target.ack_allowed = 'selecting' not in self.scenario and self.scenario != 'rx-length'
        self.probes_before_return = self.announcements_before_return = 0

    def command(self, stage):
        check(self.pending is None, 'one outstanding actual guest observation')
        self.pending = stage
        self.process.stdin.write((stage + '\n').encode())
        self.process.stdin.flush()

    def line(self, line):
        match = re.fullmatch(r'MANAGER_LINK_READY scenario=(\S+) affected=(\d+) pid=(\d+) monotonic_ms=(\d+)', line)
        if match:
            scenario, affected, pid, milliseconds = match.groups()
            check(not self.ready and scenario == self.scenario and int(affected) == self.affected and
                  int(pid) > 1, 'actual selected foreground manager process')
            self.ready = True
            self.stages.append(dict(stage='ready', pid=int(pid), guest_ms=int(milliseconds)))
            if self.scenario == 'rx-length':
                self.hardware.monitor.command('stop')
                unique = f'{self.label}-rx-{time.monotonic_ns()}'
                self.armed = ROOT / 'build' / (unique + '.armed')
                self.debugger, self.debug_log = inject('virtio' if self.affected == 0 else 'e1000',
                                                       'length', self.debug_port, unique, self.armed)
        match = re.fullmatch(r'MANAGER_LINK_FRAME index=(\d+) length=(\d+) hash=([0-9a-f]{16}) packet_type=(\d+) monotonic_ms=(\d+)', line)
        if match:
            index, length, digest, packet_type, milliseconds = match.groups()
            check(int(index) in (1, 2), 'actual Ethernet packet observer index')
            self.peers[int(index) - 1].receipt(int(length), digest, int(milliseconds), int(packet_type))
        match = re.fullmatch(r'MANAGER_LINK_DRIVER_FAILED index=(\d+) errno=(\d+) monotonic_ms=(\d+)', line)
        if match:
            index, error, milliseconds = map(int, match.groups())
            check(self.target.failed and index == self.affected + 1 and error == 5,
                  'only the physically removed driver reports permanent EIO')
            self.failures.append(dict(index=index, errno=error, guest_ms=milliseconds))
        match = re.fullmatch(r'MANAGER_LINK_STATE index=(\d+) owned=(\d+) address=([0-9a-f]{8}) mask=([0-9a-f]{8}) generation=(\d+) defaults=(\d+) manual=(\d+) hint=([0-9a-f]{8}) carrier=(\d+) administrative=(\d+)', line)
        if match:
            keys = ('index', 'owned', 'address', 'mask', 'generation', 'defaults', 'manual', 'hint',
                    'carrier', 'administrative')
            self.states.append({key: int(value, 16 if key in ('address', 'mask', 'hint') else 10)
                                for key, value in zip(keys, match.groups())})
        match = re.fullmatch(r'MANAGER_LINK_PASS stage=(\S+) affected=(\d+) monotonic_ms=(\d+)', line)
        if not match:
            return
        stage, affected, milliseconds = match.groups()
        check(stage == self.pending and int(affected) == self.affected,
              'completion matches the outstanding independent observation')
        self.pending = None
        self.stages.append(dict(stage=stage, guest_ms=int(milliseconds)))
        if stage == 'initial':
            self.initial = True
        elif stage == 'manual':
            self.manual = True
        elif stage == 'down':
            self.down = True
            self.down_ms = int(milliseconds)
        elif stage == 'progress':
            self.progress = True
        elif stage == 'revalidating':
            self.revalidating = True
        elif stage == 'flap':
            self.flaps += 1
            self.returned = self.revalidating = False
            self.stale = None
        elif stage in ('recovered', 'up'):
            self.recovered = True
        elif stage == 'finish':
            self.finished = True

    def target_delivered(self):
        return all('guest_ms' in record for record in self.target.received) and all(
            record['delivered'] or record.get('drop') == 'rx-length' for record in self.target.sent)

    def interrupt(self):
        self.target.interrupt()
        if self.target.failed:
            self.hardware.remove()
        else:
            self.hardware.carrier(False)
        self.interrupted = True

    def return_carrier(self):
        self.probes_before_return, self.announcements_before_return = (
            self.target.probes, self.target.announcements)
        if self.scenario == 'rx-length':
            self.target.offer_allowed = self.target.ack_allowed = True
        else:
            self.hardware.carrier(True)
            self.target.resume(self.initially_owned)
            self.target.ack_allowed = not self.target.old_transactions
        self.returned = True

    def drive(self):
        if not self.ready or self.finished:
            return
        target, healthy = self.target, self.healthy
        healthy_ready = healthy.announcements >= 2
        if self.scenario == 'rx-length':
            if self.debugger.poll() is None and not self.armed.exists():
                return
            if self.debugger.poll() is not None and not self.fault:
                marker = f'PACKET_FAULT_INJECTED model={"virtio" if self.affected == 0 else "e1000"} kind=length'
                check(self.debugger.returncode == 0 and marker in self.debug_log.read_text(),
                      'actual driver RX completion was corrupted at its validation boundary')
                record = next(record for record in target.sent if record['label'].startswith('2-'))
                check(not record['delivered'], 'corrupt completion never reaches a raw observer')
                record['drop'] = 'rx-length'
                target.interrupt()
                self.fault = self.interrupted = True
        for peer in self.peers:
            peer.tick(healthy_ready, self.down_ms)
        if self.pending is not None:
            return
        if 'probing' in self.scenario and target.probes and not self.interrupted and self.target_delivered():
            self.interrupt()
        if not healthy_ready:
            return
        if not self.initial:
            stage_ready = self.interrupted if 'probing' in self.scenario else (
                target.pending_ack is not None if 'selecting' in self.scenario else
                self.fault if self.scenario == 'rx-length' else
                True if self.scenario.endswith('initial') or target.disabled else
                target.announcements >= 2)
            if stage_ready and self.target_delivered():
                self.command('initial')
            return
        if self.scenario.startswith('manual-') and not self.manual:
            self.command('manual')
            return
        if not self.down:
            if not self.interrupted:
                if not self.target_delivered():
                    return
                self.interrupt()
            self.command('down')
            return
        if not self.progress:
            if healthy.acks >= 2:
                self.command('progress')
            return
        if target.failed:
            check(len(self.failures) == 1, 'permanent production-driver error was observed')
            if self.target_delivered() and all(record['delivered'] for record in healthy.sent):
                self.command('finish')
            return
        if not self.returned:
            self.return_carrier()
            return
        if target.disabled:
            self.command('up' if not self.recovered else 'finish')
            return
        if target.old_transactions and not target.fixed and self.scenario != 'rx-length' and not self.revalidating:
            request = target.pending_ack
            if request is None or 'guest_ms' not in request:
                return
            if self.stale is None:
                old = sorted(target.old_transactions)[0]
                check(old.hex() != request['transaction'], 'old ACK transaction differs from current revalidation')
                self.stale = target.send(target.reply(5, old, changed=True, ciaddr=bytes(4)), 'stale-carrier-ack')
                return
            if self.stale['delivered']:
                self.command('revalidating')
            return
        if self.scenario == 'carrier-flap' and self.revalidating and self.flaps < 2:
            if self.target_delivered():
                self.interrupt()
                self.command('flap')
            return
        target.ack_allowed = True
        if not self.recovered:
            if self.scenario == 'manual-carrier':
                if target.probes >= self.probes_before_return + 3:
                    self.command('up')
            elif target.announcements >= self.announcements_before_return + 2:
                self.command('recovered')
            return
        if self.target_delivered() and all(record['delivered'] for record in healthy.sent):
            self.command('finish')


def run(linkage, scenario, affected, firmware, transport, timeout, image):
    label = f'manager-link-{scenario}-{linkage}-lane{affected}-{firmware}-{transport}'
    attempt = f'{label}-{time.monotonic_ns()}'
    log, evidence = (ROOT / 'build' / (attempt + suffix) for suffix in ('.log', '-packets.json'))
    selector = selectors.DefaultSelector()
    peers = [LinkPeer(lane, scenario, affected) for lane in (0, 1)]
    servers = []
    control = tempfile.TemporaryDirectory(prefix='axiom64-manager-link-')
    monitor_path, test_path = (Path(control.name) / name for name in ('qmp.sock', 'qtest.sock'))
    debug_port = None
    acceleration = Acceleration()
    command = ['qemu-system-x86_64', '-machine', acceleration.machine, '-cpu', 'max', '-m', '512M', '-S',
               '-cdrom', str(image), '-nic', 'none', '-display', 'none', '-serial', 'stdio',
               '-monitor', 'none', '-no-reboot', '-device', 'isa-debug-exit,iobase=0xf4,iosize=0x04',
               '-qmp', f'unix:{monitor_path},server=on,wait=off',
               '-qtest', f'unix:{test_path},server=on,wait=off',
               '-qtest-log', str(ROOT / 'build' / (attempt + '-qtest.log'))]
    if scenario == 'rx-length':
        with socket.socket() as reservation:
            reservation.bind(('127.0.0.1', 0))
            debug_port = reservation.getsockname()[1]
        command += ['-gdb', f'tcp:127.0.0.1:{debug_port}']
    for lane, model in enumerate(('virtio-net-pci', 'e1000')):
        server = socket.socket()
        server.bind(('127.0.0.1', 0))
        server.listen(1)
        server.setblocking(False)
        servers.append(server)
        selector.register(server, selectors.EVENT_READ, ('server', lane))
        nic = f'{model},id=nic{lane},netdev=peer{lane},addr={lane + 4:x},mac={peers[lane].guest.hex(":")}'
        if lane == 0:
            nic += ',disable-legacy=on' if transport == 'modern' else ',disable-modern=on'
        command += ['-netdev', f'socket,id=peer{lane},connect=127.0.0.1:{server.getsockname()[1]}',
                    '-device', nic]
    if firmware == 'uefi':
        variables = ROOT / 'build' / (attempt + '-OVMF_VARS.fd')
        shutil.copyfile('/usr/share/OVMF/OVMF_VARS_4M.fd', variables)
        command += ['-drive', 'if=pflash,format=raw,readonly=on,file=/usr/share/OVMF/OVMF_CODE_4M.fd',
                    '-drive', f'if=pflash,format=raw,file={variables}']
    began, error, exit_at = time.monotonic(), None, None
    before_ready, line_buffer = [{}, {}], bytearray()
    monitor = hardware = controller = None
    with log.open('wb') as output:
        process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, stdin=subprocess.PIPE)
        selector.register(process.stdout, selectors.EVENT_READ, ('serial', None))
        try:
            while not (monitor_path.exists() and test_path.exists()):
                check(process.poll() is None and time.monotonic() - began < 5,
                      'actual emulator hardware controls become available')
                time.sleep(.01)
            monitor = Qmp(monitor_path)
            acceleration.observe(monitor)
            hardware = Hardware(monitor, test_path, affected, transport)
            if scenario.endswith('initial'):
                hardware.carrier(False)
            controller = Controller(process, peers, affected, hardware, attempt, debug_port)
            monitor.command('cont')
            while True:
                now = time.monotonic()
                if process.poll() is not None:
                    exit_at = exit_at or now
                    if now - exit_at > .2:
                        break
                check(now - began <= timeout, 'actual manager carrier/failure deadline')
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
                            check(14 <= size <= 1518, 'actual QEMU Ethernet packet boundary')
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
                    if peer.connection is None or peer.disconnected:
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
            if controller and controller.debugger and controller.debugger.poll() is None:
                controller.debugger.kill()
                controller.debugger.wait()
            if process.poll() is None:
                process.kill()
            returncode = process.wait()
            if hardware:
                hardware.close()
            if monitor:
                monitor.close()
            selector.close()
            process.stdin.close()
            process.stdout.close()
            for server in servers:
                server.close()
            for peer in peers:
                if peer.connection:
                    peer.connection.close()
            control.cleanup()
    text = log.read_text(errors='replace')
    required = [f'MANAGER_LINK_COMPLETE scenario={scenario} affected={affected}',
                'NETWORK_MANAGER_EXIT status=0', 'AXIOM64_TESTS_PASS', 'AXIOM64_EXIT status=0',
                f'Firmware: {firmware.upper()}']
    missing = [marker for marker in required if marker not in text]
    counts = [peer.counts() for peer in peers]
    if error is None and returncode == 1 and not missing:
        try:
            check(controller.finished and controller.down_ms is not None, 'all actual observation stages completed')
            counts = [peer.verify(controller.down_ms, peers[affected].failed) for peer in peers]
            if scenario == 'carrier-flap':
                check(controller.flaps == 2, 'two additional actual carrier flaps were observed')
        except Exception as exception:
            error = str(exception)
    evidence.write_text(json.dumps(dict(stages=controller.stages if controller else [],
                                       states=controller.states if controller else [],
                                       failures=controller.failures if controller else [],
                                       hardware=hardware.records if hardware else [], before_ready=before_ready,
                                       debugger=controller.debug_log.name if controller and controller.debug_log else None,
                                       peers=[dict(counts=peer.counts(), sent=peer.sent,
                                                   received=peer.received) for peer in peers]), indent=2) + '\n')
    result = dict(linkage=linkage, scenario=scenario, affected=affected, firmware=firmware,
                  transport=transport, returncode=returncode, error=error, missing=missing,
                  counts=counts, log=log.name, packets=evidence.name, acceleration=acceleration.evidence,
                  seconds=round(time.monotonic() - began, 3),
                  passed=returncode == 1 and error is None and not missing and controller is not None and
                  controller.finished and not any(marker in text for marker in
                                                   ('PANIC:', 'MANAGER_TEST_FAIL ', 'FAULT pid=')))
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
    parser.add_argument('--timeout', type=float, default=220)
    args = parser.parse_args()
    if args.timeout <= 0:
        parser.error('timeout must be positive')
    results = []
    report = ROOT / 'build' / f'manager-link-{args.firmware}-{args.transport}-lane{args.affected}-{args.linkage}-results.json'
    original = ROOT / 'build/rootfs-network.cpio'
    previous = original.read_bytes() if original.exists() else None
    try:
        for linkage in ('static', 'dynamic') if args.linkage == 'both' else (args.linkage,):
            for scenario in args.scenario:
                for affected in (0, 1) if args.affected == 'both' else (int(args.affected),):
                    image = fixture(linkage, scenario, affected, 'manager-link')
                    for firmware in ('bios', 'uefi') if args.firmware == 'both' else (args.firmware,):
                        for transport in ('modern', 'legacy') if args.transport == 'both' else (args.transport,):
                            result = run(linkage, scenario, affected, firmware, transport, args.timeout, image)
                            results.append(result)
                            report.write_text(json.dumps(results, indent=2) + '\n')
                            if not result['passed']:
                                raise SystemExit('Actual concurrent manager carrier/failure acceptance failed')
    finally:
        if previous is not None:
            replacement = ROOT / 'build/rootfs-manager-link-restore.cpio'
            replacement.write_bytes(previous)
            replacement.replace(original)
        elif original.exists():
            original.unlink()


if __name__ == '__main__':
    main()
