"""Verify PID1 supervision while the installed desktop and serial shell remain usable."""
import argparse
import json
import os
from pathlib import Path
import re
import selectors
import shutil
import socket
import subprocess
import time
from dhcp_peer import Peer, check
from disk_root import archive_entries, build
from ext2_test import check_fs, debugfs, dump
from fetch import ROOT
from manager_peer import ManagerPeer
from qmp import Qmp

SCENARIOS = {'no-nic': (0, 0), 'no-server': (2, 0), 'missing': (2, 2), 'healthy': (2, 3)}
PHASES = ('desktop-before', 'initial', 'kill', 'revalidating', 'recovered', 'desktop-after', 'stop')
DESKTOP_PATHS = ('/usr/libexec/Xorg', '/usr/bin/twm', '/usr/bin/xterm', '/bin/bash')


class SupervisionPeer(ManagerPeer):
    def __init__(self, lane, healthy):
        super().__init__(lane, 'restart')
        self.healthy = healthy
        # T1 is beyond the entire fixture deadline; protocol timer tests remain separate.
        self.lease_timers = self.rebound_timers = (600, 300, 525)
        self.initial_transaction = self.restart_transaction = self.pending = None
        self.approved = False
        self.discover_transactions = []
        self.initial_discovers = None
        self.restart_discover_transaction = None

    def packet(self, frame):
        before = self.discovers
        super().packet(frame)
        if self.discovers != before:
            self.discover_transactions.append(self.transaction.hex())
            if (self.initial_discovers is not None and
                    self.transaction.hex() not in self.initial_discovers and
                    self.restart_discover_transaction is None):
                self.restart_discover_transaction = self.transaction

    def send(self, frame):
        if self.healthy:
            super().send(frame)

    def answer(self, kind, transaction, changed=False):
        if self.releases:
            return  # PID1 may start a third child; it receives no new lease after teardown.
        if kind == 5 and self.reboots:
            check(self.restart_transaction is None or self.restart_transaction == transaction,
                  'restart retries keep the same pending transaction')
            self.restart_transaction = transaction
            if self.approved:
                Peer.answer(self, 5, transaction, changed=True)
            else:
                self.pending = transaction
        else:
            if kind == 5:
                self.initial_transaction = transaction
            super().answer(kind, transaction, changed)

    def approve(self):
        check(self.pending is not None, 'real INIT-REBOOT precedes the fresh ACK')
        self.approved = True
        Peer.answer(self, 5, self.pending, changed=True)
        self.pending = None

    def counts(self):
        return dict(super().counts(), initial_transaction=(self.initial_transaction or b'').hex(),
                    restart_transaction=(self.restart_transaction or b'').hex(),
                    discover_transactions=self.discover_transactions.copy(),
                    restart_discover_transaction=(self.restart_discover_transaction or b'').hex())

    def verify_initial(self):
        if self.healthy:
            check((self.discovers, self.selecting, self.probes, self.announcements, self.releases,
                   self.reboots, self.renewals, self.rebindings) == (2, 1, 3, 2, 0, 0, 0, 0),
                  'strict first-process acquisition/probing/announcement counts')
        else:
            check(self.discovers >= 1 and not any((self.selecting, self.probes, self.announcements,
                                                  self.releases, self.reboots)),
                  'missing peer remains unconfigured while the desktop works')
        self.initial_discovers = tuple(self.discover_transactions)
        return self.counts()

    def verify(self):
        if self.healthy:
            check((self.selecting, self.probes, self.announcements, self.releases,
                   self.renewals, self.rebindings) == (1, 6, 4, 1, 0, 0) and self.reboots >= 1 and
                  self.initial_transaction and self.restart_transaction and
                  self.initial_transaction != self.restart_transaction and self.pending is None,
                  'real restarted process revalidates, probes and releases the fresh ACK')
        else:
            check(self.discovers >= 2 and self.restart_discover_transaction and
                  not any((self.selecting, self.reboots, self.probes,
                                                  self.announcements, self.releases)),
                  'missing peer remains isolated through both actual manager processes')
        return self.counts()


def write_archive(destination, entries):
    with destination.open('wb') as output:
        for inode, (name, (mode, data)) in enumerate([*sorted(entries.items()), ('TRAILER!!!', (0, b''))], 1):
            encoded = name.encode() + b'\0'
            fields = [inode, mode, 0, 0, 1, 0, len(data), 0, 0, 0, 0, len(encoded), 0]
            output.write(b'070701' + b''.join(f'{value:08x}'.encode() for value in fields) + encoded)
            output.write(bytes(-output.tell() % 4))
            output.write(data)
            output.write(bytes(-output.tell() % 4))


def fixture():
    subprocess.run(['make', '-j2', 'build/axiom64.elf', 'build/rootfs.cpio', 'build/init-supervision'],
                   cwd=ROOT, check=True)
    expected = json.loads((ROOT / 'sources.lock.json').read_text())['build_musl']['version']
    actual = subprocess.check_output(['dpkg-query', '-W', '-f=${Version}', 'musl-dev'], text=True)
    check(actual == expected, 'fixture compiler libc matches the pinned build version')
    original = ROOT / 'build/rootfs.cpio'
    before = original.read_bytes()
    entries = archive_entries(original)
    for name in ('sbin/init', 'sbin/network-manager'):
        check(entries[name][1] == (ROOT / 'build' / Path(name).name).read_bytes(),
              'fixture retains the installed production init and manager bytes')
    entries['bin/init-supervision'] = (0o100755, (ROOT / 'build/init-supervision').read_bytes())
    try:
        write_archive(original, entries)
        disk = build('full')
        images = {}
        for root in ('ram', 'ext2'):
            images[root] = ROOT / 'build' / f'axiom64-normal-init-{root}.iso'
            subprocess.run(['python3', 'scripts/image.py', '--output-name', images[root].name] +
                           (['--root-device', '/dev/vda'] if root == 'ext2' else []), cwd=ROOT, check=True)
        return disk, images
    finally:
        original.write_bytes(before)


def host_filesystem(disk, label):
    directory = debugfs(disk, 'stat /etc/network')
    information = debugfs(disk, 'stat /etc/network/eth0.conf')
    check('Mode:  0700' in directory and 'User:     0' in directory and 'Group:     0' in directory,
          'host verifies private saved directory metadata')
    check('Type: regular' in information and 'Mode:  0600' in information and 'User:     0' in information and
          'Group:     0' in information and 'Links: 1' in information, 'host verifies private profile metadata')
    expected = b'axiom64-network=1\nmode=dhcp\nhostname=normal-init\nmetric=0\n'
    check(dump(disk, '/etc/network/eth0.conf', label) == expected,
          'host profile bytes equal the original production Store output')
    for path in ('/etc/network/eth0.lease', '/etc/network/eth1.lease', '/run/network-manager',
                 '/run/network-resolver', '/run/init-supervision-state', '/run/init-supervision-profile',
                 '/tmp/init-keyboard-before', '/tmp/init-keyboard-after'):
        check(not debugfs(disk, 'stat ' + path).startswith('Inode:'),
              'released hints and volatile records are absent from the disk: ' + path)
    return check_fs(disk, label)


def send(process, command):
    process.stdin.write((command + '\n').encode())
    process.stdin.flush()


def events(text):
    spawns = [(int(pid), int(tick)) for pid, tick in
              re.findall(r'^INIT_MANAGER_SPAWN pid=(\d+) monotonic_ms=(\d+)\r?$', text, re.M)]
    reaps = [(int(pid), int(status), int(tick)) for pid, status, tick in
             re.findall(r'^INIT_MANAGER_REAP pid=(\d+) status=(\d+) monotonic_ms=(\d+)\r?$', text, re.M)]
    passed = {phase: (int(pid), int(tick)) for phase, pid, tick in
              re.findall(r'^INIT_OBSERVER_PASS phase=([a-z-]+) pid=(\d+) monotonic_ms=(\d+)\r?$', text, re.M)}
    return spawns, reaps, passed


def desktop_identity(text):
    return {path: sorted(set(int(pid) for pid in re.findall(
        r'exec pid=(\d+) ' + re.escape(path) + r' \(', text))) for path in DESKTOP_PATHS}


def run(scenario, firmware, transport, root, disk_seed, images, timeout):
    interfaces, mask = SCENARIOS[scenario]
    label = f'normal-init-{scenario}-{root}-{firmware}-{transport}'
    log = ROOT / 'build' / (label + '.log')
    control = Path('/tmp') / f'axiom64-normal-init-{os.getpid()}.sock'
    control.unlink(missing_ok=True)
    selector = selectors.DefaultSelector()
    peers = [SupervisionPeer(lane, mask & (1 << lane)) for lane in range(interfaces)]
    servers = []
    disk = None
    command = ['qemu-system-x86_64', '-machine', 'pc', '-cpu', 'max', '-m', '2G', '-nic', 'none',
               '-cdrom', str(images[root]), '-display', 'none', '-serial', 'stdio', '-monitor', 'none',
               '-no-reboot', '-qmp', f'unix:{control},server=on,wait=off']
    mode = 'disable-legacy=on' if transport == 'modern' else 'disable-modern=on'
    if root == 'ext2':
        disk = ROOT / 'build' / (label + '.raw')
        shutil.copyfile(disk_seed, disk)
        command += ['-drive', f'if=none,id=root,format=raw,cache=writeback,file={disk}',
                    '-device', f'virtio-blk-pci,drive=root,{mode},rerror=report,werror=report,addr=6']
    for lane, peer in enumerate(peers):
        server = socket.socket()
        server.bind(('127.0.0.1', 0))
        server.listen(1)
        server.setblocking(False)
        servers.append(server)
        selector.register(server, selectors.EVENT_READ, ('server', lane))
        model = 'virtio-net-pci' if lane == 0 else 'e1000'
        nic = f'{model},netdev=peer{lane},addr={lane + 4:x},mac={peer.guest.hex(":")}'
        if lane == 0:
            nic += ',' + mode
        command += ['-netdev', f'socket,id=peer{lane},connect=127.0.0.1:{server.getsockname()[1]}', '-device', nic]
    if firmware == 'uefi':
        variables = ROOT / 'build' / (label + '-OVMF_VARS.fd')
        shutil.copyfile('/usr/share/OVMF/OVMF_VARS_4M.fd', variables)
        command += ['-drive', 'if=pflash,format=raw,readonly=on,file=/usr/share/OVMF/OVMF_CODE_4M.fd',
                    '-drive', f'if=pflash,format=raw,file={variables}']
    started = time.monotonic()
    stage = 'boot'
    first = second = None
    qmp = None
    keyboard = ''
    typing_phase = None
    key_at = 0
    screenshots = []
    initial_counts = []
    before_desktop = {}
    error = None
    with log.open('wb') as output:
        process = subprocess.Popen(command, stdin=subprocess.PIPE, stdout=output, stderr=subprocess.STDOUT)
        try:
            while process.poll() is None:
                now = time.monotonic()
                check(now - started < timeout, 'normal-init guest deadline exceeded at ' + stage)
                for key, ready in selector.select(.01):
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
                    if ready & selectors.EVENT_READ:
                        data = connection.recv(65536)
                        if not data:
                            selector.unregister(connection)
                            continue
                        peer.input.extend(data)
                        while len(peer.input) >= 4:
                            size = int.from_bytes(peer.input[:4], 'big')
                            check(14 <= size <= 1518, 'QEMU Ethernet frame bounds')
                            if len(peer.input) < size + 4:
                                break
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
                text = log.read_text(errors='replace')
                check(not any(value in text for value in ('PANIC:', 'FAULT pid=', 'INIT_OBSERVER_FAIL ',
                                                          'NETWORK_MANAGER_ERROR ', 'network-manager:')),
                      'normal guest reported a failure')
                spawns, reaps, passed = events(text)
                if stage == 'boot' and spawns and f'NETWORK_MANAGER_READY pid={spawns[0][0]} interfaces={interfaces}' in text:
                    first = spawns[0][0]
                    send(process, 'while ! test -f /tmp/xterm-ready; do sleep .1; done; '
                         '/bin/x11-probe --desktop && while ! test -f /tmp/init-keyboard-before; '
                         f'do sleep .1; done && /bin/init-supervision desktop-before {first} {mask} {interfaces}')
                    stage = 'desktop-before'
                if (stage in ('desktop-before', 'desktop-after') and stage != typing_phase and
                        not keyboard and qmp is None):
                    needed = 1 if stage == 'desktop-before' else 2
                    if len(re.findall(r'^XTERM_WINDOW_ID window=\d+\r?$', text, re.M)) == needed:
                        qmp = Qmp(control)
                        qmp.command('input-send-event', {'events': [
                            {'type': 'rel', 'data': {'axis': 'x', 'value': 4}},
                            {'type': 'rel', 'data': {'axis': 'y', 'value': 4}},
                            {'type': 'btn', 'data': {'button': 'left', 'down': True}}]})
                        qmp.command('input-send-event', {'events': [
                            {'type': 'btn', 'data': {'button': 'left', 'down': False}}]})
                        keyboard = 'touch /tmp/init-keyboard-' + stage[8:] + '\n'
                        typing_phase = stage
                        key_at = now
                if keyboard and now >= key_at:
                    character, keyboard = keyboard[0], keyboard[1:]
                    code = {' ': 'spc', '/': 'slash', '-': 'minus', '\n': 'ret'}.get(character, character)
                    qmp.command('send-key', {'keys': [{'type': 'qcode', 'data': code}], 'hold-time': 30})
                    key_at = now + .07
                    if not keyboard:
                        qmp.close()
                        qmp = None
                if stage == 'desktop-before' and stage in passed:
                    before_desktop = desktop_identity(text)
                    check(all(len(values) == 1 for values in before_desktop.values()), 'actual installed desktop processes')
                    snapshot = ROOT / 'build' / (label + '-before.png')
                    qmp = Qmp(control)
                    qmp.command('screendump', {'filename': str(snapshot), 'format': 'png'})
                    qmp.close()
                    qmp = None
                    screenshots.append(snapshot.name)
                    stage = 'initial-wait'
                if (stage == 'initial-wait' and
                        all((peer.announcements == 2 and
                             f'NETWORK_MANAGER_BOUND index={peer.lane + 1} method=dhcp ' in text)
                            if peer.healthy else peer.discovers >= 1 for peer in peers)):
                    send(process, f'/bin/init-supervision initial {first} {mask} {interfaces}')
                    stage = 'initial'
                if stage == 'initial' and stage in passed and all(not p.healthy or p.announcements == 2 for p in peers):
                    initial_counts = [peer.verify_initial() for peer in peers]
                    send(process, f'/bin/init-supervision kill {first} {mask} {interfaces}')
                    stage = 'kill'
                if stage == 'kill' and len(spawns) >= 2:
                    check(len(reaps) == 1 and reaps[0][:2] == (first, 9), 'PID1 reaps the SIGKILL status')
                    second = spawns[1][0]
                    check(second != first and 1000 <= spawns[1][1] - reaps[0][2] <= 10000,
                          'actual monotonic restart backoff is at least one second and bounded')
                    if (f'NETWORK_MANAGER_READY pid={second} interfaces={interfaces}' in text and
                            all(peer.pending is not None if peer.healthy else
                                peer.restart_discover_transaction is not None for peer in peers)):
                        check(f'exec pid={second} /sbin/network-manager (static ELF)' in text,
                              'PID1 execs the installed manager binary')
                        send(process, f'/bin/init-supervision revalidating {second} {mask} {interfaces}')
                        stage = 'revalidating'
                if stage == 'revalidating' and stage in passed:
                    for peer in peers:
                        if peer.healthy:
                            peer.approve()
                    stage = 'ack'
                if stage == 'ack' and all(not peer.healthy or peer.announcements == 4 for peer in peers):
                    send(process, f'/bin/init-supervision recovered {second} {mask} {interfaces}')
                    stage = 'recovered'
                if stage == 'recovered' and stage in passed:
                    send(process, '/bin/x11-probe --desktop && while ! test -f /tmp/init-keyboard-after; '
                         f'do sleep .1; done && /bin/init-supervision desktop-after {second} {mask} {interfaces}')
                    stage = 'desktop-after'
                if stage == 'desktop-after' and stage in passed:
                    check(desktop_identity(text) == before_desktop, 'the same desktop processes survive manager death')
                    windows = re.findall(r'^XTERM_WINDOW_ID window=(\d+)\r?$', text, re.M)
                    check(len(windows) == 2 and windows[0] == windows[1], 'the same normal xterm window remains usable')
                    snapshot = ROOT / 'build' / (label + '-after.png')
                    qmp = Qmp(control)
                    qmp.command('screendump', {'filename': str(snapshot), 'format': 'png'})
                    qmp.close()
                    qmp = None
                    screenshots.append(snapshot.name)
                    send(process, f'/bin/init-supervision stop {second} {mask} {interfaces}')
                    stage = 'stop'
                if stage == 'stop' and stage in passed and len(reaps) >= 2:
                    check(len(reaps) == 2 and reaps[1][:2] == (second, 0), 'PID1 reaps the checked normal SIGTERM exit')
                    send(process, '/bin/busybox poweroff -f')
                    stage = 'poweroff'
        except Exception as exception:
            error = str(exception)
        finally:
            if qmp:
                qmp.close()
            if process.poll() is None:
                process.kill()
            returncode = process.wait()
            process.stdin.close()
            selector.close()
            for server in servers:
                server.close()
            for peer in peers:
                if peer.connection:
                    peer.connection.close()
            control.unlink(missing_ok=True)
    text = log.read_text(errors='replace')
    spawns, reaps, passed = events(text)
    result = dict(scenario=scenario, firmware=firmware, transport=transport, root=root, log=log.name,
                  returncode=returncode, stage=stage, error=error, spawns=spawns, reaps=reaps, phases=passed,
                  initial_counts=initial_counts, counts=[peer.counts() for peer in peers], screenshots=screenshots,
                  desktop=before_desktop, seconds=round(time.monotonic() - started, 3), passed=False)
    try:
        check(error is None and returncode == 0 and stage == 'poweroff', 'normal boot did not finish cleanly')
        check(set(passed) == set(PHASES) and len(screenshots) == 2, 'all actual console/desktop/supervision phases')
        required = [f'Firmware: {firmware.upper()}', 'exec pid=1 /sbin/init (static ELF)',
                    'AXIOM64_EXIT status=0', 'PLATFORM_POWEROFF method=piix4', 'NETWORK_MANAGER_EXIT status=0']
        if interfaces:
            required += [f'virtio-net: index=1 transport={transport}', 'e1000: index=2 model=82540EM',
                         'NET_DEVICE index=1 name=eth0 mtu=1500 carrier=1 mac=52:54:0:12:34:10',
                         'NET_DEVICE index=2 name=eth1 mtu=1500 carrier=1 mac=52:54:0:12:34:11']
        if disk:
            required += ['VFS_ROOT_PASS filesystem=ext2 device=/dev/vda readonly=0']
        check(all(marker in text for marker in required), 'required installed kernel/driver/shutdown evidence')
        check('AXIOM64_TESTS_PASS' not in text and 'MANAGER_TEST_READY' not in text, 'normal init path is required')
        result['counts'] = [peer.verify() for peer in peers]
        if disk:
            result['disk'] = disk.name
            result['fsck'] = host_filesystem(disk, label)
        result['passed'] = True
    except Exception as exception:
        result['error'] = result['error'] or str(exception)
    print(json.dumps(result), flush=True)
    if not result['passed']:
        print(text[-5000:], flush=True)
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--firmware', choices=('bios', 'uefi', 'both'), default='both')
    parser.add_argument('--transport', choices=('modern', 'legacy', 'both'), default='both')
    parser.add_argument('--root', choices=('ram', 'ext2', 'both'), default='both')
    parser.add_argument('--scenario', choices=tuple(SCENARIOS), nargs='+', default=list(SCENARIOS))
    parser.add_argument('--timeout', type=float, default=180)
    args = parser.parse_args()
    if not 0 < args.timeout < 300:
        parser.error('timeout must be positive and below the fixture lease renewal time')
    disk, images = fixture()
    results = []
    report = ROOT / 'build' / f'normal-init-{args.firmware}-results.json'
    for firmware in ('bios', 'uefi') if args.firmware == 'both' else (args.firmware,):
        for transport in ('modern', 'legacy') if args.transport == 'both' else (args.transport,):
            for root in ('ram', 'ext2') if args.root == 'both' else (args.root,):
                for scenario in args.scenario:
                    result = run(scenario, firmware, transport, root, disk, images, args.timeout)
                    results.append(result)
                    report.write_text(json.dumps(results, indent=2) + '\n')
                    if not result['passed']:
                        raise SystemExit('Installed normal-init supervision failed')


if __name__ == '__main__':
    main()
