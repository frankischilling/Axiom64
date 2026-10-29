# SPDX-License-Identifier: GPL-3.0-or-later
"""Run real musl DNS through both Ethernet drivers on BIOS and UEFI."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import selectors
import shutil
import socket
import subprocess
import sys
import tempfile
import time
from fetch import ROOT, LOCK
from build_musl import loader as musl_loader
from dns_peer import Peer, check
from tcp_fixture_inputs import audit_fixture, digest
from dns_observer import audit as audit_dns_observer

CASES = ('numeric', 'hosts', 'wire-lane0', 'wire-lane1', 'cname', 'search', 'search-bare',
         'absolute', 'ndots', 'nxdomain', 'nodata', 'reply-filter', 'retry', 'timeout',
         'refused', 'servfail', 'parallel-nameservers')


def capture_audit(peers, text, directory):
    return audit_dns_observer(peers, text, [directory / f'lane{lane}.pcap' for lane in range(2)],
                              ('static', 'dynamic'))


def observe_frame(peer, frame, observations):
    check(len(observations) < 4096, 'bounded DNS frame observations')
    row = dict(lane=peer.lane, frame=frame.hex(), sha256=hashlib.sha256(frame).hexdigest(),
               observed_monotonic_ns=time.monotonic_ns(), started_before=peer.started)
    observations.append(row)
    try:
        peer.packet(frame)
    except Exception as failure:
        row['rejection'] = str(failure)
        raise


def fixture():
    subprocess.run(['make', '-s', '-j2', 'build/axiom64.elf', 'build/init', 'build/dns-static',
                    'build/dns-dynamic', 'busybox'], cwd=ROOT, check=True)
    expected = json.loads((ROOT / 'sources.lock.json').read_text())['build_musl']['version']
    version = subprocess.check_output(['dpkg-query', '-W', '-f=${Version}', 'musl-dev'], text=True)
    check(version == expected, 'DNS fixture uses the pinned musl build')
    parent = ROOT / 'build/dns-fixture'
    parent.mkdir(parents=True, exist_ok=True)
    directory = Path(tempfile.mkdtemp(prefix='run-', dir=parent))
    names = {'Makefile', 'dependencies.json', 'sources.lock.json', 'boot/limine.conf',
             'userspace/tests/net/dns.c', 'userspace/tests/net/dns/contract.h',
             'userspace/tests/net/dns.sh'}
    for module in list(sys.modules.values()):
        name = getattr(module, '__file__', None)
        if name and Path(name).resolve().is_relative_to(ROOT / 'scripts'):
            names.add(str(Path(name).resolve().relative_to(ROOT)))
    inputs = {}
    for name in sorted(names):
        target = directory / 'source' / name
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(ROOT / name, target)
        inputs[name] = digest(target)
    (directory / 'source-inputs.json').write_text(json.dumps(inputs, indent=2) + '\n')
    files = {name: (0o40755, b'') for name in
             ['bin', 'sbin', 'lib', 'etc', 'dev', 'proc', 'sys', 'tmp', 'run', 'root']}
    for name, source in [('sbin/init', ROOT / 'build/init'),
                         ('bin/dns-static', ROOT / 'build/dns-static'),
                         ('bin/dns-dynamic', ROOT / 'build/dns-dynamic'),
                         ('bin/busybox', ROOT / 'build' / f"busybox-{LOCK['busybox']['version']}" / 'busybox'),
                         ('lib/ld-musl-x86_64.so.1', musl_loader()),
                         ('etc/net-test.sh', ROOT / 'userspace/tests/net/dns.sh')]:
        target = directory / name
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(source, target)
        files[name] = (0o100755, target.read_bytes())
    files['etc/hosts'] = (0o100644, b'10.23.1.100 local-host.fixture\n')
    files['etc/resolv.conf'] = (0o100644, b'nameserver 10.23.1.1\n')
    with (directory / 'root.cpio').open('xb') as output:
        for inode, (name, (mode, data)) in enumerate([*sorted(files.items()), ('TRAILER!!!', (0, b''))], 1):
            encoded = name.encode() + b'\0'
            values = [inode, mode, 0, 0, 1, 0, len(data), 0, 0, 0, 0, len(encoded), 0]
            output.write(b'070701' + b''.join(f'{value:08x}'.encode() for value in values) + encoded)
            output.write(bytes(-output.tell() % 4))
            output.write(data)
            output.write(bytes(-output.tell() % 4))
    shutil.copyfile(ROOT / 'build/axiom64.elf', directory / 'kernel.elf')
    subprocess.run(['python3', 'scripts/image.py', '--test', '--suite', 'network',
                    '--initramfs', str(directory / 'root.cpio'), '--output-name', 'image.iso',
                    '--output-directory', str(directory)], cwd=ROOT, check=True,
                   stdout=subprocess.DEVNULL)
    products = {name: dict(bytes=(directory / name).stat().st_size, sha256=digest(directory / name))
                for name in ['kernel.elf', 'root.cpio', 'image.iso',
                             *(name for name, (mode, _) in files.items() if mode == 0o100755)]}
    (directory / 'products.json').write_text(json.dumps(products, indent=2) + '\n')
    audit_fixture(directory / 'image.iso', products['kernel.elf']['sha256'],
                  {name: row['sha256'] for name, row in products.items()
                   if name.startswith(('bin/', 'sbin/', 'lib/'))}, files['etc/net-test.sh'][1])
    return directory


def run(firmware, transport, timeout, fixture_directory):
    label = f'dns-{firmware}-{transport}'
    directory = fixture_directory / label
    directory.mkdir()
    log = directory / (label + '.log')
    packets = directory / (label + '-packets.json')
    observations = []
    inputs = json.loads((fixture_directory / 'source-inputs.json').read_text())
    selector = selectors.DefaultSelector()
    peers, servers = [Peer(lane) for lane in range(2)], []
    command = ['qemu-system-x86_64', '-machine', 'pc', '-cpu', 'max', '-m', '512M',
               '-cdrom', str(fixture_directory / 'image.iso'), '-nic', 'none', '-display', 'none',
               '-serial', 'stdio', '-monitor', 'none', '-no-reboot',
               '-device', 'isa-debug-exit,iobase=0xf4,iosize=0x04']
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
        command += ['-netdev', f'socket,id=peer{lane},connect=127.0.0.1:{server.getsockname()[1]}', '-device', nic]
        command += ['-object', f'filter-dump,id=capture{lane},netdev=peer{lane},file={directory}/lane{lane}.pcap']
    if firmware == 'uefi':
        variables = directory / 'OVMF_VARS.fd'
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
                for peer in peers:
                    peer.tick()
                    if peer.connection and peer.connection.fileno() in selector.get_map():
                        selector.modify(peer.connection, selectors.EVENT_READ |
                                        (selectors.EVENT_WRITE if peer.output else 0), ('peer', peer.lane))
                for key, events in selector.select(.005):
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
                            check(14 <= length <= 65553, 'QEMU Ethernet framing length')
                            if len(peer.input) < length + 4:
                                break
                            observe_frame(peer, bytes(peer.input[4:length + 4]), observations)
                            del peer.input[:length + 4]
                    if peer.output:
                        try:
                            sent = connection.send(peer.output)
                            del peer.output[:sent]
                        except BlockingIOError:
                            pass
                    selector.modify(connection, selectors.EVENT_READ |
                                    (selectors.EVENT_WRITE if peer.output else 0), ('peer', lane))
        except Exception as failure:
            error = str(failure)
        finally:
            if process.poll() is None:
                process.kill()
            status = process.wait()
            selector.close()
            for server in servers:
                server.close()
            for peer in peers:
                if peer.connection:
                    peer.connection.close()
    text = log.read_text(errors='replace')
    missing = []
    for linkage in ('static', 'dynamic'):
        actual = re.findall(r'^DNS_CASE_PASS linkage=' + linkage + r' case=(\S+) gai=-?\d+ addresses=\d+ elapsed_ms=\d+\r?$', text, re.M)
        if actual != list(CASES):
            missing.append(f'{linkage} exact seventeen-case inventory')
        for marker in (f'DNS_PARALLEL_PASS linkage={linkage} threads=8',
                       f'DNS_RECLAMATION_PASS linkage={linkage} cycles=128',
                       f'DNS_TESTS_PASS linkage={linkage} cases=17 threads=8 cycles=128'):
            if not re.search(r'^' + re.escape(marker) + r'\r?$', text, re.M):
                missing.append(marker)
    for marker in ('AXIOM64_TESTS_PASS', 'AXIOM64_EXIT status=0'):
        if not re.search(r'^' + re.escape(marker) + r'\r?$', text, re.M):
            missing.append(marker)
    evidence = []
    received_frames = 0
    if not error and not timed_out and status == 1 and not missing:
        try:
            evidence = [peer.validate() for peer in peers]
            received_frames = capture_audit(peers, text, directory)
        except Exception as failure:
            error = str(failure)
    unchanged = all(digest(ROOT / name) == expected for name, expected in inputs.items())
    captures = {path.name: dict(bytes=path.stat().st_size, sha256=digest(path))
                for path in directory.glob('lane*.pcap')}
    passed = unchanged and len(captures) == 2 and not timed_out and status == 1 and not error and not missing and bool(evidence) and not any(
        marker in text for marker in ('DNS_FAIL', 'PANIC:', 'FAULT pid='))
    packets.write_text(json.dumps({'peers': evidence or [dict(lane=peer.lane, queries=peer.queries,
        replies=peer.replies, frames=peer.frames) for peer in peers], 'received_frames': observations}, indent=2) + '\n')
    result = dict(firmware=firmware, transport=transport, returncode=status, timed_out=timed_out,
                  error=error, missing=missing, passed=passed, log=log.name, packets=packets.name,
                  actual_driver_frames=received_frames, received_frames=len(observations),
                  evidence_directory=str(directory.relative_to(ROOT)), captures=captures,
                  source_unchanged=unchanged, products_sha256=digest(fixture_directory / 'products.json'),
                  seconds=round(time.monotonic() - started, 3))
    (directory / 'result.json').write_text(json.dumps(result, indent=2) + '\n')
    for path in (log, packets):
        shutil.copyfile(path, ROOT / 'build' / path.name)
    print(json.dumps(result), flush=True)
    if not passed:
        print(text[-3000:], flush=True)
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--firmware', choices=('bios', 'uefi', 'both'), default='both')
    parser.add_argument('--transport', choices=('modern', 'legacy', 'both'), default='both')
    parser.add_argument('--timeout', type=float, default=30)
    args = parser.parse_args()
    check(args.timeout > 0, 'positive guest timeout')
    directory = fixture()
    results = []
    for firmware in ('bios', 'uefi') if args.firmware == 'both' else (args.firmware,):
        for transport in ('modern', 'legacy') if args.transport == 'both' else (args.transport,):
            result = run(firmware, transport, args.timeout, directory)
            results.append(result)
            (ROOT / 'build/dns-results.json').write_text(json.dumps(results, indent=2) + '\n')
            (directory / 'results.json').write_text(json.dumps(results, indent=2) + '\n')
            if not result['passed']:
                raise SystemExit('Actual musl DNS guest acceptance failed')


if __name__ == '__main__':
    main()
