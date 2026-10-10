# SPDX-License-Identifier: GPL-3.0-or-later
"""Run real musl DNS through both Ethernet drivers on BIOS and UEFI."""
import argparse
from collections import Counter
import json
from pathlib import Path
import re
import selectors
import shutil
import socket
import subprocess
import time
from fetch import ROOT, LOCK
from dns_peer import Peer, check

CASES = ('numeric', 'hosts', 'wire-lane0', 'wire-lane1', 'cname', 'search', 'search-bare',
         'absolute', 'ndots', 'nxdomain', 'nodata', 'reply-filter', 'retry', 'timeout',
         'refused', 'servfail', 'parallel-nameservers')


def capture_audit(peers, text):
    receipts = re.findall(r'^DNS_FRAME linkage=(static|dynamic) index=(\d+) length=(\d+) '
                          r'hash=([0-9a-f]{16}) packet_type=(\d+) monotonic_ms=(\d+)\r?$', text, re.M)
    actual = Counter((int(index), int(length), digest, int(kind))
                     for _, index, length, digest, kind, _ in receipts)
    expected = Counter()
    for peer in peers:
        for row in peer.frames:
            frame = bytes.fromhex(row['frame'])
            if frame[12:14] != b'\x08\x00':
                continue
            value = 0xcbf29ce484222325
            for byte in frame:
                value = (value ^ byte) * 0x100000001b3 & 0xffffffffffffffff
            expected[(peer.lane + 1, len(frame), f'{value:016x}', 4 if row['direction'] == 'query' else 0)] += 1
    check(actual == expected and bool(actual), 'exact actual driver receipts match every host DNS query/reply frame')
    captures = re.findall(r'^DNS_CAPTURE_PASS linkage=(static|dynamic) index=(\d+) '
                          r'packets=(\d+) dropped=(\d+)\r?$', text, re.M)
    check(len(captures) == 4 and {(linkage, int(index)) for linkage, index, _, _ in captures} ==
          {(linkage, index) for linkage in ('static', 'dynamic') for index in (1, 2)},
          'both actual capture sockets in both linkages')
    for linkage, index, count, dropped in captures:
        check(int(dropped) == 0 and int(count) == sum(1 for row in receipts if row[:2] == (linkage, index)),
              'complete capture with no dropped observer frames')
        clocks = [int(row[-1]) for row in receipts if row[:2] == (linkage, index)]
        check(clocks == sorted(clocks), 'actual driver receipt clocks are monotonic')
    return len(receipts)


def fixture():
    subprocess.run(['make', '-s', '-j2', 'build/axiom64.elf', 'build/init', 'build/dns-static',
                    'build/dns-dynamic', 'busybox'], cwd=ROOT, check=True)
    expected = json.loads((ROOT / 'sources.lock.json').read_text())['build_musl']['version']
    version = subprocess.check_output(['dpkg-query', '-W', '-f=${Version}', 'musl-dev'], text=True)
    check(version == expected, 'DNS fixture uses the pinned musl build')
    files = {name: (0o40755, b'') for name in
             ['bin', 'sbin', 'lib', 'etc', 'dev', 'proc', 'sys', 'tmp', 'run', 'root']}
    for name, source in [('sbin/init', ROOT / 'build/init'),
                         ('bin/dns-static', ROOT / 'build/dns-static'),
                         ('bin/dns-dynamic', ROOT / 'build/dns-dynamic'),
                         ('bin/busybox', ROOT / 'build' / f"busybox-{LOCK['busybox']['version']}" / 'busybox'),
                         ('lib/ld-musl-x86_64.so.1', Path('/lib/ld-musl-x86_64.so.1').resolve()),
                         ('etc/net-test.sh', ROOT / 'userspace/tests/net/dns.sh')]:
        files[name] = (0o100755, source.read_bytes())
    files['etc/hosts'] = (0o100644, b'10.23.1.100 local-host.fixture\n')
    files['etc/resolv.conf'] = (0o100644, b'nameserver 10.23.1.1\n')
    with (ROOT / 'build/rootfs-network.cpio').open('wb') as output:
        for inode, (name, (mode, data)) in enumerate([*sorted(files.items()), ('TRAILER!!!', (0, b''))], 1):
            encoded = name.encode() + b'\0'
            values = [inode, mode, 0, 0, 1, 0, len(data), 0, 0, 0, 0, len(encoded), 0]
            output.write(b'070701' + b''.join(f'{value:08x}'.encode() for value in values) + encoded)
            output.write(bytes(-output.tell() % 4))
            output.write(data)
            output.write(bytes(-output.tell() % 4))
    subprocess.run(['python3', 'scripts/image.py', '--test', '--suite', 'network',
                    '--output-name', 'axiom64-dns.iso'], cwd=ROOT, check=True,
                   stdout=subprocess.DEVNULL)


def run(firmware, transport, timeout):
    label = f'dns-{firmware}-{transport}'
    log = ROOT / 'build' / (label + '.log')
    packets = ROOT / 'build' / (label + '-packets.json')
    selector = selectors.DefaultSelector()
    peers, servers = [Peer(lane) for lane in range(2)], []
    command = ['qemu-system-x86_64', '-machine', 'pc', '-cpu', 'max', '-m', '512M',
               '-cdrom', str(ROOT / 'build/axiom64-dns.iso'), '-nic', 'none', '-display', 'none',
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
                            peer.packet(bytes(peer.input[4:length + 4]))
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
            received_frames = capture_audit(peers, text)
        except Exception as failure:
            error = str(failure)
    passed = not timed_out and status == 1 and not error and not missing and bool(evidence) and not any(
        marker in text for marker in ('DNS_FAIL', 'PANIC:', 'FAULT pid='))
    packets.write_text(json.dumps({'peers': evidence or [dict(lane=peer.lane, queries=peer.queries,
        replies=peer.replies, frames=peer.frames) for peer in peers]}, indent=2) + '\n')
    result = dict(firmware=firmware, transport=transport, returncode=status, timed_out=timed_out,
                  error=error, missing=missing, passed=passed, log=log.name, packets=packets.name,
                  actual_driver_frames=received_frames,
                  seconds=round(time.monotonic() - started, 3))
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
    fixture()
    results = []
    for firmware in ('bios', 'uefi') if args.firmware == 'both' else (args.firmware,):
        for transport in ('modern', 'legacy') if args.transport == 'both' else (args.transport,):
            result = run(firmware, transport, args.timeout)
            results.append(result)
            (ROOT / 'build/dns-results.json').write_text(json.dumps(results, indent=2) + '\n')
            if not result['passed']:
                raise SystemExit('Actual musl DNS guest acceptance failed')


if __name__ == '__main__':
    main()
