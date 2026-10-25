# SPDX-License-Identifier: GPL-3.0-or-later
"""Run actual libc UDP-to-TCP DNS fallback over both guest Ethernet drivers."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import shutil
import socket
import subprocess
import tempfile
import time
from fetch import ROOT, LOCK
from build_musl import loader, ensure
from dns_tcp_peer import Peer, check
from tcp_fault_test import exercise
from dns_observer import audit as audit_dns_observer


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def fixture(linkage):
    subprocess.run(['make', '-s', '-j2', 'build/axiom64.elf', 'build/init',
                    f'build/dns-tcp-{linkage}', 'busybox'], cwd=ROOT, check=True)
    retained = ROOT / 'build/dns-tcp-inputs'
    retained.mkdir(exist_ok=True)
    directory = Path(tempfile.mkdtemp(prefix=linkage + '-', dir=retained))
    interpreter = directory / 'ld-musl-x86_64.so.1'
    shutil.copyfile(loader('runtime'), interpreter)
    files = {name: (0o40755, b'') for name in
             ('bin', 'sbin', 'lib', 'etc', 'dev', 'proc', 'sys', 'tmp', 'run')}
    inputs = [('sbin/init', ROOT / 'build/init'),
              ('bin/dns-tcp', ROOT / f'build/dns-tcp-{linkage}'),
              ('bin/busybox', ROOT / 'build' / f"busybox-{LOCK['busybox']['version']}" / 'busybox'),
              ('lib/ld-musl-x86_64.so.1', interpreter)]
    for name, path in inputs:
        files[name] = (0o100755, path.read_bytes())
    files['etc/net-test.sh'] = (0o100755, b'#!/bin/sh\nset -e\n/bin/dns-tcp\necho AXIOM64_TESTS_PASS\n')
    files['etc/resolv.conf'] = (0o100644, b'nameserver 10.23.1.1\n')
    files['etc/hosts'] = (0o100644, b'127.0.0.1 localhost\n')
    with (ROOT / 'build/rootfs-network.cpio').open('wb') as output:
        for inode, (name, (mode, data)) in enumerate([*sorted(files.items()), ('TRAILER!!!', (0, b''))], 1):
            encoded = name.encode() + b'\0'
            fields = [inode, mode, 0, 0, 1, 0, len(data), 0, 0, 0, 0, len(encoded), 0]
            output.write(b'070701' + b''.join(f'{value:08x}'.encode() for value in fields) + encoded)
            output.write(bytes(-output.tell() % 4))
            output.write(data)
            output.write(bytes(-output.tell() % 4))
    image = ROOT / f'build/axiom64-dns-tcp-{linkage}.iso'
    subprocess.run(['python3', 'scripts/image.py', '--test', '--suite', 'network',
                    '--output-name', image.name], cwd=ROOT, check=True, stdout=subprocess.DEVNULL)
    inputs += [('kernel', ROOT / 'build/axiom64.elf'), ('image', image)]
    provenance = dict(inputs={name: dict(path=str(path.relative_to(ROOT)), sha256=digest(path))
                             for name, path in inputs},
                      providers={provider: json.loads((ensure(provider) / 'manifest.json').read_text())
                                 for provider in ('build', 'runtime')})
    (ROOT / f'build/dns-tcp-{linkage}-inputs.json').write_text(json.dumps(provenance, indent=2) + '\n')
    return image


def capture_audit(peers, text, linkage, captures):
    return audit_dns_observer(peers, text, captures, (linkage,))


def run(linkage, firmware, transport, image, timeout):
    label = f'dns-tcp-{linkage}-{firmware}-{transport}'
    log_path, peer_path = (ROOT / 'build' / (label + suffix) for suffix in ('.log', '-peer.json'))
    peers, servers, captures = [Peer(lane) for lane in range(2)], [], []
    command = ['qemu-system-x86_64', '-machine', 'pc', '-cpu', 'max', '-m', '512M', '-nic', 'none',
               '-cdrom', str(image), '-display', 'none', '-serial', 'stdio', '-monitor', 'none',
               '-no-reboot', '-device', 'isa-debug-exit,iobase=0xf4,iosize=0x04']
    started = time.monotonic()
    with tempfile.TemporaryDirectory(prefix='axiom64-dns-tcp-packets-') as capture_workspace:
        for lane, model in enumerate(('virtio-net-pci', 'e1000')):
            server = socket.socket()
            server.bind(('127.0.0.1', 0))
            server.listen(1)
            servers.append(server)
            nic = f'{model},netdev=peer{lane},addr={lane + 4:x},mac={peers[lane].guest.hex(":")}'
            if lane == 0:
                nic += ',disable-legacy=on' if transport == 'modern' else ',disable-modern=on'
            capture = ROOT / 'build' / f'{label}-lane{lane}.pcap'
            captures.append(capture)
            command += ['-netdev', f'socket,id=peer{lane},connect=127.0.0.1:{server.getsockname()[1]}',
                        '-device', nic, '-object',
                        f'filter-dump,id=capture{lane},netdev=peer{lane},file={Path(capture_workspace) / capture.name}']
        if firmware == 'uefi':
            variables = ROOT / 'build' / f'{label}-OVMF_VARS.fd'
            shutil.copyfile('/usr/share/OVMF/OVMF_VARS_4M.fd', variables)
            command += ['-drive', 'if=pflash,format=raw,readonly=on,file=/usr/share/OVMF/OVMF_CODE_4M.fd',
                        '-drive', f'if=pflash,format=raw,file={variables}']
        try:
            with log_path.open('wb') as log:
                process = subprocess.Popen(command, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                           stderr=subprocess.STDOUT)
                text, evidence, error, status = exercise(process, peers, servers, timeout, log)
        finally:
            for server in servers:
                server.close()
            for capture in captures:
                actual = Path(capture_workspace) / capture.name
                if actual.is_file():
                    shutil.copyfile(actual, capture)
    peer_path.write_text(json.dumps(evidence or [dict(lane=peer.lane, frames=peer.frames,
        transactions=peer.transactions, flows=[dict(case=flow.case, port=flow.port,
        sent=flow.sent.hex(), received=flow.received.hex(), events=flow.events,
        guest_fin=flow.guest_fin, reset=flow.reset, fin_acked=flow.fin_acked) for flow in peer.flows])
        for peer in peers], indent=2) + '\n')
    required = [f'DNS_TCP_CONFIG_PASS linkage={linkage} nics=2',
                *(f'DNS_TCP_LANE_PASS linkage={linkage} lane={lane} cases=21' for lane in range(2)),
                f'DNS_TCP_PARALLEL_PASS linkage={linkage} threads=8',
                f'DNS_TCP_RECLAMATION_PASS linkage={linkage} cycles=128',
                f'DNS_TCP_TESTS_PASS linkage={linkage} cases=43 threads=8 cycles=128',
                'AXIOM64_TESTS_PASS', 'AXIOM64_EXIT status=0', f'Firmware: {firmware.upper()}',
                f'virtio-net: index=1 transport={transport}', 'e1000: index=2 model=82540EM']
    missing = [marker for marker in required if not re.search('^' + re.escape(marker) + '\r?$', text, re.M)]
    # The driver discovery lines carry additional model fields.
    missing = [marker for marker in missing if marker not in text or not marker.startswith(('virtio-net:', 'e1000:'))]
    receipts = 0
    if not error and not missing and status == 1:
        try:
            receipts = capture_audit(peers, text, linkage, captures)
        except Exception as failure:
            error = str(failure)
    result = dict(linkage=linkage, firmware=firmware, transport=transport, returncode=status,
                  error=error, missing=missing, peer=peer_path.name, log=log_path.name,
                  captures=[path.name for path in captures], inputs=f'dns-tcp-{linkage}-inputs.json',
                  actual_driver_frames=receipts, seconds=round(time.monotonic() - started, 3),
                  passed=not error and not missing and status == 1 and receipts > 0 and
                  not any(marker in text for marker in ('DNS_FAIL', 'PANIC:', 'FAULT pid=')))
    print(json.dumps(result), flush=True)
    if not result['passed']:
        print(text[-5000:], flush=True)
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name, choices in (('linkage', ('static', 'dynamic')), ('firmware', ('bios', 'uefi')),
                          ('transport', ('modern', 'legacy'))):
        parser.add_argument('--' + name, choices=(*choices, 'both'), default='both')
    parser.add_argument('--timeout', type=float, default=60)
    args = parser.parse_args()
    check(args.timeout > 0, 'positive guest deadline')
    original = ROOT / 'build/rootfs-network.cpio'
    previous = original.read_bytes() if original.exists() else None
    results = []
    try:
        for linkage in ('static', 'dynamic') if args.linkage == 'both' else (args.linkage,):
            image = fixture(linkage)
            for firmware in ('bios', 'uefi') if args.firmware == 'both' else (args.firmware,):
                for transport in ('modern', 'legacy') if args.transport == 'both' else (args.transport,):
                    results.append(run(linkage, firmware, transport, image, args.timeout))
                    (ROOT / 'build/dns-tcp-results.json').write_text(json.dumps(results, indent=2) + '\n')
                    if not results[-1]['passed']:
                        raise SystemExit('Actual libc DNS TCP fallback guest acceptance failed')
    finally:
        if previous is not None:
            original.write_bytes(previous)
        else:
            original.unlink(missing_ok=True)


if __name__ == '__main__':
    main()
