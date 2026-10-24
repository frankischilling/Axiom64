# SPDX-License-Identifier: GPL-3.0-or-later
"""Run the actual gateway client across both linkages, firmware and NIC transports."""
import argparse
from concurrent.futures import ThreadPoolExecutor, as_completed
import hashlib
import json
from pathlib import Path
import shutil
import socket
import subprocess
import sys
import time
from build_musl import loader
from compile_uapi_client import audit_compile
from fetch import ROOT, LOCK
from ipv4_gateways import GatewayPeer
from network_test import fixture
from tcp_fault_test import exercise
from tcp_fixture_inputs import audit_fixture
from tcp_icmp_inputs import IPV4_MODULES


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


class FramedPeer(GatewayPeer):
    def __init__(self, lane):
        super().__init__(lane)
        self.outgoing = []
        self.output = bytearray()

    def receive(self, frame):
        self.outgoing.extend(super().receive(frame) or [])

    def result(self):
        return self.report()


def prepare(linkage):
    program = 'ipv4-tests' if linkage == 'static' else 'ipv4-dynamic'
    fixture(program=program, script='userspace/tests/net/ipv4_gateways.sh',
            environment={'AXIOM64_IPV4_PROGRAM': program},
            runtime_loader=loader('build') if linkage == 'dynamic' else None)
    image = ROOT / 'build' / f'axiom64-ipv4-gateway-{linkage}.iso'
    subprocess.run([sys.executable, 'scripts/image.py', '--test', '--suite', 'network',
                    '--output-name', image.name], cwd=ROOT, check=True)
    manifest = audit_compile(ROOT / 'build' / program, ROOT)
    if ('-static' in manifest['command']) != (linkage == 'static'):
        raise ValueError('gateway compile manifest has the wrong linkage')
    products = {'sbin/init': ROOT / 'build/init', f'bin/{program}': ROOT / 'build' / program,
                'bin/busybox': ROOT / 'build' / f'busybox-{LOCK["busybox"]["version"]}/busybox'}
    if linkage == 'dynamic':
        products['lib/ld-musl-x86_64.so.1'] = loader('build')
    script = (f'export AXIOM64_IPV4_PROGRAM={program}\n'.encode() +
              (ROOT / 'userspace/tests/net/ipv4_gateways.sh').read_bytes())
    image_audit = audit_fixture(image, digest(ROOT / 'build/axiom64.elf'),
                               {name: digest(path) for name, path in products.items()}, script)
    names = [*products.values(), ROOT / 'build/axiom64.elf', image,
             ROOT / 'build' / (program + '.inputs.json')]
    sources = tuple(dict.fromkeys((*manifest['sources'], *IPV4_MODULES,
        'kernel/net/ipv4/core.cpp', 'kernel/net/ipv4/socket.cpp', 'scripts/ipv4_gateway_test.py',
        'kernel/io/io.cpp', 'kernel/net/udp/core.cpp', 'kernel/include/net/udp.hpp',
        'scripts/ipv4_gateways.py', 'scripts/ipv4_gateway_capture.py', 'scripts/ipv4_expiry_capture.py',
        'scripts/ipv4_unconfigured.py', 'scripts/ipv4_unconfigured_capture.py',
        'scripts/ipv4_retained.py', 'scripts/ipv4_retained_capture.py',
        'scripts/compile_uapi_client.py', 'scripts/network_test.py', 'scripts/tcp_fixture_inputs.py',
        'scripts/tcp_fault_test.py', 'scripts/image.py', 'userspace/tests/net/ipv4_gateways.sh', 'Makefile')))
    inputs = dict(linkage=linkage, program=program, compile=manifest, image_audit=image_audit,
                  products={path.relative_to(ROOT).as_posix(): digest(path) for path in names},
                  sources={name: digest(ROOT / name) for name in sources})
    (ROOT / 'build' / f'ipv4-gateway-{linkage}-inputs.json').write_text(json.dumps(inputs, indent=2) + '\n')
    return image, inputs


def run(linkage, firmware, transport, image, inputs):
    label = f'ipv4-gateway-{linkage}-{firmware}-{transport}'
    log = ROOT / 'build' / (label + '.log')
    peers = [FramedPeer(lane) for lane in range(2)]
    servers, captures = [], []
    command = ['qemu-system-x86_64', '-machine', 'pc', '-cpu', 'max', '-m', '2G',
               '-cdrom', str(image), '-nic', 'none', '-display', 'none', '-serial', 'stdio',
               '-monitor', 'none', '-no-reboot', '-device', 'isa-debug-exit,iobase=0xf4,iosize=0x04']
    for lane in range(2):
        server = socket.socket()
        server.bind(('127.0.0.1', 0))
        server.listen(1)
        servers.append(server)
        command += ['-netdev', f'socket,id=peer{lane},connect=127.0.0.1:{server.getsockname()[1]}']
        device = (f'virtio-net-pci,disable-legacy=on' if transport == 'modern' else
                  'virtio-net-pci,disable-modern=on') if lane == 0 else 'e1000'
        command += ['-device', f'{device},netdev=peer{lane},addr={lane + 4:x},'
                    f'mac={peers[lane].guest.hex(":")}']
        capture = ROOT / 'build' / f'{label}-lane{lane}.pcap'
        captures.append(capture)
        command += ['-object', f'filter-dump,id=cap{lane},netdev=peer{lane},file={capture}']
    if firmware == 'uefi':
        variables = ROOT / 'build' / (label + '-OVMF_VARS.fd')
        shutil.copyfile('/usr/share/OVMF/OVMF_VARS_4M.fd', variables)
        command += ['-drive', 'if=pflash,format=raw,readonly=on,file=/usr/share/OVMF/OVMF_CODE_4M.fd',
                    '-drive', f'if=pflash,format=raw,file={variables}']
    started = time.monotonic()
    try:
        with log.open('wb') as output:
            process = subprocess.Popen(command, cwd=ROOT, stdout=subprocess.PIPE,
                                       stderr=subprocess.STDOUT, stdin=subprocess.DEVNULL)
            text, results, error, status = exercise(process, peers, servers, 30, output)
    finally:
        for server in servers:
            server.close()
    required = ['IPV4_GATEWAY_PASS index=1 protocols=2 datagrams=12',
                'IPV4_GATEWAY_PASS index=2 protocols=2 datagrams=12',
                'IPV4_UNCONFIGURED_PASS index=1 protocols=2 datagrams=14',
                'IPV4_UNCONFIGURED_PASS index=2 protocols=2 datagrams=14', 'AXIOM64_TESTS_PASS',
                'AXIOM64_EXIT status=0', f'Firmware: {firmware.upper()}',
                f'virtio-net: index=1 transport={transport}', 'e1000: index=2 model=82540EM']
    missing = [marker for marker in required if marker not in text]
    unchanged = all(digest(ROOT / name) == sha for group in ('products', 'sources')
                    for name, sha in inputs[group].items())
    passed = not error and not missing and status == 1 and unchanged and all(peer.passed for peer in peers)
    audits = []
    if passed:
        try:
            from ipv4_gateway_capture import verify_capture
            from ipv4_unconfigured_capture import verify_capture as verify_unconfigured
            for lane, path in enumerate(captures):
                archive = ROOT / 'build' / f'{label}-lane{lane}-damaged-{time.monotonic_ns()}.zip'
                audits.append(verify_capture(path, lane, log, archive))
                unconfigured_archive = ROOT / 'build' / f'{label}-lane{lane}-unconfigured-damaged-{time.monotonic_ns()}.zip'
                audits.append(verify_unconfigured(path, lane, log, unconfigured_archive))
        except Exception as failure:
            error = 'gateway capture audit: ' + str(failure)
            passed = False
    result = dict(passed=passed, linkage=linkage, firmware=firmware, transport=transport,
                  returncode=status, error=error, missing=missing, products_unchanged=unchanged,
                  peers=results, captures=[p.name for p in captures], log=log.name,
                  capture_audits=audits, products=inputs['products'],
                  inputs=f'ipv4-gateway-{linkage}-inputs.json', command=command,
                  seconds=time.monotonic() - started)
    print(json.dumps({key: value for key, value in result.items()
                      if key not in ('peers', 'command', 'products')}), flush=True)
    return result


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--workers', type=int, choices=(1, 2, 4), default=2)
    parser.add_argument('--linkage', choices=('static', 'dynamic', 'both'), default='both')
    parser.add_argument('--firmware', choices=('bios', 'uefi', 'both'), default='both')
    parser.add_argument('--transport', choices=('modern', 'legacy', 'both'), default='both')
    args = parser.parse_args()
    destination = ROOT / 'build/ipv4-gateway-results.json'
    destination.write_text('[]\n')
    selected = lambda value, choices: choices if value == 'both' else (value,)
    linkages = selected(args.linkage, ('static', 'dynamic'))
    prepared = {linkage: prepare(linkage) for linkage in linkages}
    results = []
    profiles = [(linkage, firmware, transport) for linkage in linkages
                for firmware in selected(args.firmware, ('bios', 'uefi'))
                for transport in selected(args.transport, ('modern', 'legacy'))]
    with ThreadPoolExecutor(max_workers=args.workers) as pool:
        pending = {pool.submit(run, *profile, *prepared[profile[0]]): profile for profile in profiles}
        for future in as_completed(pending):
            try:
                results.append(future.result())
            except Exception as failure:
                linkage, firmware, transport = pending[future]
                results.append(dict(passed=False, linkage=linkage, firmware=firmware, transport=transport,
                                    error=f'{type(failure).__name__}: {failure}'))
            destination.write_text(json.dumps(results, indent=2) + '\n')
    if len(results) != len(profiles) or not all(row['passed'] for row in results):
        raise SystemExit('Gateway guest profiles failed; original evidence is retained.')


if __name__ == '__main__':
    main()
