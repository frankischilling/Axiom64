# SPDX-License-Identifier: GPL-3.0-or-later
"""Exercise IPv6 host control and real Ethernet responses in the guest."""
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
from ipv6_host_peer import Peer
from network_test import fixture
from tcp_fault_test import exercise
from tcp_fixture_inputs import audit_fixture


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def prepare(linkage, directory):
    program = 'ipv6-host-' + linkage
    fixture(program=program, script='userspace/tests/net/ipv6_host.sh',
            environment={'AXIOM64_IPV6_PROGRAM': program},
            runtime_loader=loader('build') if linkage == 'dynamic' else None)
    image = ROOT / 'build' / f'axiom64-ipv6-host-{linkage}.iso'
    subprocess.run([sys.executable, 'scripts/image.py', '--test', '--suite', 'network',
                    '--output-name', image.name], cwd=ROOT, check=True)
    manifest = audit_compile(ROOT / 'build' / program, ROOT)
    if ('-static' in manifest['command']) != (linkage == 'static'):
        raise ValueError('IPv6 host client has the wrong linkage')
    products = {'sbin/init': ROOT / 'build/init', 'bin/' + program: ROOT / 'build' / program,
                'bin/busybox': ROOT / 'build' / f'busybox-{LOCK["busybox"]["version"]}/busybox'}
    if linkage == 'dynamic':
        products['lib/ld-musl-x86_64.so.1'] = loader('build')
    script = (f'export AXIOM64_IPV6_PROGRAM={program}\n'.encode() +
              (ROOT / 'userspace/tests/net/ipv6_host.sh').read_bytes())
    image_audit = audit_fixture(image, digest(ROOT / 'build/axiom64.elf'),
                               {name: digest(path) for name, path in products.items()}, script)
    sources = list(dict.fromkeys([*manifest['sources'], 'Makefile',
        'kernel/net/ethernet.cpp', 'kernel/io/io.cpp', 'kernel/net/netlink/socket.cpp',
        'kernel/net/netlink/addresses.cpp', 'kernel/net/netlink/inventory.cpp',
        'kernel/net/netlink/routes.cpp', 'kernel/net/netlink/ipv6.cpp',
        'kernel/include/net/netlink.hpp', 'kernel/include/net/ipv6.hpp',
        'scripts/ipv6_host_peer.py', 'scripts/ipv6_host_test.py',
        'scripts/ipv6_host_capture.py',
        'scripts/network_test.py', 'scripts/tcp_fault_test.py', 'scripts/image.py',
        'scripts/compile_uapi_client.py', 'scripts/tcp_fixture_inputs.py',
        'userspace/tests/net/ipv6_host.sh',
        *(path.relative_to(ROOT).as_posix() for base in ('kernel/net/ipv6', 'kernel/include/net/ipv6')
          for path in sorted((ROOT / base).glob('*')) if path.is_file())]))
    names = [*products.values(), image, ROOT / 'build/axiom64.elf',
             ROOT / 'build' / (program + '.inputs.json')]
    inputs = dict(linkage=linkage, program=program, compile=manifest, image_audit=image_audit,
                  products={path.relative_to(ROOT).as_posix(): digest(path) for path in names},
                  sources={name: digest(ROOT / name) for name in sources})
    (directory / (linkage + '-inputs.json')).write_text(json.dumps(inputs, indent=2) + '\n')
    return image, inputs


def run(linkage, firmware, transport, image, inputs, directory):
    label = f'{linkage}-{firmware}-{transport}'
    output = directory / label
    output.mkdir(exist_ok=False)
    peers, servers, captures = [Peer(lane) for lane in range(2)], [], []
    command = ['qemu-system-x86_64', '-machine', 'pc', '-cpu', 'max', '-m', '2G',
               '-cdrom', str(image), '-nic', 'none', '-display', 'none', '-serial', 'stdio',
               '-monitor', 'none', '-no-reboot', '-device', 'isa-debug-exit,iobase=0xf4,iosize=0x04']
    for lane in range(2):
        server = socket.socket()
        server.bind(('127.0.0.1', 0))
        server.listen(1)
        servers.append(server)
        command += ['-netdev', f'socket,id=peer{lane},connect=127.0.0.1:{server.getsockname()[1]}']
        device = ('virtio-net-pci,disable-legacy=on' if transport == 'modern' else
                  'virtio-net-pci,disable-modern=on') if lane == 0 else 'e1000'
        command += ['-device', f'{device},netdev=peer{lane},addr={lane + 4:x},'
                    f'mac={peers[lane].guest.hex(":")}']
        capture = output / f'lane{lane}.pcap'
        captures.append(capture)
        command += ['-object', f'filter-dump,id=cap{lane},netdev=peer{lane},file={capture}']
    if firmware == 'uefi':
        variables = output / 'OVMF_VARS.fd'
        shutil.copyfile('/usr/share/OVMF/OVMF_VARS_4M.fd', variables)
        command += ['-drive', 'if=pflash,format=raw,readonly=on,file=/usr/share/OVMF/OVMF_CODE_4M.fd',
                    '-drive', f'if=pflash,format=raw,file={variables}']
    began = time.monotonic()
    try:
        with (output / 'guest.log').open('wb') as log:
            process = subprocess.Popen(command, cwd=ROOT, stdout=subprocess.PIPE,
                                       stderr=subprocess.STDOUT, stdin=subprocess.DEVNULL)
            text, reports, error, status = exercise(process, peers, servers, 45, log)
    finally:
        for server in servers:
            server.close()
    markers = ['IPV6_HOST_PASS nics=2 phases_each=5 DAD=1 duplicate=1 permissions=1',
               'IPV6_HOST_ROUTES_PASS adapters=2 filtered=1',
               'AXIOM64_TESTS_PASS', 'AXIOM64_EXIT status=0', f'Firmware: {firmware.upper()}',
               f'virtio-net: index=1 transport={transport}', 'e1000: index=2 model=82540EM']
    markers += [f'IPV6_HOST_PHASE_PASS lane={lane} phase={phase}'
                for lane in range(2) for phase in range(6)]
    missing = [marker for marker in markers if marker not in text]
    unchanged = all(digest(ROOT / name) == expected for group in ('products', 'sources')
                    for name, expected in inputs[group].items())
    passed = not error and status == 1 and not missing and unchanged and all(peer.passed for peer in peers)
    audits = []
    if passed:
        try:
            from ipv6_host_capture import verify_capture
            for lane, path in enumerate(captures):
                audits.append(verify_capture(path, lane, output / 'guest.log',
                                             output / f'lane{lane}-damaged.zip'))
        except Exception as failure:
            error, passed = 'independent IPv6 capture: ' + str(failure), False
    result = dict(passed=passed, linkage=linkage, firmware=firmware, transport=transport,
                  seconds=time.monotonic() - began, returncode=status, error=error,
                  missing=missing, products_sources_unchanged=unchanged, peers=reports,
                  capture_audits=audits,
                  command=command, captures=[str(path) for path in captures])
    (output / 'result.json').write_text(json.dumps(result, indent=2) + '\n')
    print(json.dumps({key: value for key, value in result.items()
                      if key not in ('peers', 'command', 'captures')}), flush=True)
    return result


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--workers', type=int, choices=(1, 2, 4), default=2)
    parser.add_argument('--linkage', choices=('static', 'dynamic', 'both'), default='both')
    parser.add_argument('--firmware', choices=('bios', 'uefi', 'both'), default='both')
    parser.add_argument('--transport', choices=('modern', 'legacy', 'both'), default='both')
    parser.add_argument('--output-directory', type=Path, default=ROOT / 'build/ipv6-host-wire')
    args = parser.parse_args()
    args.output_directory.mkdir(parents=True, exist_ok=True)
    choose = lambda value, choices: choices if value == 'both' else (value,)
    linkages = choose(args.linkage, ('static', 'dynamic'))
    prepared = {linkage: prepare(linkage, args.output_directory) for linkage in linkages}
    results = []
    profiles = [(linkage, firmware, transport) for linkage in linkages
                for firmware in choose(args.firmware, ('bios', 'uefi'))
                for transport in choose(args.transport, ('modern', 'legacy'))]
    with ThreadPoolExecutor(max_workers=args.workers) as pool:
        pending = [pool.submit(run, *profile, *prepared[profile[0]], args.output_directory)
                   for profile in profiles]
        for future in as_completed(pending):
            results.append(future.result())
            (args.output_directory / 'results.json').write_text(json.dumps(results, indent=2) + '\n')
    return 0 if len(results) == len(profiles) and all(row['passed'] for row in results) else 1


if __name__ == '__main__':
    sys.exit(main())
