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


def prepare(linkage, directory, suite='host', image_directory=None):
    program = 'ipv6-' + suite + '-' + linkage
    fixture(program=program, script='userspace/tests/net/ipv6_host.sh',
            environment={'AXIOM64_IPV6_PROGRAM': program},
            runtime_loader=loader('build') if linkage == 'dynamic' else None)
    image = (image_directory.resolve() if image_directory else ROOT / 'build') / f'axiom64-ipv6-{suite}-{linkage}.iso'
    command = [sys.executable, 'scripts/image.py', '--test', '--suite', 'network',
               '--output-name', image.name]
    if image_directory:
        command += ['--output-directory', str(image.parent)]
    subprocess.run(command, cwd=ROOT, check=True)
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
        'kernel/net/ethernet.cpp', 'kernel/io/io.cpp', 'kernel/include/io/vectors.hpp',
        'kernel/drivers/platform/devices.cpp', 'kernel/include/drivers/platform/devices.hpp',
        'kernel/net/netlink/socket.cpp',
        'kernel/net/netlink/addresses.cpp', 'kernel/net/netlink/inventory.cpp',
        'kernel/net/netlink/routes.cpp', 'kernel/net/netlink/ipv6.cpp',
        'kernel/include/net/netlink.hpp', 'kernel/include/net/ipv6.hpp', 'kernel/include/net/inet6.hpp',
        'kernel/fs/vfs.cpp', 'kernel/include/fs/vfs.hpp', 'kernel/ipc/ipc.cpp',
        'kernel/abi/linux/syscall.cpp', 'kernel/io/socket_timeout.cpp',
        'scripts/ipv6_host_peer.py', 'scripts/ipv6_host_test.py',
        'scripts/ipv6_host_capture.py', 'scripts/ipv6_sockets_peer.py', 'scripts/ipv6_sockets_capture.py',
        'scripts/ipv6_fragments_peer.py', 'scripts/ipv6_fragments_capture.py',
        'scripts/ipv6_output_peer.py', 'scripts/ipv6_output_capture.py', 'userspace/tests/net/ipv6_fixture.h',
        'scripts/ipv6_pmtu_peer.py', 'scripts/ipv6_pmtu_capture.py',
        'scripts/ipv6_errors_peer.py', 'scripts/ipv6_errors_capture.py',
        'scripts/ipv6_expiry_peer.py', 'scripts/ipv6_expiry_capture.py',
        'scripts/packet_observation.py', 'scripts/tcp_fault_native.py',
        'scripts/ipv6_controls_peer.py', 'scripts/ipv6_controls_capture.py',
        'scripts/ipv6_control_contract.py', 'scripts/ipv6_control_fault_contract.py',
        'scripts/ipv6_control_header_contract.py', 'scripts/ipv6_controls_contract_test.py',
        'scripts/ipv6_error_controls_contract.py', 'scripts/ipv6_error_controls_test.py',
        'scripts/ipv6_copy_model.py', 'userspace/tests/net/ipv6_copy_model.c',
        'scripts/ipv6_send_controls_contract.py', 'scripts/ipv6_send_controls_test.py',
        'scripts/ipv6_send_model.py', 'userspace/tests/net/ipv6_send_model.c',
        'scripts/ipv6_error_metadata_peer.py', 'scripts/ipv6_error_metadata_capture.py',
        'scripts/network_test.py', 'scripts/tcp_fault_test.py', 'scripts/image.py',
        'scripts/compile_uapi_client.py', 'scripts/tcp_fixture_inputs.py',
        'userspace/tests/net/ipv6_host.sh',
        *(path.relative_to(ROOT).as_posix() for base in ('kernel/net/ipv6', 'kernel/include/net/ipv6')
          for path in sorted((ROOT / base).rglob('*')) if path.is_file())]))
    names = [*products.values(), image, ROOT / 'build/axiom64.elf',
             ROOT / 'build' / (program + '.inputs.json')]
    inputs = dict(linkage=linkage, program=program, compile=manifest, image_audit=image_audit,
                  products={(path.relative_to(ROOT).as_posix() if path.is_relative_to(ROOT)
                             else str(path)): digest(path) for path in names},
                  sources={name: digest(ROOT / name) for name in sources})
    (directory / (linkage + '-inputs.json')).write_text(json.dumps(inputs, indent=2) + '\n')
    return image, inputs


def run(linkage, firmware, transport, image, inputs, directory, suite='host'):
    label = f'{linkage}-{firmware}-{transport}'
    output = directory / label
    output.mkdir(exist_ok=False)
    peer_type = Peer
    if suite == 'sockets':
        from ipv6_sockets_peer import Peer as SocketPeer
        peer_type = SocketPeer
    elif suite == 'fragments':
        from ipv6_fragments_peer import Peer as FragmentPeer
        peer_type = FragmentPeer
    elif suite == 'output':
        from ipv6_output_peer import Peer as OutputPeer
        peer_type = OutputPeer
    elif suite == 'pmtu':
        from ipv6_pmtu_peer import Peer as PmtuPeer
        peer_type = PmtuPeer
    elif suite == 'errors':
        from ipv6_errors_peer import Peer as ErrorPeer
        peer_type = ErrorPeer
    elif suite == 'expiry':
        from ipv6_expiry_peer import Peer as ExpiryPeer
        peer_type = ExpiryPeer
    elif suite == 'controls':
        from ipv6_controls_peer import Peer as ControlsPeer
        peer_type = ControlsPeer
    peers, servers, captures = [peer_type(lane) for lane in range(2)], [], []
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
        if suite in ('pmtu', 'errors'):
            from packet_observation import PcapObservation
            peers[lane].observe_input = PcapObservation(capture).watch
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
            text, reports, error, status = exercise(process, peers, servers,
                650 if suite == 'expiry' else 160 if suite == 'fragments' else 120 if suite in ('output', 'pmtu', 'errors') else 45, log)
    finally:
        for server in servers:
            server.close()
    markers = ['IPV6_HOST_PASS nics=2 phases_each=5 DAD=1 duplicate=1 permissions=1',
               'IPV6_HOST_ROUTES_PASS adapters=2 filtered=1',
               'AXIOM64_TESTS_PASS', 'AXIOM64_EXIT status=0', f'Firmware: {firmware.upper()}',
               f'virtio-net: index=1 transport={transport}', 'e1000: index=2 model=82540EM']
    markers += [f'IPV6_HOST_PHASE_PASS lane={lane} phase={phase}'
                for lane in range(2) for phase in range(6)]
    if suite == 'sockets':
        markers = ['IPV6_SOCKETS_PASS nics=2 raw=1 UDP=1 loopback=1 faults=2 permissions=1',
                   'AXIOM64_TESTS_PASS', 'AXIOM64_EXIT status=0', f'Firmware: {firmware.upper()}',
                   f'virtio-net: index=1 transport={transport}', 'e1000: index=2 model=82540EM']
        markers += [f'IPV6_SOCKETS_PHASE_PASS lane={lane} phase={phase}'
                    for lane in range(2) for phase in range(3)]
    elif suite == 'fragments':
        markers = ['IPV6_FRAGMENTS_PASS nics=2 cases_each=7 maximum=65527 expiry_seconds=60',
                   'AXIOM64_TESTS_PASS', 'AXIOM64_EXIT status=0', f'Firmware: {firmware.upper()}',
                   f'virtio-net: index=1 transport={transport}', 'e1000: index=2 model=82540EM']
    elif suite == 'output':
        markers = ['IPV6_OUTPUT_PASS adapters=2 cases=432 policies=9 scopes=2 copied_vectors=1 close_reuse=1',
                   'AXIOM64_TESTS_PASS', 'AXIOM64_EXIT status=0', f'Firmware: {firmware.upper()}',
                   f'virtio-net: index=1 transport={transport}', 'e1000: index=2 model=82540EM']
    elif suite == 'pmtu':
        markers = ['IPV6_PMTU_PASS adapters=2 cases=120 policies=6 malformed_each=10',
                   'AXIOM64_TESTS_PASS', 'AXIOM64_EXIT status=0', f'Firmware: {firmware.upper()}',
                   f'virtio-net: index=1 transport={transport}', 'e1000: index=2 model=82540EM']
    elif suite == 'errors':
        markers = ['IPV6_ERRORS_PASS adapters=2 wire=120 local=30 admission=96 options=26 lifetime=4 vectors=8',
                   'AXIOM64_TESTS_PASS', 'AXIOM64_EXIT status=0', f'Firmware: {firmware.upper()}',
                   f'virtio-net: index=1 transport={transport}', 'e1000: index=2 model=82540EM']
    elif suite == 'expiry':
        markers = ['IPV6_EXPIRY_PASS adapters=2 paths=32 stages=7 lifetime_seconds=600 lower_delay_seconds=20',
                   'AXIOM64_TESTS_PASS', 'AXIOM64_EXIT status=0', f'Firmware: {firmware.upper()}',
                   f'virtio-net: index=1 transport={transport}', 'e1000: index=2 model=82540EM']
    elif suite == 'controls':
        markers = ['IPV6_CONTROLS_PASS adapters=2 cases=160 variants=20 scopes=2 transports=2',
                   'AXIOM64_TESTS_PASS', 'AXIOM64_EXIT status=0', f'Firmware: {firmware.upper()}',
                   f'virtio-net: index=1 transport={transport}', 'e1000: index=2 model=82540EM']
    missing = [marker for marker in markers if marker not in text]
    unchanged = all(digest(ROOT / name) == expected for group in ('products', 'sources')
                    for name, expected in inputs[group].items())
    passed = not error and status == 1 and not missing and unchanged and all(peer.passed for peer in peers)
    audits = []
    if passed:
        try:
            if suite == 'sockets':
                from ipv6_sockets_capture import verify_capture
            elif suite == 'fragments':
                from ipv6_fragments_capture import verify_capture
            elif suite == 'output':
                from ipv6_output_capture import verify_capture
            elif suite == 'pmtu':
                from ipv6_pmtu_capture import verify_capture
            elif suite == 'errors':
                from ipv6_errors_capture import verify_capture
            elif suite == 'expiry':
                from ipv6_expiry_capture import verify_capture
            elif suite == 'controls':
                from ipv6_controls_capture import verify_capture
            else:
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
    parser.add_argument('--suite', choices=('host', 'sockets', 'fragments', 'output', 'pmtu', 'errors', 'expiry', 'controls'), default='host')
    parser.add_argument('--workers', type=int, choices=(1, 2, 4), default=2)
    parser.add_argument('--linkage', choices=('static', 'dynamic', 'both'), default='both')
    parser.add_argument('--firmware', choices=('bios', 'uefi', 'both'), default='both')
    parser.add_argument('--transport', choices=('modern', 'legacy', 'both'), default='both')
    parser.add_argument('--output-directory', type=Path, default=None)
    parser.add_argument('--image-directory', type=Path, default=None)
    args = parser.parse_args()
    args.output_directory = args.output_directory or ROOT / 'build' / ('ipv6-' + args.suite + '-wire')
    args.output_directory.mkdir(parents=True, exist_ok=True)
    choose = lambda value, choices: choices if value == 'both' else (value,)
    linkages = choose(args.linkage, ('static', 'dynamic'))
    prepared = {linkage: prepare(linkage, args.output_directory, args.suite, args.image_directory) for linkage in linkages}
    results = []
    profiles = [(linkage, firmware, transport) for linkage in linkages
                for firmware in choose(args.firmware, ('bios', 'uefi'))
                for transport in choose(args.transport, ('modern', 'legacy'))]
    with ThreadPoolExecutor(max_workers=args.workers) as pool:
        pending = [pool.submit(run, *profile, *prepared[profile[0]], args.output_directory, args.suite)
                   for profile in profiles]
        for future in as_completed(pending):
            results.append(future.result())
            (args.output_directory / 'results.json').write_text(json.dumps(results, indent=2) + '\n')
    return 0 if len(results) == len(profiles) and all(row['passed'] for row in results) else 1


if __name__ == '__main__':
    sys.exit(main())
