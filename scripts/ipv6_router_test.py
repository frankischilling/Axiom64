# SPDX-License-Identifier: GPL-3.0-or-later
"""Compare controlled IPv6 router discovery on native Linux and real guest NICs."""
import argparse
from concurrent.futures import ThreadPoolExecutor, as_completed
import json
import os
from pathlib import Path
import platform
import shutil
import socket
import subprocess
import sys

from account_store_guest import fixture
from build_musl import loader
from compile_uapi_client import audit_compile, sources
from fetch import ROOT
from ipv6_configuration_test import adapter_model, guest_identity
from ipv6_router_capture import inspect
from ipv6_router_peer import Peer
from tcp_fault_native import Capture
from tcp_fault_test import exercise
from tcp_fixture_inputs import audit_fixture, digest

SOURCE = 'userspace/tests/net/ipv6_router.c'
MARKER = 'IPV6_ROUTER_PASS adapters=2 invalid_each=8 mac_policy_each=1 flags=4 finite_seconds=8 protection_seconds=7200 replacement_each=6 retransmit_milliseconds=2000,3000'


def build(profile, directory):
    program = directory / ('ipv6-router-' + profile)
    flags = ['-std=gnu11', '-O2', '-g', '-Wall', '-Wextra', '-Werror', SOURCE]
    if profile == 'native':
        command = ['gcc', *flags, '-o', str(program)]
        inputs = sources(command, ROOT)
        subprocess.run(command, cwd=ROOT, check=True)
        if inputs != sources(command, ROOT):
            raise ValueError('router client changed during compilation')
        program.with_suffix('.inputs.json').write_text(json.dumps(dict(command=command,
            sources=inputs, compiler='host gcc/glibc', product=dict(bytes=program.stat().st_size,
            sha256=digest(program))), indent=2) + '\n')
    else:
        subprocess.run([sys.executable, 'scripts/compile_uapi_client.py', '--output', str(program),
            '--', *flags, *(['-static'] if profile == 'static' else [])], cwd=ROOT, check=True)
    return program, audit_compile(program, ROOT)


def source_inputs(guest):
    names = {SOURCE, 'userspace/tests/net/ipv6_fixture.h', 'Makefile', 'dependencies.json',
             'sources.lock.json', 'boot/limine.conf'}
    for module in list(sys.modules.values()):
        name = getattr(module, '__file__', None)
        if name:
            path = Path(name).resolve()
            if path.is_relative_to(ROOT / 'scripts') and path.suffix == '.py':
                names.add(path.relative_to(ROOT).as_posix())
    if guest:
        names.update(path.relative_to(ROOT).as_posix() for path in (ROOT / 'kernel').rglob('*')
                     if path.is_file() and path.suffix in ('.cpp', '.hpp', '.asm', '.ld'))
        names.update(('userspace/init/main.c', 'userspace/init/console.c', 'userspace/init/console.h',
                      'userspace/init/seed_records.h'))
    return {name:digest(ROOT / name) for name in sorted(names)}


def outcome(directory, text, reports, error, status, native=False, statistics=None):
    receipt = dict(returncode=status, error=error, peer_reports=reports,
                   log_sha256=digest(directory / 'serial.log'), full_RA_acceptance=False)
    receipt['functional_passed'] = (status == (0 if native else 1) and error is None and
        len(reports) == 2 and all(row['passed'] for row in reports) and
        text.splitlines().count(MARKER) == 1 and
        not any(marker in text for marker in ('IPV6_ROUTER_FAIL', 'PANIC:', 'FAULT pid=')))
    audits, audit_error = [], None
    if receipt['functional_passed']:
        try:
            audits = [inspect(directory / f'lane{lane}.pcap', lane, text, native=native,
                              statistics=statistics[lane] if native else None) for lane in range(2)]
        except (ValueError, OSError) as exception:
            audit_error = str(exception)
    receipt.update(capture_audits=audits, capture_audit_error=audit_error,
        passed=receipt['functional_passed'] and audit_error is None and len(audits) == 2 and
               all(row['passed'] for row in audits))
    (directory / 'receipt.json').write_text(json.dumps(receipt, indent=2) + '\n')
    return receipt


def guest_run(profile, firmware, transport, case):
    directory = case / (firmware + '-' + transport)
    directory.mkdir(exist_ok=False)
    peers, servers = [Peer(lane) for lane in range(2)], []
    command = ['qemu-system-x86_64', '-machine', 'pc', '-cpu', 'max', '-m', '256M',
        '-nic', 'none', '-cdrom', str(case / 'image.iso'), '-display', 'none', '-serial', 'stdio',
        '-monitor', 'none', '-no-reboot', '-device', 'isa-debug-exit,iobase=0xf4,iosize=0x04']
    for lane in range(2):
        server = socket.socket()
        server.bind(('127.0.0.1', 0))
        server.listen(1)
        servers.append(server)
        command += ['-netdev', f'socket,id=n{lane},connect=127.0.0.1:{server.getsockname()[1]}',
            '-device', f'{adapter_model(transport)},netdev=n{lane},addr={lane+4:x},mac={peers[lane].guest.hex(":")}',
            '-object', f'filter-dump,id=f{lane},netdev=n{lane},file={directory}/lane{lane}.pcap']
    if firmware == 'uefi':
        variables = directory / 'OVMF_VARS.fd'
        shutil.copyfile('/usr/share/OVMF/OVMF_VARS_4M.fd', variables)
        command += ['-drive', 'if=pflash,format=raw,readonly=on,file=/usr/share/OVMF/OVMF_CODE_4M.fd',
                    '-drive', 'if=pflash,format=raw,file=' + str(variables)]
    with (directory / 'serial.log').open('wb') as log:
        process = subprocess.Popen(command, cwd=ROOT, stdout=subprocess.PIPE,
                                   stderr=subprocess.STDOUT, stdin=subprocess.DEVNULL)
        try:
            text, reports, error, status = exercise(process, peers, servers, 60, log)
        finally:
            for server in servers:
                server.close()
    receipt = outcome(directory, text, reports, error, status)
    identity = guest_identity(text, firmware, transport)
    receipt.update(profile=profile, firmware=firmware, transport=transport, command=command,
                   actual_firmware_and_adapters=identity)
    receipt['passed'] &= (identity and text.splitlines().count('AXIOM64_TESTS_PASS') == 1 and
                          'AXIOM64_EXIT status=0' in text)
    (directory / 'receipt.json').write_text(json.dumps(receipt, indent=2) + '\n')
    return receipt


def native_child(args):
    namespace = Path('/proc/self/ns/net').stat().st_ino
    if args.parent_net_ns is None or namespace == args.parent_net_ns:
        raise ValueError('router comparison requires its own network namespace')
    args.directory.mkdir(exist_ok=False)
    for scope in ('all', 'default'):
        Path(f'/proc/sys/net/ipv6/conf/{scope}/disable_ipv6').write_text('1\n')
    peers, channels, captures = [Peer(lane, native=True) for lane in range(2)], [], []
    offloads = {}
    for lane in range(2):
        for command in (
            ['ip', 'link', 'add', f'eth{lane}', 'type', 'veth', 'peer', 'name', f'peer{lane}'],
            ['ip', 'link', 'set', f'eth{lane}', 'address', peers[lane].guest.hex(':')],
            ['ip', 'link', 'set', f'peer{lane}', 'address', peers[lane].mac.hex(':'), 'up']):
            subprocess.run(command, check=True)
        for interface in (f'eth{lane}', f'peer{lane}'):
            before = subprocess.check_output(['ethtool', '-k', interface], text=True)
            subprocess.run(['ethtool', '-K', interface, 'tx', 'off', 'tso', 'off', 'gso', 'off', 'gro', 'off'],
                           check=True, stdout=subprocess.DEVNULL)
            after = subprocess.check_output(['ethtool', '-k', interface], text=True)
            if 'tx-checksumming: off' not in after or 'generic-segmentation-offload: off' not in after:
                raise ValueError('native Ethernet capture requires complete software checksums')
            offloads[interface] = dict(before=before, after=after)
        channel = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(3))
        channel.bind((f'peer{lane}', 0))
        channels.append(channel)
        captures.append(Capture(f'peer{lane}', args.directory / f'lane{lane}.pcap'))
    (args.directory / 'offloads.json').write_text(json.dumps(offloads, indent=2) + '\n')
    program = args.directory.parent / ('ipv6-router-' + args.child)
    command = [str(program)]
    if args.child == 'dynamic':
        command.insert(0, str(loader('build')))
    audit_compile(program, ROOT)
    inputs = source_inputs(False)
    launch = [sys.executable, str(Path(__file__).resolve()), '--launch', *command]
    status = None
    with (args.directory / 'serial.log').open('wb') as log:
        process = subprocess.Popen(launch, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                   stdin=subprocess.DEVNULL)
        try:
            text, reports, error, status = exercise(process, peers, channels, 60, log, raw=True)
        finally:
            if process.poll() is None and status is None:
                process.kill()
            code = process.wait(timeout=2)
            for channel in channels:
                channel.close()
            statistics = [capture.close() for capture in captures]
    receipt = outcome(args.directory, text, reports, error, status, native=True, statistics=statistics)
    unchanged = all(digest(ROOT / name) == wanted for name, wanted in inputs.items())
    receipt.update(profile=args.child, command=command, actual_process_exit=code, captures=statistics,
        kernel_release=platform.release(), network_namespace=namespace,
        parent_network_namespace=args.parent_net_ns, source_inputs=inputs,
        client_sha256=digest(program), source_unchanged=unchanged)
    receipt['passed'] &= code == 0 and unchanged
    (args.directory / 'receipt.json').write_text(json.dumps(receipt, indent=2) + '\n')
    return receipt


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--native', action='store_true')
    parser.add_argument('--directory', type=Path, default=ROOT / 'build/ipv6-router-wire')
    parser.add_argument('--firmware', choices=('bios', 'uefi', 'both'), default='both')
    parser.add_argument('--transport', choices=('modern', 'legacy', 'e1000', 'all'), default='all')
    parser.add_argument('--linkage', choices=('static', 'dynamic', 'both'), default='both')
    parser.add_argument('--workers', type=int, choices=(1, 2), default=2)
    parser.add_argument('--child', choices=('static', 'dynamic', 'native'), help=argparse.SUPPRESS)
    parser.add_argument('--parent-net-ns', type=int, help=argparse.SUPPRESS)
    parser.add_argument('--launch', nargs='+', help=argparse.SUPPRESS)
    args = parser.parse_args()
    if args.launch:
        result = subprocess.run(args.launch)
        print('TCP_FAULT_NATIVE_DONE status=' + str(result.returncode), flush=True)
        raise SystemExit(result.returncode)
    args.directory = args.directory.resolve()
    if args.child:
        raise SystemExit(0 if native_child(args)['passed'] else 1)
    if args.native and os.geteuid():
        raise ValueError('native router comparisons need root for isolated namespaces')
    args.directory.mkdir(parents=True, exist_ok=False)
    inputs = source_inputs(not args.native)
    (args.directory / 'source-inputs.json').write_text(json.dumps(inputs, indent=2) + '\n')
    if not args.native:
        subprocess.run(['make', '-s', '-j2', 'build/axiom64.elf', 'build/init', 'busybox'], cwd=ROOT, check=True)
    profiles = ('static', 'dynamic', 'native') if args.native else (
        ('static', 'dynamic') if args.linkage == 'both' else (args.linkage,))
    rows, cases = [], []
    for profile in profiles:
        program, manifest = build(profile, args.directory)
        case = args.directory / profile
        if args.native:
            command = ['unshare', '--mount', '--net', '--pid', '--fork', '--mount-proc', sys.executable,
                str(Path(__file__).resolve()), '--child', profile, '--directory', str(case),
                '--parent-net-ns', str(Path('/proc/self/ns/net').stat().st_ino)]
            result = subprocess.run(command, cwd=ROOT)
            receipt = json.loads((case / 'receipt.json').read_text())
            receipt['passed'] &= result.returncode == 0
            rows.append(receipt)
            print(f'IPV6_ROUTER_NATIVE profile={profile} passed={receipt["passed"]}', flush=True)
        else:
            case.mkdir()
            def builder(provider, linkage, directory):
                return program, manifest
            image = fixture(case, 'build', profile, program_builder=builder, filename='ipv6-router',
                command='/bin/ipv6-router', extra_products={'source/client.c':ROOT / SOURCE,
                'source/ipv6_fixture.h':ROOT / 'userspace/tests/net/ipv6_fixture.h',
                'source/client.inputs.json':program.with_suffix('.inputs.json')})
            products = json.loads((case / 'products.json').read_text())
            audit_fixture(image, products['kernel.elf']['sha256'],
                {name:row['sha256'] for name,row in products.items() if name not in ('image.iso','root.cpio','kernel.elf')},
                b'#!/bin/sh\nset -e\n/bin/ipv6-router\necho AXIOM64_TESTS_PASS\n')
            cases.extend((profile, firmware, transport, case)
                for firmware in (('bios','uefi') if args.firmware == 'both' else (args.firmware,))
                for transport in (('modern','legacy','e1000') if args.transport == 'all' else (args.transport,)))
    if not args.native:
        with ThreadPoolExecutor(max_workers=args.workers) as workers:
            pending = [workers.submit(guest_run, *case) for case in cases]
            for completed in as_completed(pending):
                row = completed.result()
                rows.append(row)
                print(f'IPV6_ROUTER_GUEST {row["profile"]}/{row["firmware"]}/{row["transport"]} passed={row["passed"]}', flush=True)
                (args.directory / 'results.json').write_text(json.dumps(rows, indent=2) + '\n')
    unchanged = all(digest(ROOT / name) == wanted for name,wanted in inputs.items())
    proof = dict(passed=all(row['passed'] for row in rows) and unchanged, profiles=len(rows),
        source_unchanged=unchanged, full_matrix=len(rows)==(3 if args.native else 12),
        controlled_router_subset=True, full_RA_acceptance=False)
    (args.directory / 'results.json').write_text(json.dumps(rows, indent=2) + '\n')
    (args.directory / 'acceptance.json').write_text(json.dumps(proof, indent=2) + '\n')
    print(json.dumps(proof), flush=True)
    if not proof['passed']:
        raise SystemExit(1)


if __name__ == '__main__':
    main()
