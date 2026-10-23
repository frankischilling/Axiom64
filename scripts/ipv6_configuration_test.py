#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Compare IPv6 proc configuration I/O with measured Linux handler results."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import shutil
import subprocess
import sys
import time

from account_store_guest import fixture
from build_musl import loader
from compile_uapi_client import audit_compile, sources
from fetch import ROOT
from tcp_fixture_inputs import audit_fixture

SOURCE = 'userspace/tests/net/ipv6_configuration.c'
REFERENCE = 'scripts/tests/fixtures/ipv6-configuration-linux7.json'


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def adapter_model(transport):
    if transport == 'e1000':
        return 'e1000'
    return 'virtio-net-pci,' + ('disable-legacy=on' if transport == 'modern' else 'disable-modern=on')


def guest_identity(text, firmware, transport):
    markers = ['Firmware: ' + firmware.upper()]
    for index in (1, 2):
        markers.append(f'e1000: index={index} model=82540EM' if transport == 'e1000' else
                       f'virtio-net: index={index} transport={transport}')
    return all(marker in text for marker in markers)


def observations(text):
    lines = text.splitlines()
    actual = [line for line in lines if line.startswith('IO_') and
              not line.startswith('IO_SECRET_ADDRESS ')]
    expected = json.loads((ROOT / REFERENCE).read_text())['observations']
    complete = (lines.count('SYSCTL_IO_COMPLETE counted=30') == 1 and
                lines.count('SYSCTL_FRONTEND_COMPLETE') == 1)
    return dict(passed=actual == expected and complete and 'SYSCTL_IO_FATAL' not in text,
                observations=actual, expected_count=len(expected), complete=complete,
                address_snapshots=[line for line in lines if line.startswith('IO_SECRET_ADDRESS ')])


def build(profile, directory):
    program = directory / ('ipv6-configuration-' + profile)
    flags = ['-std=gnu11', '-O2', '-g', '-Wall', '-Wextra', '-Werror', SOURCE]
    if profile == 'native':
        command = ['gcc', *flags, '-o', str(program)]
        inputs = sources(command, ROOT)
        subprocess.run(command, cwd=ROOT, check=True)
        if sources(command, ROOT) != inputs:
            raise ValueError('configuration client changed during compilation')
        program.with_suffix('.inputs.json').write_text(json.dumps(dict(command=command,
            sources=inputs, compiler='host gcc/glibc', product=dict(sha256=digest(program),
            bytes=program.stat().st_size)), indent=2) + '\n')
    else:
        subprocess.run([sys.executable, 'scripts/compile_uapi_client.py', '--output', str(program),
                        '--', *flags, *(['-static'] if profile == 'static' else [])], cwd=ROOT,
                       check=True, stdout=subprocess.DEVNULL)
    return program, audit_compile(program, ROOT)


def execute(command, directory, guest=False):
    began = time.monotonic_ns()
    timed_out = False
    try:
        result = subprocess.run(command, cwd=ROOT, stdin=subprocess.DEVNULL,
                                stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=90)
        data, code = result.stdout, result.returncode
    except subprocess.TimeoutExpired as error:
        data, code, timed_out = error.stdout or b'', None, True
    log = directory / 'serial.log'
    log.write_bytes(data)
    text = data.decode(errors='replace')
    row = observations(text)
    row.update(command=command, returncode=code, timed_out=timed_out,
               elapsed_ns=time.monotonic_ns() - began, log_sha256=digest(log),
               clock_acceptance=False, RA_protocol_acceptance=False)
    row['passed'] &= code == (1 if guest else 0) and not timed_out
    if guest:
        row['passed'] &= (text.splitlines().count('AXIOM64_TESTS_PASS') == 1 and
                          'AXIOM64_EXIT status=0' in text and
                          not any(marker in text for marker in ('PANIC:', 'FAULT pid=')))
    (directory / 'receipt.json').write_text(json.dumps(row, indent=2) + '\n')
    return row


def native_child(args):
    if not args.parent_net_ns or Path('/proc/self/ns/net').stat().st_ino == args.parent_net_ns:
        raise ValueError('configuration comparison requires a private network namespace')
    args.directory.mkdir(exist_ok=False)
    for lane in range(2):
        name, peer = f'eth{lane}', f'peer{lane}'
        subprocess.run(['ip', 'link', 'add', name, 'type', 'veth', 'peer', 'name', peer], check=True)
        subprocess.run(['ip', 'link', 'set', peer, 'up'], check=True)
        subprocess.run(['ip', 'link', 'set', name, 'address', f'52:54:00:12:34:{16 + lane:02x}',
                        'up'], check=True)
    program = args.directory.parent / ('ipv6-configuration-' + args.child)
    command = [str(program)]
    if args.child == 'dynamic':
        command.insert(0, str(loader('build')))
    row = execute(command, args.directory)
    row.update(kernel_release=platform.release(), network_namespace=Path('/proc/self/ns/net').stat().st_ino,
               parent_network_namespace=args.parent_net_ns, client_sha256=digest(program))
    (args.directory / 'receipt.json').write_text(json.dumps(row, indent=2) + '\n')
    if not row['passed']:
        raise ValueError('native configuration observations differ from the Linux reference')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--directory', type=Path, default=ROOT / 'build/ipv6-configuration')
    parser.add_argument('--native', action='store_true')
    parser.add_argument('--child', choices=('static', 'dynamic', 'native'), help=argparse.SUPPRESS)
    parser.add_argument('--parent-net-ns', type=int, help=argparse.SUPPRESS)
    args = parser.parse_args()
    args.directory = args.directory.resolve()
    if args.child:
        native_child(args)
        return
    if args.native and (os.geteuid() or os.getegid()):
        raise ValueError('native configuration comparisons need root for isolated namespaces')
    args.directory.mkdir(parents=True, exist_ok=False)
    names = [SOURCE, REFERENCE, 'scripts/ipv6_configuration_test.py', 'scripts/account_store_guest.py',
             'scripts/compile_uapi_client.py', 'scripts/tcp_fixture_inputs.py', 'scripts/image.py',
             'Makefile', 'sources.lock.json', 'dependencies.json', 'boot/limine.conf']
    if not args.native:
        names += [path.relative_to(ROOT).as_posix() for path in (ROOT / 'kernel').rglob('*')
                  if path.is_file() and path.suffix in ('.cpp', '.hpp', '.asm', '.ld')]
        names += ['userspace/init/main.c', 'userspace/init/console.c', 'userspace/init/console.h',
                  'userspace/init/seed_records.h']
    inputs = {name: digest(ROOT / name) for name in names}
    (args.directory / 'source-inputs.json').write_text(json.dumps(inputs, indent=2) + '\n')
    if not args.native:
        subprocess.run(['make', '-s', '-j2', 'build/axiom64.elf', 'build/init', 'busybox'],
                       cwd=ROOT, check=True)
    rows = []
    for profile in ('static', 'dynamic', 'native') if args.native else ('static', 'dynamic'):
        program, manifest = build(profile, args.directory)
        if args.native:
            case = args.directory / profile
            command = ['unshare', '--mount', '--net', '--pid', '--fork', '--mount-proc',
                       sys.executable, str(Path(__file__).resolve()), '--directory', str(case),
                       '--child', profile, '--parent-net-ns', str(Path('/proc/self/ns/net').stat().st_ino)]
            subprocess.run(command, cwd=ROOT, check=True)
            rows.append(json.loads((case / 'receipt.json').read_text()))
            print('IPV6_CONFIGURATION_NATIVE_PASS ' + profile, flush=True)
        else:
            case = args.directory / profile
            case.mkdir()

            def builder(provider, linkage, directory):
                assert provider == 'build' and linkage == profile
                return program, manifest

            image = fixture(case, 'build', profile, program_builder=builder,
                filename='ipv6-configuration', command='/bin/ipv6-configuration',
                extra_products={'source/client.c': ROOT / SOURCE,
                                'source/client.inputs.json': program.with_suffix('.inputs.json')})
            products = json.loads((case / 'products.json').read_text())
            expected = {name: row['sha256'] for name, row in products.items()
                        if name not in ('image.iso', 'root.cpio', 'kernel.elf')}
            audit = audit_fixture(image, digest(case / 'kernel.elf'), expected,
                b'#!/bin/sh\nset -e\n/bin/ipv6-configuration\necho AXIOM64_TESTS_PASS\n')
            for firmware in ('bios', 'uefi'):
                for transport in ('modern', 'legacy', 'e1000'):
                    output = case / (firmware + '-' + transport)
                    output.mkdir()
                    command = ['qemu-system-x86_64', '-machine', 'pc', '-cpu', 'max', '-m', '256M',
                        '-nic', 'none', '-cdrom', str(image), '-display', 'none', '-serial', 'stdio',
                        '-monitor', 'none', '-no-reboot', '-device', 'isa-debug-exit,iobase=0xf4,iosize=0x04']
                    for lane in range(2):
                        model = adapter_model(transport)
                        command += ['-netdev', f'user,id=n{lane},ipv6=off', '-device',
                            f'{model},netdev=n{lane},addr={lane + 4:x},mac=52:54:00:12:34:{16 + lane:02x}']
                    if firmware == 'uefi':
                        variables = output / 'OVMF_VARS.fd'
                        shutil.copyfile('/usr/share/OVMF/OVMF_VARS_4M.fd', variables)
                        command += ['-drive', 'if=pflash,format=raw,readonly=on,file=/usr/share/OVMF/OVMF_CODE_4M.fd',
                                    '-drive', 'if=pflash,format=raw,file=' + str(variables)]
                    row = execute(command, output, guest=True)
                    row['actual_firmware_and_adapters'] = guest_identity(
                        (output / 'serial.log').read_text(), firmware, transport)
                    row['passed'] &= row['actual_firmware_and_adapters']
                    row.update(profile=profile, firmware=firmware, transport=transport,
                               image_audit=audit, kernel_sha256=digest(case / 'kernel.elf'),
                               client_sha256=digest(program))
                    (output / 'receipt.json').write_text(json.dumps(row, indent=2) + '\n')
                    rows.append(row)
                    (args.directory / 'results.json').write_text(json.dumps(rows, indent=2) + '\n')
                    if not row['passed']:
                        raise ValueError('guest configuration comparison failed: ' + str(output))
                    print('IPV6_CONFIGURATION_GUEST_PASS ' + profile + '/' + output.name, flush=True)
    unchanged = all(digest(ROOT / name) == expected for name, expected in inputs.items())
    receipt = dict(passed=all(row['passed'] for row in rows) and unchanged,
                   profiles=len(rows), observations=sum(len(row['observations']) for row in rows),
                   source_unchanged=unchanged, clock_acceptance=False, RA_protocol_acceptance=False)
    (args.directory / 'acceptance.json').write_text(json.dumps(receipt, indent=2) + '\n')
    if not receipt['passed']:
        raise ValueError('configuration inputs changed during validation')
    print(json.dumps(receipt), flush=True)


if __name__ == '__main__':
    main()
