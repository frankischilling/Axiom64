# SPDX-License-Identifier: GPL-3.0-or-later
"""Boot real configuration recovery with both linkages and Ethernet drivers."""
import argparse
import json
from pathlib import Path
import shutil
import subprocess
import sys
import time

from build_musl import loader
from configuration_inputs import PROGRAMS, digest, freeze, missing, retain, unchanged, write
from fetch import ROOT
from network_test import fixture
from tcp_fixture_inputs import audit_fixture


def run(firmware, transport, timeout, directory, linkage):
    label = f'configuration-{firmware}-{transport}-{linkage}'
    log = directory / (label + '.log')
    command = ['qemu-system-x86_64', '-machine', 'pc', '-cpu', 'max', '-m', '2G',
               '-cdrom', str(directory / 'image.iso'), '-nic', 'none',
               '-display', 'none', '-serial', 'stdio', '-monitor', 'none', '-no-reboot',
               '-device', 'isa-debug-exit,iobase=0xf4,iosize=0x04',
               '-netdev', 'user,id=first,restrict=on',
               '-device', 'virtio-net-pci,netdev=first,addr=4,mac=52:54:00:12:34:10,' +
               ('disable-legacy=on' if transport == 'modern' else 'disable-modern=on'),
               '-netdev', 'user,id=second,restrict=on',
               '-device', 'e1000,netdev=second,addr=5,mac=52:54:00:12:34:11']
    if firmware == 'uefi':
        variables = directory / (label + '-OVMF_VARS.fd')
        shutil.copyfile('/usr/share/OVMF/OVMF_VARS_4M.fd', variables)
        command += ['-drive', 'if=pflash,format=raw,readonly=on,file=/usr/share/OVMF/OVMF_CODE_4M.fd',
                    '-drive', f'if=pflash,format=raw,file={variables}']
    started = time.monotonic()
    timed_out = False
    with log.open('xb') as output:
        process = subprocess.Popen(command, stdout=output, stderr=subprocess.STDOUT,
                                   stdin=subprocess.DEVNULL)
        try:
            process.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            timed_out = True
            process.kill()
            process.wait()
    text = log.read_text(errors='replace')
    absent = missing(text, False)
    identity = all(marker in text for marker in (
        'Firmware: ' + firmware.upper(), 'virtio-net: index=1 transport=' + transport,
        'e1000: index=2 model=82540EM'))
    result = dict(firmware=firmware, transport=transport, linkage=linkage,
                  returncode=process.returncode, timed_out=timed_out, missing=absent,
                  log=log.name, log_sha256=digest(log), command=command,
                  actual_firmware_and_adapters=identity, seconds=round(time.monotonic() - started, 3),
                  passed=not timed_out and process.returncode == 1 and not absent and identity and
                         'PANIC:' not in text and 'Page fault' not in text)
    write(directory / (label + '.json'), result)
    print(json.dumps({key: result[key] for key in (
        'firmware', 'transport', 'linkage', 'returncode', 'timed_out', 'missing', 'passed')}), flush=True)
    if not result['passed']:
        print(text[-2500:], flush=True)
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--firmware', choices=['bios', 'uefi', 'both'], default='both')
    parser.add_argument('--transport', choices=['modern', 'legacy', 'both'], default='both')
    parser.add_argument('--linkage', choices=['static', 'dynamic', 'both'], default='both')
    parser.add_argument('--directory', type=Path, default=ROOT / 'build/configuration-wire')
    parser.add_argument('--timeout', type=float, default=60)
    args = parser.parse_args()
    if args.timeout <= 0:
        parser.error('timeout must be positive')
    directory = args.directory.resolve()
    directory.mkdir(parents=True, exist_ok=False)
    linkages = ['static', 'dynamic'] if args.linkage == 'both' else [args.linkage]
    with (directory / 'build.log').open('xb') as output:
        subprocess.run(['make', '-j4', 'build/axiom64.elf', 'build/init', 'busybox',
                        *['build/' + PROGRAMS[profile] for profile in linkages]], cwd=ROOT,
                       stdin=subprocess.DEVNULL, stdout=output, stderr=subprocess.STDOUT, check=True)
    source = freeze(directory)
    shutil.copy2(ROOT / 'build/axiom64.elf', directory / 'kernel.elf')
    kernel = digest(directory / 'kernel.elf')
    receipt = dict(kind='guest', source=source, kernel_sha256=kernel, profiles={}, results=[],
                   requested=dict(firmware=args.firmware, transport=args.transport, linkage=args.linkage),
                   original_timeout_seconds=args.timeout, passed=False)
    write(directory / 'acceptance.json', receipt)
    for profile in linkages:
        selected = directory / profile
        products = retain(selected, profile)
        program = PROGRAMS[profile]
        fixture(program=program, script='userspace/tests/net/configuration.sh',
                environment={'AXIOM64_CONFIGURATION_PROGRAM': program},
                runtime_loader=loader('build') if profile == 'dynamic' else None)
        subprocess.run([sys.executable, 'scripts/image.py', '--test', '--suite', 'network',
                        '--output-name', 'image.iso', '--output-directory', str(selected)], cwd=ROOT,
                       stdin=subprocess.DEVNULL, check=True)
        shutil.copy2(ROOT / 'build/rootfs-network.cpio', selected / 'root.cpio')
        bindings = {'sbin/init': digest(ROOT / 'build/init'), 'bin/' + program: products['products']['program.elf'],
                    'bin/busybox': digest(ROOT / 'build/busybox-1.37.0/busybox')}
        if profile == 'dynamic':
            bindings['lib/ld-musl-x86_64.so.1'] = products['products']['loader.elf']
        script = ('export AXIOM64_CONFIGURATION_PROGRAM=' + program + '\n').encode() + (ROOT / 'userspace/tests/net/configuration.sh').read_bytes()
        products.update(image_audit=audit_fixture(selected / 'image.iso', kernel, bindings, script, digest(selected / 'root.cpio')),
                        bindings=bindings, image_sha256=digest(selected / 'image.iso'),
                        root_sha256=digest(selected / 'root.cpio'))
        receipt['profiles'][profile] = products
        write(directory / 'acceptance.json', receipt)
        for firmware in ['bios', 'uefi'] if args.firmware == 'both' else [args.firmware]:
            for transport in ['modern', 'legacy'] if args.transport == 'both' else [args.transport]:
                result = run(firmware, transport, args.timeout, selected, profile)
                receipt['results'].append(result)
                write(directory / 'acceptance.json', receipt)
                if not result['passed']:
                    raise RuntimeError('Configuration ownership/recovery check failed')
    receipt['source_unchanged'] = unchanged(directory)
    receipt['passed'] = receipt['source_unchanged'] and all(row['passed'] for row in receipt['results'])
    write(directory / 'acceptance.json', receipt)
    if not receipt['passed']:
        raise RuntimeError('Configuration source changed during validation')
    print(json.dumps(dict(passed=True, profiles=len(receipt['results']), kernel_sha256=kernel)), flush=True)


if __name__ == '__main__':
    main()
