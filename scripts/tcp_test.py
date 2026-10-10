# SPDX-License-Identifier: GPL-3.0-or-later
"""Run the native TCP socket/transfer client in static and dynamic loopback guests."""
import argparse
import json
from pathlib import Path
import shutil
import subprocess
import time
from fetch import ROOT, LOCK


def fixture(linkage, script=None, image_name=None):
    subprocess.run(['make', '-s', '-j2', 'build/axiom64.elf', 'build/init', f'build/tcp-{linkage}', 'busybox'], cwd=ROOT, check=True)
    expected = json.loads((ROOT / 'sources.lock.json').read_text())['build_musl']['version']
    actual = subprocess.check_output(['dpkg-query', '-W', '-f=${Version}', 'musl-dev'], text=True)
    if actual != expected:
        raise RuntimeError('TCP fixture musl differs from the locked build version')
    files = {name: (0o40755, b'') for name in ('bin', 'sbin', 'lib', 'etc', 'dev', 'proc', 'tmp', 'run')}
    for name, source in (('sbin/init', ROOT / 'build/init'),
                         ('bin/tcp-tests', ROOT / 'build' / f'tcp-{linkage}'),
                         ('bin/busybox', ROOT / 'build' / f"busybox-{LOCK['busybox']['version']}" / 'busybox'),
                         ('lib/ld-musl-x86_64.so.1', Path('/lib/ld-musl-x86_64.so.1').resolve())):
        files[name] = (0o100755, source.read_bytes())
    files['etc/net-test.sh'] = (0o100755, script or b'#!/bin/sh\nset -e\n/bin/tcp-tests\necho AXIOM64_TESTS_PASS\n')
    with (ROOT / 'build/rootfs-network.cpio').open('wb') as output:
        for inode, (name, (mode, data)) in enumerate([*sorted(files.items()), ('TRAILER!!!', (0, b''))], 1):
            encoded = name.encode() + b'\0'
            fields = [inode, mode, 0, 0, 1, 0, len(data), 0, 0, 0, 0, len(encoded), 0]
            output.write(b'070701' + b''.join(f'{value:08x}'.encode() for value in fields) + encoded)
            output.write(bytes(-output.tell() % 4))
            output.write(data)
            output.write(bytes(-output.tell() % 4))
    image = ROOT / 'build' / (image_name or f'axiom64-tcp-{linkage}.iso')
    subprocess.run(['python3', 'scripts/image.py', '--test', '--suite', 'network', '--output-name', image.name], cwd=ROOT, check=True, stdout=subprocess.DEVNULL)
    return image


def run(linkage, firmware, timeout, image):
    label = f'tcp-{linkage}-{firmware}'
    log = ROOT / 'build' / f'{label}.log'
    command = ['qemu-system-x86_64', '-machine', 'pc', '-cpu', 'max', '-m', '512M', '-nic', 'none',
               '-cdrom', str(image), '-display', 'none', '-serial', 'stdio', '-monitor', 'none',
               '-no-reboot', '-device', 'isa-debug-exit,iobase=0xf4,iosize=0x04']
    if firmware == 'uefi':
        variables = ROOT / 'build' / f'{label}-OVMF_VARS.fd'
        shutil.copyfile('/usr/share/OVMF/OVMF_VARS_4M.fd', variables)
        command += ['-drive', 'if=pflash,format=raw,readonly=on,file=/usr/share/OVMF/OVMF_CODE_4M.fd',
                    '-drive', f'if=pflash,format=raw,file={variables}']
    started, timed_out = time.monotonic(), False
    with log.open('wb') as output:
        process = subprocess.Popen(command, stdout=output, stderr=subprocess.STDOUT)
        try:
            process.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            timed_out = True
        finally:
            if process.poll() is None:
                process.kill()
                process.wait()
    text = log.read_text(errors='replace')
    required = ('TCP_CREATE_PASS variants=8', 'TCP_BINDINGS_PASS ', 'TCP_OPTIONS_PASS ', 'TCP_REFUSED_PASS ',
                'TCP_VECTORS_PASS ', 'TCP_WAITALL_PASS ', 'TCP_WAITALL_SIGNALS_PASS ',
                'TCP_RETAINED_READ_PASS cases=2', 'TCP_RESOURCE_CYCLES_PASS count=300',
                'TCP_CLIENT_PASS ', 'TCP_LOOPBACK_PASS bytes=262144',
                'TCP_TEST_PASS', 'AXIOM64_TESTS_PASS', 'AXIOM64_EXIT status=0', f'Firmware: {firmware.upper()}')
    missing = [marker for marker in required if marker not in text]
    result = dict(linkage=linkage, firmware=firmware, returncode=process.returncode,
                  timed_out=timed_out, missing=missing, log=log.name,
                  seconds=round(time.monotonic() - started, 3),
                  passed=not timed_out and process.returncode == 1 and not missing and
                  not any(marker in text for marker in ('TCP_TEST_FAIL ', 'PANIC:', 'FAULT pid=')))
    print(json.dumps(result), flush=True)
    if not result['passed']:
        print(text[-5000:], flush=True)
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--linkage', choices=('static', 'dynamic', 'both'), default='both')
    parser.add_argument('--firmware', choices=('bios', 'uefi', 'both'), default='both')
    parser.add_argument('--timeout', type=float, default=80)
    args = parser.parse_args()
    if args.timeout <= 0:
        parser.error('timeout must be positive')
    results = []
    original = ROOT / 'build/rootfs-network.cpio'
    previous = original.read_bytes() if original.exists() else None
    try:
        for linkage in ('static', 'dynamic') if args.linkage == 'both' else (args.linkage,):
            image = fixture(linkage)
            for firmware in ('bios', 'uefi') if args.firmware == 'both' else (args.firmware,):
                result = run(linkage, firmware, args.timeout, image)
                results.append(result)
                (ROOT / 'build/tcp-results.json').write_text(json.dumps(results, indent=2) + '\n')
                if not result['passed']:
                    raise SystemExit('Guest TCP loopback failed')
    finally:
        if previous is None:
            original.unlink(missing_ok=True)
        else:
            original.write_bytes(previous)


if __name__ == '__main__':
    main()
