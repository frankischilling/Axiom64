# SPDX-License-Identifier: GPL-3.0-or-later
"""Exercise actual x86-64 seccomp syscalls on an isolated four-CPU guest."""
import argparse
from pathlib import Path
import subprocess
import sys

from boot_media_test import run_guest
from build_musl import loader
from fetch import LOCK, ROOT
from newc import write_cpio


def compile_client(directory, linkage):
    binary = directory / 'seccomp-test'
    flags = ['-static'] if linkage == 'static' else []
    subprocess.run([sys.executable, 'scripts/compile_uapi_client.py', '--output', str(binary),
                    '--', '-std=c11', '-O2', '-g', '-Wall', '-Wextra', '-Werror', '-pthread',
                    *flags, 'userspace/tests/security/seccomp.c'], cwd=ROOT, check=True)
    return binary


def make_archive(directory, binary, *, dynamic=False, linux=False):
    files = {name: (0o40755, b'') for name in ('bin', 'dev', 'etc', 'lib', 'proc', 'run', 'sbin', 'tmp')}
    busybox = ROOT / 'build' / ('busybox-' + LOCK['busybox']['version']) / 'busybox'
    files['bin/busybox'] = (0o100755, busybox.read_bytes())
    files['bin/seccomp-test'] = (0o100755, binary.read_bytes())
    if dynamic:
        files['lib/ld-musl-x86_64.so.1'] = (0o100755, loader().read_bytes())
    if linux:
        files['init'] = (0o100755, b'#!/bin/busybox sh\n/bin/busybox mount -t proc proc /proc\n'
                         b'/bin/busybox uname -r\n/bin/seccomp-test\nexec /bin/busybox poweroff -f\n')
    else:
        files['sbin/init'] = (0o100755, (ROOT / 'build/init').read_bytes())
        files['etc/net-test.sh'] = (0o100755, b'#!/bin/sh\nset -e\n/bin/seccomp-test\n'
                                    b'echo AXIOM64_TESTS_PASS\n')
    archive = directory / 'root.cpio'
    write_cpio(archive, files)
    return archive


def compare_linux(output, kernel, binary):
    output.mkdir()
    archive = make_archive(output, binary, linux=True)
    log = output / 'serial.log'
    command = ['qemu-system-x86_64', '-machine', 'q35', '-cpu', 'max', '-smp', '4', '-m', '512M',
               '-kernel', kernel, '-initrd', archive, '-nic', 'none', '-display', 'none',
               '-serial', 'stdio', '-monitor', 'none', '-no-reboot', '-append',
               'rdinit=/init console=ttyS0 quiet panic=1']
    with log.open('wb') as stream:
        subprocess.run(command, stdin=subprocess.DEVNULL, stdout=stream, stderr=subprocess.STDOUT,
                       check=True, timeout=90)
    lines = log.read_text(errors='replace').splitlines()
    if 'SECCOMP_TEST_PASS' not in lines:
        raise RuntimeError(f'Linux comparison failed in {log}\n' + '\n'.join(lines[-20:]))
    print('SECCOMP_LINUX_PASS', flush=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--directory', type=Path, default=ROOT / 'build/seccomp-test')
    parser.add_argument('--linux-kernel', type=Path, help='Linux bzImage for the optional ABI comparison')
    args = parser.parse_args()
    output = args.directory.resolve()
    output.mkdir(parents=True)
    subprocess.run(['make', '-s', '-j2', 'build/axiom64.elf', 'build/init', 'busybox'], cwd=ROOT, check=True)
    for linkage in ('static', 'dynamic'):
        case = output / linkage
        case.mkdir()
        binary = compile_client(case, linkage)
        if args.linux_kernel and linkage == 'static':
            compare_linux(output / 'linux', args.linux_kernel.resolve(), binary)
        archive = make_archive(case, binary, dynamic=linkage == 'dynamic')
        image = case / 'seccomp.iso'
        subprocess.run([sys.executable, 'scripts/image.py', '--test', '--suite', 'network',
                        '--initramfs', str(archive), '--output-directory', str(case),
                        '--output-name', image.name, '--kernel-option', 'smp.scheduler'],
                       cwd=ROOT, check=True, stdout=subprocess.DEVNULL)
        for firmware in ('bios', 'uefi'):
            guest = case / firmware
            guest.mkdir()
            run_guest(guest, 'iso', firmware, image, 'SECCOMP_TEST_PASS', archive.stat().st_size, smp=4)
            print(f'SECCOMP_GUEST_PASS {linkage}/{firmware}', flush=True)


if __name__ == '__main__':
    main()
