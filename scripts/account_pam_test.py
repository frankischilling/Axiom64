#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
# @file    scripts/account_pam_test.py
# @brief   Exercise graphical account authentication on disposable NVMe images.
# @author  frankischilling
# @date    2026-11-22
#
# Copyright (C) 2026 frankischilling
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program. If not, see <https://gnu.org/licenses/>.

"""Boot the installed PAM module and its account fixtures under both firmwares."""

import argparse
import json
from pathlib import Path
import shutil
import subprocess
import tarfile
import tempfile

from boot_media import build_medium
from build_accounts import MODULES, environment
from build_libxcrypt import runtime_files as crypt_files, ensure as password_library
from build_musl import compiler_args, runtime_files as musl_files
from build_pam_accounts import stage_pam
from fetch import LOCK, ROOT
from newc import write_cpio
from ports import LOCKFILE, locked_package, overlay_tar

INIT = b"""#!/bin/sh
export PATH=/bin:/usr/bin:/sbin:/usr/sbin
/bin/busybox mkdir -p /etc/axiom64 /var/log/axiom64
if /usr/bin/account-pam; then
    count=$(/bin/busybox grep -c denied /var/log/axiom64/login/auth.log)
    recovered=$(/bin/busybox grep -c recovered /var/log/axiom64/login/auth.log)
    if test "$count" -eq 5 && test "$recovered" -eq 1; then
        printf 'PAM_DENIAL_AUDIT_RECORDS=%s\n' "$count"
        printf 'PAM_RECOVERED_LEASE_RECORDS=%s\n' "$recovered"
        printf 'ACCOUNT_PAM_GUEST_PASS\n'
    fi
fi
exec /bin/busybox poweroff -f
"""


def test_archive(staging):
    archive, libpam = stage_pam(staging)
    packages = {p['name']: p for p in json.loads(LOCKFILE.read_text())['packages']}
    files = {name: entry for name, entry in musl_files().items()
             if name.startswith('lib/') or name == 'usr/lib/libc.so'}
    files.update({name: entry for name, entry in crypt_files().items()
                  if name.startswith('usr/lib/libcrypt.so.')})
    for path, payload in ((archive, 'usr/lib/libpam.so*'),
                          (locked_package(packages['libintl']), 'usr/lib/libintl.so*')):
        with tarfile.open(path, 'r:gz', ignore_zeros=True) as stream:
            overlay_tar(files, stream, include=(payload,))

    (staging / 'libc.musl-x86_64.so.1').write_bytes(files['lib/ld-musl-x86_64.so.1'][1])
    crypt = password_library('runtime') / 'dynamic/stage/usr'
    accounts = ROOT / 'userspace/accounts'
    runner = staging / 'account-pam'
    subprocess.run([
        *compiler_args('build'), '-std=c11', '-O2', '-Wall', '-Wextra', '-Werror', f'-I{staging}',
        f'-I{crypt / "include"}', *(str(accounts / f'{name}.c') for name in (*MODULES, 'logbook_rotation')),
        str(ROOT / 'userspace/tests/security/account-pam.c'), str(libpam), f'-L{crypt / "lib"}',
        f'-Wl,-rpath-link,{staging}', '-lcrypt', '-o', str(runner),
    ], check=True, env=environment())
    busybox = ROOT / 'build' / f'busybox-{LOCK["busybox"]["version"]}' / 'busybox'
    files.update({
        'bin/busybox': (0o100755, busybox.read_bytes()),
        'bin/sh': (0o120777, b'/bin/busybox'),
        'etc/pam.d/axiom64-test': (0o100644, (ROOT / 'userspace/desktop/pam/sddm.conf').read_bytes()),
        'sbin/init': (0o100755, INIT),
        'usr/bin/account-pam': (0o100755, runner.read_bytes()),
        'usr/lib/security/pam_axiom64.so': (0o100644, (ROOT / 'build/pam_axiom64.so').read_bytes()),
    })
    for path in tuple(files):
        for parent in Path(path).parents:
            if parent != Path('.'):
                files.setdefault(parent.as_posix(), (0o40755, b''))
    rootfs = staging / 'test.cpio'
    write_cpio(rootfs, files)
    return rootfs


def test_boot(image, firmware, log, staging):
    command = ['qemu-system-x86_64', '-machine', 'q35', '-cpu', 'max', '-m', '1G', '-nic', 'none',
               '-display', 'none', '-monitor', 'none', '-serial', 'stdio', '-no-reboot',
               '-device', 'isa-debug-exit,iobase=0xf4,iosize=4', '-snapshot',
               '-drive', f'if=none,id=system,format=raw,file={image}',
               '-device', 'nvme,drive=system,serial=AXIOM64,bootindex=1']
    if firmware == 'uefi':
        variables = staging / 'VARS.fd'
        shutil.copyfile('/usr/share/OVMF/OVMF_VARS_4M.fd', variables)
        command += ['-drive', 'if=pflash,format=raw,readonly=on,file=/usr/share/OVMF/OVMF_CODE_4M.fd',
                    '-drive', f'if=pflash,format=raw,file={variables}']
    with log.open('wb') as output:
        result = subprocess.run(command, stdin=subprocess.DEVNULL, stdout=output,
                                stderr=subprocess.STDOUT, timeout=150)
    markers = {f'Firmware: {firmware.upper()}', 'ACCOUNT_PAM_GUEST_PASS', 'PAM_DENIAL_AUDIT_RECORDS=5',
               'PAM_RECOVERED_LEASE_RECORDS=1', 'ACCOUNT_PAM_RECOVERED_SUPERVISOR_LEASE',
               'ACCOUNT_PAM_DENIED_PASSWORD_AND_ACCOUNT', 'ACCOUNT_PAM_VERIFIED_CREDENTIAL_AND_REJECTED_IDENTITY_CHANGE',
               'ACCOUNT_PAM_REJECTED_STALE_AND_PASSWORD_CHANGE_REQUIRED', 'ACCOUNT_PAM_REJECTED_UNPRIVILEGED_CALLER',
               'nvme: controller=0 shutdown complete', 'AXIOM64_EXIT status=0'}
    if result.returncode != 1 or not markers.issubset(log.read_text(errors='replace').splitlines()):
        raise RuntimeError(f'Account PAM checks failed under {firmware}. See {log}')
    print(f'Account PAM checks passed under {firmware}. {log}', flush=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--directory', type=Path, default=ROOT / 'build/account-pam')
    args = parser.parse_args()
    args.directory.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix='axiom64-account-pam-') as temporary:
        staging = Path(temporary)
        image = staging / 'system.raw'
        build_medium('disk', image, ROOT / 'build/axiom64.elf', test_archive(staging), '',
                     installed=True, root_mib=256)
        subprocess.run(['sfdisk', '--verify', image], check=True)
        for firmware in ('bios', 'uefi'):
            test_boot(image, firmware, args.directory / f'{firmware}.log', staging)


if __name__ == '__main__':
    main()
