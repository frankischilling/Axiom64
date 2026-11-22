#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
# @file    scripts/nvme_install_pxe.py
# @brief   Build a PXE maintenance image for NVMe installation.
# @author  frankischilling
# @date    2026-11-22
#
# Takes the pinned Python and SSH runtime from the installed desktop archive.
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

"""Run the NVMe installer from PXE and transfer its image by SFTP."""
import argparse
from collections import deque
from ipaddress import IPv4Address, IPv4Interface
import os
from pathlib import Path, PurePosixPath
import posixpath
import re
import stat
import subprocess
import tempfile

from boot_media import build_medium
from disk_root import archive_entries
from fetch import ROOT
from newc import write_cpio


LOADER = 'lib/ld-musl-x86_64.so.1'


def runtime_files(source, scratch):
    available = archive_entries(source)
    libraries = {}
    for directory in ('lib', 'usr/lib'):
        for name in available:
            if posixpath.dirname(name) == directory:
                libraries.setdefault(posixpath.basename(name), name)
    libraries['libc.musl-x86_64.so.1'] = LOADER
    pending = deque(('bin/busybox', LOADER, 'usr/bin/python3', 'usr/bin/ssh-keygen', 'usr/sbin/sshd'))
    pending.extend(name for name in available
                   if name.startswith(('usr/lib/python3.', 'usr/lib/ssh/', 'usr/share/licenses/')))
    selected = {}
    executable = scratch / 'probe.elf'
    while pending:
        name = pending.popleft()
        if name in selected:
            continue
        if name not in available:
            raise ValueError(f'{source.name} lacks maintenance runtime path {name}')
        mode, data = selected[name] = available[name]
        if stat.S_ISLNK(mode):
            absolute = posixpath.join('/' + posixpath.dirname(name), os.fsdecode(data))
            pending.append(posixpath.normpath(absolute).lstrip('/'))
        if stat.S_ISREG(mode) and data.startswith(b'\x7fELF'):
            executable.write_bytes(data)
            description = subprocess.check_output(['readelf', '-d', executable],
                                                  env={**os.environ, 'LC_ALL': 'C'}, text=True)
            for library in re.findall(r'Shared library: \[(.*?)\]', description):
                if library not in libraries:
                    raise ValueError(f'{name} needs {library}')
                pending.append(libraries[library])
    return selected


def setup(files, args, public_key):
    for path in ('dev', 'etc', 'etc/ssh', 'home', 'proc', 'run', 'sys', 'var', 'var/empty'):
        files[path] = 0o40755, b''
    for path in ('home/bench', 'root'):
        files[path] = 0o40700, b''
    files['tmp'] = 0o41777, b''
    for applet in ('sh', 'id', 'true', 'false', 'cat'):
        files[f'bin/{applet}'] = 0o120777, b'busybox'
    files['etc/passwd'] = (0o100644, b'root:x:0:0:root:/root:/bin/sh\n'
                           b'sshd:x:74:74:sshd:/var/empty:/bin/false\n'
                           b'bench:x:1000:1000:bench:/home/bench:/bin/sh\n')
    files['etc/group'] = 0o100644, b'root:x:0:\nsshd:x:74:\nbench:x:1000:\n'
    files['etc/shadow'] = (0o100600, b'root:!:0:0:99999:7:::\nsshd:!:0:0:99999:7:::\n'
                           b'bench:*:0:0:99999:7:::\n')
    files['etc/ssh/bench.pub'] = 0o100644, public_key + b'\n'
    config = f'''Port 22
ListenAddress {args.address.ip}
HostKey /run/sshd_ed25519_key
AuthorizedKeysFile /etc/ssh/bench.pub
AuthenticationMethods publickey
PubkeyAuthentication yes
PasswordAuthentication no
KbdInteractiveAuthentication no
PermitRootLogin no
AllowUsers bench@{args.client}
StrictModes yes
PidFile /run/sshd.pid
Subsystem sftp internal-sftp
'''
    files['etc/ssh/sshd_config'] = 0o100644, config.encode()
    init = f'''#!/bin/busybox sh
set -eu
umask 077
export PATH=/usr/bin:/usr/sbin:/bin:/sbin HOME=/root
/bin/busybox chown 1000:1000 /home/bench
/bin/busybox ifconfig {args.interface} {args.address.ip} netmask {args.address.netmask} up
/usr/bin/ssh-keygen -q -t ed25519 -N '' -f /run/sshd_ed25519_key
/usr/bin/ssh-keygen -lf /run/sshd_ed25519_key.pub
/usr/sbin/sshd -e -t -f /etc/ssh/sshd_config
/usr/sbin/sshd -D -e -f /etc/ssh/sshd_config &
printf '%s\\n' 'Send the install bundle with SFTP to /home/bench.' \\
    'Run python3 /installer.py inspect /dev/nvme0n1 to check the drive.'
exec /bin/busybox sh -i
'''
    files['sbin/init'] = 0o100755, init.encode()
    files['installer.py'] = 0o100644, (ROOT / 'scripts/nvme_install.py').read_bytes()
    for path in list(files):
        for parent in PurePosixPath(path).parents:
            if str(parent) != '.':
                files.setdefault(str(parent), (0o40755, b''))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('output', type=Path, help='new TFTP directory')
    parser.add_argument('--source', type=Path, default=ROOT / 'build/rootfs-installed-desktop.cpio')
    parser.add_argument('--kernel', type=Path, default=ROOT / 'build/axiom64.elf')
    parser.add_argument('--authorized-key', type=Path, required=True, help='Ed25519 public key')
    parser.add_argument('--address', type=IPv4Interface, required=True, help='IPv4 address and prefix')
    parser.add_argument('--client', type=IPv4Address, required=True, help='allowed build-host address')
    parser.add_argument('--interface', default='eth0', help='guest Ethernet interface')
    parser.add_argument('--usb-keyboard', action='store_true',
                        help='enable a directly attached USB boot keyboard')
    args = parser.parse_args()
    if args.client not in args.address.network or args.client == args.address.ip:
        parser.error('choose two addresses on the maintenance subnet')
    if not re.fullmatch(r'[a-zA-Z0-9_.-]{1,15}', args.interface) or args.interface.startswith('-'):
        parser.error('invalid interface name')
    public_key = args.authorized_key.read_bytes().strip()
    if not re.fullmatch(rb'ssh-ed25519 [A-Za-z0-9+/]+={0,2}(?: [^\r\n]*)?', public_key):
        parser.error('expected one Ed25519 public key')
    with tempfile.TemporaryDirectory(prefix='axiom64-pxe-installer-') as scratch:
        work = Path(scratch)
        files = runtime_files(args.source, work)
        setup(files, args, public_key)
        archive = work / 'maintenance.cpio'
        write_cpio(archive, files)
        options = ' fbconsole'
        if args.usb_keyboard:
            options += ' usb.xhci=keyboard'
        build_medium('pxe', args.output, args.kernel, archive, options)
    print(f'PXE maintenance tree: {args.output}')


if __name__ == '__main__':
    main()
