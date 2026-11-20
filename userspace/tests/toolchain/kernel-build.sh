#!/bin/sh
# SPDX-License-Identifier: GPL-3.0-or-later
#
# @file    userspace/tests/toolchain/kernel-build.sh
# @brief   Compile and export the Axiom64 kernel from the guest.
# @author  frankischilling
# @date    2026-11-19
#
# Verifies the imported inputs before building and records the kernel digest.
# The temporary ext2 volume provides a checked export for the next boot.
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

set -eu
export LC_ALL=C PATH=/bin:/usr/bin:/sbin:/usr/sbin
mkdir -p /mnt/kernel-export
mount -t ext2 /dev/vda /mnt/kernel-export
cd /root/kernel-build
sha256sum -c inputs.sha256 > /mnt/kernel-export/source-check.log
test ! -e build
gcc --version
g++ --version
nasm -v
ld --version
make --version
if test -f build-tools.sh; then
    /bin/sh build-tools.sh
    /tmp/guest-tools/make -j2 NASM=/tmp/guest-tools/nasm build/axiom64.elf
else
    make -j2 build/axiom64.elf
fi
test -s build/axiom64.elf
if test -f build-system.sh; then
    /bin/sh build-system.sh
fi
cp build/axiom64.elf /mnt/kernel-export/axiom64.elf
sha256sum build/axiom64.elf /mnt/kernel-export/axiom64.elf
sync
umount /mnt/kernel-export
echo AXIOM64_KERNEL_EXPORTED
echo AXIOM64_TESTS_PASS
