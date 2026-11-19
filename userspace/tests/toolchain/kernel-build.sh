#!/bin/sh
# SPDX-License-Identifier: GPL-3.0-or-later
# @file userspace/tests/toolchain/kernel-build.sh
# @brief Build the complete kernel with the installed guest toolchain.
# @author frankischilling
# @date 2026-11-19

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
