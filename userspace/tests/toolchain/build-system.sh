#!/bin/sh
# SPDX-License-Identifier: GPL-3.0-or-later
# @file userspace/tests/toolchain/build-system.sh
# @brief Build init, a small root filesystem, and a bootable ISO from the guest.
# @author frankischilling
# @date 2026-11-19

set -eu
set -o pipefail
project=/root/kernel-build
export_dir=/mnt/kernel-export
root=/tmp/guest-root
media=/tmp/guest-iso
mkdir -p "$root" "$media/boot/limine" "$media/EFI/BOOT"
cd "$root"
mkdir bin dev etc lib proc run sbin sys tmp
chmod 1777 tmp
gcc -std=c11 -O2 -g -Wall -Wextra -Werror -static \
    "$project/userspace/init/main.c" "$project/userspace/init/console.c" -o sbin/init
gcc -std=c11 -O2 -g -Wall -Wextra -Werror -static "$project/userspace/tests/abi/abi.c" -o bin/abi-static
gcc -std=c11 -O2 -g -Wall -Wextra -Werror '-DABI_LINKAGE="dynamic"' \
    "$project/userspace/tests/abi/abi.c" -o bin/abi-dynamic
cp /bin/busybox bin/busybox
cp /lib/ld-musl-x86_64.so.1 lib/ld-musl-x86_64.so.1
ln -s /bin/busybox bin/sh
ln -s /lib/ld-musl-x86_64.so.1 lib/libc.so
printf '%s\n' '#!/bin/sh' 'set -eu' '/bin/abi-static' '/bin/abi-dynamic' 'echo AXIOM64_TESTS_PASS' > etc/boot-test.sh
chmod 755 etc/boot-test.sh
find bin dev etc lib proc run sbin sys tmp -print0 | sort -z | \
    cpio -o -0 -H newc --renumber-inodes --ignore-devno > "$export_dir/rootfs.cpio"
sha256sum sbin/init bin/abi-static bin/abi-dynamic
echo AXIOM64_GUEST_ROOTFS_BUILT

tar xf "$project/limine-binary.tar.gz" -C /tmp
make -C /tmp/limine-binary CC=gcc
cp /tmp/limine-binary/limine-bios.sys /tmp/limine-binary/limine-bios-cd.bin \
    /tmp/limine-binary/limine-uefi-cd.bin /tmp/limine-binary/LICENSE "$media/boot/limine/"
cp /tmp/limine-binary/BOOTX64.EFI "$media/EFI/BOOT/"
sed 's/init=\/sbin\/init/init=\/sbin\/init test suite=full/' "$project/boot/limine.conf" > "$media/boot/limine/limine.conf"
cp "$project/build/axiom64.elf" "$media/boot/axiom64.elf"
cp "$export_dir/rootfs.cpio" "$media/boot/rootfs.cpio"
xorriso -as mkisofs -quiet -R -J -b boot/limine/limine-bios-cd.bin -no-emul-boot \
    -boot-load-size 4 -boot-info-table --efi-boot boot/limine/limine-uefi-cd.bin \
    --efi-boot-part --efi-boot-image --protective-msdos-label "$media" -o "$export_dir/guest-built.iso"
/tmp/limine-binary/limine bios-install "$export_dir/guest-built.iso"
sha256sum "$export_dir/rootfs.cpio" "$export_dir/guest-built.iso"
echo AXIOM64_GUEST_IMAGE_BUILT
