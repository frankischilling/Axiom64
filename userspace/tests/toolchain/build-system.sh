#!/bin/sh
# SPDX-License-Identifier: GPL-3.0-or-later
#
# @file    userspace/tests/toolchain/build-system.sh
# @brief   Create a bootable test image inside Axiom64.
# @author  frankischilling
# @date    2026-11-19
#
# Builds the libc, init and both ABI clients, then writes the initramfs and ISO.
# A native Limine build installs the BIOS portion of the exported media.
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
set -o pipefail
project=/root/kernel-build
export_dir=/mnt/kernel-export
# Keep the installed headers and libraries off the compiler's RAM filesystem.
root=$export_dir/guest-root
media=/tmp/guest-iso
mkdir -p "$root" "$media/boot/limine" "$media/EFI/BOOT"
/bin/sh "$project/build-runtime.sh" "$root"
cc=$project/guest-musl-gcc
workspace=/tmp/guest-busybox
mkdir "$workspace"
mount -t ramfs none "$workspace"
export TMPDIR="$workspace/tmp"
mkdir "$TMPDIR"
tar xf "$project/busybox.tar.bz2" -C "$workspace"
cd "$workspace"/busybox-*/
make defconfig < /dev/null
/bin/sh "$project/configure-busybox.sh" .config
make oldconfig < /dev/null
make -j2 "CC=$cc" HOSTCC=gcc < /dev/null
./busybox --list > "$workspace/applets"
busybox_source=$PWD

cd "$root"
mkdir -p bin dev etc lib proc run sbin sys tmp usr/share/licenses/BusyBox usr/share/doc/BusyBox
chmod 1777 tmp
"$cc" -std=c11 -O2 -g -Wall -Wextra -Werror -static \
    "$project/userspace/init/main.c" "$project/userspace/init/console.c" -o sbin/init
"$cc" -std=c11 -O2 -g -Wall -Wextra -Werror -static \
    "$project/userspace/tests/abi/abi.c" -Wl,-Map,"$workspace/abi-static.map" -o bin/abi-static
"$cc" -std=c11 -O2 -g -Wall -Wextra -Werror '-DABI_LINKAGE="dynamic"' \
    "$project/userspace/tests/abi/abi.c" -Wl,-Map,"$workspace/abi-dynamic.map" -o bin/abi-dynamic
grep -Fx "LOAD $root/usr/lib/libc.a" "$workspace/abi-static.map"
grep -Fx "LOAD $root/usr/lib/libc.so" "$workspace/abi-dynamic.map"
cp "$busybox_source/busybox" bin/busybox
cp "$busybox_source/LICENSE" usr/share/licenses/BusyBox/LICENSE
cp "$busybox_source/.config" usr/share/doc/BusyBox/config
while IFS= read -r applet; do
    if [ "$applet" != busybox ]; then
        ln -s /bin/busybox "bin/$applet"
    fi
done < "$workspace/applets"
unset TMPDIR
umount "$workspace"
cat > etc/boot-test.sh <<'BOOT'
#!/bin/sh
set -eu
printf 'alpha\nbeta\n' > /tmp/shell-data
test "$(cat /tmp/shell-data | wc -l)" -eq 2
cp /tmp/shell-data /tmp/shell-copy
cmp /tmp/shell-data /tmp/shell-copy
rm /tmp/shell-data /tmp/shell-copy
echo BUSYBOX_SHELL_PASS
/bin/abi-static
/bin/abi-dynamic
echo AXIOM64_TESTS_PASS
BOOT
chmod 755 etc/boot-test.sh
find bin dev etc lib proc run sbin sys tmp usr -print0 | sort -z | \
    cpio -o -0 -H newc --renumber-inodes --ignore-devno > "$export_dir/rootfs.cpio"
sha256sum sbin/init bin/abi-static bin/abi-dynamic bin/busybox \
    usr/share/licenses/BusyBox/LICENSE usr/share/doc/BusyBox/config \
    lib/ld-musl-x86_64.so.1 usr/lib/libc.a usr/lib/libssp_nonshared.a usr/lib/Scrt1.o usr/lib/musl-gcc.specs \
    usr/share/licenses/musl/COPYRIGHT
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
