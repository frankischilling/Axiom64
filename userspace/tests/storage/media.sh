#!/bin/sh
# SPDX-License-Identifier: GPL-3.0-or-later
# @file    userspace/tests/storage/media.sh
# @brief   Format and reopen a guest-owned ext2 image.
# @author  frankischilling
# @date    2026-11-20
#
# Creates a disk image in Axiom64 and verifies its use after further boots.
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

case "$AXIOM64_PHASE" in
    write)
        /bin/busybox mount -t ext2 /dev/vda /mnt/media
        /bin/busybox truncate -s 32M /mnt/media/guest.ext2
        /bin/busybox mke2fs -F -b 4096 -I 128 -L GUESTMEDIA /mnt/media/guest.ext2
        /bin/busybox sha256sum /mnt/media/guest.ext2
        /bin/busybox umount /mnt/media
        echo GUEST_EXT2_MEDIA_CREATED
        ;;
    verify)
        /bin/busybox mount -t ext2 /dev/vda /mnt/media
        printf '%s\n' 'formatted inside Axiom64' > /mnt/media/proof.txt
        /bin/busybox umount /mnt/media
        echo GUEST_EXT2_MEDIA_MOUNTED
        ;;
    readonly)
        /bin/busybox mount -t ext2 -o ro /dev/vda /mnt/media
        test "$(/bin/busybox cat /mnt/media/proof.txt)" = 'formatted inside Axiom64'
        /bin/busybox umount /mnt/media
        echo GUEST_EXT2_MEDIA_REBOOT_PASS
        ;;
    *)
        exit 1
        ;;
esac
/bin/busybox poweroff -f
