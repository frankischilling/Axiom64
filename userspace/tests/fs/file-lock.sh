#!/bin/sh
# SPDX-License-Identifier: GPL-3.0-or-later
set -eu
echo FILE_LOCK_FILESYSTEM ramfs
/bin/file-lock-static /tmp/locks-static --guest
/bin/file-lock-dynamic /tmp/locks-dynamic --guest
/bin/busybox mkdir -p /tmp/lock-disk
/bin/busybox mount -t ext2 /dev/vda /tmp/lock-disk
echo FILE_LOCK_FILESYSTEM ext2
/bin/file-lock-static /tmp/lock-disk/locks-static --guest
/bin/file-lock-dynamic /tmp/lock-disk/locks-dynamic --guest
/bin/busybox sync
/bin/busybox umount /tmp/lock-disk
/bin/busybox mount -t ext2 -o ro /dev/vda /tmp/lock-disk
/bin/file-lock-static --readonly /tmp/lock-disk/seed.txt
/bin/file-lock-dynamic --readonly /tmp/lock-disk/seed.txt
/bin/busybox umount /tmp/lock-disk
echo FILE_LOCK_UNMOUNT_PASS
echo AXIOM64_TESTS_PASS
