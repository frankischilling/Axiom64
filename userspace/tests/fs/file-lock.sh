#!/bin/sh
# SPDX-License-Identifier: GPL-3.0-or-later
# /**
#  * @file    userspace/tests/fs/file-lock.sh
#  * @brief   Guest file lock test.
#  * @author  frankischilling
#  * @date    2026-11-18
#  *
#  * Runs static and dynamic lock clients on ramfs and ext2, then checks a
#  * read-only ext2 mount.
#  *
#  * Copyright (C) 2026 frankischilling
#  *
#  * This program is free software: you can redistribute it and/or modify
#  * it under the terms of the GNU General Public License as published by
#  * the Free Software Foundation, either version 3 of the License, or
#  * (at your option) any later version.
#  *
#  * This program is distributed in the hope that it will be useful,
#  * but WITHOUT ANY WARRANTY; without even the implied warranty of
#  * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
#  * GNU General Public License for more details.
#  *
#  * You should have received a copy of the GNU General Public License
#  * along with this program. If not, see <https://gnu.org/licenses/>.
#  */
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
