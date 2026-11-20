#!/bin/sh
# SPDX-License-Identifier: GPL-3.0-or-later
# /**
#  * @file    userspace/tests/net/ownership.sh
#  * @brief   Guest file ownership test.
#  * @author  frankischilling
#  * @date    2026-11-18
#  *
#  * Runs both linkage variants on ramfs or ext2 and verifies that the ext2 seed
#  * remains intact.
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
set -e
root=/tmp
if [ "$OWNERSHIP_VOLUME" = ext2 ]; then
    /bin/busybox mount -t ext2 /dev/vda /data
    /bin/busybox cmp /data/seed.txt /etc/ownership-seed
    root=/data
fi
/bin/ownership-tests "$root/owner-static"
/bin/ownership-dynamic "$root/owner-dynamic"
/bin/busybox sync
if [ "$OWNERSHIP_VOLUME" = ext2 ]; then
    /bin/busybox cmp /data/seed.txt /etc/ownership-seed
    /bin/busybox umount /data
    echo OWNERSHIP_UNMOUNT_PASS
fi
echo "OWNERSHIP_VOLUME_PASS volume=$OWNERSHIP_VOLUME"
echo AXIOM64_TESTS_PASS
