#!/bin/sh
# SPDX-License-Identifier: GPL-3.0-or-later
# /**
#  * @file    userspace/tests/net/profile-privacy.sh
#  * @brief   Guest network profile privacy test.
#  * @author  frankischilling
#  * @date    2026-11-18
#  *
#  * Checks that process and profile access rules hold on ramfs or ext2 and
#  * preserves the seed data.
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
if [ "$PROFILE_VOLUME" = ext2 ]; then
    /bin/busybox mount -t ext2 /dev/vda /data
    /bin/busybox cmp /data/seed.txt /etc/profile-seed
    root=/data
fi
/bin/abi-static
/bin/abi-dynamic
/bin/profile-privacy-tests "$root/profile-static"
/bin/profile-privacy-dynamic "$root/profile-dynamic"
/bin/busybox rmdir "$root/profile-static" "$root/profile-dynamic"
/bin/busybox sync
if [ "$PROFILE_VOLUME" = ext2 ]; then
    /bin/busybox cmp /data/seed.txt /etc/profile-seed
    /bin/busybox umount /data
    echo PROFILE_PRIVACY_UNMOUNT_PASS
fi
echo "PROFILE_PRIVACY_VOLUME_PASS volume=$PROFILE_VOLUME"
echo AXIOM64_TESTS_PASS
