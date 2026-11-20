#!/bin/sh
# SPDX-License-Identifier: GPL-3.0-or-later
# @file    userspace/tests/fs/ext2.sh
# @brief   Guest ext2 filesystem test.
# @author  frankischilling
# @date    2026-11-18
#
# Checks a command-line mount and read-only remount before running the selected
# ext2 test phase.
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
if [ "$AXIOM64_PHASE" = write ]; then
    mkdir -p /tmp/ext2-cli
    mount -t ext2 /dev/vda /tmp/ext2-cli
    echo command-line-mount > /tmp/ext2-cli/cli.txt
    sync
    umount /tmp/ext2-cli
    mount -t ext2 -o ro /dev/vda /tmp/ext2-cli
    test "$(cat /tmp/ext2-cli/cli.txt)" = command-line-mount
    umount /tmp/ext2-cli
    echo EXT2_COMMANDS_PASS
fi
exec /bin/ext2-tests "$AXIOM64_PHASE"
