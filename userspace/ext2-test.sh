#!/bin/sh
# SPDX-License-Identifier: GPL-3.0-or-later
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
