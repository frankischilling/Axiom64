#!/bin/sh
# SPDX-License-Identifier: GPL-3.0-or-later
# /**
#  * @file    userspace/tests/boot.sh
#  * @brief   Initial guest smoke test.
#  * @author  frankischilling
#  * @date    2026-11-18
#  *
#  * Runs the installed ABI, threading, and core application checks during a test
#  * boot.
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
/bin/abi-static
/bin/abi-dynamic
/bin/thread-static
/bin/thread-dynamic
/bin/futex-static
/bin/futex-dynamic
/bin/lifecycle-static
/bin/lifecycle-dynamic
/bin/thread-io-static --guest
/bin/thread-io-dynamic --guest
/bin/ipc-tests
/bin/signal-tests
/bin/vfs-tests
echo 'BUSYBOX_ASH_STARTED'
uname -a
printf 'alpha\nbeta\n' > /tmp/shell-data
test "$(cat /tmp/shell-data | wc -l)" -eq 2
test "$(printf 'hello world' | tr a-z A-Z)" = 'HELLO WORLD'
mkdir /tmp/shell-dir
cp /tmp/shell-data /tmp/shell-dir/copy
cmp /tmp/shell-data /tmp/shell-dir/copy
rm /tmp/shell-dir/copy
rmdir /tmp/shell-dir
/bin/busybox sh -c 'exit 7' && exit 1 || test "$?" -eq 7
echo 'BUSYBOX_SHELL_PASS'
if test "${AXIOM64_SUITE:-full}" = abi; then
    echo AXIOM64_TESTS_PASS
    exit 0
fi
gcc --version
as --version
ld --version
make -C /root/toolchain-test test
echo 'NATIVE_TOOLCHAIN_PASS'
/bin/busybox sh /etc/desktop-test.sh
