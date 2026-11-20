#!/bin/sh
# SPDX-License-Identifier: GPL-3.0-or-later
# /**
#  * @file    userspace/tests/threads/run.sh
#  * @brief   Guest threading test selection.
#  * @author  frankischilling
#  * @date    2026-11-18
#  *
#  * Runs the selected thread, futex, lifecycle, and I/O workloads and builds the
#  * native thread test in a full run.
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
if test "${AXIOM64_PHASE:-none}" = cond; then
    /bin/thread-static cond
elif test "${AXIOM64_PHASE:-none}" = io; then
    failed=0
    /bin/thread-io-static --guest || failed=1
    /bin/thread-io-dynamic --guest || failed=1
    test "$failed" = 0
else
    /bin/thread-static
    /bin/thread-dynamic
    /bin/futex-static
    /bin/futex-dynamic
    /bin/lifecycle-static
    /bin/lifecycle-dynamic
    /bin/thread-io-static --guest
    /bin/thread-io-dynamic --guest
    g++ -std=c++20 -O2 -pthread /root/toolchain-test/threads.cpp -o /tmp/native-threads
    /tmp/native-threads
fi
echo AXIOM64_TESTS_PASS
