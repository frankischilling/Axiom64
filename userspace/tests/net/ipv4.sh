#!/bin/sh
# SPDX-License-Identifier: GPL-3.0-or-later
# /**
#  * @file    userspace/tests/net/ipv4.sh
#  * @brief   Guest IPv4 socket and command-line tests.
#  * @author  frankischilling
#  * @date    2026-11-18
#  *
#  * Runs the IPv4 client and uses command-line tools to verify both interfaces
#  * outside fault mode.
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
/bin/ipv4-tests
if [ "${AXIOM64_IP_FAULT:-0}" = 1 ]; then
    echo AXIOM64_TESTS_PASS
    exit 0
fi
/bin/busybox ifconfig eth0 10.23.1.2 netmask 255.255.255.0 up
/bin/busybox ifconfig eth1 10.23.2.2 netmask 255.255.255.0 up
/bin/busybox route add default gw 10.23.1.1
/bin/busybox ping -n -c 2 -w 5 -I eth0 10.23.1.1
/bin/busybox ping -n -c 2 -w 5 -I eth1 10.23.2.1
/bin/busybox route del default gw 10.23.1.1
echo IPV4_BUSYBOX_PASS
echo AXIOM64_TESTS_PASS
