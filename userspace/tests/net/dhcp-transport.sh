#!/bin/sh
# SPDX-License-Identifier: GPL-3.0-or-later
# /**
#  * @file    userspace/tests/net/dhcp-transport.sh
#  * @brief   Guest DHCP transport test.
#  * @author  frankischilling
#  * @date    2026-11-18
#  *
#  * Configures IPv6 address generation for the fixture and runs the DHCP
#  * transport client.
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
printf '1\n' > /proc/sys/net/ipv6/conf/all/addr_gen_mode
/bin/dhcp-transport-tests
echo AXIOM64_TESTS_PASS
