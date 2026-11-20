#!/bin/sh
# SPDX-License-Identifier: GPL-3.0-or-later
# /**
#  * @file    userspace/tests/net/ipv6_host.sh
#  * @brief   Guest IPv6 host fixture setup.
#  * @author  frankischilling
#  * @date    2026-11-18
#  *
#  * Sets interface policy for controlled address and DAD observations before
#  * running the selected client.
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
# These cohorts own their manual addresses and DAD packets. Match the native
# fixture before its readiness barrier while retaining the normal DAD interval.
printf '1\n' > /proc/sys/net/ipv6/conf/all/addr_gen_mode
for scope in /proc/sys/net/ipv6/conf/*; do
    printf '0\n' > "$scope/accept_ra"
    printf '0\n' > "$scope/autoconf"
    printf '0\n' > "$scope/enhanced_dad"
    printf '0\n' > "$scope/router_solicitations"
done
printf '1\n' > /proc/sys/net/ipv6/conf/all/disable_ipv6
printf '0\n' > /proc/sys/net/ipv6/conf/all/disable_ipv6
/bin/"$AXIOM64_IPV6_PROGRAM"
echo AXIOM64_TESTS_PASS
