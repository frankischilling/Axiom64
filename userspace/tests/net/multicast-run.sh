#!/bin/sh
# SPDX-License-Identifier: GPL-3.0-or-later
# @file    userspace/tests/net/multicast-run.sh
# @brief   Guest multicast client launcher.
# @author  frankischilling
# @date    2026-11-18
#
# Configures the fixture's address generation and runs the selected multicast
# client.
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
printf '1\n' > /proc/sys/net/ipv6/conf/all/addr_gen_mode
"${AXIOM64_MULTICAST_CLIENT:-/bin/ipv4-multicast-static}"
echo AXIOM64_TESTS_PASS
