#!/bin/sh
# SPDX-License-Identifier: GPL-3.0-or-later
# @file    userspace/tests/net/pci_bridge_windows.sh
# @brief   Checks guest interfaces after a PCI bridge blocks one adapter.
# @author  frankischilling
# @date    2026-11-21
#
# Confirms that the unaffected adapter remains available in userspace.
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
/bin/busybox ifconfig eth0
if /bin/busybox ifconfig eth1; then
    echo 'Unexpected bridged Ethernet interface'
    exit 1
fi
echo AXIOM64_TESTS_PASS
