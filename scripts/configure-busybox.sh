#!/bin/sh
# SPDX-License-Identifier: GPL-3.0-or-later
#
# @file    scripts/configure-busybox.sh
# @brief   Select the BusyBox configuration used by Axiom64.
# @author  frankischilling
# @date    2026-11-20
#
# Apply the same BusyBox options in hosted and native package builds.
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
config=$1
sed -i \
    -e '/^CONFIG_STATIC=/d' -e '/^# CONFIG_STATIC is not set$/d' \
    -e '/^CONFIG_TC=/d' -e '/^# CONFIG_TC is not set$/d' \
    -e '/^CONFIG_SELINUX=/d' -e '/^# CONFIG_SELINUX is not set$/d' "$config"
printf '%s\n' 'CONFIG_STATIC=y' '# CONFIG_TC is not set' '# CONFIG_SELINUX is not set' >> "$config"
