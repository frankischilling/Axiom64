#!/bin/sh
# SPDX-License-Identifier: GPL-3.0-or-later
# @file    userspace/desktop/xorg-seat.sh
# @brief   Start Xorg with the input configuration available on this boot.
# @author  frankischilling
# @date    2026-11-23
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
# along with this program. If not, see <https://www.gnu.org/licenses/>.

set -eu
config=/etc/X11/xorg.conf
discovery=/etc/X11/xorg-udev.conf
if test -r "$discovery" && test -x /sys/class/input; then
    attempt=0
    while test "$attempt" -lt 20; do
        if test -r /run/axiom64-input-ready; then
            config=$discovery
            break
        fi
        sleep 0.1
        attempt=$((attempt + 1))
    done
fi
exec /usr/libexec/Xorg -config "$config" "$@"
