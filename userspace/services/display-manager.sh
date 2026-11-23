#!/bin/sh
# SPDX-License-Identifier: GPL-3.0-or-later
# @file    userspace/services/display-manager.sh
# @brief   Start the installed display manager after console provisioning.
# @author  frankischilling
# @date    2026-11-22
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
umask 022
while ! test -L /etc/axiom64/accounts/current || ! test -S /run/dbus/system_bus_socket; do
    sleep 1
done
/usr/bin/accountctl ensure-sddm
home=/var/lib/sddm
directory=/var/run/sddm
mkdir -p "$directory"
if test -L "$home" || test "$(stat -c '%u:%g:%a' "$home")" != 499:499:700 ||
    test -L "$directory" || test "$(stat -c '%u:%g:%a' "$directory")" != 0:0:755; then
    printf '%s\n' 'SDDM requires a private greeter home and a root-owned runtime directory.' >&2
    exit 1
fi
exec /usr/bin/sddm
