#!/bin/sh
# SPDX-License-Identifier: GPL-3.0-or-later
# @file    userspace/services/system-bus.sh
# @brief   Prepare the service account and run the system D-Bus daemon.
# @author  frankischilling
# @date    2026-11-21
#
# Leaves the foreground daemon under init supervision.
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
/usr/bin/dbus-uuidgen --ensure=/etc/machine-id
while test ! -L /etc/axiom64/accounts/current; do
    sleep 1
done
/usr/bin/accountctl ensure-messagebus
prepare_policykit() {
    /usr/bin/accountctl ensure-polkitd || return 1
    for directory in /etc/polkit-1/rules.d /usr/share/polkit-1/rules.d; do
        test -d "$directory" && ! test -L "$directory" || return 1
        case "$(stat -c '%u:%g:%a' "$directory")" in
            498:498:700) ;;
            0:0:700)
                chown 498:498 "$directory" || return 1
                ;;
            *) return 1 ;;
        esac
    done
}
if test -x /usr/lib/polkit-1/polkitd && ! prepare_policykit; then
    printf '%s\n' 'PolicyKit requires its service account and private rules directories.' >&2
fi
if test -x /usr/libexec/elogind/elogind &&
    ! grep -q '^cgroup2 /sys/fs/cgroup cgroup2 ' /proc/mounts; then
    if ! mkdir -p /sys/fs/cgroup ||
        ! mount -t cgroup2 -o nosuid,nodev,noexec cgroup2 /sys/fs/cgroup; then
        printf '%s\n' 'Could not mount the unified hierarchy for elogind.' >&2
    fi
fi
helper=/usr/libexec/dbus-daemon-launch-helper
if test -e "$helper"; then
    if ! test -f "$helper" || test -L "$helper"; then
        printf '%s\n' 'D-Bus launch helper must be a regular executable.' >&2
        exit 1
    fi
    case "$(stat -c '%u:%g:%a' "$helper")" in
        0:81:4750) ;;
        0:0:4750)
            chown 0:81 "$helper"
            chmod 4750 "$helper"
            ;;
        *)
            printf '%s\n' 'D-Bus launch helper has unexpected ownership or permissions.' >&2
            exit 1
            ;;
    esac
fi
directory=/run/dbus
mkdir -p "$directory"
if test -L "$directory" || test "$(stat -c '%u:%g:%a' "$directory")" != 0:0:755; then
    printf '%s\n' 'D-Bus requires a root-owned /run/dbus directory with mode 0755.' >&2
    exit 1
fi
# Only init manages the foreground daemon. Remove a node left by a crash.
if test -S "$directory/system_bus_socket"; then
    rm "$directory/system_bus_socket"
fi
exec /usr/bin/dbus-daemon --system --nofork --nopidfile --nosyslog
