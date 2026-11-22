#!/bin/sh
# SPDX-License-Identifier: GPL-3.0-or-later
# @file    userspace/desktop/plasma-shell.sh
# @brief   Start the Plasma shell after Activities has answered.
# @author  frankischilling
# @date    2026-11-22
#
# Uses the display and session bus set up by KWin.
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
umask 077

start_activities() {
    # Activation completes when the daemon owns its name on this session bus.
    if test -n "${DBUS_SESSION_BUS_ADDRESS:-}" &&
        /usr/bin/dbus-update-activation-environment WAYLAND_DISPLAY DISPLAY XAUTHORITY \
            XDG_RUNTIME_DIR XDG_SESSION_TYPE &&
        /usr/bin/dbus-send --session --print-reply --reply-timeout=120000 \
            --dest=org.freedesktop.DBus /org/freedesktop/DBus \
            org.freedesktop.DBus.StartServiceByName string:org.kde.ActivityManager uint32:0 \
            >/dev/null; then
        printf '%s\n' 'Plasma Activities is ready.'
    else
        printf '%s\n' 'Could not start Plasma Activities before launching the shell.' >&2
    fi
}

state=${XDG_STATE_HOME:-$HOME/.local/state}/axiom64
if mkdir -p "$state" && start_activities > "$state/plasma-activities.log" 2>&1; then
    :
else
    start_activities
fi
exec /usr/bin/plasmashell "$@"
