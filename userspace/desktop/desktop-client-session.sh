#!/bin/sh
# SPDX-License-Identifier: GPL-3.0-or-later
# @file    userspace/desktop/desktop-client-session.sh
# @brief   Authenticated X11 client session.
# @author  frankischilling
# @date    2026-11-18
#
# Starts the window manager and clients with a seat authorization file and
# cleans them up when the terminal exits.
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
export DISPLAY=:0
export XAUTHORITY=/run/axiom64-seat/client.auth
cleanup() {
    for process in "${xterm:-}" "${xeyes:-}" "${twm:-}"; do
        if test -n "$process"; then kill "$process" 2>/dev/null || true; fi
    done
    wait 2>/dev/null || true
}
trap cleanup EXIT
trap 'exit 0' HUP INT TERM
/usr/bin/twm -f /etc/X11/system.twmrc &
twm=$!
sleep .2
/usr/bin/xeyes -geometry 120x80+850+50 &
xeyes=$!
/usr/bin/xterm -title 'Axiom64 - Terminal' -geometry 90x32+40+50 -fn fixed -e /usr/libexec/desktop-terminal &
xterm=$!
wait "$xterm"
