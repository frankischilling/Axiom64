#!/bin/sh
# SPDX-License-Identifier: GPL-3.0-or-later
# @file    userspace/desktop/x11-session.sh
# @brief   Isolated X11 test session.
# @author  frankischilling
# @date    2026-11-18
#
# Starts the framebuffer X server and provides helpers for launching and
# cleaning up the desktop fixture.
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
# Explicit isolated desktop fixture. Normal login uses an authenticated seat.
x11_server() {
    mkdir -p /tmp/.X11-unix /var/log
    set --
    if ! test -r /usr/lib/dri/swrast_dri.so; then
        set -- -extension GLX
    fi
    /usr/libexec/Xorg :0 -config /etc/X11/xorg.conf -nolisten tcp -noreset -ac -retro -dumbSched \
        "$@" -logfile /var/log/Xorg.0.log > /tmp/xorg-output 2>&1 &
    xorg=$!
    ready=0
    for attempt in $(seq 1 100); do
        if /bin/x11-probe --ready; then ready=1; break; fi
        sleep .1
    done
    if test "$ready" -ne 1; then
        cat /tmp/xorg-output /var/log/Xorg.0.log
        return 1
    fi
    export DISPLAY=:0
}
x11_clients() {
    /usr/bin/twm -f /etc/X11/system.twmrc > /tmp/twm-output 2>&1 &
    twm=$!
    sleep .2
    /usr/bin/xeyes -geometry 120x80+850+50 > /tmp/xeyes-output 2>&1 &
    xeyes=$!
    /usr/bin/xterm -title 'Axiom64 - Bash' -geometry 90x32+40+50 -fn fixed -e /bin/bash /etc/xterm-session.sh > /tmp/xterm-output 2>&1 &
    xterm=$!
}
x11_stop() {
    for process in "${xterm:-}" "${xeyes:-}" "${twm:-}" "${xorg:-}"; do
        if test -n "$process"; then kill "$process" 2>/dev/null || true; fi
    done
    wait 2>/dev/null || true
}
