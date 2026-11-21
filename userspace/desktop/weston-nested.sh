#!/bin/sh
# SPDX-License-Identifier: GPL-3.0-or-later
# @file    userspace/desktop/weston-nested.sh
# @brief   Run a Weston desktop on the active X11 display.
# @author  frankischilling
# @date    2026-11-21
#
# Gives each compositor a private socket directory and retries startup while
# its X11 window and Wayland socket are being created.
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
if test -z "${DISPLAY:-}"; then
    printf '%s\n' 'Start Weston from an X11 desktop or an X11 terminal.' >&2
    exit 1
fi
if test "$#" -gt 0; then
    if test "$1" != -- || test "$#" -lt 2; then
        printf '%s\n' 'Usage: weston-nested [-- COMMAND [ARGUMENT ...]]' >&2
        exit 2
    fi
    shift
fi
umask 077
runtime=$(mktemp -d /tmp/axiom64-wayland.XXXXXXXX)
export XDG_RUNTIME_DIR="$runtime" WAYLAND_DISPLAY=wayland-0
cleanup() {
    for pid in "${client:-}" "${server:-}"; do
        if test -n "$pid"; then kill "$pid" 2>/dev/null || true; fi
    done
    wait 2>/dev/null || true
    rm -rf -- "$runtime"
}
trap cleanup EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM
/usr/bin/weston --backend=x11 --renderer=pixman --shell=desktop-shell.so --no-config \
    --socket="$WAYLAND_DISPLAY" --width=800 --height=600 &
server=$!
if test "$#" -gt 0; then
    attempts=0
    while test ! -S "$runtime/$WAYLAND_DISPLAY"; do
        if ! kill -0 "$server" 2>/dev/null || test "$attempts" -ge 200; then
            printf '%s\n' 'Weston did not create its Wayland socket.' >&2
            exit 1
        fi
        attempts=$((attempts + 1))
        sleep .1
    done
    "$@" &
    client=$!
fi
status=0
wait "$server" || status=$?
server=
exit "$status"
