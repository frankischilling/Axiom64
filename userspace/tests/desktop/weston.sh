#!/bin/sh
# SPDX-License-Identifier: GPL-3.0-or-later
# @file    userspace/tests/desktop/weston.sh
# @brief   Exercise the nested Wayland desktop inside the guest.
# @author  frankischilling
# @date    2026-11-21
#
# Starts a regular-user compositor and checks its socket and client lifecycle.
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
if test "${1:-}" = clients; then
    test "$(id -u)" = 1000
    test "$(stat -c '%u:%g:%a' "$XDG_RUNTIME_DIR")" = 1000:1000:700
    printf '%s\n' "$XDG_RUNTIME_DIR" > runtime-directory
    /usr/bin/wayland-info > wayland-info.log
    grep -q "interface: 'wl_shm'" wayland-info.log
    grep -q "capabilities: pointer keyboard" wayland-info.log
    grep -q "interface: 'xdg_wm_base'" wayland-info.log
    /usr/bin/weston-simple-shm &
    shm=$!
    sleep 2
    kill -0 "$shm"
    echo WESTON_SHM_READY
    while test ! -f show-terminal; do sleep .1; done
    kill "$shm"
    wait "$shm" || true
    /usr/bin/weston-terminal &
    terminal=$!
    sleep 2
    kill -0 "$terminal"
    : > terminal-ready
    while test ! -f input-ok; do sleep .1; done
    echo WESTON_KEYBOARD_PASS
    # Let the compositor disconnect the terminal. Keep this process live until
    # the parent test exercises the launcher's signal handler.
    wait "$terminal"
    exit 0
fi

export PATH=/usr/bin:/bin:/sbin:/usr/sbin HOME=/tmp/player SHELL=/bin/sh
mkdir "$HOME"
chown 1000:1000 "$HOME"
cd "$HOME"
. /etc/x11-session.sh
x11_server
setuidgid player /usr/bin/weston-nested -- /etc/boot-test.sh clients &
launcher=$!
while test ! -s runtime-directory; do kill -0 "$launcher"; sleep .1; done
runtime=$(cat runtime-directory)
if setuidgid other env XDG_RUNTIME_DIR="$runtime" WAYLAND_DISPLAY=wayland-0 /usr/bin/wayland-info; then
    echo 'Weston admitted a client from a foreign UID.'
    exit 1
fi
echo WESTON_FOREIGN_DENIED
IFS= read -r action
test "$action" = terminal
: > show-terminal
while test ! -f terminal-ready; do kill -0 "$launcher"; sleep .1; done
/bin/x11-probe --focus-title Weston
echo WESTON_KEYBOARD_READY
while test ! -f input-ok; do kill -0 "$launcher"; sleep .1; done
# The print and the wait in the ordinary process must have time to run.
sleep 1
kill -TERM "$launcher"
status=0
wait "$launcher" || status=$?
test "$status" -eq 143
test ! -e "$runtime"
echo WESTON_RUNTIME_RETIRED
printf '%s\n' WESTON_TEST_PASS
poweroff -f
