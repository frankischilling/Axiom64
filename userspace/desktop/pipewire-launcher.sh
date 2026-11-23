#!/bin/sh
# SPDX-License-Identifier: GPL-3.0-or-later
# @file    userspace/desktop/pipewire-launcher.sh
# @brief   Start audio services for the installed desktop.
# @author  frankischilling
# @date    2026-11-22
#
# Selects the native HDA playback device and starts the session audio services.
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
if ! test -w /dev/snd/pcmC0D0p; then
    exec /usr/libexec/pipewire-launcher
fi

runtime=${XDG_RUNTIME_DIR:?Plasma must set XDG_RUNTIME_DIR}
if test -S "$runtime/pipewire-0"; then
    exit 0
fi

umask 077
PIPEWIRE_CONFIG_DIR=/etc/axiom64/pipewire-hda /usr/bin/pipewire &
server=$!
manager=
pulse=
cleanup() {
    for child in "$pulse" "$manager" "$server"; do
        if test -n "$child"; then
            kill "$child" 2>/dev/null || :
            wait "$child" 2>/dev/null || :
        fi
    done
}
trap cleanup EXIT
trap 'exit 0' HUP INT TERM

for attempt in 1 2 3 4 5; do
    if test -S "$runtime/pipewire-0"; then
        /usr/bin/wireplumber &
        manager=$!
        /usr/bin/pipewire -c pipewire-pulse.conf &
        pulse=$!
        wait "$server"
        exit
    fi
    kill -0 "$server" 2>/dev/null || break
    sleep 1
done
echo 'PipeWire did not open its session socket.' >&2
exit 1
