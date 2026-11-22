#!/bin/sh
# SPDX-License-Identifier: GPL-3.0-or-later
# @file    userspace/desktop/plasma-session.sh
# @brief   Start KDE Plasma from the authenticated desktop seat.
# @author  frankischilling
# @date    2026-11-22
#
# Runs KWin on the seat's X11 display until it can use native graphics.
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
state=${XDG_STATE_HOME:-$HOME/.local/state}/axiom64
mkdir -p "$state"
XDG_RUNTIME_DIR=$(mktemp -d /tmp/axiom64-plasma-XXXXXX)
export XDG_RUNTIME_DIR
trap 'rm -rf -- "$XDG_RUNTIME_DIR"' EXIT
trap 'exit 0' HUP INT TERM

export QT_QUICK_BACKEND=software LIBGL_ALWAYS_SOFTWARE=1
export QT_QPA_PLATFORMTHEME=kde XCURSOR_THEME=breeze_cursors
/usr/bin/startplasma-wayland > "$state/plasma-session.log" 2>&1
