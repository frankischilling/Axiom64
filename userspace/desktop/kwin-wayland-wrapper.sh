#!/bin/sh
# SPDX-License-Identifier: GPL-3.0-or-later
# @file    userspace/desktop/kwin-wayland-wrapper.sh
# @brief   Size the nested compositor for the authenticated X11 seat.
# @author  frankischilling
# @date    2026-11-24
#
# Passes the parent screen size to the installed KWin wrapper.
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
if test -z "${WAYLAND_DISPLAY:-}" && size=$(/usr/libexec/axiom64-x11-screen-size); then
    width=${size%% *}
    height=${size#* }
    printf 'Axiom64 X11 screen: %sx%s\n' "$width" "$height"
    set -- --width "$width" --height "$height" "$@"
fi
exec /usr/bin/kwin_wayland_wrapper "$@"
