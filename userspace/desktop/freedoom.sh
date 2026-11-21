#!/bin/sh
# SPDX-License-Identifier: GPL-3.0-or-later
# @file    userspace/desktop/freedoom.sh
# @brief   Launch a vendored Freedoom campaign.
# @author  frankischilling
# @date    2026-11-21
#
# Selects the shipped IWAD and the available playback backend.
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
case ${1:-2} in
    1|2) phase=${1:-2} ;;
    *) printf '%s\n' 'Usage: freedoom [1|2] [Chocolate Doom options]' >&2; exit 2 ;;
esac
if test "$#" -ne 0; then shift; fi
export SDL_RENDER_DRIVER=${SDL_RENDER_DRIVER:-software}
if test -w /dev/dsp; then
    export SDL_AUDIODRIVER=${SDL_AUDIODRIVER:-dsp}
fi
exec /usr/bin/chocolate-doom -window -iwad "/usr/share/games/doom/freedoom$phase.wad" "$@"
