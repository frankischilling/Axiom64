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
if test -d /usr/share/i18n/locales/musl; then
    export MUSL_LOCPATH="${MUSL_LOCPATH:-/usr/share/i18n/locales/musl}"
fi
if test "${1:-}" = --display-manager; then
    : "${DISPLAY:?SDDM did not set DISPLAY.}" "${XAUTHORITY:?SDDM did not set XAUTHORITY.}"
else
    export DISPLAY=:0
    export XAUTHORITY=/run/axiom64-seat/client.auth
fi
cleanup() {
    for process in "${terminal:-}" "${xeyes:-}" "${twm:-}"; do
        if test -n "$process"; then kill "$process" 2>/dev/null || true; fi
    done
    wait 2>/dev/null || true
}
trap cleanup EXIT
trap 'exit 0' HUP INT TERM
eduroam=/usr/share/axiom64/auto-eduroam
if test -n "${HOME:-}" && test -d "$eduroam"; then
    ln -sT "$eduroam" "$HOME/auto-eduroam" 2>/dev/null || true
fi
seed_desktop() {
    test -n "${HOME:-}" || return 0
    state="$HOME/.local/share/axiom64/$1"
    shift
    test ! -e "$state" || return 0
    mkdir -p "$HOME/Desktop" "${state%/*}" || return
    for entry in "$@"; do
        test -f "$entry" || continue
        target="$HOME/Desktop/${entry##*/}"
        if test ! -e "$target" && test ! -L "$target"; then
            cp "$entry" "$target" || return
        fi
    done
    : > "$state"
}
seed_desktop desktop-shortcuts /etc/skel/Desktop/freedoom-*.desktop ||
    printf '%s\n' 'Could not install the Freedoom shortcuts.' >&2
seed_desktop weston-shortcut /etc/skel/Desktop/weston-nested.desktop ||
    printf '%s\n' 'Could not install the Weston shortcut.' >&2
if test -x /usr/bin/thunar; then
    seed_desktop thunar-shortcut /etc/skel/Desktop/thunar.desktop ||
        printf '%s\n' 'Could not install the Thunar shortcut.' >&2
    if test -n "${HOME:-}" && test -z "${GDK_PIXBUF_MODULE_FILE:-}"; then
        pixbuf_dir="${XDG_CACHE_HOME:-$HOME/.cache}/gdk-pixbuf"
        if mkdir -p "$pixbuf_dir" && pixbuf_tmp=$(mktemp "$pixbuf_dir/loaders.XXXXXX"); then
            if /usr/bin/gdk-pixbuf-query-loaders > "$pixbuf_tmp" &&
                mv -f "$pixbuf_tmp" "$pixbuf_dir/loaders.cache"; then
                GDK_PIXBUF_MODULE_FILE="$pixbuf_dir/loaders.cache"
                export GDK_PIXBUF_MODULE_FILE
            else
                rm -f "$pixbuf_tmp"
            fi
        fi
    fi
fi
if test -x /usr/bin/kitty; then
    seed_desktop kitty-shortcut /etc/skel/Desktop/kitty.desktop ||
        printf '%s\n' 'Could not install the kitty shortcut.' >&2
fi
if test -x /usr/bin/btop; then
    seed_desktop btop-shortcut /etc/skel/Desktop/btop.desktop ||
        printf '%s\n' 'Could not install the btop shortcut.' >&2
    if test -n "${HOME:-}"; then
        config_dir="${XDG_CONFIG_HOME:-$HOME/.config}/btop"
        config="$config_dir/btop.conf"
        if test ! -e "$config" && test ! -L "$config"; then
            (umask 077; mkdir -p "$config_dir" && set -C && printf '%s\n' 'use_fstab = False' > "$config") ||
                printf '%s\n' 'Could not write the btop defaults.' >&2
        fi
    fi
fi
if test -x /usr/libexec/axiom64-plasma-session; then
    exec /usr/libexec/axiom64-plasma-session
fi
/usr/bin/twm -f /etc/X11/system.twmrc &
twm=$!
sleep .2
/usr/bin/xeyes -geometry 120x80+850+50 &
xeyes=$!
if test -x /usr/bin/kitty; then
    /usr/bin/kitty --title 'Axiom64 - Terminal' -o remember_window_size=no \
        -o initial_window_width=90c -o initial_window_height=28c /usr/libexec/desktop-terminal &
else
    /usr/bin/xterm -title 'Axiom64 - Terminal' -geometry 90x32+40+50 -fn fixed \
        -e /usr/libexec/desktop-terminal &
fi
terminal=$!
wait "$terminal"
