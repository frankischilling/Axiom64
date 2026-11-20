#!/bin/bash
# SPDX-License-Identifier: GPL-3.0-or-later
# @file    userspace/desktop/xterm-session.sh
# @brief   Desktop test terminal.
# @author  frankischilling
# @date    2026-11-18
#
# Prints the environment banner, records the terminal readiness marker, and
# starts an interactive Bash shell.
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
set -e
printf '\033[2J\033[HAxiom64\n\n'
printf 'Xorg framebuffer / twm / xterm / Bash %s\n\n' "$BASH_VERSION"
uname -a
printf '\nNative GNU tools and musl are available.\n'
printf 'Try: gcc --version, make -C /root/toolchain-test test, or zsh\n\n'
printf 'XTERM_BASH_PASS\n' > /tmp/xterm-ready
export PS1='axiom64:\w\$ '
exec /bin/bash --noprofile --norc -i
