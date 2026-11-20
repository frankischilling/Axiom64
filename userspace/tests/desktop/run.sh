#!/bin/sh
# SPDX-License-Identifier: GPL-3.0-or-later
# /**
#  * @file    userspace/tests/desktop/run.sh
#  * @brief   Guest X11 and shell test.
#  * @author  frankischilling
#  * @date    2026-11-18
#  *
#  * Checks the framebuffer device and selected shells before running the X11
#  * window and terminal fixture.
#  *
#  * Copyright (C) 2026 frankischilling
#  *
#  * This program is free software: you can redistribute it and/or modify
#  * it under the terms of the GNU General Public License as published by
#  * the Free Software Foundation, either version 3 of the License, or
#  * (at your option) any later version.
#  *
#  * This program is distributed in the hope that it will be useful,
#  * but WITHOUT ANY WARRANTY; without even the implied warranty of
#  * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
#  * GNU General Public License for more details.
#  *
#  * You should have received a copy of the GNU General Public License
#  * along with this program. If not, see <https://gnu.org/licenses/>.
#  */
set -eu
/bin/x11-probe --device
/bin/bash --noprofile --norc -c 'test "$(printf bash | tr a-z A-Z)" = BASH; echo BASH_SHELL_PASS'
/bin/zsh -f -c 'test "$(printf zsh | tr a-z A-Z)" = ZSH; echo ZSH_SHELL_PASS'
. /etc/x11-session.sh
trap x11_stop EXIT
x11_server
echo XORG_SERVER_PASS
/bin/x11-probe --paint
x11_clients
for attempt in $(seq 1 100); do
    if test -f /tmp/xterm-ready; then break; fi
    sleep .1
done
if ! test -f /tmp/xterm-ready; then
    cat /tmp/twm-output /tmp/xeyes-output /tmp/xterm-output /var/log/Xorg.0.log
    echo XTERM_START_FAIL
    exit 1
fi
cat /tmp/xterm-ready
sleep 1
/bin/x11-probe --desktop
echo DESKTOP_INPUT_READY
for attempt in $(seq 1 100); do
    if test -f /tmp/x11-input-pass; then break; fi
    sleep .1
done
if ! test -f /tmp/x11-input-pass; then
    cat /tmp/twm-output /tmp/xeyes-output /tmp/xterm-output
    echo X11_INPUT_FAIL
    exit 1
fi
echo X11_KEYBOARD_PASS
echo DESKTOP_CAPTURE_READY
sleep 2
echo X11_DESKTOP_PASS
x11_stop
trap - EXIT
echo AXIOM64_TESTS_PASS
