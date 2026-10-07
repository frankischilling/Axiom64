#!/bin/sh
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
