#!/bin/sh
set -eu
export DISPLAY=:0
export XAUTHORITY=/run/axiom64-seat/client.auth
cleanup() {
    for process in "${xterm:-}" "${xeyes:-}" "${twm:-}"; do
        if test -n "$process"; then kill "$process" 2>/dev/null || true; fi
    done
    wait 2>/dev/null || true
}
trap cleanup EXIT
trap 'exit 0' HUP INT TERM
/usr/bin/twm -f /etc/X11/system.twmrc &
twm=$!
sleep .2
/usr/bin/xeyes -geometry 120x80+850+50 &
xeyes=$!
/usr/bin/xterm -title 'Axiom64 - Terminal' -geometry 90x32+40+50 -fn fixed -e /usr/libexec/desktop-terminal &
xterm=$!
wait "$xterm"
