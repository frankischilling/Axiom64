#!/bin/sh
# Shared startup for interactive boots and the desktop test.
x11_server() {
    mkdir -p /tmp/.X11-unix /var/log
    /usr/libexec/Xorg :0 -config /etc/X11/xorg.conf -nolisten tcp -noreset -ac -retro -dumbSched -extension GLX -logfile /var/log/Xorg.0.log > /tmp/xorg-output 2>&1 &
    xorg=$!
    ready=0
    for attempt in $(seq 1 100); do
        if /bin/x11-probe --ready; then ready=1; break; fi
        sleep .1
    done
    if test "$ready" -ne 1; then
        cat /tmp/xorg-output /var/log/Xorg.0.log
        return 1
    fi
    export DISPLAY=:0
}
x11_clients() {
    /usr/bin/twm -f /etc/X11/system.twmrc > /tmp/twm-output 2>&1 &
    twm=$!
    sleep .2
    /usr/bin/xeyes -geometry 120x80+850+50 > /tmp/xeyes-output 2>&1 &
    xeyes=$!
    /usr/bin/xterm -title 'Axiom64 - Bash' -geometry 90x32+40+50 -fn fixed -e /bin/bash /etc/xterm-session.sh > /tmp/xterm-output 2>&1 &
    xterm=$!
}
x11_stop() {
    for process in "${xterm:-}" "${xeyes:-}" "${twm:-}" "${xorg:-}"; do
        if test -n "$process"; then kill "$process" 2>/dev/null || true; fi
    done
    wait 2>/dev/null || true
}
