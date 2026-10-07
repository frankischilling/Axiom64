#!/bin/sh
set -eu
. /etc/x11-session.sh
trap x11_stop EXIT
trap 'exit 0' INT TERM
rm -f /tmp/xterm-ready
x11_server
x11_clients
echo 'Xorg desktop started. Logs are in /var/log/Xorg.0.log and /tmp/xterm-output.'
wait "$xterm" || true
