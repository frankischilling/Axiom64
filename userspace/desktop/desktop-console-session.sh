#!/bin/sh
set -eu
export DISPLAY=:0
export XAUTHORITY=/run/axiom64-seat/client.auth
exec "$SHELL" -l
