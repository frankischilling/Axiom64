#!/bin/sh
# SPDX-License-Identifier: GPL-3.0-or-later
# @file    userspace/services/networkmanager.sh
# @brief   Start the installed desktop's network service.
# @author  frankischilling
# @date    2026-11-23
#
# Copyright (C) 2026 frankischilling

set -eu

# The system bus waits until there is a local account database.
until test -S /run/dbus/system_bus_socket; do
    sleep 1
done

# The native service leaves this link in /etc. Its target lives in /run.
resolver=/run/network-resolver/resolv.conf
if [ "$(readlink /etc/resolv.conf 2>/dev/null || :)" = "$resolver" ] &&
   [ ! -e "$resolver" ] && [ ! -L "$resolver" ] && [ ! -L /run/network-resolver ]; then
    if ! mkdir -p -m 0755 /run/network-resolver ||
       ! ln -s /run/NetworkManager/resolv.conf "$resolver"; then
        printf '%s\n' 'NetworkManager: could not prepare the Axiom64 resolver path' >&2
    fi
fi

exec /usr/sbin/NetworkManager --no-daemon
