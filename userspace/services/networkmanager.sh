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

exec /usr/sbin/NetworkManager --no-daemon
