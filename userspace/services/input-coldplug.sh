#!/bin/sh
# SPDX-License-Identifier: GPL-3.0-or-later
# @file    userspace/services/input-coldplug.sh
# @brief   Ask udev to classify the input devices present at boot.
# @author  frankischilling
# @date    2026-11-22
#
# Copyright (C) 2026 frankischilling

set -eu

attempt=0
until test -S /run/udev/control; do
    attempt=$((attempt + 1))
    test "$attempt" -lt 20 || exit 1
    sleep 0.1
done

/sbin/udevadm trigger --action=add --subsystem-match=input --sysname-match='event*'

input_classified() {
    found=no
    for device in /sys/class/input/event*/dev; do
        test -r "$device" || continue
        IFS= read -r number < "$device" || return 1
        test -r "/run/udev/data/c$number" || return 1
        found=yes
    done
    test "$found" = yes
}

attempt=0
until input_classified; do
    attempt=$((attempt + 1))
    test "$attempt" -lt 30 || exit 1
    sleep 0.1
done
