#!/bin/sh
# SPDX-License-Identifier: GPL-3.0-or-later
# @file    userspace/desktop/localectl.sh
# @brief   List the system's installed musl locale data.
# @author  frankischilling
# @date    2026-11-23
#
# Copyright (C) 2026 frankischilling

set -eu
if test "${1:-}" = --no-pager; then shift; fi
command=${1:-}
if test "$#" -ne 0; then shift; fi
if test "${1:-}" = --no-pager; then shift; fi
if test "$command" = list-locales && test "$#" -eq 0; then
    LC_ALL=C
    export LC_ALL
    printf '%s\n' C C.UTF-8
    for path in /usr/share/i18n/locales/musl/*.UTF-8; do
        if test -f "$path"; then
            printf '%s\n' "${path##*/}"
        fi
    done
    exit 0
fi
printf '%s\n' 'Usage: localectl [--no-pager] list-locales' >&2
exit 2
