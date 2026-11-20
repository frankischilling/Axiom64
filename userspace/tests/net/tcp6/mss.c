// SPDX-License-Identifier: GPL-3.0-or-later
/**
 * @file    userspace/tests/net/tcp6/mss.c
 * @brief   IPv6 TCP segment size test.
 * @author  frankischilling
 * @date    2026-11-18
 *
 * Checks socket maximum segment size controls for IPv6 connections.
 *
 * Copyright (C) 2026 frankischilling
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program. If not, see <https://gnu.org/licenses/>.
 */
#define _GNU_SOURCE
#include "../tcp_maxseg.h"
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>

int main(int argc, char** argv) {
    int native = argc == 2 && !strcmp(argv[1], "--native");
    if (argc != 1 && !native) {
        fprintf(stderr, "usage: %s [--native]\n", argv[0]);
        return 2;
    }
    tcp_maxseg_options_family(native, AF_INET6);
    return 0;
}
