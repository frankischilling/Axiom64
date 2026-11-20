// SPDX-License-Identifier: GPL-3.0-or-later
/**
 * @file    userspace/tests/net/ipv4_query.h
 * @brief   IPv4 network query test helpers.
 * @author  frankischilling
 * @date    2026-11-18
 *
 * Builds and interprets configuration queries used by IPv4 test clients.
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
#ifndef AXIOM64_TEST_IPV4_QUERY_H
#define AXIOM64_TEST_IPV4_QUERY_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/utsname.h>

static int ipv4_query_releases(void) {
    struct utsname identity;
    if (uname(&identity)) {
        perror("IPv4 query kernel identity");
        exit(1);
    }
    if (!strcmp(identity.sysname, "Axiom64"))
        return 1;
    unsigned major, minor;
    if (strcmp(identity.sysname, "Linux") ||
        sscanf(identity.release, "%u.%u", &major, &minor) != 2) {
        fprintf(stderr, "Unknown IPv4 query kernel identity\n");
        exit(1);
    }
    // Linux 6.7 moved these IP option accesses outside the socket lock.
    return major < 6 || (major == 6 && minor < 7);
}

#endif
