// SPDX-License-Identifier: GPL-3.0-or-later
/**
 * @file    userspace/tests/net/dns-tcp-probe.c
 * @brief   DNS TCP probe.
 * @author  frankischilling
 * @date    2026-11-18
 *
 * Issues DNS traffic over TCP and reports observations used by the fixture.
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
#include <arpa/inet.h>
#include <netdb.h>
#include <stdio.h>
#include <time.h>

int main(int argc, char** argv) {
    if (argc != 2)
        return 2;
    struct addrinfo hints = {
        .ai_family = AF_INET, .ai_socktype = SOCK_STREAM, .ai_flags = AI_NUMERICSERV};
    struct addrinfo* result = NULL;
    struct timespec before, after;
    clock_gettime(CLOCK_MONOTONIC, &before);
    int error = getaddrinfo(argv[1], "8080", &hints, &result);
    clock_gettime(CLOCK_MONOTONIC, &after);
    unsigned count = 0;
    unsigned bad = 0;
    for (struct addrinfo* row = result; row; row = row->ai_next) {
        const struct sockaddr_in* address = (const struct sockaddr_in*)row->ai_addr;
        unsigned ip = ntohl(address->sin_addr.s_addr);
        if (row->ai_family != AF_INET || row->ai_socktype != SOCK_STREAM ||
            row->ai_protocol != IPPROTO_TCP || row->ai_addrlen != sizeof(*address) ||
            ntohs(address->sin_port) != 8080 || ip < 0x0a174001 || ip >= 0x0a174029)
            bad++;
        count++;
    }
    if (result)
        freeaddrinfo(result);
    double elapsed =
        (after.tv_sec - before.tv_sec) * 1000.0 + (after.tv_nsec - before.tv_nsec) / 1000000.0;
    printf("DNS_TCP_PROBE name=%s error=%d count=%u bad=%u elapsed_ms=%.3f\n", argv[1], error,
           count, bad, elapsed);
    return 0;
}
