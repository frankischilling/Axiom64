// SPDX-License-Identifier: GPL-3.0-or-later
/**
 * @file    userspace/tests/net/tcp_test.h
 * @brief   Shared TCP socket test helpers.
 * @author  frankischilling
 * @date    2026-11-18
 *
 * Declares the helpers used by the connection and accept tests.
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
#pragma once

#include <errno.h>
#include <signal.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>

#define CHECK(value)                                                                               \
    do {                                                                                           \
        if (!(value)) {                                                                            \
            fprintf(stderr, "TCP_TEST_FAIL line=%d errno=%d expression=%s\n", __LINE__, errno,     \
                    #value);                                                                       \
            exit(1);                                                                               \
        }                                                                                          \
    } while (0)

struct sockaddr_in;

struct RetainedAccept {
    int listener, result, error;
    atomic_int entered, done;
};

extern volatile sig_atomic_t interrupted;

void send_all(int fd, const uint8_t* data, size_t length);
void readable(int fd);
void interruption(int signal);
void wait_child(pid_t child);
int tcp_listener(struct sockaddr_in* local);
void* retained_accept(void* opaque);
void accept_waiting(struct RetainedAccept* operation, int expected);
void tcp_accept_tests(const char* executable);
