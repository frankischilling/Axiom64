// SPDX-License-Identifier: GPL-3.0-or-later
/**
 * @file    userspace/tests/abi/virtual-console.c
 * @brief   Verify the kernel foreground virtual console.
 * @author  frankischilling
 * @date    2026-11-23
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
#include <errno.h>
#include <fcntl.h>
#include <linux/vt.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/ioctl.h>
#include <unistd.h>

#define CHECK(expr)                                                                                \
    do {                                                                                           \
        if (!(expr)) {                                                                             \
            fprintf(stderr, "FOREGROUND_CONSOLE_FAIL line=%d errno=%d %s\n", __LINE__, errno,      \
                    #expr);                                                                        \
            _Exit(1);                                                                              \
        }                                                                                          \
    } while (0)

int main(void) {
    const char* path = "/sys/class/tty/tty0/active";
    int tty = open("/dev/tty0", O_RDONLY | O_NOCTTY | O_CLOEXEC);
    int active = open(path, O_RDONLY | O_CLOEXEC);
    CHECK(tty >= 0 && active >= 0);
    struct vt_stat state;
    CHECK(ioctl(tty, VT_GETSTATE, &state) == 0);
    CHECK(state.v_active == 1 && state.v_state == 3);
    char name[16], expected[16];
    CHECK(snprintf(expected, sizeof(expected), "tty%u\n", state.v_active) == 5);
    CHECK(read(active, name, 2) == 2);
    CHECK(read(active, name + 2, sizeof(name) - 2) == 3);
    CHECK(!memcmp(name, expected, 5));
    CHECK(read(active, name, sizeof(name)) == 0);
    CHECK(lseek(active, 0, SEEK_SET) == 0);
    CHECK(read(active, name, sizeof(name)) == 5 && !memcmp(name, expected, 5));
    CHECK(open(path, O_WRONLY) == -1 && errno == EACCES);

    int epoll = epoll_create1(EPOLL_CLOEXEC);
    CHECK(epoll >= 0);
    struct epoll_event watch = {.events = 0, .data.fd = active};
    CHECK(epoll_ctl(epoll, EPOLL_CTL_ADD, active, &watch) == 0);
    CHECK(epoll_wait(epoll, &watch, 1, 0) == 0);
    watch.events = EPOLLIN | EPOLLPRI;
    CHECK(epoll_ctl(epoll, EPOLL_CTL_MOD, active, &watch) == 0);
    CHECK(epoll_wait(epoll, &watch, 1, 0) == 1 && watch.events == EPOLLIN);
    struct pollfd descriptor = {.fd = active, .events = POLLPRI};
    CHECK(poll(&descriptor, 1, 0) == 0);
    CHECK(ioctl(tty, VT_ACTIVATE, 1) == 0 && ioctl(tty, VT_WAITACTIVE, 1) == 0);
    CHECK(ioctl(tty, VT_ACTIVATE, 2) == -1 && errno == ENXIO);
    CHECK(ioctl(tty, VT_WAITACTIVE, 0) == -1 && errno == ENXIO);
    CHECK(ioctl(tty, VT_GETSTATE, &state) == 0 && state.v_active == 1);
    CHECK(poll(&descriptor, 1, 0) == 0);
    puts("FOREGROUND_CONSOLE_PASS");
    return 0;
}
