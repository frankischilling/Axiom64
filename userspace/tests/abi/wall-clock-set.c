// SPDX-License-Identifier: GPL-3.0-or-later
/**
 * @file    userspace/tests/abi/wall-clock-set.c
 * @brief   Exercise guest wall-clock changes and authorization.
 * @author  frankischilling
 * @date    2026-11-22
 *
 * Checks clock changes and verifies that unprivileged callers are denied.
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
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/syscall.h>
#include <sys/time.h>
#include <sys/timerfd.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#define CHECK(expr)                                                                                \
    do {                                                                                           \
        if (!(expr)) {                                                                             \
            fprintf(stderr, "WALL_CLOCK_SET_FAIL line=%d errno=%d %s\n", __LINE__, errno, #expr);  \
            _Exit(1);                                                                              \
        }                                                                                          \
    } while (0)

int main(void) {
    struct timespec wall, before, after;
    CHECK(clock_gettime(CLOCK_REALTIME, &wall) == 0);
    CHECK(clock_gettime(CLOCK_MONOTONIC, &before) == 0);
    CHECK(clock_settime(CLOCK_MONOTONIC, &wall) == -1 && errno == EINVAL);
    CHECK(syscall(SYS_clock_settime, CLOCK_REALTIME, (void*)1) == -1 && errno == EFAULT);
    struct timespec bad = {.tv_sec = -1, .tv_nsec = 0};
    CHECK(clock_settime(CLOCK_REALTIME, &bad) == -1 && errno == EINVAL);
    bad = (struct timespec){.tv_sec = wall.tv_sec, .tv_nsec = 1000000000};
    CHECK(clock_settime(CLOCK_REALTIME, &bad) == -1 && errno == EINVAL);

    pid_t child = fork();
    CHECK(child >= 0);
    if (!child) {
        CHECK(setgid(65534) == 0 && setuid(65534) == 0);
        CHECK(clock_settime(CLOCK_REALTIME, &wall) == -1 && errno == EPERM);
        struct timeval value = {.tv_sec = wall.tv_sec, .tv_usec = 0};
        CHECK(syscall(SYS_settimeofday, &value, 0) == -1 && errno == EPERM);
        _Exit(0);
    }
    int status;
    CHECK(waitpid(child, &status, 0) == child && WIFEXITED(status) && !WEXITSTATUS(status));

    int absolute = timerfd_create(CLOCK_REALTIME, TFD_NONBLOCK);
    int relative = timerfd_create(CLOCK_REALTIME, TFD_NONBLOCK);
    CHECK(absolute >= 0 && relative >= 0);
    struct itimerspec setting = {.it_value = {.tv_sec = wall.tv_sec + 60, .tv_nsec = 0}};
    CHECK(timerfd_settime(absolute, TFD_TIMER_ABSTIME, &setting, 0) == 0);
    setting.it_value.tv_sec = 60;
    CHECK(timerfd_settime(relative, 0, &setting, 0) == 0);
    struct timespec changed = {.tv_sec = wall.tv_sec + 120, .tv_nsec = 250000000};
    CHECK(clock_settime(CLOCK_REALTIME, &changed) == 0);
    CHECK(clock_gettime(CLOCK_REALTIME, &after) == 0);
    CHECK(after.tv_sec == changed.tv_sec && after.tv_nsec >= changed.tv_nsec);
    CHECK(clock_gettime(CLOCK_MONOTONIC, &after) == 0);
    CHECK(after.tv_sec >= before.tv_sec && after.tv_sec - before.tv_sec < 10);

    uint64_t expirations;
    CHECK(read(absolute, &expirations, sizeof(expirations)) == sizeof(expirations) &&
          expirations == 1);
    CHECK(read(relative, &expirations, sizeof(expirations)) == -1 && errno == EAGAIN);
    CHECK(close(absolute) == 0 && close(relative) == 0);

    // This follows KDE's helper, which uses settimeofday with no timezone.
    struct timeval time = {.tv_sec = wall.tv_sec + 5, .tv_usec = 420000};
    CHECK(syscall(SYS_settimeofday, &time, 0) == 0);
    struct timeval current;
    CHECK(gettimeofday(&current, NULL) == 0);
    CHECK(current.tv_sec == time.tv_sec && current.tv_usec >= time.tv_usec);

    struct timezone timezone = {.tz_minuteswest = 901, .tz_dsttime = 0};
    CHECK(syscall(SYS_settimeofday, NULL, &timezone) == -1 && errno == EINVAL);
    timezone = (struct timezone){.tz_minuteswest = -60, .tz_dsttime = 1};
    CHECK(syscall(SYS_settimeofday, &time, &timezone) == 0);
    struct timezone reported;
    CHECK(syscall(SYS_gettimeofday, NULL, &reported) == 0);
    CHECK(reported.tz_minuteswest == timezone.tz_minuteswest &&
          reported.tz_dsttime == timezone.tz_dsttime);
    puts("WALL_CLOCK_SET_PASS");
    return 0;
}
