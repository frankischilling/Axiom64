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
#include <poll.h>
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

static pid_t start_sleeper(int type, const struct timespec* time, int* done) {
    int ready[2], result[2];
    CHECK(pipe(ready) == 0 && pipe(result) == 0);
    pid_t sleeper = fork();
    CHECK(sleeper >= 0);
    if (!sleeper) {
        close(ready[0]);
        close(result[0]);
        CHECK(write(ready[1], "R", 1) == 1);
        CHECK(clock_nanosleep(CLOCK_REALTIME, type, time, NULL) == 0);
        CHECK(write(result[1], "D", 1) == 1);
        _Exit(0);
    }
    close(ready[1]);
    close(result[1]);
    char byte;
    CHECK(read(ready[0], &byte, 1) == 1 && byte == 'R');
    close(ready[0]);
    *done = result[0];
    return sleeper;
}

static void check_sleepers_on_clock_change(const struct timespec* wall) {
    const struct timespec absolute = {.tv_sec = wall->tv_sec + 30};
    const struct timespec interval = {.tv_sec = 2};
    int absolute_done, relative_done;
    pid_t absolute_pid = start_sleeper(TIMER_ABSTIME, &absolute, &absolute_done);
    pid_t relative_pid = start_sleeper(0, &interval, &relative_done);
    struct pollfd sleepers[2] = {{absolute_done, POLLIN, 0}, {relative_done, POLLIN, 0}};
    CHECK(poll(sleepers, 2, 80) == 0);

    const struct timespec future = {.tv_sec = wall->tv_sec + 60};
    CHECK(clock_settime(CLOCK_REALTIME, &future) == 0);
    CHECK(poll(sleepers, 2, 1000) == 1 && sleepers[0].revents & POLLIN && sleepers[1].revents == 0);
    char result;
    CHECK(read(absolute_done, &result, 1) == 1 && result == 'D');
    CHECK(close(absolute_done) == 0);
    int status;
    CHECK(waitpid(absolute_pid, &status, 0) == absolute_pid && WIFEXITED(status) &&
          !WEXITSTATUS(status));

    // The same relative sleep must also survive the clock being set backward.
    CHECK(clock_settime(CLOCK_REALTIME, wall) == 0);
    CHECK(poll(sleepers + 1, 1, 3000) == 1 && sleepers[1].revents & POLLIN);
    CHECK(read(relative_done, &result, 1) == 1 && result == 'D');
    CHECK(close(relative_done) == 0);
    CHECK(waitpid(relative_pid, &status, 0) == relative_pid && WIFEXITED(status) &&
          !WEXITSTATUS(status));
    puts("CLOCK_SLEEP_WALL_STEP_PASS");
}

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

    CHECK(clock_settime(CLOCK_REALTIME, &wall) == 0);
    check_sleepers_on_clock_change(&wall);

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
