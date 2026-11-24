// SPDX-License-Identifier: GPL-3.0-or-later
/**
 * @file    userspace/tests/abi/clock-sleep.c
 * @brief   Check Linux relative and absolute sleep calls.
 * @author  frankischilling
 * @date    2026-11-23
 *
 * Runs the same sleep, signal, and argument checks on Linux and Axiom64.
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
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/syscall.h>
#include <sys/time.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#define CHECK(expr)                                                                                \
    do {                                                                                           \
        if (!(expr)) {                                                                             \
            fprintf(stderr, "CLOCK_SLEEP_FAIL line=%d errno=%d %s\n", __LINE__, errno, #expr);     \
            _Exit(1);                                                                              \
        }                                                                                          \
    } while (0)

static volatile sig_atomic_t signals;

static int64_t ns(const struct timespec* value) {
    return (int64_t)value->tv_sec * 1000000000 + value->tv_nsec;
}

static int64_t now(clockid_t clock) {
    struct timespec time;
    CHECK(clock_gettime(clock, &time) == 0);
    return ns(&time);
}

static struct timespec from_ns(int64_t value) {
    return (struct timespec){value / 1000000000, value % 1000000000};
}

static void timer_signal(int signal) {
    if (signal == SIGALRM)
        ++signals;
}

static void interrupt_sleep(void) {
    signals = 0;
    const struct itimerval alarm = {.it_value = {.tv_usec = 60000}};
    CHECK(setitimer(ITIMER_REAL, &alarm, NULL) == 0);
}

static void check_clock(clockid_t clock) {
    const struct timespec request = {.tv_nsec = 35000000};
    const int64_t started = now(CLOCK_MONOTONIC);
    CHECK(clock_nanosleep(clock, 0, &request, NULL) == 0);
    CHECK(now(CLOCK_MONOTONIC) - started >= ns(&request));

    const int64_t target = now(clock) + ns(&request);
    const struct timespec deadline = from_ns(target);
    CHECK(clock_nanosleep(clock, TIMER_ABSTIME, &deadline, NULL) == 0);
    CHECK(now(clock) >= target);

    // Expired absolute requests ignore the remaining-time address.
    CHECK(syscall(SYS_clock_nanosleep, clock, TIMER_ABSTIME, &deadline, (void*)1) == 0);
}

static void check_interruptions(void) {
    const struct sigaction action = {.sa_handler = timer_signal, .sa_flags = SA_RESTART};
    CHECK(sigaction(SIGALRM, &action, NULL) == 0);
    const struct timespec request = {.tv_sec = 2, .tv_nsec = 250000000};
    struct timespec left;
    interrupt_sleep();
    CHECK(clock_nanosleep(CLOCK_MONOTONIC, 0, &request, &left) == EINTR);
    CHECK(signals == 1 && ns(&left) > 0 && ns(&left) < ns(&request));
    CHECK(left.tv_nsec >= 0 && left.tv_nsec < 1000000000);

    interrupt_sleep();
    CHECK(syscall(SYS_nanosleep, &request, &left) == -1 && errno == EINTR);
    CHECK(signals == 1 && ns(&left) > 0 && ns(&left) < ns(&request));

    const struct timespec deadline = from_ns(now(CLOCK_MONOTONIC) + ns(&request));
    left = (struct timespec){17, 42};
    interrupt_sleep();
    CHECK(clock_nanosleep(CLOCK_MONOTONIC, TIMER_ABSTIME, &deadline, &left) == EINTR);
    CHECK(signals == 1 && left.tv_sec == 17 && left.tv_nsec == 42);

    interrupt_sleep();
    CHECK(syscall(SYS_clock_nanosleep, CLOCK_REALTIME, 0, &request, (void*)1) == -1 &&
          errno == EFAULT && signals == 1);

    const struct timespec large = {.tv_sec = INT64_MAX};
    interrupt_sleep();
    CHECK(clock_nanosleep(CLOCK_BOOTTIME, 0, &large, &left) == EINTR);
    CHECK(signals == 1 && left.tv_sec > 1000000000 && left.tv_sec < INT64_MAX &&
          left.tv_nsec >= 0 && left.tv_nsec < 1000000000);
}

int main(void) {
    const struct timespec zero = {0, 0};
    const struct timespec invalid = {0, 1000000000};
    const struct timespec negative = {-1, 0};
    CHECK(clock_nanosleep(CLOCK_MONOTONIC, 2, &zero, NULL) == 0);
    CHECK(clock_nanosleep(CLOCK_MONOTONIC, 0, &invalid, NULL) == EINVAL);
    CHECK(clock_nanosleep(CLOCK_MONOTONIC, 0, &negative, NULL) == EINVAL);
    CHECK(clock_nanosleep(CLOCK_THREAD_CPUTIME_ID, 0, &zero, NULL) == EINVAL);
    CHECK(clock_nanosleep(CLOCK_MONOTONIC_RAW, 0, &zero, NULL) == EOPNOTSUPP);
    CHECK(clock_nanosleep(CLOCK_MONOTONIC_COARSE, 0, &zero, NULL) == EOPNOTSUPP);
    CHECK(clock_nanosleep(CLOCK_REALTIME_COARSE, 0, &zero, NULL) == EOPNOTSUPP);
    CHECK(syscall(SYS_clock_nanosleep, CLOCK_MONOTONIC, 0, (void*)1, NULL) == -1 &&
          errno == EFAULT);
    CHECK(syscall(SYS_clock_nanosleep, CLOCK_MONOTONIC, 0, &zero, (void*)1) == 0);
    check_clock(CLOCK_REALTIME);
    check_clock(CLOCK_MONOTONIC);
    check_clock(CLOCK_BOOTTIME);
    check_interruptions();
    // Reuse the same thread after a signal, including the legacy syscall.
    const struct timespec short_sleep = {.tv_nsec = 25000000};
    const int64_t started = now(CLOCK_MONOTONIC);
    CHECK(syscall(SYS_nanosleep, &short_sleep, NULL) == 0);
    CHECK(now(CLOCK_MONOTONIC) - started >= ns(&short_sleep));
    puts("CLOCK_SLEEP_PASS");
    return 0;
}
