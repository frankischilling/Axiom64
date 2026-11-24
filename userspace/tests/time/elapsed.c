// SPDX-License-Identifier: GPL-3.0-or-later
/**
 * @file    userspace/tests/time/elapsed.c
 * @brief   Elapsed clock userspace test.
 * @author  frankischilling
 * @date    2026-11-18
 *
 * Checks observed monotonic time and wait deadlines against the test workload.
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
#include <inttypes.h>
#include <poll.h>
#include <sched.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/time.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

static volatile sig_atomic_t alarm_seen;

static void alarm_handler(int number) {
    (void)number;
    alarm_seen = 1;
}

static void require(int condition, const char* operation) {
    if (!condition) {
        perror(operation);
        exit(1);
    }
}

static uint64_t clock_ns(void) {
    struct timespec now;
    require(!clock_gettime(CLOCK_MONOTONIC, &now), "clock_gettime");
    require(now.tv_sec >= 0 && now.tv_nsec >= 0 && now.tv_nsec < 1000000000, "clock value");
    return (uint64_t)now.tv_sec * 1000000000 + (uint64_t)now.tv_nsec;
}

static void report(const char* stage, uint64_t before) {
    uint64_t after = clock_ns();
    require(after >= before, "clock monotonicity");
    printf("CLOCK_ELAPSED stage=%s before=%" PRIu64 " after=%" PRIu64 " elapsed_ns=%" PRIu64 "\n",
           stage, before, after, after - before);
}

static void sleep_ms(unsigned milliseconds) {
    struct timespec delay = {milliseconds / 1000, (milliseconds % 1000) * 1000000};
    while (nanosleep(&delay, NULL))
        require(errno == EINTR, "nanosleep");
}

static void check_clock_precision(void) {
    struct timespec resolution, boot_resolution, coarse_resolution, coarse;
    require(!clock_getres(CLOCK_MONOTONIC, &resolution) && !resolution.tv_sec &&
                resolution.tv_nsec == 1000,
            "microsecond monotonic resolution with an elapsed counter");
    require(!clock_getres(CLOCK_BOOTTIME, &boot_resolution) && !boot_resolution.tv_sec &&
                boot_resolution.tv_nsec == resolution.tv_nsec,
            "boot and monotonic resolution agree");
    require(!clock_getres(CLOCK_MONOTONIC_COARSE, &coarse_resolution) &&
                !coarse_resolution.tv_sec && coarse_resolution.tv_nsec == 10000000 &&
                !clock_gettime(CLOCK_MONOTONIC_COARSE, &coarse) && coarse.tv_nsec % 10000000 == 0,
            "coarse clock retains the scheduler tick");
    int sub_tick = 0;
    for (unsigned sample = 0; sample < 256 && !sub_tick; ++sample) {
        uint64_t before = clock_ns();
        struct timespec boot;
        require(!clock_gettime(CLOCK_BOOTTIME, &boot), "boot clock");
        uint64_t boot_ns = (uint64_t)boot.tv_sec * 1000000000 + (uint64_t)boot.tv_nsec;
        uint64_t after = clock_ns();
        require(before <= boot_ns && boot_ns <= after && boot_ns % 1000 == 0,
                "boot and monotonic timestamps share the elapsed counter");
        sub_tick = boot_ns % 10000000 != 0;
    }
    require(sub_tick, "hardware readings retain the fraction of a scheduler tick");
    puts("CLOCK_SUBTICK_PASS resolution_ns=1000");
}

int main(void) {
    setvbuf(stdout, NULL, _IOLBF, 0);
    check_clock_precision();
    uint64_t before = clock_ns();
    sleep_ms(100);
    require(clock_ns() - before >= 100000000, "relative sleep does not use up its first tick");
    report("sleep-before", before);
    require(!mkdir("/mnt", 0755) && !mkdir("/mnt/clock", 0755), "mkdir");
    before = clock_ns();
    require(!mount("/dev/vda", "/mnt/clock", "ext2", 0, NULL), "mount");
    report("mount", before);
    int fd = open("/mnt/clock/elapsed", O_RDWR | O_CREAT | O_TRUNC, 0600);
    require(fd >= 0 && write(fd, "clock\n", 6) == 6, "write");

    int ready[2], done[2];
    require(!pipe(ready) && !pipe(done), "pipe");
    pid_t child = fork();
    require(child >= 0, "fork");
    if (!child) {
        close(ready[0]);
        close(done[0]);
        close(fd);
        struct timespec deadline;
        require(!clock_gettime(CLOCK_MONOTONIC, &deadline), "child deadline");
        deadline.tv_sec++;
        uint32_t word = 0;
        require(write(ready[1], "r", 1) == 1, "child ready");
        require(!sched_yield(), "child startup yield");
        long waited;
        do {
            waited = syscall(SYS_futex, &word, 9 | 128, 0, &deadline, NULL, UINT32_MAX);
        } while (waited < 0 && errno == EINTR);
        require(waited == -1 && errno == ETIMEDOUT, "child absolute futex timeout");
        require(write(done[1], "d", 1) == 1, "child wake");
        _exit(0);
    }
    close(ready[1]);
    close(done[1]);
    char byte;
    require(read(ready[0], &byte, 1) == 1 && byte == 'r', "child startup");
    struct sigaction action = {.sa_handler = alarm_handler};
    sigemptyset(&action.sa_mask);
    require(!sigaction(SIGALRM, &action, NULL), "sigaction");
    struct itimerval timer = {.it_value = {.tv_sec = 2}};
    require(!setitimer(ITIMER_REAL, &timer, NULL), "setitimer");
    before = clock_ns();
    require(!fsync(fd), "fsync");
    report("fsync", before);
    struct pollfd descriptor = {.fd = done[0], .events = POLLIN};
    int result;
    do {
        result = poll(&descriptor, 1, 200);
    } while (result < 0 && errno == EINTR);
    require(result >= 0, "poll");
    int child_ready =
        result == 1 && (descriptor.revents & POLLIN) && read(done[0], &byte, 1) == 1 && byte == 'd';
    printf("CLOCK_DEADLINE alarm=%d child_ready=%d\n", (int)alarm_seen, child_ready);
    timer = (struct itimerval){0};
    require(!setitimer(ITIMER_REAL, &timer, NULL), "timer clear");
    before = clock_ns();
    sleep_ms(100);
    report("sleep-after", before);
    struct timeval wall;
    require(!gettimeofday(&wall, NULL), "gettimeofday");
    struct timespec realtime;
    require(!clock_gettime(CLOCK_REALTIME, &realtime), "realtime agreement");
    uint64_t real = (uint64_t)realtime.tv_sec * 1000000000 + (uint64_t)realtime.tv_nsec,
             wall_ns = (uint64_t)wall.tv_sec * 1000000000 + (uint64_t)wall.tv_usec * 1000;
    require(real >= wall_ns && real - wall_ns <= 20000000, "wall clock interface agreement");
    int status;
    while (waitpid(child, &status, 0) < 0)
        require(errno == EINTR, "waitpid");
    require(WIFEXITED(status) && !WEXITSTATUS(status), "child status");
    require(!close(fd), "close");
    close(ready[0]);
    close(done[0]);
    puts("CLOCK_ELAPSED_TESTS_PASS");
    return 0;
}
