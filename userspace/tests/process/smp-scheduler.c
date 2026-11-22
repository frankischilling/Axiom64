// SPDX-License-Identifier: GPL-3.0-or-later
/**
 * @file    userspace/tests/process/smp-scheduler.c
 * @brief   Exercise userspace scheduling on twelve logical CPUs.
 * @author  frankischilling
 * @date    2026-11-22
 *
 * Forks workers and records actual execution across the guest CPU set.
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
#include <sys/mman.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

enum { workers = 12 };

struct Shared {
    unsigned ready, start, stop;
    uint64_t mask;
    uint64_t runs[workers];
};

static void check(int ok, const char* reason) {
    if (!ok) {
        fprintf(stderr, "SMP_SCHED_FAIL %s errno=%d\n", reason, errno);
        exit(1);
    }
}

static uint64_t milliseconds(void) {
    struct timespec ts;
    check(!clock_gettime(CLOCK_MONOTONIC, &ts), "clock");
    return (uint64_t)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

static void pause_poll(void) {
    struct timespec duration = {0, 1000000};
    nanosleep(&duration, NULL);
}

int main(void) {
    uint64_t affinity = 0;
    check(syscall(SYS_sched_getaffinity, 0, sizeof(affinity), &affinity) == 8, "affinity mask");
    check(affinity == (1ull << workers) - 1, "online CPU count");
    struct Shared* state =
        mmap(NULL, sizeof(*state), PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, 0);
    check(state != MAP_FAILED, "shared state");
    pid_t children[workers];
    for (unsigned i = 0; i < workers; ++i) {
        children[i] = fork();
        check(children[i] >= 0, "fork");
        if (!children[i]) {
            __atomic_add_fetch(&state->ready, 1, __ATOMIC_RELEASE);
            while (!__atomic_load_n(&state->start, __ATOMIC_ACQUIRE))
                __asm__ volatile("pause");
            while (!__atomic_load_n(&state->stop, __ATOMIC_ACQUIRE)) {
                unsigned cpu, node;
                check(!syscall(SYS_getcpu, &cpu, &node, 0) && cpu < workers && !node, "getcpu");
                __atomic_fetch_or(&state->mask, 1ull << cpu, __ATOMIC_RELAXED);
                ++state->runs[i];
                for (unsigned pause = 0; pause < 1000; ++pause)
                    __asm__ volatile("pause");
            }
            _exit(0);
        }
    }
    uint64_t end = milliseconds() + 8000;
    while (__atomic_load_n(&state->ready, __ATOMIC_ACQUIRE) != workers && milliseconds() < end)
        pause_poll();
    check(state->ready == workers, "all workers ready");
    __atomic_store_n(&state->start, 1, __ATOMIC_RELEASE);
    end = milliseconds() + 5000;
    while (__atomic_load_n(&state->mask, __ATOMIC_RELAXED) != affinity && milliseconds() < end)
        pause_poll();
    __atomic_store_n(&state->stop, 1, __ATOMIC_RELEASE);
    for (unsigned i = 0; i < workers; ++i) {
        int status;
        check(waitpid(children[i], &status, 0) == children[i] && WIFEXITED(status) &&
                  WEXITSTATUS(status) == 0 && state->runs[i],
              "worker exit");
    }
    printf("SMP_SCHED_CPU_MASK %llx\n", (unsigned long long)state->mask);
    check(state->mask == affinity, "worker CPU coverage");
    puts("SMP_SCHED_RUNTIME_PASS");
    return 0;
}
