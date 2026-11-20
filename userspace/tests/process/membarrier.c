// SPDX-License-Identifier: GPL-3.0-or-later
/**
 * @file    userspace/tests/process/membarrier.c
 * @brief   Verify Linux membarrier commands and registration lifetimes.
 * @author  frankischilling
 * @date    2026-11-19
 *
 * Runs actual syscalls across fork, exec, CLONE_VM and POSIX threads.
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
#include <pthread.h>
#include <sched.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>

enum {
    query = 0,
    global = 1 << 0,
    global_expedited = 1 << 1,
    register_global_expedited = 1 << 2,
    private_expedited = 1 << 3,
    register_private_expedited = 1 << 4,
    private_sync_core = 1 << 5,
    register_private_sync_core = 1 << 6,
    private_rseq = 1 << 7,
    register_private_rseq = 1 << 8,
    get_registrations = 1 << 9,
    common_commands = 0x7f,
};

static long barrier(uint64_t command, uint64_t flags, int cpu) {
    long result = syscall(SYS_membarrier, command, flags, cpu);
    return result == -1 ? -errno : result;
}

#define REQUIRE(condition)                                                                         \
    do {                                                                                           \
        if (!(condition)) {                                                                        \
            fprintf(stderr, "MEMBARRIER_FAIL line=%d check=%s\n", __LINE__, #condition);           \
            exit(1);                                                                               \
        }                                                                                          \
    } while (0)

static bool reports_registrations;

static void expect_registrations(int expected) {
    REQUIRE(barrier(get_registrations, 0, 0) == (reports_registrations ? expected : -EINVAL));
}

static void verify_clean_context(bool guest) {
    long commands = barrier(query, 0, 0);
    REQUIRE(commands >= 0 && (commands & common_commands) == common_commands);
    REQUIRE(!guest || commands == (common_commands | get_registrations));
    reports_registrations = (commands & get_registrations) != 0;
    expect_registrations(0);
    REQUIRE(barrier(private_expedited, 0, 0) == -EPERM);
    REQUIRE(barrier(private_sync_core, 0, 0) == -EPERM);
}

static int register_private(void* unused) {
    (void)unused;
    REQUIRE(barrier(private_expedited, 0, 0) == -EPERM);
    REQUIRE(barrier(register_private_expedited, 0, 0) == 0);
    REQUIRE(barrier(private_expedited, 0, 0) == 0);
    expect_registrations(register_private_sync_core | register_private_expedited);
    return 0;
}

static void wait_success(pid_t child) {
    REQUIRE(child > 0);
    int status;
    REQUIRE(waitpid(child, &status, 0) == child);
    REQUIRE(WIFEXITED(status) && WEXITSTATUS(status) == 0);
}

static void* register_global(void* unused) {
    (void)unused;
    expect_registrations(register_private_sync_core | register_private_expedited);
    REQUIRE(barrier(private_sync_core, 0, 0) == 0);
    REQUIRE(barrier(private_expedited, 0, 0) == 0);
    REQUIRE(barrier(register_global_expedited, 0, 0) == 0);
    return NULL;
}

int main(int argc, char** argv) {
    if (argc == 2 && (!strcmp(argv[1], "--exec-guest") || !strcmp(argv[1], "--exec-native"))) {
        verify_clean_context(!strcmp(argv[1], "--exec-guest"));
        puts("MEMBARRIER_EXEC_PASS");
        return 0;
    }

    bool guest = argc == 2 && !strcmp(argv[1], "--guest");
    verify_clean_context(guest);
    REQUIRE(barrier(query, 1, 0) == -EINVAL);
    REQUIRE(barrier(global, 2, 0) == -EINVAL);
    REQUIRE(barrier(global | global_expedited, 0, 0) == -EINVAL);
    REQUIRE(barrier(1u << 30, 0, 0) == -EINVAL);
    REQUIRE(barrier(global, 0, -1) == 0);
    REQUIRE(barrier(global_expedited, 0, -1) == 0);
    REQUIRE(barrier(register_private_sync_core, 1, 0) == -EINVAL);
    REQUIRE(barrier(private_sync_core, 0, 0) == -EPERM);
    if (guest) {
        REQUIRE(barrier(private_rseq, 0, 0) == -EINVAL);
        REQUIRE(barrier(register_private_rseq, 0, 0) == -EINVAL);
        REQUIRE(barrier(private_rseq, 1, 0) == -EINVAL);
    }
    REQUIRE(barrier((1ull << 32) | register_private_sync_core, 1ull << 32, -1) == 0);
    REQUIRE(barrier(register_private_sync_core, 0, 0) == 0);
    REQUIRE(barrier(private_sync_core, 0, -1) == 0);
    REQUIRE(barrier(private_expedited, 0, 0) == -EPERM);
    expect_registrations(register_private_sync_core);

    pid_t child = fork();
    REQUIRE(child >= 0);
    if (child == 0) {
        expect_registrations(register_private_sync_core);
        REQUIRE(barrier(private_sync_core, 0, 0) == 0);
        _exit(register_private(NULL));
    }
    wait_success(child);
    expect_registrations(register_private_sync_core);
    REQUIRE(barrier(private_expedited, 0, 0) == -EPERM);

    const size_t stack_size = 64 * 1024;
    char* stack =
        mmap(NULL, stack_size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    REQUIRE(stack != MAP_FAILED);
    wait_success(clone(register_private, stack + stack_size, CLONE_VM | SIGCHLD, NULL));
    REQUIRE(munmap(stack, stack_size) == 0);
    expect_registrations(register_private_sync_core | register_private_expedited);
    REQUIRE(barrier(private_expedited, 0, 0) == 0);

    pthread_t thread;
    REQUIRE(pthread_create(&thread, NULL, register_global, NULL) == 0);
    REQUIRE(pthread_join(thread, NULL) == 0);
    int registrations =
        register_private_sync_core | register_global_expedited | register_private_expedited;
    expect_registrations(registrations);
    REQUIRE(barrier(private_expedited, 0, -1) == 0);
    REQUIRE(barrier(private_sync_core, 0, 0) == 0);

    child = fork();
    REQUIRE(child >= 0);
    if (child == 0) {
        expect_registrations(registrations);
        REQUIRE(barrier(private_expedited, 0, 0) == 0);
        if (argc == 3)
            execl(argv[2], argv[2], argv[0], "--exec-native", (char*)NULL);
        else
            execl(argv[0], argv[0], guest ? "--exec-guest" : "--exec-native", (char*)NULL);
        REQUIRE(false);
    }
    wait_success(child);
    expect_registrations(registrations);
    puts("MEMBARRIER_PASS");
    return 0;
}
