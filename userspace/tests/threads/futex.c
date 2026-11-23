// SPDX-License-Identifier: GPL-3.0-or-later
/**
 * @file    userspace/tests/threads/futex.c
 * @brief   Futex userspace test.
 * @author  frankischilling
 * @date    2026-11-18
 *
 * Checks waits, wakes, timeouts, and coordination between threads.
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
#include <limits.h>
#include <pthread.h>
#include <signal.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#ifndef FUTEX_LINKAGE
#define FUTEX_LINKAGE "static"
#endif
#define CHECK(expr)                                                                                \
    do {                                                                                           \
        if (!(expr)) {                                                                             \
            fprintf(stderr, "FUTEX_FAIL line=%d: %s errno=%d\n", __LINE__, #expr, errno);          \
            exit(1);                                                                               \
        }                                                                                          \
    } while (0)

enum {
    WAIT = 0,
    WAKE = 1,
    REQUEUE = 3,
    CMP_REQUEUE = 4,
    WAKE_OP = 5,
    WAIT_BITSET = 9,
    WAKE_BITSET = 10,
    PRIVATE = 128
};

static long futex(uint32_t* word, int op, int value, const void* fourth, uint32_t* second,
                  uint32_t mask) {
    return syscall(SYS_futex, word, op, value, fourth, second, mask);
}

static atomic_uint entered;
static volatile sig_atomic_t signaled;

static void signal_handler(int signal) {
    if (signal == SIGUSR1)
        signaled++;
}

struct Waiter {
    uint32_t* word;
    int op, value, timed, error;
    uint32_t mask;
    struct timespec deadline;
};

static void* waiter(void* pointer) {
    struct Waiter* args = pointer;
    atomic_fetch_add(&entered, 1);
    long result =
        futex(args->word, args->op, args->value, args->timed ? &args->deadline : 0, 0, args->mask);
    CHECK(args->error ? result == -1 && errno == args->error : result == 0);
    return 0;
}

static struct timespec later(long milliseconds) {
    struct timespec at;
    CHECK(clock_gettime(CLOCK_MONOTONIC, &at) == 0);
    at.tv_nsec += milliseconds * 1000000;
    at.tv_sec += at.tv_nsec / 1000000000;
    at.tv_nsec %= 1000000000;
    return at;
}

static void await_waiters(unsigned count) {
    struct timespec limit = later(2000), now;
    while (atomic_load(&entered) != count) {
        sched_yield();
        CHECK(clock_gettime(CLOCK_MONOTONIC, &now) == 0);
        CHECK(now.tv_sec < limit.tv_sec ||
              (now.tv_sec == limit.tv_sec && now.tv_nsec < limit.tv_nsec));
    }
    usleep(20000);
}

static void expect_child(pid_t child, int expected) {
    int status;
    CHECK(waitpid(child, &status, 0) == child && WIFEXITED(status) &&
          WEXITSTATUS(status) == expected);
}

static uint32_t encode_op(unsigned op, int operand, unsigned compare, int argument) {
    return (op << 28) | (compare << 24) | (((uint32_t)operand & 0xfff) << 12) |
           ((uint32_t)argument & 0xfff);
}

static void check_wake_op(void) {
    const struct {
        unsigned op;
        int operand;
        uint32_t first, expected;
    } updates[] = {
        {0, -17, 10, (uint32_t)-17}, {1, -3, 10, 7}, {2 | 8, 4, 1, 17}, {3, 6, 247, 241},
        {4, 15, 241, 254},
    };

    uint32_t word[2] = {7, 0};
    for (size_t i = 0; i < sizeof(updates) / sizeof(updates[0]); i++) {
        word[1] = updates[i].first;
        uint32_t code = encode_op(updates[i].op, updates[i].operand, 0, word[1]);
        CHECK(futex(word, WAKE_OP | PRIVATE, 1, (void*)1, word + 1, code) == 0);
        CHECK(word[1] == updates[i].expected);
    }
    CHECK(futex(word, WAKE_OP | PRIVATE, 1, (void*)1, word + 1, encode_op(7, 1, 0, 0)) == -1 &&
          errno == ENOSYS && word[1] == 254);
    CHECK(futex(word, WAKE_OP | PRIVATE, 1, (void*)1, word + 1, encode_op(0, 8, 6, 0)) == -1 &&
          errno == ENOSYS && word[1] == 8);
    uint32_t code = encode_op(0, 3, 0, 8);
    CHECK(futex(word, WAKE_OP | PRIVATE, 1, (void*)1, NULL, code) == -1 && errno == EFAULT);
    CHECK(futex(word, WAKE_OP | PRIVATE, 1, (void*)1, (void*)((char*)word + 1), code) == -1 &&
          errno == EINVAL);
    uint32_t* mapped = mmap(NULL, 4096, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, 0);
    CHECK(mapped != MAP_FAILED);
    *mapped = 42;
    CHECK(mprotect(mapped, 4096, PROT_READ) == 0);
    CHECK(futex(word, WAKE_OP | PRIVATE, 1, (void*)1, mapped, code) == -1 && errno == EFAULT &&
          *mapped == 42);
    CHECK(mprotect(mapped, 4096, PROT_READ | PROT_WRITE) == 0);

    for (int private = 0; private <= PRIVATE; private += PRIVATE) {
        uint32_t* pair = private ? word : mapped;
        pair[0] = 7;
        pair[1] = (uint32_t)-3;
        pthread_t threads[2];
        struct Waiter args[] = {{.word = pair, .op = WAIT | private, .value = 7},
                                {.word = pair + 1, .op = WAIT | private, .value = -3}};
        atomic_store(&entered, 0);
        for (size_t i = 0; i < 2; i++)
            CHECK(pthread_create(&threads[i], 0, waiter, &args[i]) == 0);
        await_waiters(2);
        // The comparison uses the signed value before the update.
        int compare = private ? 2 : 5;
        CHECK(futex(pair, WAKE_OP | private, 1, (void*)1, pair + 1, encode_op(1, 4, compare, -1)) ==
              (private ? 2 : 1));
        CHECK(pair[0] == 7 && pair[1] == 1);
        if (!private)
            CHECK(futex(pair + 1, WAKE, 1, 0, 0, 0) == 1);
        for (size_t i = 0; i < 2; i++)
            CHECK(pthread_join(threads[i], 0) == 0);
    }
    CHECK(munmap(mapped, 4096) == 0);
    puts("FUTEX_WAKE_OP_PASS");
}

int main(void) {
    check_wake_op();
    uint32_t words[2] = {44, 44};
    struct timespec immediate = {0, 0}, invalid = {0, 1000000000};
    CHECK(futex(words, WAIT | PRIVATE, 43, 0, 0, 0) == -1 && errno == EAGAIN);
    CHECK(futex(words, WAIT | PRIVATE, 44, &immediate, 0, 0) == -1 && errno == ETIMEDOUT);
    CHECK(futex(words, WAIT, 44, &invalid, 0, 0) == -1 && errno == EINVAL);
    const struct timespec relative = {0, 30000000};
    for (unsigned attempt = 0; attempt < 8; ++attempt) {
        struct timespec before, after;
        CHECK(clock_gettime(CLOCK_MONOTONIC, &before) == 0);
        CHECK(futex(words, WAIT | PRIVATE, 44, &relative, 0, 0) == -1 && errno == ETIMEDOUT);
        CHECK(clock_gettime(CLOCK_MONOTONIC, &after) == 0);
        int64_t elapsed =
            (after.tv_sec - before.tv_sec) * INT64_C(1000000000) + after.tv_nsec - before.tv_nsec;
        CHECK(elapsed >= relative.tv_nsec);
    }
    CHECK(futex(words, WAKE | PRIVATE, -1, 0, 0, 0) == 0);
    CHECK(futex(words, WAKE_BITSET | PRIVATE, 1, 0, 0, 0) == -1 && errno == EINVAL);
    CHECK(futex((uint32_t*)((char*)words + 1), WAIT, 44, 0, 0, 0) == -1 && errno == EINVAL);
    CHECK(futex((uint32_t*)(uintptr_t)0x12345000, WAKE, 1, 0, 0, 0) == -1 && errno == EFAULT);
    CHECK(futex(words, 127, 0, 0, 0, 0) == -1 && errno == ENOSYS);
    pthread_t threads[3];
    struct Waiter args[3];
    atomic_store(&entered, 0);
    for (unsigned i = 0; i < 2; i++) {
        args[i] = (struct Waiter){
            .word = words, .op = WAIT_BITSET | PRIVATE, .value = 44, .mask = 1u << i};
        CHECK(pthread_create(&threads[i], 0, waiter, &args[i]) == 0);
    }
    await_waiters(2);
    CHECK(futex(words, WAKE_BITSET | PRIVATE, 2, 0, 0, 4) == 0);
    CHECK(futex(words, WAKE_BITSET | PRIVATE, 2, 0, 0, 1) == 1);
    CHECK(futex(words, WAKE_BITSET | PRIVATE, 2, 0, 0, 2) == 1);
    for (unsigned i = 0; i < 2; i++)
        CHECK(pthread_join(threads[i], 0) == 0);
    atomic_store(&entered, 0);
    for (unsigned i = 0; i < 3; i++) {
        args[i] = (struct Waiter){.word = words, .op = WAIT | PRIVATE, .value = 44};
        CHECK(pthread_create(&threads[i], 0, waiter, &args[i]) == 0);
    }
    await_waiters(3);
    CHECK(futex(words, CMP_REQUEUE | PRIVATE, 1, (void*)2, words + 1, 43) == -1 && errno == EAGAIN);
    CHECK(futex(words, CMP_REQUEUE | PRIVATE, 1, (void*)2, words + 1, 44) == 3);
    CHECK(futex(words, WAKE | PRIVATE, INT_MAX, 0, 0, 0) == 0);
    CHECK(futex(words + 1, WAKE | PRIVATE, INT_MAX, 0, 0, 0) == 2);
    for (unsigned i = 0; i < 3; i++)
        CHECK(pthread_join(threads[i], 0) == 0);
    struct sigaction action = {.sa_handler = signal_handler};
    CHECK(sigemptyset(&action.sa_mask) == 0 && sigaction(SIGUSR1, &action, 0) == 0);
    atomic_store(&entered, 0);
    args[0] = (struct Waiter){.word = words, .op = WAIT | PRIVATE, .value = 44, .error = EINTR};
    CHECK(pthread_create(threads, 0, waiter, args) == 0);
    await_waiters(1);
    CHECK(pthread_kill(threads[0], SIGUSR1) == 0);
    CHECK(pthread_join(threads[0], 0) == 0 && signaled == 1);
    puts("FUTEX_BITSET_REQUEUE_PASS");

    int fd = open("/tmp/futex-alias", O_CREAT | O_EXCL | O_RDWR, 0600);
    CHECK(fd >= 0 && ftruncate(fd, 4096) == 0);
    uint32_t* first = mmap(0, 4096, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    uint32_t* second = mmap(0, 4096, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    CHECK(first != MAP_FAILED && second != MAP_FAILED && first != second);
    *first = 44;
    atomic_store(&entered, 0);
    args[0] = (struct Waiter){.word = first, .op = WAIT, .value = 44};
    CHECK(pthread_create(threads, 0, waiter, args) == 0);
    await_waiters(1);
    CHECK(munmap(first, 4096) == 0);
    CHECK(futex(second, WAKE | PRIVATE, 1, 0, 0, 0) == 0);
    CHECK(futex(second, WAKE, 1, 0, 0, 0) == 1);
    CHECK(pthread_join(threads[0], 0) == 0);
    CHECK(munmap(second, 4096) == 0 && close(fd) == 0 && unlink("/tmp/futex-alias") == 0);
    first = mmap(0, 4096, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, 0);
    CHECK(first != MAP_FAILED);
    *first = 44;
    atomic_store(&entered, 0);
    args[0] = (struct Waiter){.word = first,
                              .op = WAIT_BITSET,
                              .value = 44,
                              .timed = 1,
                              .error = ETIMEDOUT,
                              .mask = UINT32_MAX,
                              .deadline = later(300)};
    CHECK(pthread_create(threads, 0, waiter, args) == 0);
    await_waiters(1);
    CHECK(munmap(first, 4096) == 0);
    second =
        mmap(first, 4096, PROT_READ | PROT_WRITE, MAP_FIXED | MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    CHECK(second == first);
    *second = 44;
    CHECK(futex(second, WAKE, 1, 0, 0, 0) == 0);
    CHECK(pthread_join(threads[0], 0) == 0 && munmap(second, 4096) == 0);
    puts("FUTEX_MAPPING_LIFETIME_PASS");

    uint32_t* shared = mmap(0, 4096, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, 0);
    CHECK(shared != MAP_FAILED);
    atomic_store((_Atomic uint32_t*)shared, 0);
    pid_t child = fork();
    CHECK(child >= 0);
    struct timespec limit = {2, 0};
    if (!child) {
        atomic_store((_Atomic uint32_t*)shared, 1);
        CHECK(futex(shared, WAKE, 1, 0, 0, 0) >= 0);
        while (atomic_load((_Atomic uint32_t*)shared) != 2)
            CHECK(futex(shared, WAIT, 1, &limit, 0, 0) == 0 || errno == EAGAIN);
        _exit(23);
    }
    while (!atomic_load((_Atomic uint32_t*)shared))
        CHECK(futex(shared, WAIT, 0, &limit, 0, 0) == 0 || errno == EAGAIN);
    atomic_store((_Atomic uint32_t*)shared, 2);
    CHECK(futex(shared, WAKE, 1, 0, 0, 0) >= 0);
    expect_child(child, 23);
    CHECK(munmap(shared, 4096) == 0);
    printf("FUTEX_TESTS_PASS linkage=%s\n", FUTEX_LINKAGE);
    return 0;
}
