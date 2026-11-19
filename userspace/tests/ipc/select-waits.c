// SPDX-License-Identifier: GPL-3.0-or-later
/**
 * @file    userspace/tests/ipc/select-waits.c
 * @brief   Select and pselect wait test.
 * @author  frankischilling
 * @date    2026-11-18
 *
 * Exercises descriptor sets, deadlines, and signal mask handling during waits.
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
#include <grp.h>
#include <limits.h>
#include <poll.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/resource.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#define CHECK(condition)                                                                           \
    do {                                                                                           \
        if (!(condition)) {                                                                        \
            fprintf(stderr, "SELECT_WAITS_FAIL line=%d errno=%d %s\n", __LINE__, errno,            \
                    #condition);                                                                   \
            _Exit(1);                                                                              \
        }                                                                                          \
    } while (0)

struct mask_argument {
    const void* address;
    size_t bytes;
};

static long raw_select(int nfds, void* read_set, void* write_set, void* except_set, void* timeout) {
    return syscall(SYS_select, nfds, read_set, write_set, except_set, timeout);
}

static long raw_pselect(int nfds, void* read_set, void* write_set, void* except_set, void* timeout,
                        const struct mask_argument* mask) {
    return syscall(SYS_pselect6, nfds, read_set, write_set, except_set, timeout, mask);
}

static int64_t monotonic(void) {
    struct timespec time;
    CHECK(clock_gettime(CLOCK_MONOTONIC, &time) == 0);
    return (int64_t)time.tv_sec * 1000000000 + time.tv_nsec;
}

static void child_done(pid_t child) {
    int status;
    CHECK(waitpid(child, &status, 0) == child && WIFEXITED(status) && WEXITSTATUS(status) == 0);
}

static void one_byte(int fd, char expected) {
    char byte;
    CHECK(read(fd, &byte, 1) == 1 && byte == expected);
}

static void arguments(void) {
    struct timespec zero = {0, 0}, invalid = {0, 1000000000};
    uint64_t mask = 0;
    struct mask_argument bad_size = {&mask, 7}, bad_mask = {(void*)1, 8}, ignored = {NULL, 99};
    CHECK(raw_pselect(0, NULL, NULL, NULL, &zero, &ignored) == 0);
    CHECK(raw_pselect(-1, NULL, NULL, NULL, &invalid, (void*)1) == -1 && errno == EFAULT);
    CHECK(raw_pselect(-1, NULL, NULL, NULL, &invalid, &bad_size) == -1 && errno == EINVAL);
    CHECK(raw_pselect(1, (void*)1, NULL, NULL, (void*)1, &bad_size) == -1 && errno == EFAULT);
    CHECK(raw_pselect(1, (void*)1, NULL, NULL, &zero, &bad_size) == -1 && errno == EINVAL);
    CHECK(raw_pselect(-1, NULL, NULL, NULL, &zero, &bad_mask) == -1 && errno == EFAULT);
    CHECK(raw_pselect(-1, NULL, NULL, NULL, &zero, NULL) == -1 && errno == EINVAL);
    CHECK(raw_select(-1, NULL, NULL, NULL, (void*)1) == -1 && errno == EFAULT);
    CHECK(raw_select(-1, NULL, NULL, NULL, NULL) == -1 && errno == EINVAL);
    struct timeval immediate = {0, 0};
    CHECK(raw_select(0, (void*)1, (void*)1, (void*)1, &immediate) == 0);
    CHECK(raw_select(INT_MAX, NULL, NULL, NULL, &immediate) == 0);
    puts("SELECT_WAITS_CASE argument-order");
}

static void bitmap_capacity(void) {
    long page = sysconf(_SC_PAGESIZE);
    CHECK(page > 0);
    char* area = mmap(NULL, 2 * page, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    CHECK(area != MAP_FAILED && mprotect(area + page, page, PROT_NONE) == 0);
    uint64_t* one_word = (uint64_t*)(area + page - sizeof(*one_word));
    struct timeval zero = {0, 0};
    CHECK(raw_select(INT_MAX, one_word, NULL, NULL, &zero) == 0 && *one_word == 0);
    CHECK(dup2(STDOUT_FILENO, 64) == 64);
    CHECK(raw_select(INT_MAX, one_word, NULL, NULL, &zero) == -1 && errno == EFAULT);

    struct rlimit limits;
    CHECK(getrlimit(RLIMIT_NOFILE, &limits) == 0);
    struct rlimit reduced = {32, limits.rlim_max};
    CHECK(setrlimit(RLIMIT_NOFILE, &reduced) == 0);
    uint64_t two_words[2] = {0, 1};
    CHECK(raw_select(65, NULL, two_words, NULL, &zero) == 1 && two_words[1] == 1);
    CHECK(setrlimit(RLIMIT_NOFILE, &limits) == 0);

    CHECK(close(64) == 0);
    CHECK(raw_select(65, two_words, NULL, NULL, &zero) == -1 && errno == EBADF);
    CHECK(two_words[1] == 1);
    pid_t child = fork();
    CHECK(child >= 0);
    if (!child) {
        CHECK(raw_select(INT_MAX, one_word, NULL, NULL, &zero) == 0);
        _Exit(0);
    }
    child_done(child);
    CHECK(munmap(area, page * 2) == 0);
    puts("SELECT_WAITS_CASE bitmap-capacity");
}

static void readiness_masks(void) {
    int ends[2];
    CHECK(socketpair(AF_UNIX, SOCK_STREAM, 0, ends) == 0);
    CHECK(write(ends[1], "x", 1) == 1);
    fd_set input, output, exceptional;
    FD_ZERO(&input);
    FD_SET(ends[0], &input);
    output = input;
    exceptional = input;
    struct timeval zero = {0, 0};
    CHECK(raw_select(ends[0] + 1, &input, &output, &exceptional, &zero) == 2);
    CHECK(FD_ISSET(ends[0], &input) && FD_ISSET(ends[0], &output));
    CHECK(!FD_ISSET(ends[0], &exceptional));
    CHECK(close(ends[0]) == 0 && close(ends[1]) == 0);

    CHECK(pipe(ends) == 0 && close(ends[1]) == 0);
    FD_ZERO(&input);
    FD_SET(ends[0], &input);
    output = input;
    exceptional = input;
    CHECK(raw_select(ends[0] + 1, &input, &output, &exceptional, &zero) == 1);
    CHECK(FD_ISSET(ends[0], &input) && !FD_ISSET(ends[0], &output));
    CHECK(!FD_ISSET(ends[0], &exceptional) && close(ends[0]) == 0);

    int path = open("/dev/null", O_PATH);
    CHECK(path >= 0);
    FD_ZERO(&input);
    FD_SET(path, &input);
    output = input;
    exceptional = input;
    CHECK(raw_select(path + 1, &input, &output, &exceptional, &zero) == 3);
    CHECK(FD_ISSET(path, &input) && FD_ISSET(path, &output) && FD_ISSET(path, &exceptional));
    CHECK(close(path) == 0);
    puts("SELECT_WAITS_CASE readiness-masks");
}

static void deadlines(void) {
    struct timeval select_time = {0, 31001};
    int64_t start = monotonic();
    CHECK(raw_select(0, NULL, NULL, NULL, &select_time) == 0);
    int64_t elapsed = monotonic() - start;
    CHECK(!select_time.tv_sec && !select_time.tv_usec && elapsed >= 31001000);
    printf("SELECT_WAITS_DEADLINE select request_ns=31001000 elapsed_ns=%lld\n",
           (long long)elapsed);

    struct timespec raw = {0, 31000001};
    start = monotonic();
    CHECK(raw_pselect(0, NULL, NULL, NULL, &raw, NULL) == 0);
    elapsed = monotonic() - start;
    CHECK(!raw.tv_sec && !raw.tv_nsec && elapsed >= 31000001);
    printf("SELECT_WAITS_DEADLINE pselect request_ns=31000001 elapsed_ns=%lld\n",
           (long long)elapsed);

    struct timespec libc = {0, 11000001};
    CHECK(pselect(0, NULL, NULL, NULL, &libc, NULL) == 0 && libc.tv_nsec == 11000001);
    int fd = open("/dev/null", O_RDONLY);
    CHECK(fd >= 0);
    fd_set readable;
    FD_ZERO(&readable);
    FD_SET(fd, &readable);
    select_time = (struct timeval){-1, 2000123};
    CHECK(raw_select(fd + 1, &readable, NULL, NULL, &select_time) == 1);
    CHECK(select_time.tv_sec >= 0 && select_time.tv_sec <= 1);
    CHECK(select_time.tv_usec >= 0 && select_time.tv_usec < 1000000);
    raw = (struct timespec){INT64_MAX, 999999999};
    CHECK(raw_pselect(fd + 1, &readable, NULL, NULL, &raw, NULL) == 1 && raw.tv_sec > 0);
    CHECK(close(fd) == 0);

    long page = sysconf(_SC_PAGESIZE);
    CHECK(page > 0);
    void* memory = mmap(NULL, page, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    CHECK(memory != MAP_FAILED);
    *(struct timeval*)memory = (struct timeval){0, 11001};
    CHECK(mprotect(memory, page, PROT_READ) == 0);
    CHECK(raw_select(0, NULL, NULL, NULL, memory) == 0);
    CHECK(((struct timeval*)memory)->tv_usec == 11001);
    CHECK(munmap(memory, page) == 0);
    puts("SELECT_WAITS_CASE deadlines");
}

static volatile sig_atomic_t handled;

static void handler(int signal) {
    if (signal == SIGUSR1)
        handled++;
}

static void temporary_mask(void) {
    struct sigaction action = {.sa_handler = handler, .sa_flags = SA_RESTART};
    sigset_t blocked, original, observed;
    CHECK(sigemptyset(&action.sa_mask) == 0 && sigaction(SIGUSR1, &action, NULL) == 0);
    CHECK(sigemptyset(&blocked) == 0 && sigaddset(&blocked, SIGUSR1) == 0);
    CHECK(sigprocmask(SIG_BLOCK, &blocked, &original) == 0);
    CHECK(kill(getpid(), SIGUSR1) == 0);
    int ready = open("/dev/null", O_RDONLY);
    int ends[2];
    CHECK(ready >= 0 && pipe(ends) == 0 && ends[0] > ready);
    uint64_t unblocked = 0;
    struct mask_argument mask = {&unblocked, 8};
    struct timespec timeout = {2, 0};
    fd_set bits;
    FD_ZERO(&bits);
    FD_SET(ready, &bits);
    FD_SET(ends[0], &bits);
    CHECK(raw_pselect(ends[0] + 1, &bits, NULL, NULL, &timeout, &mask) == 1);
    CHECK(FD_ISSET(ready, &bits) && !FD_ISSET(ends[0], &bits) && handled == 0);
    FD_SET(ends[0], &bits);
    FD_CLR(ready, &bits);
    timeout = (struct timespec){2, 0};
    CHECK(raw_pselect(ends[0] + 1, &bits, NULL, NULL, &timeout, &mask) == -1 && errno == EINTR);
    CHECK(handled == 1 && FD_ISSET(ends[0], &bits) && timeout.tv_sec <= 2);
    CHECK(sigprocmask(SIG_SETMASK, NULL, &observed) == 0 && sigismember(&observed, SIGUSR1) == 1);
    CHECK(sigprocmask(SIG_SETMASK, &original, NULL) == 0);
    CHECK(close(ready) == 0 && close(ends[0]) == 0 && close(ends[1]) == 0);
    puts("SELECT_WAITS_CASE temporary-signal-mask");
}

static void retained_set(int use_pselect) {
    int source[2], control[2], ack[2];
    CHECK(pipe(source) == 0 && pipe(control) == 0 && pipe(ack) == 0);
    CHECK(write(control[1], "C", 1) == 1);
    fd_set* bits =
        mmap(NULL, sizeof(*bits), PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, 0);
    CHECK(bits != MAP_FAILED);
    FD_ZERO(bits);
    FD_SET(source[0], bits);
    pid_t child = fork();
    CHECK(child >= 0);
    if (!child) {
        CHECK(write(ack[1], "R", 1) == 1);
        struct timespec nano = {2, 0};
        struct timeval micro = {2, 0};
        long result = use_pselect ? raw_pselect(control[0] + 1, bits, NULL, NULL, &nano, NULL)
                                  : raw_select(control[0] + 1, bits, NULL, NULL, &micro);
        CHECK(result == 1 && FD_ISSET(source[0], bits) && !FD_ISSET(control[0], bits));
        CHECK(write(ack[1], "D", 1) == 1);
        _Exit(0);
    }
    one_byte(ack[0], 'R');
    struct pollfd status = {.fd = ack[0], .events = POLLIN};
    CHECK(poll(&status, 1, 90) == 0);
    FD_CLR(source[0], bits);
    FD_SET(control[0], bits);
    CHECK(poll(&status, 1, 90) == 0 && FD_ISSET(control[0], bits));
    CHECK(write(source[1], "S", 1) == 1 && poll(&status, 1, 1000) == 1);
    one_byte(ack[0], 'D');
    child_done(child);
    CHECK(munmap(bits, sizeof(*bits)) == 0);
    CHECK(close(source[0]) == 0 && close(source[1]) == 0);
    CHECK(close(control[0]) == 0 && close(control[1]) == 0);
    CHECK(close(ack[0]) == 0 && close(ack[1]) == 0);
    puts(use_pselect ? "SELECT_WAITS_CASE retained-pselect" : "SELECT_WAITS_CASE retained-select");
}

static void stopped_wait(int use_pselect) {
    int channel[2];
    CHECK(pipe(channel) == 0);
    pid_t child = fork();
    CHECK(child >= 0);
    if (!child) {
        CHECK(close(channel[0]) == 0 && write(channel[1], "R", 1) == 1);
        struct timespec nano = {0, 500000000};
        struct timeval micro = {0, 500000};
        if (use_pselect)
            CHECK(raw_pselect(0, NULL, NULL, NULL, &nano, NULL) == 0 && !nano.tv_nsec);
        else
            CHECK(raw_select(0, NULL, NULL, NULL, &micro) == 0 && !micro.tv_usec);
        CHECK(write(channel[1], "D", 1) == 1);
        _Exit(0);
    }
    CHECK(close(channel[1]) == 0);
    one_byte(channel[0], 'R');
    struct pollfd status = {.fd = channel[0], .events = POLLIN};
    CHECK(poll(&status, 1, 90) == 0 && kill(child, SIGSTOP) == 0);
    int stopped = 0;
    CHECK(waitpid(child, &stopped, WUNTRACED) == child && WIFSTOPPED(stopped));
    CHECK(poll(&status, 1, 550) == 0 && kill(child, SIGCONT) == 0);
    CHECK(poll(&status, 1, 110) == 0 && poll(&status, 1, 1000) == 1);
    one_byte(channel[0], 'D');
    child_done(child);
    CHECK(close(channel[0]) == 0);
    puts(use_pselect ? "SELECT_WAITS_CASE stopped-pselect" : "SELECT_WAITS_CASE stopped-select");
}

int main(int argc, char** argv) {
    CHECK(setvbuf(stdout, NULL, _IOLBF, 0) == 0);
    alarm(20);
    if (argc == 2 && !strcmp(argv[1], "--ordinary"))
        CHECK(setgroups(0, NULL) == 0 && setgid(65534) == 0 && setuid(65534) == 0);
    else
        CHECK(argc == 1);
    arguments();
    bitmap_capacity();
    readiness_masks();
    deadlines();
    temporary_mask();
    retained_set(0);
    retained_set(1);
    stopped_wait(0);
    stopped_wait(1);
    printf("SELECT_WAITS_PASS uid=%lu\n", (unsigned long)getuid());
    return 0;
}
