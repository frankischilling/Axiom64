// SPDX-License-Identifier: GPL-3.0-or-later
/**
 * @file    userspace/tests/ipc/poll-waits.c
 * @brief   Poll and ppoll wait test.
 * @author  frankischilling
 * @date    2026-11-18
 *
 * Exercises descriptor event masks, wait timing, and signal interruption.
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
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/resource.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#define CHECK(condition)                                                                           \
    do {                                                                                           \
        if (!(condition)) {                                                                        \
            fprintf(stderr, "POLL_WAITS_FAIL line=%d errno=%d %s\n", __LINE__, errno, #condition); \
            _Exit(1);                                                                              \
        }                                                                                          \
    } while (0)

static long raw_ppoll(void* descriptors, unsigned count, const struct timespec* timeout,
                      const sigset_t* mask, size_t size) {
    return syscall(SYS_ppoll, descriptors, count, timeout, mask, size);
}

static int64_t monotonic(void) {
    struct timespec time;
    CHECK(clock_gettime(CLOCK_MONOTONIC, &time) == 0);
    return (int64_t)time.tv_sec * 1000000000 + time.tv_nsec;
}

static void one_byte(int fd, char expected) {
    char byte;
    CHECK(read(fd, &byte, 1) == 1 && byte == expected);
}

static void child_done(pid_t child) {
    int status;
    CHECK(waitpid(child, &status, 0) == child && WIFEXITED(status) && WEXITSTATUS(status) == 0);
}

static void descriptors_and_validation(void) {
    struct timespec zero = {0};
    CHECK(raw_ppoll(NULL, 0, &zero, NULL, 99) == 0);
    sigset_t mask;
    CHECK(sigemptyset(&mask) == 0);
    struct timespec invalid[] = {{-1, 0}, {0, -1}, {0, 1000000000}};
    for (size_t i = 0; i < sizeof(invalid) / sizeof(invalid[0]); ++i)
        CHECK(raw_ppoll((void*)1, 1, &invalid[i], (void*)1, 8) == -1 && errno == EINVAL);
    CHECK(raw_ppoll(NULL, 0, (void*)1, &mask, 7) == -1 && errno == EFAULT);
    CHECK(raw_ppoll((void*)1, 1, &zero, &mask, 7) == -1 && errno == EINVAL);
    CHECK(raw_ppoll(NULL, 0, &zero, (void*)1, 8) == -1 && errno == EFAULT);
    CHECK(raw_ppoll((void*)1, 1, &zero, NULL, 0) == -1 && errno == EFAULT);

    struct rlimit limits;
    CHECK(getrlimit(RLIMIT_NOFILE, &limits) == 0);
    struct rlimit lower = {.rlim_cur = 2, .rlim_max = limits.rlim_max};
    CHECK(setrlimit(RLIMIT_NOFILE, &lower) == 0);
    CHECK(raw_ppoll((void*)1, 3, &zero, NULL, 0) == -1 && errno == EINVAL);
    CHECK(syscall(SYS_poll, (void*)1, 3, 0) == -1 && errno == EINVAL);
    CHECK(setrlimit(RLIMIT_NOFILE, &limits) == 0);

    int tube[2];
    CHECK(pipe(tube) == 0 && close(tube[1]) == 0);
    int path = open("/", O_PATH | O_CLOEXEC);
    CHECK(path >= 0);
    struct pollfd entries[] = {
        {.fd = -23, .events = POLLIN, .revents = -1},
        {.fd = INT_MAX, .revents = -1},
        {.fd = path, .revents = -1},
        {.fd = tube[0], .revents = -1},
    };
    CHECK(raw_ppoll(entries, sizeof(entries) / sizeof(entries[0]), &zero, NULL, 0) == 3);
    CHECK(entries[0].revents == 0 && entries[1].revents == POLLNVAL);
    CHECK(entries[2].revents == POLLNVAL && entries[3].revents == POLLHUP);
    CHECK(entries[0].fd == -23 && entries[0].events == POLLIN && entries[3].events == 0);
    CHECK(close(path) == 0 && close(tube[0]) == 0);
    puts("POLL_WAITS_CASE arguments-and-masks");
}

static void output_fields(void) {
    int tube[2];
    CHECK(pipe(tube) == 0 && write(tube[1], "M", 1) == 1);
    long page = sysconf(_SC_PAGESIZE);
    CHECK(page > 0);
    char* pages =
        mmap(NULL, 2 * (size_t)page, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    CHECK(pages != MAP_FAILED);
    char* address = pages + page - offsetof(struct pollfd, revents);
    struct pollfd entry = {.fd = tube[0], .events = POLLIN, .revents = -1};
    memcpy(address, &entry, sizeof(entry));
    CHECK(mprotect(pages, page, PROT_READ) == 0);
    CHECK(syscall(SYS_poll, address, 1, 0) == 1);
    memcpy(&entry, address, sizeof(entry));
    CHECK(entry.fd == tube[0] && entry.events == POLLIN && entry.revents == POLLIN);
    CHECK(mprotect(pages + page, page, PROT_READ) == 0);
    struct timespec zero = {0};
    CHECK(raw_ppoll(address, 1, &zero, NULL, 0) == -1 && errno == EFAULT);
    CHECK(munmap(pages, 2 * (size_t)page) == 0 && close(tube[0]) == 0 && close(tube[1]) == 0);
    puts("POLL_WAITS_CASE revents-copy");
}

static void deadlines(void) {
    struct timespec raw = {.tv_nsec = 31000001};
    int64_t start = monotonic();
    CHECK(raw_ppoll(NULL, 0, &raw, NULL, 0) == 0 && !raw.tv_sec && !raw.tv_nsec);
    int64_t elapsed = monotonic() - start;
    CHECK(elapsed >= 31000001 && elapsed < 2000000000);
    const struct timespec timeout = {.tv_nsec = 11000001};
    start = monotonic();
    CHECK(ppoll(NULL, 0, &timeout, NULL) == 0);
    CHECK(monotonic() - start >= 11000001 && timeout.tv_nsec == 11000001);

    long page = sysconf(_SC_PAGESIZE);
    CHECK(page > 0);
    struct timespec* protected =
        mmap(NULL, page, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    CHECK(protected != MAP_FAILED);
    *protected = timeout;
    CHECK(mprotect(protected, page, PROT_READ) == 0);
    CHECK(raw_ppoll(NULL, 0, protected, NULL, 0) == 0 && protected->tv_nsec == 11000001);
    CHECK(munmap(protected, page) == 0);
    printf("POLL_WAITS_DEADLINE request_ns=31000001 elapsed_ns=%lld\n", (long long)elapsed);
    puts("POLL_WAITS_CASE raw-and-libc-deadlines");
}

static volatile sig_atomic_t caught;

static void handle_signal(int number) {
    caught = number;
}

static void temporary_mask(void) {
    struct sigaction action = {.sa_handler = handle_signal, .sa_flags = SA_RESTART};
    struct sigaction previous;
    sigset_t blocked, previous_mask, temporary, after;
    CHECK(sigemptyset(&action.sa_mask) == 0 && sigaction(SIGUSR1, &action, &previous) == 0);
    CHECK(sigemptyset(&blocked) == 0 && sigaddset(&blocked, SIGUSR1) == 0);
    CHECK(sigprocmask(SIG_BLOCK, &blocked, &previous_mask) == 0 && sigemptyset(&temporary) == 0);
    CHECK(raise(SIGUSR1) == 0 && caught == 0);

    int tube[2];
    CHECK(pipe(tube) == 0 && write(tube[1], "R", 1) == 1);
    struct pollfd entry = {.fd = tube[0], .events = POLLIN};
    struct timespec time = {.tv_sec = 2, .tv_nsec = 123456789};
    CHECK(raw_ppoll(&entry, 1, &time, &temporary, 8) == 1 && entry.revents == POLLIN);
    CHECK(caught == 0 && time.tv_sec == 2 && time.tv_nsec <= 123456789);
    one_byte(tube[0], 'R');

    time = (struct timespec){.tv_sec = 2, .tv_nsec = 123456789};
    CHECK(raw_ppoll(&entry, 1, &time, &temporary, 8) == -1 && errno == EINTR);
    CHECK(caught == SIGUSR1 && entry.revents == 0 && time.tv_sec == 2 && time.tv_nsec <= 123456789);
    CHECK(sigprocmask(SIG_SETMASK, NULL, &after) == 0 && sigismember(&after, SIGUSR1) == 1);
    CHECK(raise(SIGUSR1) == 0);
    struct timespec instant = {0};
    CHECK(raw_ppoll(NULL, 0, &instant, &temporary, 8) == -1 && errno == EINTR);
    CHECK(sigprocmask(SIG_SETMASK, &previous_mask, NULL) == 0);
    CHECK(sigaction(SIGUSR1, &previous, NULL) == 0 && close(tube[0]) == 0 && close(tube[1]) == 0);
    puts("POLL_WAITS_CASE temporary-signal-mask");
}

static void retained_array(int use_ppoll) {
    int source[2], control[2];
    CHECK(pipe(source) == 0 && pipe(control) == 0);
    struct pollfd* shared =
        mmap(NULL, sizeof(*shared), PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, 0);
    CHECK(shared != MAP_FAILED);
    *shared = (struct pollfd){.fd = source[0], .events = POLLIN, .revents = -1};
    pid_t child = fork();
    CHECK(child >= 0);
    if (!child) {
        CHECK(close(control[0]) == 0 && write(control[1], "B", 1) == 1);
        struct timespec limit = {.tv_sec = 2};
        long ready = use_ppoll ? raw_ppoll(shared, 1, &limit, NULL, 0) : poll(shared, 1, 2000);
        CHECK(ready == 1 && shared->revents == POLLIN);
        CHECK(shared->fd == -1 && shared->events == POLLOUT);
        CHECK(write(control[1], "D", 1) == 1);
        _Exit(0);
    }
    CHECK(close(control[1]) == 0);
    one_byte(control[0], 'B');
    struct pollfd ack = {.fd = control[0], .events = POLLIN};
    CHECK(poll(&ack, 1, 90) == 0 && shared->revents == -1);
    shared->fd = -1;
    shared->events = POLLOUT;
    CHECK(write(source[1], "P", 1) == 1 && poll(&ack, 1, 1000) == 1);
    one_byte(control[0], 'D');
    child_done(child);
    CHECK(close(control[0]) == 0 && close(source[0]) == 0 && close(source[1]) == 0);
    CHECK(munmap(shared, sizeof(*shared)) == 0);
    puts(use_ppoll ? "POLL_WAITS_CASE retained-ppoll" : "POLL_WAITS_CASE retained-poll");
}

static void stopped_wait(int use_ppoll) {
    int pipefd[2];
    CHECK(pipe(pipefd) == 0);
    pid_t child = fork();
    CHECK(child >= 0);
    if (!child) {
        CHECK(close(pipefd[0]) == 0 && write(pipefd[1], "B", 1) == 1);
        struct timespec timeout = {.tv_nsec = 500000000};
        long result = use_ppoll ? raw_ppoll(NULL, 0, &timeout, NULL, 0) : poll(NULL, 0, 500);
        CHECK(result == 0 && (!use_ppoll || !timeout.tv_nsec));
        CHECK(write(pipefd[1], "D", 1) == 1);
        _Exit(0);
    }
    CHECK(close(pipefd[1]) == 0);
    one_byte(pipefd[0], 'B');
    struct pollfd status = {.fd = pipefd[0], .events = POLLIN};
    CHECK(poll(&status, 1, 80) == 0 && kill(child, SIGSTOP) == 0);
    int stopped;
    CHECK(waitpid(child, &stopped, WUNTRACED) == child && WIFSTOPPED(stopped));
    CHECK(poll(&status, 1, 600) == 0 && kill(child, SIGCONT) == 0);
    CHECK(poll(&status, 1, 180) == (use_ppoll ? 0 : 1));
    if (use_ppoll)
        CHECK(poll(&status, 1, 1000) == 1);
    one_byte(pipefd[0], 'D');
    child_done(child);
    CHECK(close(pipefd[0]) == 0);
    puts(use_ppoll ? "POLL_WAITS_CASE stopped-ppoll" : "POLL_WAITS_CASE stopped-poll");
}

int main(int argc, char** argv) {
    CHECK(setvbuf(stdout, NULL, _IOLBF, 0) == 0);
    alarm(16);
    if (argc == 2 && strcmp(argv[1], "--ordinary") == 0)
        CHECK(setgroups(0, NULL) == 0 && setgid(65534) == 0 && setuid(65534) == 0);
    else
        CHECK(argc == 1);
    descriptors_and_validation();
    output_fields();
    deadlines();
    temporary_mask();
    retained_array(0);
    retained_array(1);
    stopped_wait(0);
    stopped_wait(1);
    printf("POLL_WAITS_PASS uid=%lu\n", (unsigned long)getuid());
    return 0;
}
