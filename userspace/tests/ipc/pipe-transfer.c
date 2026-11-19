// SPDX-License-Identifier: GPL-3.0-or-later
/**
 * @file    userspace/tests/ipc/pipe-transfer.c
 * @brief   Pipe-to-pipe splice and tee tests.
 * @author  frankischilling
 * @date    2026-11-18
 *
 * Exercises shared and moved pipe slots, packet boundaries, and held
 * descriptions across blocked transfers.
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
#include <poll.h>
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <unistd.h>

#define CHECK(condition)                                                                           \
    do {                                                                                           \
        if (!(condition)) {                                                                        \
            fprintf(stderr, "PIPE_TRANSFER_FAIL line=%d errno=%d %s\n", __LINE__, errno,           \
                    #condition);                                                                   \
            exit(1);                                                                               \
        }                                                                                          \
    } while (0)

static void close_pair(int pair[2]) {
    CHECK(close(pair[0]) == 0 && close(pair[1]) == 0);
}

static void arguments(void) {
    int source[2], target[2];
    CHECK(pipe(source) == 0 && pipe(target) == 0);
    CHECK(splice(-1, NULL, -1, NULL, 0, ~0u) == 0);
    CHECK(tee(-1, -1, 0, ~0u) == -1 && errno == EINVAL);
    CHECK(tee(-1, -1, 0, 0) == 0);
    CHECK(splice(-1, NULL, target[1], NULL, 1, 0) == -1 && errno == EBADF);
    CHECK(tee(source[0], source[1], 1, 0) == -1 && errno == EINVAL);
    CHECK(tee(source[1], target[1], 1, 0) == -1 && errno == EBADF);
    CHECK(tee(source[0], target[0], 1, 0) == -1 && errno == EBADF);
    loff_t offset = 0;
    CHECK(splice(source[0], &offset, target[1], NULL, 1, 0) == -1 && errno == ESPIPE);
    CHECK(splice(source[0], NULL, target[1], &offset, 1, 0) == -1 && errno == ESPIPE);
    CHECK(tee(source[0], target[1], 1, SPLICE_F_NONBLOCK) == -1 && errno == EAGAIN);
    CHECK(close(source[1]) == 0);
    CHECK(splice(source[0], NULL, target[1], NULL, 1, 0) == 0);
    CHECK(tee(source[0], target[1], 1, 0) == 0);
    CHECK(close(source[0]) == 0);
    close_pair(target);
    puts("PIPE_TRANSFER_CASE arguments");
}

static void streams(void) {
    int source[2], target[2];
    char buffer[8];
    CHECK(pipe2(source, O_NONBLOCK) == 0 && pipe2(target, O_NONBLOCK) == 0);
    CHECK(fcntl(target[1], F_SETPIPE_SZ, 4096) == 4096);
    CHECK(write(source[1], "abcd", 4) == 4);
    CHECK(tee(source[0], target[1], 2, SPLICE_F_MORE) == 2);
    CHECK(read(target[0], buffer, 1) == 1 && buffer[0] == 'a');
    CHECK(write(target[1], "x", 1) == -1 && errno == EAGAIN);
    CHECK(splice(source[0], NULL, target[1], NULL, 2, 0) == -1 && errno == EAGAIN);
    CHECK(read(target[0], buffer, 1) == 1 && buffer[0] == 'b');
    CHECK(splice(source[0], NULL, target[1], NULL, 2, SPLICE_F_MOVE) == 2);
    CHECK(read(target[0], buffer, sizeof(buffer)) == 2 && !memcmp(buffer, "ab", 2));
    CHECK(write(source[1], "ef", 2) == 2);
    CHECK(splice(source[0], NULL, target[1], NULL, sizeof(buffer), 0) == 4);
    CHECK(write(target[1], "gh", 2) == 2);
    CHECK(read(target[0], buffer, sizeof(buffer)) == 6 && !memcmp(buffer, "cdefgh", 6));
    CHECK(read(source[0], buffer, 1) == -1 && errno == EAGAIN);
    close_pair(source);
    close_pair(target);
    puts("PIPE_TRANSFER_CASE shared-and-moved-slots");
}

static void packets(void) {
    int source[2], target[2];
    char buffer[8];
    CHECK(pipe2(source, O_DIRECT | O_NONBLOCK) == 0 && pipe2(target, O_NONBLOCK) == 0);
    CHECK(write(source[1], "abcd", 4) == 4);
    CHECK(splice(source[0], NULL, target[1], NULL, 2, 0) == 2);
    CHECK(read(target[0], buffer, 1) == 1 && buffer[0] == 'a');
    CHECK(read(target[0], buffer, sizeof(buffer)) == -1 && errno == EAGAIN);
    CHECK(tee(source[0], target[1], 8, 0) == 2);
    CHECK(read(target[0], buffer, sizeof(buffer)) == 2 && !memcmp(buffer, "cd", 2));
    CHECK(read(source[0], buffer, sizeof(buffer)) == 2 && !memcmp(buffer, "cd", 2));
    close_pair(source);
    close_pair(target);
    puts("PIPE_TRANSFER_CASE packet-boundaries");
}

static void readiness(void) {
    int source[2], target[2];
    CHECK(pipe(source) == 0 && pipe(target) == 0);
    CHECK(fcntl(source[1], F_SETPIPE_SZ, 4096) == 4096);
    CHECK(write(source[1], "p", 1) == 1);
    int epoll = epoll_create1(EPOLL_CLOEXEC);
    struct epoll_event input = {.events = EPOLLOUT | EPOLLET, .data.u64 = 1};
    struct epoll_event output = {.events = EPOLLIN | EPOLLET, .data.u64 = 2};
    CHECK(epoll >= 0 && epoll_ctl(epoll, EPOLL_CTL_ADD, source[1], &input) == 0);
    CHECK(epoll_ctl(epoll, EPOLL_CTL_ADD, target[0], &output) == 0);
    struct epoll_event events[2];
    CHECK(epoll_wait(epoll, events, 2, 0) == 0);
    CHECK(tee(source[0], target[1], 1, 0) == 1);
    CHECK(epoll_wait(epoll, events, 2, 1000) == 1 && events[0].data.u64 == 2);
    CHECK(events[0].events == EPOLLIN);
    char byte;
    CHECK(read(target[0], &byte, 1) == 1 && byte == 'p');
    CHECK(splice(source[0], NULL, target[1], NULL, 1, 0) == 1);
    unsigned seen = 0;
    while (seen != 3) {
        int count = epoll_wait(epoll, events, 2, 1000);
        CHECK(count > 0);
        for (int i = 0; i < count; ++i) {
            unsigned id = events[i].data.u64;
            CHECK((id == 1 || id == 2) && !(seen & id));
            CHECK(events[i].events == (id == 1 ? EPOLLOUT : EPOLLIN));
            seen |= id;
        }
    }
    CHECK(read(target[0], &byte, 1) == 1 && byte == 'p');
    CHECK(close(epoll) == 0);
    close_pair(source);
    close_pair(target);
    puts("PIPE_TRANSFER_CASE readiness");
}

static volatile sig_atomic_t broken_pipes;

static void record_sigpipe(int signo) {
    if (signo == SIGPIPE)
        ++broken_pipes;
}

static void broken_output(void) {
    int source[2], target[2];
    CHECK(pipe2(source, O_NONBLOCK) == 0 && pipe(target) == 0);
    struct sigaction action = {.sa_handler = record_sigpipe}, previous;
    CHECK(sigemptyset(&action.sa_mask) == 0 && sigaction(SIGPIPE, &action, &previous) == 0);
    CHECK(close(target[0]) == 0 && write(source[1], "x", 1) == 1);
    CHECK(tee(source[0], target[1], 1, 0) == -1 && errno == EPIPE);
    CHECK(splice(source[0], NULL, target[1], NULL, 1, 0) == -1 && errno == EPIPE);
    CHECK(broken_pipes == 2);
    char byte;
    CHECK(read(source[0], &byte, 1) == 1 && byte == 'x');
    CHECK(close(target[1]) == 0 && sigaction(SIGPIPE, &previous, NULL) == 0);
    close_pair(source);
    puts("PIPE_TRANSFER_CASE broken-output");
}

struct transfer {
    int source, target, ready, complete;
    int duplicate;
    int expected_error;
};

static void* transfer_one(void* argument) {
    struct transfer* transfer = argument;
    CHECK(write(transfer->ready, "r", 1) == 1);
    ssize_t count = transfer->duplicate
                        ? tee(transfer->source, transfer->target, 1, 0)
                        : splice(transfer->source, NULL, transfer->target, NULL, 1, 0);
    if (transfer->expected_error)
        CHECK(count == -1 && errno == transfer->expected_error);
    else
        CHECK(count == 1);
    CHECK(write(transfer->complete, "c", 1) == 1);
    return NULL;
}

static void blocked(int duplicate) {
    int source[2], target[2], replacement[2], ready[2], complete[2];
    CHECK(pipe(source) == 0 && pipe(target) == 0 && pipe2(replacement, O_NONBLOCK) == 0);
    CHECK(pipe(ready) == 0 && pipe(complete) == 0);
    char block[4096] = {0};
    if (!duplicate) {
        CHECK(fcntl(target[1], F_SETPIPE_SZ, sizeof(block)) == sizeof(block));
        CHECK(write(source[1], "s", 1) == 1);
        CHECK(write(target[1], block, sizeof(block)) == sizeof(block));
    }
    struct transfer transfer = {
        .source = source[0],
        .target = target[1],
        .ready = ready[1],
        .complete = complete[1],
        .duplicate = duplicate,
    };
    pthread_t worker;
    CHECK(pthread_create(&worker, NULL, transfer_one, &transfer) == 0);
    char byte;
    CHECK(read(ready[0], &byte, 1) == 1 && byte == 'r');
    struct pollfd done = {.fd = complete[0], .events = POLLIN};
    CHECK(poll(&done, 1, 80) == 0);
    int selected = duplicate ? source[0] : target[1];
    CHECK(dup2(replacement[duplicate ? 0 : 1], selected) == selected);
    if (duplicate)
        CHECK(write(source[1], "s", 1) == 1);
    else
        CHECK(read(target[0], block, sizeof(block)) == sizeof(block));
    CHECK(poll(&done, 1, 3000) == 1 && read(complete[0], &byte, 1) == 1 && byte == 'c');
    CHECK(pthread_join(worker, NULL) == 0);
    CHECK(read(target[0], &byte, 1) == 1 && byte == 's');
    CHECK(read(replacement[0], &byte, 1) == -1 && errno == EAGAIN);
    close_pair(source);
    close_pair(target);
    close_pair(replacement);
    close_pair(ready);
    close_pair(complete);
    puts(duplicate ? "PIPE_TRANSFER_CASE retained-input" : "PIPE_TRANSFER_CASE retained-output");
}

static volatile sig_atomic_t caught_signal;

static void report_interrupt(int signo) {
    if (signo == SIGUSR1) {
        int saved = errno;
        ssize_t ignored = write(caught_signal, "i", 1);
        (void)ignored;
        errno = saved;
    }
}

static void interrupt(int restart) {
    int source[2], target[2], ready[2], complete[2], caught[2];
    CHECK(pipe(source) == 0 && pipe(target) == 0 && pipe(ready) == 0 && pipe(complete) == 0);
    CHECK(pipe(caught) == 0 && fcntl(target[0], F_SETFL, O_NONBLOCK) == 0);
    caught_signal = caught[1];
    struct sigaction action = {
        .sa_handler = report_interrupt,
        .sa_flags = restart ? SA_RESTART : 0,
    };
    struct sigaction previous;
    CHECK(sigemptyset(&action.sa_mask) == 0 && sigaction(SIGUSR1, &action, &previous) == 0);
    struct transfer transfer = {
        .source = source[0],
        .target = target[1],
        .ready = ready[1],
        .complete = complete[1],
        .duplicate = 1,
        .expected_error = restart ? 0 : EINTR,
    };
    pthread_t worker;
    CHECK(pthread_create(&worker, NULL, transfer_one, &transfer) == 0);
    char byte;
    CHECK(read(ready[0], &byte, 1) == 1 && byte == 'r');
    struct pollfd done = {.fd = complete[0], .events = POLLIN};
    CHECK(poll(&done, 1, 80) == 0);
    CHECK(pthread_kill(worker, SIGUSR1) == 0);
    CHECK(read(caught[0], &byte, 1) == 1 && byte == 'i');
    if (restart) {
        CHECK(poll(&done, 1, 80) == 0 && write(source[1], "s", 1) == 1);
    }
    CHECK(poll(&done, 1, 3000) == 1 && read(complete[0], &byte, 1) == 1 && byte == 'c');
    CHECK(pthread_join(worker, NULL) == 0);
    if (restart) {
        CHECK(read(target[0], &byte, 1) == 1 && byte == 's');
        CHECK(read(source[0], &byte, 1) == 1 && byte == 's');
    } else {
        CHECK(read(target[0], &byte, 1) == -1 && errno == EAGAIN);
    }
    CHECK(sigaction(SIGUSR1, &previous, NULL) == 0);
    close_pair(source);
    close_pair(target);
    close_pair(ready);
    close_pair(complete);
    close_pair(caught);
    puts(restart ? "PIPE_TRANSFER_CASE restart" : "PIPE_TRANSFER_CASE interruption");
}

int main(int argc, char** argv) {
    if (argc == 2) {
        CHECK(!strcmp(argv[1], "--ordinary"));
        CHECK(setgroups(0, NULL) == 0 && setgid(65534) == 0 && setuid(65534) == 0);
    } else {
        CHECK(argc == 1);
    }
    arguments();
    streams();
    packets();
    readiness();
    broken_output();
    blocked(0);
    blocked(1);
    interrupt(0);
    interrupt(1);
    printf("PIPE_TRANSFER_PASS uid=%u\n", (unsigned)getuid());
    return 0;
}
