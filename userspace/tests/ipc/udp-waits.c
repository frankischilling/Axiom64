// SPDX-License-Identifier: GPL-3.0-or-later
/**
 * @file    userspace/tests/ipc/udp-waits.c
 * @brief   UDP readiness wait test.
 * @author  frankischilling
 * @date    2026-11-18
 *
 * Checks notification of blocked waiters on IPv4 and IPv6 datagram socket
 * operations.
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
#include <arpa/inet.h>
#include <errno.h>
#include <grp.h>
#include <poll.h>
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <time.h>
#include <unistd.h>

#define CHECK(condition)                                                                           \
    do {                                                                                           \
        if (!(condition)) {                                                                        \
            fprintf(stderr, "UDP_WAITS_FAIL line=%d errno=%d %s\n", __LINE__, errno, #condition);  \
            _Exit(1);                                                                              \
        }                                                                                          \
    } while (0)

enum wait_call { WAIT_POLL, WAIT_PPOLL, WAIT_SELECT, WAIT_PSELECT };

static const char* const names[] = {"poll", "ppoll", "select", "pselect"};

struct wait_case {
    enum wait_call call;
    int watched, sync, result, ready;
};

static void* worker(void* argument) {
    struct wait_case* test = argument;
    struct pollfd selected = {.fd = test->watched, .events = POLLIN | POLLRDNORM};
    struct timeval micro = {0, 600000};
    struct timespec nano = {0, 600000000};
    fd_set input;
    FD_ZERO(&input);
    FD_SET(test->watched, &input);
    CHECK(write(test->sync, "R", 1) == 1);
    switch (test->call) {
    case WAIT_POLL:
        test->result = poll(&selected, 1, 600);
        break;
    case WAIT_PPOLL:
        test->result = syscall(SYS_ppoll, &selected, 1, &nano, NULL, 0);
        break;
    case WAIT_SELECT:
        test->result = syscall(SYS_select, test->watched + 1, &input, NULL, NULL, &micro);
        break;
    case WAIT_PSELECT:
        test->result = syscall(SYS_pselect6, test->watched + 1, &input, NULL, NULL, &nano, NULL);
        break;
    }
    test->ready = test->call >= WAIT_SELECT ? !!FD_ISSET(test->watched, &input) : selected.revents;
    CHECK(write(test->sync, "D", 1) == 1);
    return NULL;
}

static void one_byte(int fd, char expected) {
    char value;
    CHECK(read(fd, &value, 1) == 1 && value == expected);
}

static void udp_pair(int family, int pair[2]) {
    struct sockaddr_storage endpoint;
    memset(&endpoint, 0, sizeof(endpoint));
    socklen_t length;
    if (family == AF_INET) {
        struct sockaddr_in* address = (void*)&endpoint;
        address->sin_family = AF_INET;
        address->sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        length = sizeof(*address);
    } else {
        struct sockaddr_in6* address = (void*)&endpoint;
        address->sin6_family = AF_INET6;
        address->sin6_addr = in6addr_loopback;
        length = sizeof(*address);
    }
    pair[0] = socket(family, SOCK_DGRAM, 0);
    pair[1] = socket(family, SOCK_DGRAM, 0);
    CHECK(pair[0] >= 0 && pair[1] >= 0);
    CHECK(bind(pair[0], (void*)&endpoint, length) == 0);
    CHECK(getsockname(pair[0], (void*)&endpoint, &length) == 0);
    CHECK(connect(pair[1], (void*)&endpoint, length) == 0);
}

static void send_and_consume(int sender, int receiver, size_t length) {
    char received = 0;
    CHECK(send(sender, "U", length, 0) == (ssize_t)length);
    CHECK(recv(receiver, &received, 1, 0) == (ssize_t)length);
    CHECK(!length || received == 'U');
}

static void consume_error(int socket) {
    CHECK(send(socket, "U", 1, 0) == 1);
    struct pollfd error = {.fd = socket, .events = 0};
    CHECK(poll(&error, 1, 200) == 1 && error.revents == POLLERR);
    int pending = 0;
    socklen_t size = sizeof(pending);
    CHECK(getsockopt(socket, SOL_SOCKET, SO_ERROR, &pending, &size) == 0);
    CHECK(pending == ECONNREFUSED && size == sizeof(pending));
    CHECK(poll(&error, 1, 0) == 0);
}

static void udp_pulse(enum wait_call call, int family, int error) {
    int pair[2], control[2], replacement[2], other[2] = {-1, -1};
    udp_pair(family, pair);
    if (error) {
        CHECK(close(pair[0]) == 0);
        pair[0] = pair[1];
    } else {
        udp_pair(family, other);
    }
    CHECK(pipe(control) == 0 && pipe(replacement) == 0);
    CHECK(write(replacement[1], "N", 1) == 1);
    int alias = dup(pair[0]);
    CHECK(alias >= 0);

    struct pollfd original = {.fd = alias, .events = POLLIN | POLLRDNORM};
    CHECK(poll(&original, 1, 0) == 0);
    struct wait_case test = {.call = call, .watched = pair[0], .sync = control[1]};
    pthread_t thread;
    CHECK(pthread_create(&thread, NULL, worker, &test) == 0);
    one_byte(control[0], 'R');
    struct pollfd ack = {.fd = control[0], .events = POLLIN};
    CHECK(poll(&ack, 1, 70) == 0);
    CHECK(dup2(replacement[0], pair[0]) == pair[0]);
    if (!error)
        send_and_consume(other[1], other[0], 1);
    CHECK(poll(&ack, 1, 70) == 0);

    if (error)
        consume_error(alias);
    else
        send_and_consume(pair[1], alias, call % 2);
    CHECK(poll(&original, 1, 0) == 0);
    CHECK(poll(&ack, 1, 120) == 1);
    one_byte(control[0], 'D');
    CHECK(pthread_join(thread, NULL) == 0);
    CHECK(test.result == 1 && test.ready == (call >= WAIT_SELECT ? 1 : POLLIN | POLLRDNORM));
    one_byte(pair[0], 'N');
    CHECK(close(alias) == 0 && close(pair[0]) == 0);
    if (!error)
        CHECK(close(pair[1]) == 0 && close(other[0]) == 0 && close(other[1]) == 0);
    CHECK(close(control[0]) == 0 && close(control[1]) == 0);
    CHECK(close(replacement[0]) == 0 && close(replacement[1]) == 0);
    printf("UDP_WAITS_CASE %s-%s-%s\n", names[call], family == AF_INET ? "ipv4" : "ipv6",
           error ? "error-pulse" : "data-pulse");
}

static void udp_masks(int family) {
    int pair[2];
    udp_pair(family, pair);
    struct pollfd descriptor = {.fd = pair[0], .events = POLLRDNORM | POLLWRNORM | POLLWRBAND};
    CHECK(poll(&descriptor, 1, 0) == 1 && descriptor.revents == (POLLWRNORM | POLLWRBAND));
    CHECK(send(pair[1], "", 0, 0) == 0);
    descriptor.events = POLLRDNORM;
    CHECK(poll(&descriptor, 1, 1000) == 1 && descriptor.revents == POLLRDNORM);
    descriptor.events |= POLLWRNORM | POLLWRBAND;
    CHECK(poll(&descriptor, 1, 0) == 1 &&
          descriptor.revents == (POLLRDNORM | POLLWRNORM | POLLWRBAND));
    char unused;
    CHECK(recv(pair[0], &unused, 1, 0) == 0);
    CHECK(close(pair[0]) == 0 && close(pair[1]) == 0);
    puts(family == AF_INET ? "UDP_WAITS_CASE ipv4-poll-masks" : "UDP_WAITS_CASE ipv6-poll-masks");
}

int main(int argc, char** argv) {
    CHECK(setvbuf(stdout, NULL, _IOLBF, 0) == 0);
    alarm(18);
    if (argc == 2 && !strcmp(argv[1], "--ordinary"))
        CHECK(setgroups(0, NULL) == 0 && setgid(65534) == 0 && setuid(65534) == 0);
    else
        CHECK(argc == 1);
    for (enum wait_call call = WAIT_POLL; call <= WAIT_PSELECT; ++call) {
        // Space IPv4 errors past the guest's one-second rate limit. This
        // delay takes place before arming the next descriptor wait.
        const struct timespec spacing = {1, 50000000};
        CHECK(nanosleep(&spacing, NULL) == 0);
        udp_pulse(call, AF_INET, 0);
        udp_pulse(call, AF_INET, 1);
        udp_pulse(call, AF_INET6, 0);
        udp_pulse(call, AF_INET6, 1);
    }
    udp_masks(AF_INET);
    udp_masks(AF_INET6);
    printf("UDP_WAITS_PASS uid=%lu\n", (unsigned long)getuid());
    return 0;
}
