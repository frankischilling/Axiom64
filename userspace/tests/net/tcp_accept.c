// SPDX-License-Identifier: GPL-3.0-or-later
/**
 * @file    userspace/tests/net/tcp_accept.c
 * @brief   TCP accept and listener lifetime tests.
 * @author  frankischilling
 * @date    2026-11-18
 *
 * Exercises accept flags, interrupted waits, descriptor reservations, and listener teardown.
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
#include "tcp_test.h"
#include <arpa/inet.h>
#include <fcntl.h>
#include <poll.h>
#include <pthread.h>
#include <string.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <sys/time.h>
#include <sys/wait.h>
#include <unistd.h>

static void accept_descriptors(void) {
    struct rlimit original, limit;
    CHECK(getrlimit(RLIMIT_NOFILE, &original) == 0 && original.rlim_cur >= 16);
    limit = original;
    if (limit.rlim_cur > 128) {
        limit.rlim_cur = 128;
        CHECK(setrlimit(RLIMIT_NOFILE, &limit) == 0);
    }
    int listener = socket(AF_INET, SOCK_STREAM, 0);
    int client = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK, 0);
    CHECK(listener >= 0 && client >= 0);
    struct sockaddr_in local = {.sin_family = AF_INET, .sin_addr.s_addr = htonl(INADDR_LOOPBACK)};
    CHECK(bind(listener, (struct sockaddr*)&local, sizeof(local)) == 0 && listen(listener, 4) == 0);
    socklen_t length = sizeof(local);
    CHECK(getsockname(listener, (struct sockaddr*)&local, &length) == 0);
    struct timeval timeout = {0, 50000};
    CHECK(setsockopt(listener, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) == 0);
    int held[128], count = 0, fd;
    while ((fd = dup(listener)) >= 0) {
        CHECK(count < 128);
        held[count++] = fd;
    }
    CHECK(errno == EMFILE && count > 0);
    errno = 0;
    CHECK(accept4(listener, NULL, NULL, SOCK_NONBLOCK | SOCK_CLOEXEC) == -1 && errno == EMFILE);
    CHECK(connect(client, (struct sockaddr*)&local, sizeof(local)) == -1 && errno == EINPROGRESS);
    readable(listener);
    errno = 0;
    CHECK(accept(listener, NULL, NULL) == -1 && errno == EMFILE);
    int expected = held[--count];
    CHECK(close(expected) == 0);
    fd = accept4(listener, NULL, NULL, SOCK_NONBLOCK | SOCK_CLOEXEC);
    CHECK(fd == expected && (fcntl(fd, F_GETFL) & O_NONBLOCK) && (fcntl(fd, F_GETFD) & FD_CLOEXEC));
    send_all(client, (const uint8_t*)"kept", 4);
    readable(fd);
    uint8_t bytes[4];
    CHECK(recv(fd, bytes, sizeof(bytes), 0) == 4 && !memcmp(bytes, "kept", 4));
    CHECK(close(fd) == 0 && close(client) == 0);
    while (count)
        CHECK(close(held[--count]) == 0);
    CHECK(close(listener) == 0);
    if (limit.rlim_cur != original.rlim_cur)
        CHECK(setrlimit(RLIMIT_NOFILE, &original) == 0);
    puts("TCP_ACCEPT_DESCRIPTORS_PASS empty_listener full_table queued_child preserved flags");
}

void* retained_accept(void* opaque) {
    struct RetainedAccept* operation = opaque;
    atomic_store(&operation->entered, 1);
    operation->result = accept4(operation->listener, NULL, NULL, SOCK_NONBLOCK | SOCK_CLOEXEC);
    operation->error = errno;
    atomic_store(&operation->done, 1);
    return NULL;
}

void accept_waiting(struct RetainedAccept* operation, int expected) {
    for (unsigned attempt = 0; attempt < 1000; attempt++) {
        CHECK(!atomic_load(&operation->done));
        if (atomic_load(&operation->entered)) {
            int probe = dup(operation->listener);
            CHECK(probe >= expected && close(probe) == 0);
            if (probe != expected) {
                errno = 0;
                CHECK(fcntl(expected, F_GETFD) == -1 && errno == EBADF);
                return;
            }
        }
        CHECK(usleep(1000) == 0);
    }
    CHECK(!"blocked accept did not reserve its descriptor");
}

int tcp_listener(struct sockaddr_in* local) {
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    CHECK(fd >= 0);
    *local = (struct sockaddr_in){.sin_family = AF_INET, .sin_addr.s_addr = htonl(INADDR_LOOPBACK)};
    CHECK(bind(fd, (struct sockaddr*)local, sizeof(*local)) == 0 && listen(fd, 4) == 0);
    socklen_t length = sizeof(*local);
    CHECK(getsockname(fd, (struct sockaddr*)local, &length) == 0);
    return fd;
}

static void accept_lifetime(void) {
    for (unsigned replace = 0; replace < 2; replace++) {
        struct sockaddr_in old_address, new_address;
        int listener = tcp_listener(&old_address);
        int old_client = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK, 0);
        CHECK(old_client >= 0);
        int expected = dup(listener);
        CHECK(expected >= 0 && close(expected) == 0);
        struct RetainedAccept operation = {.listener = listener};
        pthread_t thread;
        CHECK(pthread_create(&thread, NULL, retained_accept, &operation) == 0);
        accept_waiting(&operation, expected);
        int replacement;
        if (replace) {
            replacement = tcp_listener(&new_address);
            CHECK(dup2(replacement, listener) == listener && close(replacement) == 0);
        } else {
            CHECK(close(listener) == 0);
            replacement = tcp_listener(&new_address);
            CHECK(replacement == listener);
        }
        int new_client = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK, 0);
        CHECK(new_client >= 0);
        CHECK(connect(new_client, (struct sockaddr*)&new_address, sizeof(new_address)) == -1 &&
              errno == EINPROGRESS);
        readable(listener);
        CHECK(!atomic_load(&operation.done));
        CHECK(connect(old_client, (struct sockaddr*)&old_address, sizeof(old_address)) == -1 &&
              errno == EINPROGRESS);
        CHECK(pthread_join(thread, NULL) == 0 && operation.result == expected);
        send_all(old_client, (const uint8_t*)"old", 3);
        readable(expected);
        uint8_t bytes[8];
        CHECK(recv(expected, bytes, sizeof(bytes), 0) == 3 && !memcmp(bytes, "old", 3));
        int accepted = accept4(listener, NULL, NULL, SOCK_NONBLOCK);
        CHECK(accepted >= 0);
        send_all(new_client, (const uint8_t*)"new", 3);
        readable(accepted);
        CHECK(recv(accepted, bytes, sizeof(bytes), 0) == 3 && !memcmp(bytes, "new", 3));
        CHECK(close(expected) == 0);
        readable(old_client);
        CHECK(recv(old_client, bytes, 1, 0) == 0);
        CHECK(close(accepted) == 0 && close(old_client) == 0 && close(new_client) == 0 &&
              close(listener) == 0);
    }
    puts("TCP_ACCEPT_LIFETIME_PASS cases=2 fd_close_reuse dup2 original_listener independent_child "
         "owner_release");
}

static void accept_signals(void) {
    struct sigaction previous, action = {.sa_handler = interruption};
    sigemptyset(&action.sa_mask);
    CHECK(sigaction(SIGUSR1, NULL, &previous) == 0);
    for (unsigned mode = 0; mode < 3; mode++) {
        action.sa_flags = mode ? SA_RESTART : 0;
        CHECK(sigaction(SIGUSR1, &action, NULL) == 0);
        struct sockaddr_in local;
        int listener = tcp_listener(&local);
        int client = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK, 0);
        CHECK(client >= 0);
        if (mode == 2) {
            struct timeval timeout = {2, 0};
            CHECK(setsockopt(listener, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) == 0);
        }
        int expected = dup(listener);
        CHECK(expected >= 0 && close(expected) == 0);
        struct RetainedAccept operation = {.listener = listener};
        pthread_t thread;
        interrupted = 0;
        CHECK(pthread_create(&thread, NULL, retained_accept, &operation) == 0);
        accept_waiting(&operation, expected);
        CHECK(pthread_kill(thread, SIGUSR1) == 0);
        for (unsigned attempt = 0; !interrupted; attempt++)
            CHECK(attempt < 1000 && usleep(1000) == 0);
        if (mode == 1) {
            accept_waiting(&operation, expected);
            CHECK(connect(client, (struct sockaddr*)&local, sizeof(local)) == -1 &&
                  errno == EINPROGRESS);
            CHECK(pthread_join(thread, NULL) == 0 && operation.result == expected &&
                  close(expected) == 0);
        } else {
            CHECK(pthread_join(thread, NULL) == 0 && operation.result == -1 &&
                  operation.error == EINTR);
            CHECK(dup(listener) == expected && close(expected) == 0);
        }
        CHECK(interrupted == 1 && close(client) == 0 && close(listener) == 0);
    }
    CHECK(sigaction(SIGUSR1, &previous, NULL) == 0);
    puts("TCP_ACCEPT_SIGNALS_PASS cases=3 restart interrupted finite_timeout slot_release");
}

static void accept_reservation(void) {
    struct rlimit original, limit;
    CHECK(getrlimit(RLIMIT_NOFILE, &original) == 0 && original.rlim_cur >= 16);
    limit = original;
    if (limit.rlim_cur > 128) {
        limit.rlim_cur = 128;
        CHECK(setrlimit(RLIMIT_NOFILE, &limit) == 0);
    }
    int listener = socket(AF_INET, SOCK_STREAM, 0);
    int client = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK, 0);
    CHECK(listener >= 0 && client >= 0);
    struct sockaddr_in local = {.sin_family = AF_INET, .sin_addr.s_addr = htonl(INADDR_LOOPBACK)};
    CHECK(bind(listener, (struct sockaddr*)&local, sizeof(local)) == 0 && listen(listener, 4) == 0);
    socklen_t length = sizeof(local);
    CHECK(getsockname(listener, (struct sockaddr*)&local, &length) == 0);
    int expected = dup(listener);
    CHECK(expected >= 0 && close(expected) == 0);
    struct RetainedAccept operation = {.listener = listener};
    pthread_t thread;
    CHECK(pthread_create(&thread, NULL, retained_accept, &operation) == 0);
    int held[128], count = 0, fd = -1;
    for (unsigned attempt = 0; attempt < 1000; attempt++) {
        CHECK(!atomic_load(&operation.done));
        if (atomic_load(&operation.entered)) {
            fd = dup(listener);
            CHECK(fd >= expected);
            if (fd != expected)
                break; // Allocation skipped the waiting call's reserved slot.
            CHECK(close(fd) == 0);
        }
        CHECK(usleep(1000) == 0);
    }
    CHECK(fd > expected && !atomic_load(&operation.done));
    held[count++] = fd;
    errno = 0;
    CHECK(fcntl(expected, F_GETFD) == -1 && errno == EBADF);
    errno = 0;
    CHECK(close(expected) == -1 && errno == EBADF);
    errno = 0;
    // musl retries EBUSY in its wrapper; compare the Linux syscall itself here.
    CHECK(syscall(SYS_dup2, listener, expected) == -1 && errno == EBUSY);
    errno = 0;
    CHECK(syscall(SYS_dup3, listener, expected, O_CLOEXEC) == -1 && errno == EBUSY);
    while ((fd = dup(listener)) >= 0) {
        CHECK(count < 128);
        held[count++] = fd;
    }
    CHECK(errno == EMFILE && !atomic_load(&operation.done));
    pid_t child = fork();
    CHECK(child >= 0);
    if (!child) {
        // A private fork table contains installed files, not another thread's reservation.
        CHECK(dup(listener) == expected);
        _exit(0);
    }
    wait_child(child);
    CHECK(connect(client, (struct sockaddr*)&local, sizeof(local)) == -1 && errno == EINPROGRESS);
    CHECK(pthread_join(thread, NULL) == 0 && operation.result == expected);
    CHECK((fcntl(expected, F_GETFL) & O_NONBLOCK) && (fcntl(expected, F_GETFD) & FD_CLOEXEC));
    CHECK(close(expected) == 0 && close(client) == 0);
    while (count)
        CHECK(close(held[--count]) == 0);
    struct timeval timeout = {0, 10000};
    CHECK(setsockopt(listener, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) == 0);
    expected = dup(listener);
    CHECK(expected >= 0 && close(expected) == 0);
    for (unsigned attempt = 0; attempt < 3; attempt++) {
        errno = 0;
        CHECK(accept(listener, NULL, NULL) == -1 && errno == EAGAIN);
        CHECK(dup(listener) == expected && close(expected) == 0);
    }
    CHECK(close(listener) == 0);
    if (limit.rlim_cur != original.rlim_cur)
        CHECK(setrlimit(RLIMIT_NOFILE, &original) == 0);
    puts(
        "TCP_ACCEPT_RESERVATION_PASS blocked_slot pressure dup2_busy fork_private timeout_release");
}

static void accept_teardown(const char* executable) {
    for (unsigned fatal = 0; fatal < 2; fatal++) {
        struct sockaddr_in local;
        int listener = tcp_listener(&local);
        CHECK(fcntl(listener, F_SETFD, FD_CLOEXEC) == 0);
        int client = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
        int ready[2];
        CHECK(client >= 0 && pipe2(ready, O_CLOEXEC) == 0);
        pid_t child = fork();
        CHECK(child >= 0);
        if (!child) {
            CHECK(close(ready[0]) == 0);
            int expected = dup(listener);
            CHECK(expected >= 0 && close(expected) == 0);
            struct RetainedAccept operation = {.listener = listener};
            pthread_t thread;
            CHECK(pthread_create(&thread, NULL, retained_accept, &operation) == 0);
            accept_waiting(&operation, expected);
            CHECK(write(ready[1], "r", 1) == 1);
            if (fatal) {
                for (;;)
                    pause();
            }
            char minimum[16];
            CHECK(snprintf(minimum, sizeof(minimum), "%d", expected) > 0);
            char* arguments[] = {(char*)executable, "--accept-exec-check", minimum, NULL};
            execv(executable, arguments);
            CHECK(!"exec did not replace the accepting thread group");
        }
        CHECK(close(listener) == 0 && close(ready[1]) == 0);
        char marker;
        CHECK(read(ready[0], &marker, 1) == 1 && marker == 'r');
        if (fatal) {
            CHECK(kill(child, SIGKILL) == 0);
            int status;
            CHECK(waitpid(child, &status, 0) == child && WIFSIGNALED(status) &&
                  WTERMSIG(status) == SIGKILL);
        } else
            wait_child(child);
        CHECK(close(ready[0]) == 0);
        CHECK(connect(client, (struct sockaddr*)&local, sizeof(local)) == -1 &&
              errno == EINPROGRESS);
        struct pollfd item = {.fd = client, .events = POLLOUT};
        CHECK(poll(&item, 1, 2000) == 1 && (item.revents & POLLERR));
        int error = 0;
        socklen_t length = sizeof(error);
        CHECK(getsockopt(client, SOL_SOCKET, SO_ERROR, &error, &length) == 0 &&
              error == ECONNREFUSED && close(client) == 0);
    }
    puts("TCP_ACCEPT_TEARDOWN_PASS cases=2 exec_private_slot fatal_group listener_owner_release");
}

void tcp_accept_tests(const char* executable) {
    accept_descriptors();
    accept_reservation();
    accept_lifetime();
    accept_signals();
    accept_teardown(executable);
}
