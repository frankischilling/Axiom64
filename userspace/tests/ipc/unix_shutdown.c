// SPDX-License-Identifier: GPL-3.0-or-later
/**
 * @file    userspace/tests/ipc/unix_shutdown.c
 * @brief   Unix socket shutdown test.
 * @author  frankischilling
 * @date    2026-11-18
 *
 * Exercises half-close, peer closure, interrupted operations, and waiter
 * wakeups.
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
#include <signal.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/epoll.h>
#include <sys/select.h>
#include <sys/un.h>
#include <sys/uio.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

static pid_t waiting_child;

static void fail(int line, const char* expression) {
    int error = errno;
    if (waiting_child > 0) {
        kill(waiting_child, SIGKILL);
        waitpid(waiting_child, NULL, 0);
    }
    fprintf(stderr, "UNIX_SHUTDOWN_FAIL line=%d expression=%s errno=%d\n", line, expression, error);
    exit(1);
}

#define CHECK(value)                                                                               \
    do {                                                                                           \
        if (!(value))                                                                              \
            fail(__LINE__, #value);                                                                \
    } while (0)

static void readiness(int fd, unsigned expected) {
    struct pollfd descriptor = {.fd = fd, .events = POLLIN | POLLOUT | POLLRDHUP};
    int result = poll(&descriptor, 1, 0);
    if ((unsigned short)descriptor.revents != expected)
        fprintf(stderr, "UNIX_SHUTDOWN_POLL expected=%u actual=%u\n", expected,
                (unsigned)descriptor.revents);
    CHECK(result == !!expected && (unsigned short)descriptor.revents == expected);
    int epoll = epoll_create1(EPOLL_CLOEXEC);
    struct epoll_event event = {.events = EPOLLIN | EPOLLOUT | EPOLLRDHUP,
                                .data = {.u64 = 0xabc123}};
    CHECK(epoll >= 0 && !epoll_ctl(epoll, EPOLL_CTL_ADD, fd, &event));
    memset(&event, 0, sizeof(event));
    result = epoll_wait(epoll, &event, 1, 0);
    CHECK(result == !!expected &&
          (!result || (event.events == expected && event.data.u64 == 0xabc123)));
    CHECK(!close(epoll));
    fd_set readers, writers, exceptions;
    FD_ZERO(&readers);
    FD_ZERO(&writers);
    FD_ZERO(&exceptions);
    FD_SET(fd, &readers);
    FD_SET(fd, &writers);
    FD_SET(fd, &exceptions);
    struct timeval timeout = {0};
    int readable = !!(expected & (POLLIN | POLLHUP));
    int writable = !!(expected & POLLOUT);
    CHECK(select(fd + 1, &readers, &writers, &exceptions, &timeout) == readable + writable);
    CHECK(!!FD_ISSET(fd, &readers) == readable && !!FD_ISSET(fd, &writers) == writable &&
          !FD_ISSET(fd, &exceptions));
}

static void exchange(int first, int second) {
    char value;
    CHECK(send(first, "a", 1, MSG_NOSIGNAL) == 1 && recv(second, &value, 1, 0) == 1 &&
          value == 'a');
    CHECK(send(second, "b", 1, MSG_NOSIGNAL) == 1 && recv(first, &value, 1, 0) == 1 &&
          value == 'b');
}

static void listeners(void) {
    unsigned cases = 0;
    for (int how = SHUT_RD; how <= SHUT_RDWR; how++) {
        for (int pending = 0; pending < 2; pending++) {
            for (int pathname = 0; pathname < 2; pathname++) {
                for (int duplicate = 0; duplicate < 2; duplicate++) {
                    struct sockaddr_un address = {.sun_family = AF_UNIX};
                    char name[96];
                    CHECK(snprintf(name, sizeof(name), "/tmp/ax-shutdown-%ld-%u", (long)getpid(),
                                   cases) > 0);
                    if (pathname)
                        strcpy(address.sun_path, name);
                    else
                        strcpy(address.sun_path + 1, name);
                    socklen_t length = offsetof(struct sockaddr_un, sun_path) + strlen(name) + 1;
                    int listener = socket(AF_UNIX, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
                    CHECK(listener >= 0);
                    CHECK(!bind(listener, (struct sockaddr*)&address, length) &&
                          !listen(listener, 2));
                    if (duplicate) {
                        int copy = fcntl(listener, F_DUPFD_CLOEXEC, 0);
                        CHECK(copy >= 0 && !close(listener));
                        listener = copy;
                    }
                    int client = -1;
                    if (pending) {
                        client = socket(AF_UNIX, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
                        CHECK(client >= 0 && !connect(client, (struct sockaddr*)&address, length));
                    }
                    readiness(listener, pending ? POLLIN : 0);
                    CHECK(!shutdown(listener, how) && !shutdown(listener, how));
                    unsigned events = pending ? POLLIN : 0;
                    if (how != SHUT_WR)
                        events |= POLLIN | POLLRDHUP;
                    if (how == SHUT_RDWR)
                        events |= POLLHUP;
                    readiness(listener, events);
                    errno = 0;
                    int accepted = accept4(listener, NULL, NULL, SOCK_NONBLOCK | SOCK_CLOEXEC);
                    if (pending) {
                        CHECK(accepted >= 0);
                        exchange(client, accepted);
                        CHECK(!close(accepted) && !close(client));
                    } else {
                        CHECK(accepted == -1 && errno == EAGAIN);
                    }
                    readiness(listener, events & ~((how == SHUT_WR) ? POLLIN : 0));
                    if (how != SHUT_WR) {
                        int flags = fcntl(listener, F_GETFL);
                        CHECK(flags >= 0 && !fcntl(listener, F_SETFL, flags & ~O_NONBLOCK));
                        errno = 0;
                        CHECK(accept4(listener, NULL, NULL, SOCK_CLOEXEC) == -1 && errno == EINVAL);
                    }
                    int probe = socket(AF_UNIX, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
                    CHECK(probe >= 0);
                    errno = 0;
                    int result = connect(probe, (struct sockaddr*)&address, length);
                    if (how == SHUT_WR) {
                        CHECK(!result);
                        accepted = accept4(listener, NULL, NULL, SOCK_NONBLOCK | SOCK_CLOEXEC);
                        CHECK(accepted >= 0);
                        exchange(probe, accepted);
                        CHECK(!close(accepted));
                    } else {
                        CHECK(result == -1 && errno == ECONNREFUSED);
                    }
                    CHECK(!close(probe) && !close(listener));
                    if (pathname)
                        CHECK(!unlink(name));
                    cases++;
                }
            }
        }
    }
    CHECK(cases == 24);
    puts("UNIX_SHUTDOWN_LISTENER_PASS cases=24 names=abstract,path duplicate repeated pending "
         "exchange");
}

static unsigned stream_events(int read_closed, int write_closed, int queued) {
    return POLLOUT | ((queued || read_closed) ? POLLIN : 0) | (read_closed ? POLLRDHUP : 0) |
           ((read_closed && write_closed) ? POLLHUP : 0);
}

static void connected(void) {
    unsigned cases = 0;
    for (int how = SHUT_RD; how <= SHUT_RDWR; how++) {
        for (int other = -1; other <= SHUT_RDWR; other++) {
            for (int queued = 0; queued < 2; queued++) {
                for (int duplicate = 0; duplicate < 2; duplicate++) {
                    int pair[2];
                    CHECK(
                        !socketpair(AF_UNIX, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0, pair));
                    int alias = duplicate ? fcntl(pair[0], F_DUPFD_CLOEXEC, 0) : -1;
                    CHECK(!duplicate || alias >= 0);
                    if (queued) {
                        CHECK(send(pair[0], "abcd", 4, MSG_NOSIGNAL) == 4);
                        CHECK(send(pair[1], "wxyz", 4, MSG_NOSIGNAL) == 4);
                    }
                    readiness(pair[0], POLLOUT | (queued ? POLLIN : 0));
                    readiness(pair[1], POLLOUT | (queued ? POLLIN : 0));
                    CHECK(!shutdown(duplicate ? alias : pair[0], how));
                    CHECK(!shutdown(pair[0], how));
                    int read_closed[2] = {how != SHUT_WR, how != SHUT_RD};
                    int write_closed[2] = {how != SHUT_RD, how != SHUT_WR};
                    if (other >= 0) {
                        CHECK(!shutdown(pair[1], other));
                        read_closed[1] |= other != SHUT_WR;
                        write_closed[1] |= other != SHUT_RD;
                        read_closed[0] |= other != SHUT_RD;
                        write_closed[0] |= other != SHUT_WR;
                    }
                    for (int lane = 0; lane < 2; lane++) {
                        readiness(pair[lane],
                                  stream_events(read_closed[lane], write_closed[lane], queued));
                        char data[4];
                        const char* expected = lane ? "abcd" : "wxyz";
                        if (queued) {
                            CHECK(recv(pair[lane], data, sizeof(data), MSG_PEEK) == 4 &&
                                  !memcmp(data, expected, sizeof(data)));
                            struct iovec vector = {.iov_base = data, .iov_len = sizeof(data)};
                            struct msghdr message = {.msg_iov = &vector, .msg_iovlen = 1};
                            ssize_t count = cases % 3 == 0   ? read(pair[lane], data, sizeof(data))
                                            : cases % 3 == 1 ? readv(pair[lane], &vector, 1)
                                                             : recvmsg(pair[lane], &message, 0);
                            CHECK(count == 4 && !memcmp(data, expected, sizeof(data)));
                        }
                        errno = 0;
                        ssize_t count = recv(pair[lane], data, sizeof(data), 0);
                        CHECK(read_closed[lane] ? count == 0 : count == -1 && errno == EAGAIN);
                        readiness(pair[lane],
                                  stream_events(read_closed[lane], write_closed[lane], 0));
                    }
                    for (int lane = 0; lane < 2; lane++) {
                        errno = 0;
                        ssize_t count = send(pair[lane], "a", 1, MSG_NOSIGNAL);
                        if (write_closed[lane])
                            CHECK(count == -1 && errno == EPIPE);
                        else {
                            char data;
                            CHECK(count == 1 && recv(pair[1 - lane], &data, 1, 0) == 1 &&
                                  data == 'a');
                        }
                    }
                    CHECK(!duplicate || !close(alias));
                    CHECK(!close(pair[0]) && !close(pair[1]));
                    cases++;
                }
            }
        }
    }
    CHECK(cases == 48);
    puts("UNIX_SHUTDOWN_CONNECTED_PASS cases=48 queued peek scalar vector message aliases "
         "poll epoll select reciprocal no_signal");
}

static void unconnected(void) {
    unsigned cases = 0;
    for (int how = SHUT_RD; how <= SHUT_RDWR; how++) {
        for (int binding = 0; binding < 3; binding++) {
            for (int duplicate = 0; duplicate < 2; duplicate++) {
                int fd = socket(AF_UNIX, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
                CHECK(fd >= 0);
                char name[96];
                CHECK(snprintf(name, sizeof(name), "/tmp/ax-shutdown-ready-%ld-%u", (long)getpid(),
                               cases) > 0);
                if (binding) {
                    struct sockaddr_un address = {.sun_family = AF_UNIX};
                    strcpy(address.sun_path + (binding == 1), name);
                    socklen_t length = offsetof(struct sockaddr_un, sun_path) + strlen(name) + 1;
                    CHECK(!bind(fd, (struct sockaddr*)&address, length));
                }
                int alias = duplicate ? fcntl(fd, F_DUPFD_CLOEXEC, 0) : -1;
                CHECK(!duplicate || alias >= 0);
                readiness(fd, POLLOUT | POLLHUP);
                CHECK(!shutdown(duplicate ? alias : fd, how));
                readiness(fd, POLLOUT | POLLHUP | (how != SHUT_WR ? POLLIN | POLLRDHUP : 0));
                CHECK(!duplicate || !close(alias));
                CHECK(!close(fd));
                if (binding == 2)
                    CHECK(!unlink(name));
                cases++;
            }
        }
    }
    CHECK(cases == 18);
    puts("UNIX_SHUTDOWN_UNCONNECTED_PASS cases=18 names=unbound,abstract,path aliases poll epoll "
         "select");
}

static uint64_t monotonic_ns(void) {
    struct timespec now;
    CHECK(!clock_gettime(CLOCK_MONOTONIC, &now));
    return (uint64_t)now.tv_sec * 1000000000 + (uint64_t)now.tv_nsec;
}

static void sleeping(pid_t child) {
    char path[64], text[2048];
    CHECK(snprintf(path, sizeof(path), "/proc/%ld/stat", (long)child) > 0);
    uint64_t began = monotonic_ns();
    for (;;) {
        int fd = open(path, O_RDONLY | O_CLOEXEC);
        CHECK(fd >= 0);
        ssize_t count = read(fd, text, sizeof(text) - 1);
        CHECK(count > 0 && !close(fd));
        text[count] = 0;
        char* state = strrchr(text, ')');
        CHECK(state && state[1] == ' ' && state[2] != 'Z');
        if (state[2] == 'S')
            return;
        CHECK(monotonic_ns() - began < 2000000000);
        CHECK(!usleep(1000));
    }
}

enum wait_kind { WAIT_READ, WAIT_SEND, WAIT_ACCEPT, WAIT_POLL, WAIT_EDGE, WAIT_SELECT };

struct wait_result {
    ssize_t result;
    int error;
    unsigned events;
    unsigned char byte;
};

static void waits(void) {
    unsigned cases = 0;
    for (int kind = WAIT_READ; kind <= WAIT_SELECT; kind++) {
        for (int peer = 0; peer < (kind == WAIT_ACCEPT ? 1 : 2); peer++) {
            for (int duplicate = 0; duplicate < 2; duplicate++) {
                int sockets[2] = {-1, -1}, ready[2], result[2];
                if (kind == WAIT_ACCEPT) {
                    sockets[0] = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
                    CHECK(sockets[0] >= 0);
                    struct sockaddr_un address = {.sun_family = AF_UNIX};
                    int length = snprintf(address.sun_path + 1, sizeof(address.sun_path) - 1,
                                          "ax-shutdown-wait-%ld-%u", (long)getpid(), cases);
                    CHECK(length > 0 && length < (int)sizeof(address.sun_path) - 1);
                    CHECK(!bind(sockets[0], (struct sockaddr*)&address,
                                offsetof(struct sockaddr_un, sun_path) + 1 + length));
                    CHECK(!listen(sockets[0], 2));
                } else {
                    CHECK(!socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0, sockets));
                }
                size_t queued = 0;
                unsigned char bytes[4096];
                memset(bytes, 0x5a, sizeof(bytes));
                if (kind == WAIT_SEND) {
                    int flags = fcntl(sockets[0], F_GETFL);
                    CHECK(flags >= 0 && !fcntl(sockets[0], F_SETFL, flags | O_NONBLOCK));
                    for (;;) {
                        ssize_t count = send(sockets[0], bytes, sizeof(bytes), MSG_NOSIGNAL);
                        if (count == -1) {
                            CHECK(errno == EAGAIN);
                            break;
                        }
                        CHECK(count > 0 && queued < 16 * 1024 * 1024);
                        queued += (size_t)count;
                    }
                    CHECK(queued && !fcntl(sockets[0], F_SETFL, flags));
                }
                int actor = sockets[peer];
                int alias = duplicate ? fcntl(actor, F_DUPFD_CLOEXEC, 0) : -1;
                CHECK(!duplicate || alias >= 0);
                CHECK(!pipe2(ready, O_CLOEXEC) && !pipe2(result, O_CLOEXEC));
                pid_t child = fork();
                CHECK(child >= 0);
                if (!child) {
                    CHECK(!close(ready[0]) && !close(result[0]));
                    struct wait_result observed = {.byte = 0x5a};
                    int epoll = -1;
                    if (kind == WAIT_EDGE) {
                        epoll = epoll_create1(EPOLL_CLOEXEC);
                        struct epoll_event event = {.events = EPOLLIN | EPOLLRDHUP | EPOLLET,
                                                    .data = {.u64 = 0xabc123}};
                        CHECK(epoll >= 0 && !epoll_ctl(epoll, EPOLL_CTL_ADD, sockets[0], &event));
                        CHECK(!epoll_wait(epoll, &event, 1, 0));
                    }
                    CHECK(write(ready[1], "r", 1) == 1);
                    errno = 0;
                    if (kind == WAIT_READ)
                        observed.result = recv(sockets[0], &observed.byte, 1, 0);
                    else if (kind == WAIT_SEND)
                        observed.result = send(sockets[0], "!", 1, MSG_NOSIGNAL);
                    else if (kind == WAIT_ACCEPT)
                        observed.result = accept4(sockets[0], NULL, NULL, SOCK_CLOEXEC);
                    else if (kind == WAIT_POLL) {
                        struct pollfd descriptor = {.fd = sockets[0], .events = POLLIN | POLLRDHUP};
                        observed.result = poll(&descriptor, 1, -1);
                        observed.events = (unsigned short)descriptor.revents;
                    } else if (kind == WAIT_EDGE) {
                        struct epoll_event event = {0};
                        observed.result = epoll_wait(epoll, &event, 1, -1);
                        CHECK(observed.result != 1 || event.data.u64 == 0xabc123);
                        observed.events = event.events;
                    } else {
                        fd_set readers;
                        FD_ZERO(&readers);
                        FD_SET(sockets[0], &readers);
                        observed.result = select(sockets[0] + 1, &readers, NULL, NULL, NULL);
                        observed.events = FD_ISSET(sockets[0], &readers) ? POLLIN : 0;
                    }
                    observed.error = errno;
                    CHECK(write(result[1], &observed, sizeof(observed)) == sizeof(observed));
                    _exit(0);
                }
                waiting_child = child;
                CHECK(!close(ready[1]) && !close(result[1]));
                char token;
                CHECK(read(ready[0], &token, 1) == 1 && token == 'r');
                sleeping(child);
                int how =
                    kind == WAIT_SEND ? (peer ? SHUT_RD : SHUT_WR) : (peer ? SHUT_WR : SHUT_RD);
                CHECK(!shutdown(duplicate ? alias : actor, how));
                struct pollfd completed = {.fd = result[0], .events = POLLIN};
                CHECK(poll(&completed, 1, 3000) == 1 && (completed.revents & POLLIN));
                struct wait_result observed;
                CHECK(read(result[0], &observed, sizeof(observed)) == sizeof(observed));
                int status;
                pid_t reaped = waitpid(child, &status, 0);
                waiting_child = 0;
                CHECK(reaped == child && WIFEXITED(status) && !WEXITSTATUS(status));
                int error = kind == WAIT_SEND ? EPIPE : kind == WAIT_ACCEPT ? EINVAL : 0;
                ssize_t expected = kind == WAIT_READ ? 0 : error ? -1 : 1;
                unsigned events = kind == WAIT_SELECT ? POLLIN
                                  : kind >= WAIT_POLL ? POLLIN | POLLRDHUP
                                                      : 0;
                CHECK(observed.result == expected && observed.error == error &&
                      observed.events == events && observed.byte == 0x5a);
                while (queued) {
                    size_t wanted = queued < sizeof(bytes) ? queued : sizeof(bytes);
                    ssize_t count = recv(sockets[1], bytes, wanted, 0);
                    CHECK(count > 0 && (size_t)count <= wanted);
                    for (ssize_t index = 0; index < count; index++)
                        CHECK(bytes[index] == 0x5a);
                    queued -= (size_t)count;
                }
                CHECK(!close(ready[0]) && !close(result[0]));
                CHECK(!duplicate || !close(alias));
                CHECK(!close(sockets[0]));
                CHECK(sockets[1] < 0 || !close(sockets[1]));
                cases++;
            }
        }
    }
    CHECK(cases == 22);
    puts("UNIX_SHUTDOWN_WAIT_PASS cases=22 blocked=22 reads sends accepts poll epoll_edge select "
         "aliases retained_bytes");
}

int main(int argc, char** argv) {
    CHECK(argc == 1 || (argc == 2 && !strcmp(argv[1], "--ordinary")));
    if (argc == 2) {
        CHECK(!geteuid() && !setgroups(0, NULL) && !setresgid(65534, 65534, 65534) &&
              !setresuid(65534, 65534, 65534));
    }
    printf("UNIX_SHUTDOWN_IDENTITY uid=%u euid=%u gid=%u egid=%u groups=%d\n", getuid(), geteuid(),
           getgid(), getegid(), getgroups(0, NULL));
    listeners();
    connected();
    unconnected();
    waits();
    puts("UNIX_SHUTDOWN_PASS groups=4");
    return 0;
}
