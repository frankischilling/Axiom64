// SPDX-License-Identifier: GPL-3.0-or-later
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <grp.h>
#include <poll.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/epoll.h>
#include <sys/select.h>
#include <sys/un.h>
#include <sys/uio.h>
#include <unistd.h>

#define CHECK(value)                                                                               \
    do {                                                                                           \
        if (!(value)) {                                                                            \
            fprintf(stderr, "UNIX_SHUTDOWN_FAIL line=%d expression=%s errno=%d\n", __LINE__,       \
                    #value, errno);                                                                \
            exit(1);                                                                               \
        }                                                                                          \
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
    puts("UNIX_SHUTDOWN_PASS groups=3");
    return 0;
}
