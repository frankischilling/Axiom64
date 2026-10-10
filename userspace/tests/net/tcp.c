// SPDX-License-Identifier: GPL-3.0-or-later
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/tcp.h>
#include <net/if.h>
#include <poll.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/epoll.h>
#include <sys/uio.h>
#include <sys/ioctl.h>
#include <sys/time.h>
#include <sys/wait.h>
#include <unistd.h>

#define CHECK(value)                                                                               \
    do {                                                                                           \
        if (!(value)) {                                                                            \
            fprintf(stderr, "TCP_TEST_FAIL line=%d errno=%d expression=%s\n", __LINE__, errno,     \
                    #value);                                                                       \
            exit(1);                                                                               \
        }                                                                                          \
    } while (0)

static void creation(void) {
    const int flags[] = {0, SOCK_NONBLOCK, SOCK_CLOEXEC, SOCK_NONBLOCK | SOCK_CLOEXEC};
    const int protocols[] = {0, IPPROTO_TCP};
    unsigned count = 0;
    for (unsigned p = 0; p < sizeof(protocols) / sizeof(protocols[0]); p++)
        for (unsigned f = 0; f < sizeof(flags) / sizeof(flags[0]); f++) {
            int fd = socket(AF_INET, SOCK_STREAM | flags[f], protocols[p]);
            CHECK(fd >= 0);
            int value = 0;
            socklen_t length = sizeof(value);
            CHECK(getsockopt(fd, SOL_SOCKET, SO_TYPE, &value, &length) == 0 &&
                  value == SOCK_STREAM);
            length = sizeof(value);
            CHECK(getsockopt(fd, SOL_SOCKET, SO_PROTOCOL, &value, &length) == 0 &&
                  value == IPPROTO_TCP);
            CHECK(!!(fcntl(fd, F_GETFL) & O_NONBLOCK) == !!(flags[f] & SOCK_NONBLOCK));
            CHECK(!!(fcntl(fd, F_GETFD) & FD_CLOEXEC) == !!(flags[f] & SOCK_CLOEXEC));
            struct sockaddr_in address;
            length = sizeof(address);
            CHECK(getsockname(fd, (struct sockaddr*)&address, &length) == 0);
            CHECK(length == sizeof(address) && address.sin_family == AF_INET && !address.sin_port &&
                  !address.sin_addr.s_addr);
            CHECK(close(fd) == 0);
            count++;
        }
    errno = 0;
    CHECK(socket(AF_INET, SOCK_STREAM, IPPROTO_UDP) == -1 && errno == EPROTONOSUPPORT);
    errno = 0;
    CHECK(socket(AF_INET, SOCK_STREAM | 0x10000, 0) == -1 && errno == EINVAL);
    printf("TCP_CREATE_PASS variants=%u flags names protocols errors\n", count);
}

static void timeouts(int fd) {
    struct timeval timeout = {5, 0};
    CHECK(setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) == 0);
    CHECK(setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout)) == 0);
}

static void send_all(int fd, const uint8_t* data, size_t length) {
    while (length) {
        ssize_t count = send(fd, data, length, MSG_NOSIGNAL);
        if (count < 0 && errno == EINTR)
            continue;
        CHECK(count > 0 && (size_t)count <= length);
        data += count;
        length -= count;
    }
}

static uint8_t pattern(size_t position) {
    return (uint8_t)((position * 37) ^ (position >> 8));
}

static uint64_t hash_byte(uint64_t hash, uint8_t value) {
    return (hash ^ value) * UINT64_C(1099511628211);
}

enum { payload_bytes = 262144 };

static void client(int listener, const struct sockaddr_in* destination) {
    CHECK(close(listener) == 0);
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    CHECK(fd >= 0);
    timeouts(fd);
    CHECK(connect(fd, (const struct sockaddr*)destination, sizeof(*destination)) == 0);
    struct sockaddr_in peer, local;
    socklen_t length = sizeof(peer);
    CHECK(getpeername(fd, (struct sockaddr*)&peer, &length) == 0 &&
          peer.sin_port == destination->sin_port);
    length = sizeof(local);
    CHECK(getsockname(fd, (struct sockaddr*)&local, &length) == 0 && local.sin_port &&
          local.sin_addr.s_addr == htonl(INADDR_LOOPBACK));
    uint8_t bytes[4096];
    uint64_t expected = UINT64_C(14695981039346656037);
    for (size_t position = 0; position < payload_bytes; position += sizeof(bytes)) {
        for (size_t at = 0; at < sizeof(bytes); at++) {
            bytes[at] = pattern(position + at);
            expected = hash_byte(expected, bytes[at]);
        }
        send_all(fd, bytes, sizeof(bytes));
    }
    CHECK(shutdown(fd, SHUT_WR) == 0);
    uint8_t digest[8];
    size_t received = 0;
    while (received < sizeof(digest)) {
        ssize_t count = recv(fd, digest + received, sizeof(digest) - received, 0);
        CHECK(count > 0);
        received += count;
    }
    uint64_t actual = 0;
    for (unsigned at = 0; at < sizeof(digest); at++)
        actual = actual << 8 | digest[at];
    CHECK(actual == expected && recv(fd, bytes, 1, 0) == 0);
    CHECK(close(fd) == 0);
    puts("TCP_CLIENT_PASS connect names partial_send shutdown reply eof");
    fflush(stdout);
    _exit(0);
}

static void loopback(void) {
    int listener = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    CHECK(listener >= 0);
    struct sockaddr_in destination = {.sin_family = AF_INET,
                                      .sin_addr.s_addr = htonl(INADDR_LOOPBACK)};
    CHECK(bind(listener, (struct sockaddr*)&destination, sizeof(destination)) == 0);
    CHECK(listen(listener, 8) == 0);
    socklen_t length = sizeof(destination);
    CHECK(getsockname(listener, (struct sockaddr*)&destination, &length) == 0 &&
          destination.sin_port);
    int value = 0;
    length = sizeof(value);
    CHECK(getsockopt(listener, SOL_SOCKET, SO_ACCEPTCONN, &value, &length) == 0 && value == 1);
    pid_t pid = fork();
    CHECK(pid >= 0);
    if (!pid)
        client(listener, &destination);
    struct sockaddr_in peer;
    length = sizeof(peer);
    int fd = accept4(listener, (struct sockaddr*)&peer, &length, SOCK_CLOEXEC);
    CHECK(fd >= 0 && peer.sin_family == AF_INET && peer.sin_port &&
          peer.sin_addr.s_addr == htonl(INADDR_LOOPBACK));
    CHECK(fcntl(fd, F_GETFD) & FD_CLOEXEC);
    CHECK(!(fcntl(fd, F_GETFL) & O_NONBLOCK));
    timeouts(fd);
    CHECK(close(listener) == 0);
    uint8_t bytes[8192];
    size_t received = 0;
    uint64_t digest = UINT64_C(14695981039346656037);
    for (;;) {
        ssize_t count = recv(fd, bytes, sizeof(bytes), 0);
        if (count < 0 && errno == EINTR)
            continue;
        CHECK(count >= 0);
        if (!count)
            break;
        for (ssize_t at = 0; at < count; at++) {
            CHECK(received < payload_bytes && bytes[at] == pattern(received));
            received++;
            digest = hash_byte(digest, bytes[at]);
        }
    }
    CHECK(received == payload_bytes);
    uint8_t response[8];
    for (unsigned at = 0; at < sizeof(response); at++)
        response[at] = digest >> (56 - at * 8);
    send_all(fd, response, sizeof(response));
    CHECK(shutdown(fd, SHUT_WR) == 0 && close(fd) == 0);
    int status;
    CHECK(waitpid(pid, &status, 0) == pid && WIFEXITED(status) && !WEXITSTATUS(status));
    printf("TCP_LOOPBACK_PASS bytes=%u bind listen accept4 fork exact_bytes half_close\n",
           payload_bytes);
}

static void readable(int fd) {
    struct pollfd item = {.fd = fd, .events = POLLIN};
    CHECK(poll(&item, 1, 2000) == 1 && (item.revents & POLLIN) && !(item.revents & POLLERR));
}

static void pair_sockets(int pair[2]) {
    int listener = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK, 0);
    CHECK(listener >= 0);
    struct sockaddr_in local = {.sin_family = AF_INET, .sin_addr.s_addr = htonl(INADDR_ANY)};
    CHECK(bind(listener, (struct sockaddr*)&local, sizeof(local)) == 0 && listen(listener, 4) == 0);
    socklen_t size = sizeof(local);
    CHECK(getsockname(listener, (struct sockaddr*)&local, &size) == 0);
    errno = 0;
    CHECK(accept4(listener, NULL, NULL, 0) == -1 && errno == EAGAIN);
    pair[0] = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
    CHECK(pair[0] >= 0);
    local.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    errno = 0;
    CHECK(connect(pair[0], (struct sockaddr*)&local, sizeof(local)) == -1 && errno == EINPROGRESS);
    readable(listener);
    pair[1] = accept4(listener, NULL, NULL, SOCK_NONBLOCK | SOCK_CLOEXEC);
    CHECK(pair[1] >= 0 && (fcntl(pair[1], F_GETFL) & O_NONBLOCK) &&
          (fcntl(pair[1], F_GETFD) & FD_CLOEXEC));
    struct pollfd item = {.fd = pair[0], .events = POLLOUT};
    CHECK(poll(&item, 1, 2000) == 1 && (item.revents & POLLOUT) && !(item.revents & POLLERR));
    int error = -1;
    size = sizeof(error);
    CHECK(getsockopt(pair[0], SOL_SOCKET, SO_ERROR, &error, &size) == 0 && !error);
    CHECK(close(listener) == 0);
}

static void options(void) {
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    CHECK(fd >= 0);
    const int names[] = {TCP_NODELAY, TCP_USER_TIMEOUT};
    for (unsigned at = 0; at < sizeof(names) / sizeof(names[0]); at++) {
        int value = -1;
        socklen_t size = sizeof(value);
        CHECK(getsockopt(fd, IPPROTO_TCP, names[at], &value, &size) == 0 && value == 0);
        value = names[at] == TCP_NODELAY ? 1 : 2000;
        CHECK(setsockopt(fd, IPPROTO_TCP, names[at], &value, sizeof(value)) == 0);
        int actual = 0;
        size = sizeof(actual);
        CHECK(getsockopt(fd, IPPROTO_TCP, names[at], &actual, &size) == 0 && actual == value);
    }
    int value = -1;
    errno = 0;
    CHECK(setsockopt(fd, IPPROTO_TCP, TCP_USER_TIMEOUT, &value, sizeof(value)) == -1 &&
          errno == EINVAL);
    value = 87;
    errno = 0;
    CHECK(setsockopt(fd, IPPROTO_TCP, TCP_MAXSEG, &value, sizeof(value)) == -1 && errno == EINVAL);
    value = 32768;
    errno = 0;
    CHECK(setsockopt(fd, IPPROTO_TCP, TCP_MAXSEG, &value, sizeof(value)) == -1 && errno == EINVAL);
    errno = 0;
    CHECK(setsockopt(fd, IPPROTO_TCP, 9999, &value, sizeof(value)) == -1 && errno == ENOPROTOOPT);
    CHECK(close(fd) == 0);
    puts("TCP_OPTIONS_PASS nodelay user_timeout maxseg invalid_bounds");
}

static void bindings(void) {
    int first = socket(AF_INET, SOCK_STREAM, 0);
    int second = socket(AF_INET, SOCK_STREAM, 0);
    int datagram = socket(AF_INET, SOCK_DGRAM, 0);
    CHECK(first >= 0 && second >= 0 && datagram >= 0);
    struct sockaddr_in local = {.sin_family = AF_INET};
    socklen_t size = sizeof(local);
    errno = 0;
    CHECK(getpeername(first, (struct sockaddr*)&local, &size) == -1 && errno == ENOTCONN);
    CHECK(bind(first, (struct sockaddr*)&local, sizeof(local)) == 0);
    size = sizeof(local);
    CHECK(getsockname(first, (struct sockaddr*)&local, &size) == 0 && local.sin_port &&
          !local.sin_addr.s_addr);
    CHECK(bind(datagram, (struct sockaddr*)&local, sizeof(local)) == 0);
    errno = 0;
    CHECK(bind(first, (struct sockaddr*)&local, sizeof(local)) == -1 && errno == EINVAL);
    local.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    errno = 0;
    CHECK(bind(second, (struct sockaddr*)&local, sizeof(local)) == -1 && errno == EADDRINUSE);
    errno = 0;
    CHECK(accept4(second, NULL, NULL, 0) == -1 && errno == EINVAL);
    CHECK(close(first) == 0 && close(second) == 0 && close(datagram) == 0);
    puts("TCP_BINDINGS_PASS wildcard conflicts independent_udp_names errors");
}

static void vectors(void) {
    int pair[2];
    pair_sockets(pair);

    enum { bytes = 12293 };

    uint8_t sent[bytes], received[bytes];
    for (unsigned at = 0; at < bytes; at++)
        sent[at] = pattern(at);
    errno = 0;
    CHECK(recv(pair[1], received, 1, MSG_DONTWAIT) == -1 && errno == EAGAIN);
    struct iovec output[] = {{sent, 5000}, {sent + 5000, 1}, {sent + 5001, bytes - 5001}};
    struct msghdr message = {.msg_iov = output, .msg_iovlen = 3};
    CHECK(sendmsg(pair[0], &message, MSG_NOSIGNAL) == bytes);
    readable(pair[1]);
    struct sockaddr_in peer;
    struct iovec input[] = {
        {received, 5000}, {received + 5000, 1}, {received + 5001, bytes - 5001}};
    message = (struct msghdr){
        .msg_name = &peer, .msg_namelen = sizeof(peer), .msg_iov = input, .msg_iovlen = 3};
    // The peer has no concurrent writer; repeat peek until the complete payload has arrived.
    ssize_t count;
    do {
        count = recvmsg(pair[1], &message, MSG_PEEK);
        CHECK(count > 0 && count <= bytes && !memcmp(sent, received, count));
    } while (count != bytes);
    CHECK(!message.msg_namelen && !message.msg_controllen && !message.msg_flags);
    int copy = dup(pair[1]);
    CHECK(copy >= 0 && close(pair[1]) == 0);
    CHECK(readv(copy, input, 3) == bytes && !memcmp(sent, received, bytes));
    int epoll = epoll_create1(EPOLL_CLOEXEC);
    CHECK(epoll >= 0);
    struct epoll_event event = {.events = EPOLLIN | EPOLLRDHUP, .data.u64 = 0x746370};
    CHECK(epoll_ctl(epoll, EPOLL_CTL_ADD, copy, &event) == 0);
    CHECK(shutdown(pair[0], SHUT_WR) == 0);
    CHECK(epoll_wait(epoll, &event, 1, 2000) == 1 && event.data.u64 == 0x746370 &&
          (event.events & EPOLLIN) && (event.events & EPOLLRDHUP));
    CHECK(recv(copy, received, 1, 0) == 0);
    CHECK(close(copy) == 0 && close(pair[0]) == 0 && close(epoll) == 0);
    puts("TCP_VECTORS_PASS nonblocking sendmsg recvmsg peek readv dup poll epoll eof");
}

static void refused(void) {
    int listener = socket(AF_INET, SOCK_STREAM, 0);
    CHECK(listener >= 0);
    struct sockaddr_in local = {.sin_family = AF_INET, .sin_addr.s_addr = htonl(INADDR_LOOPBACK)};
    CHECK(bind(listener, (struct sockaddr*)&local, sizeof(local)) == 0);
    socklen_t size = sizeof(local);
    CHECK(getsockname(listener, (struct sockaddr*)&local, &size) == 0 && close(listener) == 0);
    int fd = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK, 0);
    CHECK(fd >= 0);
    int value = -1;
    size = sizeof(value);
    CHECK(getsockopt(fd, SOL_SOCKET, SO_ERROR, &value, &size) == 0 && value == 0);
    CHECK(connect(fd, (struct sockaddr*)&local, sizeof(local)) == -1 && errno == EINPROGRESS);
    struct pollfd item = {.fd = fd, .events = POLLOUT};
    CHECK(poll(&item, 1, 2000) == 1 && (item.revents & POLLOUT) && (item.revents & POLLERR));
    size = sizeof(value);
    CHECK(getsockopt(fd, SOL_SOCKET, SO_ERROR, &value, &size) == 0 && value == ECONNREFUSED);
    size = sizeof(value);
    CHECK(getsockopt(fd, SOL_SOCKET, SO_ERROR, &value, &size) == 0 && value == 0);
    CHECK(close(fd) == 0);
    puts("TCP_REFUSED_PASS nonblocking poll so_error clear");
}

static uint8_t wire_byte(size_t position, unsigned lane, unsigned phase) {
    return pattern(position) ^ (phase * 73) ^ (lane * 11);
}

static void wire_send(int fd, unsigned lane, unsigned phase) {
    uint8_t bytes[4096];
    for (size_t position = 0; position < payload_bytes; position += sizeof(bytes)) {
        for (size_t at = 0; at < sizeof(bytes); at++)
            bytes[at] = wire_byte(position + at, lane, phase);
        send_all(fd, bytes, sizeof(bytes));
    }
    CHECK(shutdown(fd, SHUT_WR) == 0);
}

static void wire_receive(int fd, unsigned lane, unsigned phase) {
    uint8_t bytes[8192];
    size_t position = 0;
    for (;;) {
        ssize_t count = recv(fd, bytes, sizeof(bytes), 0);
        CHECK(count >= 0);
        if (!count)
            break;
        for (ssize_t at = 0; at < count; at++, position++)
            CHECK(position < payload_bytes && bytes[at] == wire_byte(position, lane, phase));
    }
    CHECK(position == payload_bytes);
}

static void configure(void) {
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    CHECK(fd >= 0);
    for (unsigned lane = 0; lane < 2; lane++) {
        struct ifreq request = {0};
        snprintf(request.ifr_name, sizeof(request.ifr_name), "eth%u", lane);
        struct sockaddr_in value = {.sin_family = AF_INET,
                                    .sin_addr.s_addr = htonl(0x0a170102 + (lane << 8))};
        memcpy(&request.ifr_addr, &value, sizeof(value));
        CHECK(ioctl(fd, SIOCSIFADDR, &request) == 0);
        value.sin_addr.s_addr = htonl(0xffffff00);
        memcpy(&request.ifr_netmask, &value, sizeof(value));
        CHECK(ioctl(fd, SIOCSIFNETMASK, &request) == 0 && ioctl(fd, SIOCGIFFLAGS, &request) == 0);
        request.ifr_flags |= IFF_UP;
        CHECK(ioctl(fd, SIOCSIFFLAGS, &request) == 0);
    }
    CHECK(close(fd) == 0);
    puts("TCP_CONFIG_PASS nics=2");
}

static void wire(unsigned lane, unsigned port) {
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    CHECK(fd >= 0);
    timeouts(fd);
    struct sockaddr_in peer = {.sin_family = AF_INET,
                               .sin_port = htons(port),
                               .sin_addr.s_addr = htonl(0x0a170101 + (lane << 8))};
    CHECK(connect(fd, (struct sockaddr*)&peer, sizeof(peer)) == 0);
    wire_send(fd, lane, 1);
    wire_receive(fd, lane, 2);
    CHECK(close(fd) == 0);
    printf("TCP_NATIVE_SERVER_PASS index=%u bytes_each=%u\n", lane + 1, payload_bytes);
    int listener = socket(AF_INET, SOCK_STREAM, 0);
    CHECK(listener >= 0);
    struct sockaddr_in local = {.sin_family = AF_INET,
                                .sin_port = htons(41000 + lane),
                                .sin_addr.s_addr = htonl(0x0a170102 + (lane << 8))};
    CHECK(bind(listener, (struct sockaddr*)&local, sizeof(local)) == 0 && listen(listener, 4) == 0);
    printf("TCP_SERVER_READY index=%u\n", lane + 1);
    fflush(stdout);
    fd = accept(listener, NULL, NULL);
    CHECK(fd >= 0 && close(listener) == 0);
    timeouts(fd);
    wire_receive(fd, lane, 3);
    wire_send(fd, lane, 4);
    CHECK(close(fd) == 0);
    printf("TCP_NATIVE_CLIENT_PASS index=%u bytes_each=%u\n", lane + 1, payload_bytes);
    fflush(stdout);
}

int main(int argc, char** argv) {
    signal(SIGPIPE, SIG_IGN);
    alarm(60);
    creation();
    bindings();
    options();
    refused();
    vectors();
    fflush(stdout);
    loopback();
    if (argc == 4 && !strcmp(argv[1], "--wire")) {
        configure();
        for (unsigned lane = 0; lane < 2; lane++) {
            char* end;
            unsigned long port = strtoul(argv[lane + 2], &end, 10);
            CHECK(!*end && port > 0 && port <= 65535);
            wire(lane, port);
        }
        CHECK(usleep(100000) == 0);
    } else
        CHECK(argc == 1);
    puts("TCP_TEST_PASS");
    return 0;
}
