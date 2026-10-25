// SPDX-License-Identifier: GPL-3.0-or-later
#define _GNU_SOURCE
#include "tcp_maxseg.h"
#include <arpa/inet.h>
#include <errno.h>
#include <netinet/tcp.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <sys/time.h>
#include <unistd.h>

#define CHECK(value)                                                                               \
    do {                                                                                           \
        if (!(value)) {                                                                            \
            fprintf(stderr, "TCP_MAXSEG_FAIL line=%d errno=%d expression=%s\n", __LINE__, errno,   \
                    #value);                                                                       \
            exit(1);                                                                               \
        }                                                                                          \
    } while (0)

static void expect_maxseg(int fd, int expected) {
    int actual = -1, raw = -1;
    socklen_t size = sizeof(actual), raw_size = sizeof(raw);
    CHECK(getsockopt(fd, IPPROTO_TCP, TCP_MAXSEG, &actual, &size) == 0 && size == sizeof(actual));
    CHECK(syscall(SYS_getsockopt, fd, IPPROTO_TCP, TCP_MAXSEG, &raw, &raw_size) == 0 &&
          raw_size == sizeof(raw));
    if (actual != expected || raw != expected)
        fprintf(stderr, "TCP_MAXSEG_VALUE expected=%d actual=%d raw=%d\n", expected, actual, raw);
    CHECK(actual == expected && raw == expected);
}

static void set_maxseg(int fd, int requested) {
    CHECK(setsockopt(fd, IPPROTO_TCP, TCP_MAXSEG, &requested, sizeof(requested)) == 0);
}

static void reject_invalid_maxseg(int fd, int expected) {
    const int requests[] = {-1, 87, 32768};
    for (unsigned at = 0; at < sizeof(requests) / sizeof(requests[0]); at++) {
        errno = 0;
        CHECK(setsockopt(fd, IPPROTO_TCP, TCP_MAXSEG, &requests[at], sizeof(requests[at])) == -1 &&
              errno == EINVAL);
        expect_maxseg(fd, expected);
    }
}

static int endpoint(int family) {
    int fd = socket(family, SOCK_STREAM | SOCK_CLOEXEC, 0);
    struct timeval timeout = {.tv_sec = 2};
    CHECK(fd >= 0 && setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) == 0 &&
          setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout)) == 0);
    return fd;
}

static void disconnect_socket(int fd) {
    struct sockaddr unspecified = {.sa_family = AF_UNSPEC};
    CHECK(connect(fd, &unspecified, sizeof(unspecified)) == 0);
}

struct Address {
    union {
        struct sockaddr_in four;
        struct sockaddr_in6 six;
    } value;

    socklen_t length;
};

static struct Address loopback(int family) {
    struct Address address = {0};
    if (family == AF_INET6) {
        address.value.six.sin6_family = AF_INET6;
        address.value.six.sin6_addr = in6addr_loopback;
        address.length = sizeof(address.value.six);
    } else {
        address.value.four.sin_family = AF_INET;
        address.value.four.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        address.length = sizeof(address.value.four);
    }
    return address;
}

static struct Address listen_socket(int fd, int family) {
    struct Address address = loopback(family);
    CHECK(bind(fd, (struct sockaddr*)&address.value, address.length) == 0 && listen(fd, 4) == 0);
    socklen_t length = address.length;
    CHECK(getsockname(fd, (struct sockaddr*)&address.value, &length) == 0 &&
          length == address.length);
    return address;
}

static void fresh(int family) {
    const int requests[] = {-1, 0, 88, 536, 1200, 1460, 1600, 32767};
    for (unsigned at = 0; at < sizeof(requests) / sizeof(requests[0]); at++) {
        int fd = endpoint(family);
        expect_maxseg(fd, 536);
        if (requests[at] >= 0)
            set_maxseg(fd, requests[at]);
        int expected = requests[at] > 0 ? requests[at] : 536;
        expect_maxseg(fd, expected);
        reject_invalid_maxseg(fd, expected);
        int alias = dup(fd);
        CHECK(alias >= 0);
        expect_maxseg(alias, expected);
        CHECK(close(alias) == 0);
        struct Address address = loopback(family);
        CHECK(bind(fd, (struct sockaddr*)&address.value, address.length) == 0);
        expect_maxseg(fd, expected);
        CHECK(listen(fd, 4) == 0);
        expect_maxseg(fd, expected);
        disconnect_socket(fd);
        expect_maxseg(fd, 536);
        CHECK(close(fd) == 0);
    }
}

static int expected_connected_maxseg(int fd, int client_limit, int listener_limit, int native) {
    int expected = client_limit < listener_limit ? client_limit : listener_limit;
    if (native) {
        struct tcp_info info;
        socklen_t length = sizeof(info);
        CHECK(getsockopt(fd, IPPROTO_TCP, TCP_INFO, &info, &length) == 0 &&
              length >= offsetof(struct tcp_info, tcpi_options) + sizeof(info.tcpi_options));
        if (info.tcpi_options & TCPI_OPT_TIMESTAMPS)
            expected -= 12;
    } else if (expected > 1460)
        expected = 1460;
    return expected;
}

static void transfer(int client, int accepted, unsigned pattern) {
    unsigned char original[32], copy[32];
    memset(original, (int)pattern, sizeof(original));
    CHECK(send(client, original, sizeof(original), MSG_NOSIGNAL) == sizeof(original));
    CHECK(recv(accepted, copy, sizeof(copy), MSG_WAITALL) == sizeof(copy) &&
          !memcmp(copy, original, sizeof(copy)));
    CHECK(send(accepted, copy, sizeof(copy), MSG_NOSIGNAL) == sizeof(copy));
    CHECK(recv(client, copy, sizeof(copy), MSG_WAITALL) == sizeof(copy) &&
          !memcmp(copy, original, sizeof(copy)));
}

static void lifecycle(int native, int family, int client_limit, int listener_limit) {
    int listener = endpoint(family), client = endpoint(family);
    set_maxseg(listener, listener_limit);
    struct Address address = listen_socket(listener, family);
    expect_maxseg(listener, listener_limit);
    set_maxseg(client, client_limit);
    CHECK(connect(client, (struct sockaddr*)&address.value, address.length) == 0);
    int accepted = accept(listener, NULL, NULL);
    CHECK(accepted >= 0);
    int expected = expected_connected_maxseg(client, client_limit, listener_limit, native);
    expect_maxseg(client, expected);
    expect_maxseg(accepted,
                  expected_connected_maxseg(accepted, client_limit, listener_limit, native));
    expect_maxseg(listener, listener_limit);
    int alias = dup(client);
    CHECK(alias >= 0);
    const int requests[] = {0, 600, 1600, 32767, 88};
    for (unsigned at = 0; at < sizeof(requests) / sizeof(requests[0]); at++) {
        set_maxseg(alias, requests[at]);
        expect_maxseg(client, expected);
        transfer(client, accepted, at);
        expect_maxseg(client, expected);
        reject_invalid_maxseg(alias, expected);
    }
    CHECK(close(alias) == 0);
    disconnect_socket(client);
    expect_maxseg(client, expected);
    set_maxseg(client, 0);
    expect_maxseg(client, expected);
    set_maxseg(client, 1600);
    expect_maxseg(client, 1600);
    unsigned char byte;
    errno = 0;
    CHECK(recv(accepted, &byte, 1, 0) == -1 && errno == ECONNRESET);
    expect_maxseg(accepted, listener_limit);
    CHECK(close(accepted) == 0);
    CHECK(connect(client, (struct sockaddr*)&address.value, address.length) == 0);
    accepted = accept(listener, NULL, NULL);
    CHECK(accepted >= 0);
    expect_maxseg(client, expected_connected_maxseg(client, 1600, listener_limit, native));
    expect_maxseg(accepted, expected_connected_maxseg(accepted, 1600, listener_limit, native));
    transfer(client, accepted, 42);
    CHECK(close(accepted) == 0 && close(client) == 0 && close(listener) == 0);
}

void tcp_maxseg_options_family(int native, int family) {
    fresh(family);
    const int client_limits[] = {1200, 536, 1460, 88, 32767};
    const int listener_limits[] = {536, 1200, 1460, 1600, 1200};
    for (unsigned at = 0; at < sizeof(client_limits) / sizeof(client_limits[0]); at++)
        lifecycle(native, family, client_limits[at], listener_limits[at]);
    printf("%s_MAXSEG_PASS fresh=8 lifecycle=5 post_sets=25\n",
           family == AF_INET6 ? "TCP6" : "TCP");
}

void tcp_maxseg_options(int native) {
    tcp_maxseg_options_family(native, AF_INET);
}
