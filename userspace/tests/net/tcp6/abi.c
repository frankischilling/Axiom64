// SPDX-License-Identifier: GPL-3.0-or-later
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <unistd.h>

static void require(int condition, const char* operation, unsigned detail) {
    if (!condition) {
        printf("TCP6_ABI_FAIL operation=%s detail=%u errno=%d\n", operation, detail, errno);
        exit(1);
    }
}

static int stream(void) {
    int fd = socket(AF_INET6, SOCK_STREAM | SOCK_NONBLOCK, IPPROTO_TCP);
    require(fd >= 0, "IPv6 stream creation", 0);
    return fd;
}

static int expected_address(unsigned family, unsigned length, int connecting) {
    if (length < 2 || length > 128)
        return EINVAL;
    if (family == AF_PACKET)
        return EAFNOSUPPORT;
    if (connecting && family == AF_UNSPEC)
        return 0;
    if (length < 24)
        return EINVAL;
    if (family != AF_INET6)
        return EAFNOSUPPORT;
    return connecting ? EINPROGRESS : 0;
}

static unsigned addresses(uint16_t port) {
    const unsigned families[] = {AF_UNSPEC, AF_INET, AF_INET6, AF_PACKET};
    const unsigned lengths[] = {0, 1, 2, 16, 23, 24, 27, 28, 129};
    unsigned cases = 0;
    for (unsigned connecting = 0; connecting < 2; connecting++)
        for (unsigned family = 0; family < sizeof(families) / sizeof(*families); family++)
            for (unsigned at = 0; at < sizeof(lengths) / sizeof(*lengths); at++) {
                int fd = stream();
                uint8_t bytes[160] = {0};
                struct sockaddr_in6 address = {0};
                address.sin6_family = families[family];
                address.sin6_port = connecting ? port : 0;
                address.sin6_addr = in6addr_loopback;
                memcpy(bytes, &address, sizeof(address));
                errno = 0;
                long result = syscall(connecting ? SYS_connect : SYS_bind, fd, bytes, lengths[at]);
                int observed = result < 0 ? errno : 0;
                require(observed == expected_address(families[family], lengths[at], connecting),
                        connecting ? "connect address import" : "bind address import", cases);
                require(!close(fd), "close imported address", cases++);
            }
    return cases;
}

static unsigned only_options(void) {
    const unsigned lengths[] = {0, 1, 3, 4, 8};
    unsigned cases = 0;
    for (unsigned bound = 0; bound < 2; bound++)
        for (unsigned at = 0; at < sizeof(lengths) / sizeof(*lengths); at++) {
            int fd = stream(), value = 1;
            if (bound) {
                struct sockaddr_in6 address = {.sin6_family = AF_INET6};
                require(!bind(fd, (struct sockaddr*)&address, sizeof(address)), "bind V6ONLY",
                        cases);
            }
            errno = 0;
            int result = setsockopt(fd, IPPROTO_IPV6, IPV6_V6ONLY, &value, lengths[at]);
            int expected = bound || lengths[at] < 4 ? EINVAL : 0;
            require((result < 0 ? errno : 0) == expected, "set V6ONLY", cases);
            value = -1;
            socklen_t length = sizeof(value);
            require(!getsockopt(fd, IPPROTO_IPV6, IPV6_V6ONLY, &value, &length) &&
                        length == sizeof(value) && value == (expected ? 0 : 1),
                    "V6ONLY value after set", cases);
            require(!close(fd), "close V6ONLY", cases++);
        }
    return cases;
}

static unsigned names(void) {
    const uint32_t lengths[] = {0, 1, 2, 16, 27, 28, 128, UINT32_MAX};
    unsigned cases = 0;
    for (unsigned valid = 0; valid < 2; valid++)
        for (unsigned at = 0; at < sizeof(lengths) / sizeof(*lengths); at++) {
            int fd = stream();
            uint8_t bytes[128], expected[128];
            memset(bytes, 0xa7, sizeof(bytes));
            memset(expected, 0xa7, sizeof(expected));
            socklen_t length = lengths[at];
            int expected_error = ((int32_t)length < 0) ? EINVAL : length && !valid ? EFAULT : 0;
            errno = 0;
            long result =
                syscall(SYS_getsockname, fd, valid ? bytes : (void*)(uintptr_t)1, &length);
            require((result < 0 ? errno : 0) == expected_error, "getsockname result", cases);
            require(length == (expected_error ? lengths[at] : 28), "getsockname length", cases);
            if (!expected_error && valid) {
                struct sockaddr_in6 empty = {.sin6_family = AF_INET6};
                size_t copied = lengths[at] < sizeof(empty) ? lengths[at] : sizeof(empty);
                memcpy(expected, &empty, copied);
            }
            require(!memcmp(bytes, expected, sizeof(bytes)), "getsockname copy and guard", cases);
            require(!close(fd), "close getsockname", cases++);
        }
    return cases;
}

int main(void) {
    int listener = stream(), value = 1;
    require(!setsockopt(listener, IPPROTO_IPV6, IPV6_V6ONLY, &value, sizeof(value)),
            "listener V6ONLY", 0);
    struct sockaddr_in6 address = {.sin6_family = AF_INET6, .sin6_addr = IN6ADDR_LOOPBACK_INIT};
    require(!bind(listener, (struct sockaddr*)&address, sizeof(address)), "bind listener", 0);
    require(!listen(listener, 32), "listen", 0);
    socklen_t length = sizeof(address);
    require(!getsockname(listener, (struct sockaddr*)&address, &length) &&
                length == sizeof(address),
            "listener name", 0);
    unsigned address_cases = addresses(address.sin6_port);
    unsigned option_cases = only_options();
    unsigned name_cases = names();
    require(!close(listener), "close listener", 0);
    printf("TCP6_ABI_PASS address_cases=%u option_cases=%u name_cases=%u\n", address_cases,
           option_cases, name_cases);
    return 0;
}
