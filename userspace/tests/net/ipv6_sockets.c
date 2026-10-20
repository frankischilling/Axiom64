// SPDX-License-Identifier: GPL-3.0-or-later
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <linux/if_addr.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <net/if.h>
#include <netinet/icmp6.h>
#include <netpacket/packet.h>
#include <poll.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/time.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

static unsigned indices[2];
static unsigned char macs[2][6];
static int packets[2];

static void check(int value, const char* reason) {
    if (!value) {
        fprintf(stderr, "IPV6_SOCKETS_FAIL %s errno=%d\n", reason, errno);
        exit(1);
    }
}

static uint64_t now(void) {
    struct timespec value;
    check(!clock_gettime(CLOCK_MONOTONIC, &value), "monotonic socket clock");
    return (uint64_t)value.tv_sec * 1000000000ULL + value.tv_nsec;
}

static struct sockaddr_in6 address(unsigned lane, unsigned host, unsigned port, int link) {
    struct sockaddr_in6 result = {.sin6_family = AF_INET6, .sin6_port = htons(port)};
    if (link) {
        result.sin6_addr.s6_addr[0] = 0xfe;
        result.sin6_addr.s6_addr[1] = 0x80;
        result.sin6_scope_id = indices[lane];
    } else {
        result.sin6_addr.s6_addr[0] = 0x20;
        result.sin6_addr.s6_addr[1] = 1;
        result.sin6_addr.s6_addr[2] = 0x0d;
        result.sin6_addr.s6_addr[3] = 0xb8;
        result.sin6_addr.s6_addr[5] = lane + 1;
    }
    result.sin6_addr.s6_addr[15] = host;
    return result;
}

static struct sockaddr_in6 loopback(unsigned port) {
    struct sockaddr_in6 result = {
        .sin6_family = AF_INET6, .sin6_port = htons(port), .sin6_addr = IN6ADDR_LOOPBACK_INIT};
    return result;
}

static int create(int type) {
    int fd = socket(AF_INET6, type | SOCK_CLOEXEC, type == SOCK_RAW ? IPPROTO_ICMPV6 : 0);
    check(fd >= 0, "actual IPv6 socket");
    return fd;
}

static void option(int fd, int level, int name, int value) {
    check(!setsockopt(fd, level, name, &value, sizeof(value)), "IPv6 socket option");
}

static int get(int fd, int level, int name) {
    int value = -1;
    socklen_t length = sizeof(value);
    check(!getsockopt(fd, level, name, &value, &length) && length == sizeof(value),
          "actual IPv6 socket option result");
    return value;
}

static void readable(int fd, int events) {
    struct pollfd item = {.fd = fd, .events = events};
    check(poll(&item, 1, 5000) == 1 && (item.revents & events), "finite socket readiness");
}

static void bind_address(int fd, struct sockaddr_in6 value) {
    check(!bind(fd, (struct sockaddr*)&value, sizeof(value)), "IPv6 socket binding");
}

static void connect_address(int fd, struct sockaddr_in6 value) {
    check(!connect(fd, (struct sockaddr*)&value, sizeof(value)), "IPv6 socket connection");
}

static void receive_exact(int fd, void* bytes, size_t size) {
    readable(fd, POLLIN);
    check(recv(fd, bytes, size, MSG_DONTWAIT) == (ssize_t)size, "exact IPv6 datagram size");
}

static unsigned abi_cases, abi_failures;

static int abi_value(long result, long wanted, int wanted_error, const char* reason) {
    int error = result < 0 ? errno : 0;
    int passed = result == wanted && error == wanted_error;
    printf("IPV6_SOCKETS_ABI_CASE name=%s result=%ld errno=%d passed=%d\n", reason, result, error,
           passed);
    abi_cases++;
    abi_failures += !passed;
    return passed;
}

static int abi_error(long result, int wanted, const char* reason) {
    return abi_value(result, -1, wanted, reason);
}

static long raw_short_output(int fd, unsigned char* payload, unsigned length,
                             struct sockaddr_in6* target, unsigned capacity, int vectored) {
    struct iovec vectors[2] = {{payload, length ? 1 : 0}, {payload + 1, length ? length - 1 : 0}};
    struct msghdr message = {
        .msg_name = target, .msg_namelen = capacity, .msg_iov = vectors, .msg_iovlen = 2};
    errno = 0;
    return vectored ? sendmsg(fd, &message, 0)
                    : sendto(fd, payload, length, 0, (struct sockaddr*)target, capacity);
}

static void raw_short_abi(void) {
    int fd = create(SOCK_RAW);
    unsigned char payload[4] = {129};
    for (unsigned unreachable = 0; unreachable < 2; unreachable++) {
        struct sockaddr_in6 target = loopback(58);
        if (unreachable)
            check(inet_pton(AF_INET6, "2001:db8:ffff::1", &target.sin6_addr) == 1,
                  "unrouted raw header fixture");
        for (unsigned length = 0; length < 4; length++) {
            for (unsigned vectored = 0; vectored < 2; vectored++) {
                int error = length < 2 ? EFAULT : unreachable ? ENETUNREACH : EINVAL;
                const char* reason =
                    unreachable
                        ? (length < 2 ? "raw-prefix-before-route" : "raw-route-before-checksum")
                        : (length < 2 ? "raw-short-prefix" : "raw-short-checksum");
                abi_error(raw_short_output(fd, payload, length, &target, sizeof(target), vectored),
                          error, reason);
            }
        }
    }
    for (unsigned length = 0; length < 2; length++)
        for (unsigned vectored = 0; vectored < 2; vectored++)
            abi_error(raw_short_output(fd, payload, length, NULL, 0, vectored), EDESTADDRREQ,
                      "raw-destination-before-prefix");
    for (unsigned kind = 0; kind < 3; kind++) {
        struct sockaddr_in6 target = loopback(kind == 2 ? 17 : 58);
        if (!kind)
            target.sin6_family = AF_INET;
        for (unsigned vectored = 0; vectored < 2; vectored++)
            abi_error(
                raw_short_output(fd, payload, 0, &target, kind == 1 ? 1 : sizeof(target), vectored),
                !kind ? EAFNOSUPPORT : EINVAL,
                !kind       ? "raw-family-before-prefix"
                : kind == 1 ? "raw-address-before-prefix"
                            : "raw-protocol-before-prefix");
    }
    close(fd);
}

static void raw_payload_fault_abi(void) {
    unsigned char* pages =
        mmap(NULL, 8192, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    check(pages != MAP_FAILED && !mprotect(pages + 4096, 4096, PROT_NONE),
          "raw payload fault fixture");
    int fd = create(SOCK_RAW);
    for (unsigned unreachable = 0; unreachable < 2; unreachable++) {
        struct sockaddr_in6 target = loopback(58);
        if (unreachable)
            check(inet_pton(AF_INET6, "2001:db8:ffff::1", &target.sin6_addr) == 1,
                  "unrouted raw payload fixture");
        for (unsigned available = 1; available <= 2; available++) {
            unsigned char* payload = pages + 4096 - available;
            payload[0] = 129;
            if (available == 2)
                payload[1] = 0;
            for (unsigned length = 2; length < 4; length++)
                for (unsigned vectored = 0; vectored < 2; vectored++) {
                    int error = available < 2        ? EFAULT
                                : unreachable        ? ENETUNREACH
                                : length > available ? EFAULT
                                                     : EINVAL;
                    const char* reason = available < 2        ? "raw-prefix-copy-before-route"
                                         : unreachable        ? "raw-route-before-tail-copy"
                                         : length > available ? "raw-tail-copy-fault"
                                                              : "raw-checksum-after-copy";
                    abi_error(
                        raw_short_output(fd, payload, length, &target, sizeof(target), vectored),
                        error, reason);
                }
        }
    }
    close(fd);
    check(!munmap(pages, 8192), "raw payload fault fixture release");
}

static void scoped_abi(void) {
    for (unsigned type = SOCK_DGRAM; type <= SOCK_RAW; type++) {
        for (unsigned length = 25; length < 28; length++) {
            struct sockaddr_in6 local = address(1, 2, type == SOCK_RAW ? 58 : 0, 1);
            struct sockaddr_in6 peer = address(1, 1, type == SOCK_RAW ? 58 : 59998, 1);
            int fd = create(type);
            abi_error(bind(fd, (struct sockaddr*)&local, length), EINVAL, "partial-scope-bind");
            close(fd);
            fd = create(type);
            abi_error(connect(fd, (struct sockaddr*)&peer, length), EINVAL,
                      "partial-scope-connect");
            close(fd);
            for (unsigned connect_call = 0; connect_call < 2; connect_call++) {
                fd = create(type);
                check(!setsockopt(fd, SOL_SOCKET, SO_BINDTODEVICE, "eth0", 5),
                      "short scope device fixture");
                long result = connect_call ? connect(fd, (struct sockaddr*)&peer, length)
                                           : bind(fd, (struct sockaddr*)&local, length);
                if (!result) {
                    char device[16] = {0};
                    socklen_t capacity = sizeof(device);
                    check(!getsockopt(fd, SOL_SOCKET, SO_BINDTODEVICE, device, &capacity),
                          "short address device result");
                    // A successful call must also retain the original binding.
                    result = capacity == 5 && !strcmp(device, "eth0") ? 0 : 1;
                }
                abi_value(result, 0, 0,
                          connect_call ? "bound-partial-scope-connect"
                                       : "bound-partial-scope-bind");
                close(fd);
            }
        }
        for (unsigned short_address = 0; short_address < 2; short_address++) {
            int fd = create(type);
            check(!setsockopt(fd, SOL_SOCKET, SO_BINDTODEVICE, "eth0", 5),
                  "disconnect device fixture");
            connect_address(fd, address(0, 1, type == SOCK_RAW ? 58 : 59998, 1));
            struct sockaddr_in6 unspecified = {0};
            check(!connect(fd, (struct sockaddr*)&unspecified,
                           short_address ? 2 : sizeof(unspecified)),
                  "IPv6 disconnect");
            char device[16] = {0};
            socklen_t capacity = sizeof(device);
            check(!getsockopt(fd, SOL_SOCKET, SO_BINDTODEVICE, device, &capacity),
                  "disconnected device result");
            abi_value(capacity, 0, 0, "disconnect-device-cleared");
            close(fd);
        }
    }
}

static void unspecified_output_abi(void) {
    unsigned char payload[8] = {129}, received[8];
    int server = create(SOCK_DGRAM);
    bind_address(server, loopback(0));
    struct sockaddr_in6 destination;
    socklen_t capacity = sizeof(destination);
    check(!getsockname(server, (struct sockaddr*)&destination, &capacity),
          "AF_UNSPEC receive fixture");
    for (unsigned type = SOCK_DGRAM; type <= SOCK_RAW; type++) {
        int fd = create(type);
        if (type == SOCK_DGRAM)
            connect_address(fd, destination);
        struct sockaddr_in6 named = loopback(type == SOCK_RAW ? 58 : 59997);
        named.sin6_family = AF_UNSPEC;
        struct iovec vector = {payload, sizeof(payload)};
        struct msghdr message = {
            .msg_name = &named, .msg_namelen = sizeof(named), .msg_iov = &vector, .msg_iovlen = 1};
        for (unsigned length = 1; length <= sizeof(named); length++) {
            message.msg_namelen = length;
            for (unsigned vectored = 0; vectored < 2; vectored++) {
                long result = vectored ? sendmsg(fd, &message, 0)
                                       : sendto(fd, payload, sizeof(payload), 0,
                                                (struct sockaddr*)&named, length);
                if (length < (type == SOCK_RAW ? 24 : 2))
                    abi_error(result, EINVAL,
                              type == SOCK_RAW ? "short-raw-output" : "short-unspecified-output");
                else if (abi_value(result, sizeof(payload), 0, "unspecified-named-output") &&
                         type == SOCK_DGRAM) {
                    receive_exact(server, received, sizeof(received));
                    check(!memcmp(payload, received, sizeof(payload)),
                          "AF_UNSPEC uses the connected UDP destination");
                }
            }
        }
        for (unsigned family = 0; family < 2; family++) {
            named.sin6_family = family ? AF_INET6 : AF_UNIX;
            message.msg_namelen = 2;
            for (unsigned vectored = 0; vectored < 2; vectored++)
                abi_error(
                    vectored ? sendmsg(fd, &message, 0)
                             : sendto(fd, payload, sizeof(payload), 0, (struct sockaddr*)&named, 2),
                    EINVAL, family ? "short-inet6-output" : "short-other-family");
            if (!family) {
                message.msg_namelen = sizeof(named);
                for (unsigned vectored = 0; vectored < 2; vectored++)
                    abi_error(vectored ? sendmsg(fd, &message, 0)
                                       : sendto(fd, payload, sizeof(payload), 0,
                                                (struct sockaddr*)&named, sizeof(named)),
                              type == SOCK_RAW ? EAFNOSUPPORT : EINVAL,
                              type == SOCK_RAW ? "raw-other-family" : "UDP-other-family");
            }
        }
        close(fd);
    }
    for (unsigned length = 1; length <= sizeof(destination); length++) {
        for (unsigned vectored = 0; vectored < 2; vectored++) {
            int fd = create(SOCK_DGRAM);
            struct sockaddr_in6 named = destination;
            named.sin6_family = AF_UNSPEC;
            struct iovec vector = {payload, sizeof(payload)};
            struct msghdr message = {
                .msg_name = &named, .msg_namelen = length, .msg_iov = &vector, .msg_iovlen = 1};
            abi_error(vectored ? sendmsg(fd, &message, 0)
                               : sendto(fd, payload, sizeof(payload), 0, (struct sockaddr*)&named,
                                        length),
                      length < 2 ? EINVAL : EDESTADDRREQ,
                      length < 2 ? "short-unspecified-output" : "unspecified-unconnected-output");
            close(fd);
        }
    }
    close(server);
}

static void error_copy_abi(void) {
    unsigned char* pages =
        mmap(NULL, 8192, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    check(pages != MAP_FAILED && !mprotect(pages, 4096, PROT_NONE), "SO_ERROR fault fixture");
    for (unsigned kind = 0; kind < 6; kind++) {
        int fd = create(SOCK_DGRAM), value = -1;
        connect_address(fd, loopback(59996));
        check(send(fd, "x", 1, 0) == 1, "SO_ERROR actual closed-port request");
        readable(fd, POLLERR);
        socklen_t length = kind == 2 ? (socklen_t)-1 : kind == 4 ? 0 : sizeof(value);
        check(!mprotect(pages + 4096, 4096, PROT_READ | PROT_WRITE), "SO_ERROR length preparation");
        memcpy(pages + 4096, &length, sizeof(length));
        if (kind == 1)
            check(!mprotect(pages + 4096, 4096, PROT_READ), "SO_ERROR read-only capacity");
        void* output = &value;
        if (kind == 0 || kind == 4)
            output = pages;
        socklen_t* capacity = kind == 1   ? (socklen_t*)(pages + 4096)
                              : kind == 3 ? (socklen_t*)pages
                              : kind == 5 ? NULL
                                          : &length;
        long result = getsockopt(fd, SOL_SOCKET, SO_ERROR, output, capacity);
        if (kind == 0 || kind == 1)
            abi_error(result, EFAULT, "error-output-fault");
        else if (kind == 2)
            abi_error(result, EINVAL, "error-invalid-length");
        else if (kind == 3 || kind == 5)
            abi_error(result, EFAULT, "error-length-fault");
        else
            abi_value(result, 0, 0, "error-empty-output");
        int consumed = kind == 0 || kind == 1 || kind == 4;
        abi_value(get(fd, SOL_SOCKET, SO_ERROR), consumed ? 0 : ECONNREFUSED, 0,
                  consumed ? "consumed-error" : "preserved-error");
        if (kind == 1)
            check(value == ECONNREFUSED, "SO_ERROR value precedes output length fault");
        close(fd);
    }
    check(!munmap(pages, 8192), "release SO_ERROR fault fixture");
}

static void abi_contract(void) {
    unsigned char bytes[129] = {0}, payload[8] = {129};
    struct sockaddr_in6 target;
    unsigned char* mapped =
        mmap(NULL, 8192, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    check(mapped != MAP_FAILED && !mprotect(mapped + 4096, 4096, PROT_NONE),
          "address import fault fixture");
    unsigned char* tail = mapped + 4096 - sizeof(target);
    for (unsigned type = SOCK_DGRAM; type <= SOCK_RAW; type++) {
        int fd = create(type), previous = get(fd, SOL_SOCKET, SO_REUSEADDR), one = !previous;
        if (abi_error(syscall(SYS_setsockopt, fd, SOL_SOCKET, SO_REUSEADDR, &one, (unsigned)-1),
                      EINVAL, "negative-option-length"))
            check(get(fd, SOL_SOCKET, SO_REUSEADDR) == previous,
                  "failed option preserves prior value");
        check(previous == (type == SOCK_RAW), "Linux raw and UDP reuse defaults");
        close(fd);
        target = loopback(type == SOCK_RAW ? 0 : 59998);
        memcpy(bytes, &target, sizeof(target));
        const unsigned fault_lengths[] = {0, 1, 129, (unsigned)-1};
        for (unsigned n = 0; n < 4; n++) {
            unsigned length = fault_lengths[n];
            int wanted = n == 1 ? EFAULT : EINVAL;
            const char* reason = n == 0   ? "empty-address-input"
                                 : n == 1 ? "one-byte-address-fault"
                                 : n == 2 ? "oversized-address-input"
                                          : "negative-address-before-fault";
            fd = create(type);
            abi_error(syscall(SYS_bind, fd, mapped + 4096, length), wanted, reason);
            abi_error(syscall(SYS_connect, fd, mapped + 4096, length), wanted, reason);
            abi_error(syscall(SYS_sendto, fd, payload, sizeof(payload), 0, mapped + 4096, length),
                      wanted, reason);
            struct iovec vector = {payload, sizeof(payload)};
            struct msghdr message = {.msg_name = mapped + 4096,
                                     .msg_namelen = length,
                                     .msg_iov = &vector,
                                     .msg_iovlen = 1};
            abi_error(sendmsg(fd, &message, 0),
                      n == 0             ? EDESTADDRREQ
                      : n == 1 || n == 2 ? EFAULT
                                         : EINVAL,
                      n == 0   ? "empty-message-destination"
                      : n == 2 ? "clamped-address-fault"
                               : reason);
            close(fd);
        }
        for (unsigned n = 0; n < 2; n++) {
            unsigned length = n ? 129 : (unsigned)-1;
            fd = create(type);
            abi_error(syscall(SYS_bind, fd, bytes, length), EINVAL, "invalid-bind-length");
            close(fd);
            fd = create(type);
            abi_error(syscall(SYS_connect, fd, bytes, length), EINVAL, "invalid-connect-length");
            close(fd);
            fd = create(type);
            abi_error(syscall(SYS_sendto, fd, payload, sizeof(payload), 0, bytes, length), EINVAL,
                      "invalid-send-address-length");
            close(fd);
        }
        memcpy(tail, &target, sizeof(target));
        fd = create(type);
        abi_error(syscall(SYS_bind, fd, tail, 128), EFAULT, "full-bind-address-import");
        close(fd);
        fd = create(type);
        abi_error(syscall(SYS_connect, fd, tail, 128), EFAULT, "full-connect-address-import");
        close(fd);
        fd = create(type);
        abi_error(syscall(SYS_sendto, fd, payload, sizeof(payload), 0, tail, 128), EFAULT,
                  "full-send-address-import");
        memset(tail, 0, sizeof(target));
        abi_error(syscall(SYS_connect, fd, tail, 128), EFAULT, "disconnect-address-import");
        close(fd);
        for (unsigned n = 0; n < 2; n++) {
            fd = create(type);
            target = loopback(0);
            memcpy(bytes, &target, sizeof(target));
            check(!bind(fd, (struct sockaddr*)bytes, n ? 128 : 24),
                  "Linux IPv6 address length boundaries");
            close(fd);
        }
        fd = create(type);
        check(!setsockopt(fd, SOL_SOCKET, SO_BINDTODEVICE, "eth0", 5), "scope conflict fixture");
        target = address(1, 1, type == SOCK_RAW ? 58 : 59998, 1);
        int rejected = abi_error(connect(fd, (struct sockaddr*)&target, sizeof(target)), EINVAL,
                                 "conflicting-connect-device");
        char device[16] = {0};
        socklen_t length = sizeof(device);
        if (rejected)
            check(!getsockopt(fd, SOL_SOCKET, SO_BINDTODEVICE, device, &length) && length == 5 &&
                      !strcmp(device, "eth0"),
                  "failed connection preserves explicit device");
        close(fd);
        fd = create(type);
        check(!setsockopt(fd, SOL_SOCKET, SO_BINDTODEVICE, "eth0", 5), "scope bind fixture");
        // Linux bind may replace an explicit device with its link-local scope.
        bind_address(fd, address(1, 2, 0, 1));
        memset(device, 0, sizeof(device));
        length = sizeof(device);
        check(!getsockopt(fd, SOL_SOCKET, SO_BINDTODEVICE, device, &length) && length == 5 &&
                  !strcmp(device, "eth1"),
              "link-local bind retains Linux scope precedence");
        close(fd);
    }
    int raw = create(SOCK_RAW);
    struct icmp6_filter filter;
    ICMP6_FILTER_SETBLOCKALL(&filter);
    abi_error(syscall(SYS_setsockopt, raw, IPPROTO_ICMPV6, ICMP6_FILTER, &filter, (unsigned)-1),
              EINVAL, "negative-filter-length");
    target = loopback(17);
    abi_error(sendto(raw, payload, sizeof(payload), 0, (struct sockaddr*)&target, sizeof(target)),
              EINVAL, "raw-named-protocol");
    for (unsigned n = 0; n < 2; n++) {
        target = loopback(n ? 58 : 0);
        check(sendto(raw, payload, sizeof(payload), 0, (struct sockaddr*)&target, sizeof(target)) ==
                  sizeof(payload),
              "raw named output accepts zero or its own protocol");
    }
    close(raw);
    int server = create(SOCK_DGRAM), client = create(SOCK_DGRAM);
    bind_address(server, loopback(0));
    socklen_t length = sizeof(target);
    check(!getsockname(server, (struct sockaddr*)&target, &length), "length fixture name");
    connect_address(client, target);
    struct iovec vector = {payload, 1};
    struct msghdr message = {
        .msg_name = &target, .msg_namelen = (socklen_t)-1, .msg_iov = &vector, .msg_iovlen = 1};
    abi_error(sendmsg(client, &message, 0), EINVAL, "negative-sendmsg-address-length");
    check(send(client, payload, 1, 0) == 1, "negative recvmsg fixture");
    readable(server, POLLIN);
    abi_error(recvmsg(server, &message, MSG_DONTWAIT), EINVAL, "negative-recvmsg-capacity");
    unsigned char received;
    receive_exact(server, &received, 1);
    memcpy(bytes, &target, sizeof(target));
    message.msg_name = bytes;
    message.msg_namelen = 129;
    check(sendmsg(client, &message, 0) == 1, "sendmsg clamps positive address storage length");
    receive_exact(server, &received, 1);
    message.msg_name = mapped + 4096;
    message.msg_namelen = 0;
    check(sendmsg(client, &message, 0) == 1, "zero address length uses connected destination");
    receive_exact(server, &received, 1);
    for (unsigned peek = 0; peek < 2; peek++) {
        check(send(client, payload, 1, 0) == 1, "negative receive length fixture");
        readable(server, POLLIN);
        length = (socklen_t)-1;
        unsigned char received = 0;
        int rejected = abi_error(
            recvfrom(server, &received, 1, peek ? MSG_PEEK : 0, (struct sockaddr*)&target, &length),
            EINVAL, "negative-receive-capacity");
        if (rejected)
            check(received == payload[0] && length == (socklen_t)-1,
                  "receive data precedes invalid address capacity");
        if (peek)
            receive_exact(server, &received, 1);
        check(recv(server, &received, 1, MSG_DONTWAIT) == -1 && errno == EAGAIN,
              "invalid address capacity retains peek and consume ownership");
        for (unsigned bad = 0; bad < 2; bad++) {
            check(send(client, payload, 1, 0) == 1, "unreadable receive length fixture");
            readable(server, POLLIN);
            received = 0;
            abi_error(recvfrom(server, &received, 1, peek ? MSG_PEEK : 0, (struct sockaddr*)&target,
                               bad ? (socklen_t*)(mapped + 4096) : NULL),
                      EFAULT, "unreadable-receive-capacity");
            check(received == payload[0], "receive data precedes address capacity copy fault");
            if (peek)
                receive_exact(server, &received, 1);
            check(recv(server, &received, 1, MSG_DONTWAIT) == -1 && errno == EAGAIN,
                  "faulted address capacity retains peek and consume ownership");
        }
    }
    close(client);
    close(server);
    check(!munmap(mapped, 8192), "release address import fault fixture");
    scoped_abi();
    unspecified_output_abi();
    error_copy_abi();
    raw_short_abi();
    raw_payload_fault_abi();
    check(!abi_failures, "IPv6 ABI regression cases");
    printf("IPV6_SOCKETS_ABI_PASS cases=%u\n", abi_cases);
}

static void local_contract(void) {
    int server = create(SOCK_DGRAM), client = create(SOCK_DGRAM);
    option(server, IPPROTO_IPV6, IPV6_V6ONLY, 1);
    bind_address(server, loopback(0));
    struct sockaddr_in6 target;
    socklen_t length = sizeof(target);
    check(!getsockname(server, (struct sockaddr*)&target, &length) && length == sizeof(target) &&
              target.sin6_family == AF_INET6 && target.sin6_port,
          "bound IPv6 socket name");
    connect_address(client, target);
    check(get(client, SOL_SOCKET, SO_DOMAIN) == AF_INET6 &&
              get(client, SOL_SOCKET, SO_PROTOCOL) == IPPROTO_UDP,
          "IPv6 protocol identity");
    struct stat status;
    check(!fstat(client, &status) && S_ISSOCK(status.st_mode), "IPv6 description metadata");
    unsigned char sent[23], received[23];
    for (unsigned n = 0; n < sizeof(sent); n++)
        sent[n] = n * 11 + 3;
    int alias = dup(server);
    check(alias >= 0 && !close(server), "shared IPv6 description ownership");
    check(send(client, sent, sizeof(sent), 0) == sizeof(sent), "loopback UDP send");
    readable(alias, POLLIN);
    int available = -1;
    check(!ioctl(alias, FIONREAD, &available) && available == sizeof(sent), "IPv6 FIONREAD");
    check(recv(alias, received, 7, MSG_PEEK | MSG_TRUNC) == sizeof(sent),
          "IPv6 peek and truncation");
    receive_exact(alias, received, sizeof(received));
    check(!memcmp(sent, received, sizeof(sent)), "kernel loopback UDP bytes");
    unsigned char* guard = mmap(NULL, 4096, PROT_NONE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    check(guard != MAP_FAILED, "receive fault fixture");
    check(send(client, sent, sizeof(sent), 0) == sizeof(sent), "fault fixture datagram");
    readable(alias, POLLIN);
    check(recv(alias, guard, 7, MSG_PEEK) == -1 && errno == EFAULT, "peek copy fault");
    check(recv(alias, guard, 7, 0) == -1 && errno == EFAULT, "consuming copy fault");
    check(recv(alias, received, sizeof(received), MSG_DONTWAIT) == -1 && errno == EAGAIN,
          "faulted datagram was consumed");
    struct timeval timeout = {0, 20000};
    check(!setsockopt(alias, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)),
          "IPv6 receive deadline");
    uint64_t began = now();
    check(recv(alias, guard, 7, 0) == -1 && errno == EAGAIN, "unavailable receive deadline");
    check(now() - began >= 20000000ULL, "complete original receive interval");
    check(!munmap(guard, 4096), "release receive fault fixture");
    int refused = create(SOCK_DGRAM);
    connect_address(refused, loopback(59999));
    check(send(refused, sent, 1, 0) == 1, "unbound loopback UDP output");
    readable(refused, POLLERR);
    check(get(refused, SOL_SOCKET, SO_ERROR) == ECONNREFUSED && !get(refused, SOL_SOCKET, SO_ERROR),
          "actual loopback ICMPv6 port error ownership");
    close(refused);
    close(alias);
    close(client);
    puts("IPV6_SOCKETS_LOCAL_PASS shared=1 faults=2 deadline=1 refused=1");
}

static void barrier(unsigned lane, unsigned phase) {
    unsigned char frame[60] = {2, 'I', 'P', '6', lane, 0};
    memcpy(frame + 6, macs[lane], 6);
    frame[12] = 0x88;
    frame[13] = 0xb7;
    memcpy(frame + 14, "IP6S", 4);
    frame[18] = lane;
    frame[19] = phase;
    struct sockaddr_ll target = {.sll_family = AF_PACKET,
                                 .sll_protocol = htons(0x88b7),
                                 .sll_ifindex = indices[lane],
                                 .sll_halen = 6};
    memcpy(target.sll_addr, frame, 6);
    check(sendto(packets[lane], frame, sizeof(frame), 0, (struct sockaddr*)&target,
                 sizeof(target)) == sizeof(frame),
          "socket Ethernet barrier");
    uint64_t began = now();
    for (;;) {
        unsigned char reply[1600];
        struct pollfd item = {.fd = packets[lane], .events = POLLIN};
        check(poll(&item, 1, 100) >= 0, "socket barrier poll");
        ssize_t size = recv(packets[lane], reply, sizeof(reply), MSG_DONTWAIT);
        if (size >= 21 && !memcmp(reply, macs[lane], 6) && reply[12] == 0x88 && reply[13] == 0xb7 &&
            !memcmp(reply + 14, "IP6S", 4) && reply[18] == lane && reply[19] == phase &&
            reply[20] == 1)
            break;
        check(now() - began < 10000000000ULL, "finite socket barrier");
    }
    printf("IPV6_SOCKETS_PHASE_PASS lane=%u phase=%u\n", lane, phase);
}

static void configure(unsigned lane, int link) {
    int fd = socket(AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC, NETLINK_ROUTE);
    check(fd >= 0, "socket fixture address control");

    struct {
        struct nlmsghdr header;
        struct ifaddrmsg address;
        struct rtattr field;
        struct in6_addr value;
    } message = {0};

    message.header = (struct nlmsghdr){sizeof(message), RTM_NEWADDR,
                                       NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE | NLM_F_EXCL, 1, 0};
    message.address = (struct ifaddrmsg){AF_INET6, 64, IFA_F_NODAD, 0, indices[lane]};
    message.field = (struct rtattr){20, IFA_ADDRESS};
    message.value = address(lane, 2, 0, link).sin6_addr;
    struct sockaddr_nl kernel = {.nl_family = AF_NETLINK};
    check(sendto(fd, &message, sizeof(message), 0, (struct sockaddr*)&kernel, sizeof(kernel)) ==
              sizeof(message),
          "explicit socket fixture address");
    unsigned char response[256];
    ssize_t size = recv(fd, response, sizeof(response), 0);
    struct nlmsgerr result;
    check(size >= (ssize_t)NLMSG_LENGTH(sizeof(result)) &&
              ((struct nlmsghdr*)response)->nlmsg_type == NLMSG_ERROR,
          "fixture address acknowledgement");
    memcpy(&result, NLMSG_DATA((struct nlmsghdr*)response), sizeof(result));
    check(!result.error, "fixture address mutation result");
    close(fd);
}

static int wire_socket(unsigned lane, int type, unsigned local_port, unsigned peer_port, int link) {
    int fd = create(type);
    char name[16];
    snprintf(name, sizeof(name), "eth%u", lane);
    check(!setsockopt(fd, SOL_SOCKET, SO_BINDTODEVICE, name, strlen(name) + 1),
          "IPv6 bound device");
    if (type == SOCK_DGRAM)
        option(fd, IPPROTO_IPV6, IPV6_V6ONLY, 1);
    bind_address(fd, address(lane, 2, local_port, link));
    connect_address(fd, address(lane, 1, peer_port, link));
    struct sockaddr_in6 actual, wanted = address(lane, 2, type == SOCK_RAW ? 58 : local_port, link);
    socklen_t size = sizeof(actual);
    check(!getsockname(fd, (struct sockaddr*)&actual, &size) && size == sizeof(actual) &&
              !memcmp(&actual, &wanted, sizeof(actual)),
          "actual scoped local socket name");
    size = sizeof(actual);
    wanted = address(lane, 1, peer_port, link);
    check(!getpeername(fd, (struct sockaddr*)&actual, &size) && size == sizeof(actual) &&
              !memcmp(&actual, &wanted, sizeof(actual)),
          "actual scoped peer socket name");
    return fd;
}

static void wire(unsigned lane) {
    int raw = wire_socket(lane, SOCK_RAW, 0, 58, 0);
    option(raw, IPPROTO_IPV6, IPV6_UNICAST_HOPS, 37);
    check(get(raw, IPPROTO_IPV6, IPV6_CHECKSUM) == 2, "kernel ICMPv6 checksum ownership");
    struct icmp6_filter filter;
    ICMP6_FILTER_SETBLOCKALL(&filter);
    ICMP6_FILTER_SETPASS(ICMP6_ECHO_REPLY, &filter);
    check(!setsockopt(raw, IPPROTO_ICMPV6, ICMP6_FILTER, &filter, sizeof(filter)),
          "full ICMPv6 filter");
    unsigned char echo[19] = {128, 0, 0xa5, 0x5a, 0x6a, 0x10 + lane, 0x27, 1};
    for (unsigned n = 8; n < sizeof(echo); n++)
        echo[n] = n * 7 + lane;
    barrier(lane, 1);
    struct iovec vectors[2] = {{echo, 3}, {echo + 3, sizeof(echo) - 3}};
    struct msghdr message = {.msg_iov = vectors, .msg_iovlen = 2};
    check(sendmsg(raw, &message, 0) == sizeof(echo), "raw ICMPv6 vectored output");
    unsigned char received[128];
    receive_exact(raw, received, sizeof(echo));
    check(received[0] == 129 && !received[1] && !memcmp(received + 4, echo + 4, sizeof(echo) - 4),
          "original raw ICMPv6 reply without IP header");
    int udp = wire_socket(lane, SOCK_DGRAM, 41000 + lane, 42000 + lane, 0);
    check(send(udp, NULL, 0, 0) == 0, "zero-length UDP output");
    readable(udp, POLLIN);
    check(recv(udp, NULL, 0, MSG_PEEK) == 0 && recv(udp, NULL, 0, 0) == 0,
          "zero-length UDP ownership");
    unsigned char payload[41];
    for (unsigned n = 0; n < sizeof(payload); n++)
        payload[n] = n * 13 + lane;
    vectors[0] = (struct iovec){payload, 7};
    vectors[1] = (struct iovec){payload + 7, sizeof(payload) - 7};
    check(sendmsg(udp, &message, 0) == sizeof(payload), "UDP vectored output");
    readable(udp, POLLIN);
    int alias = dup(udp);
    check(alias >= 0 && !close(udp), "wire UDP retained alias");
    struct sockaddr_in6 source;
    struct iovec incoming[2] = {{received, 7}, {received + 7, 17}};
    struct msghdr reply = {
        .msg_name = &source, .msg_namelen = sizeof(source), .msg_iov = incoming, .msg_iovlen = 2};
    check(recvmsg(alias, &reply, MSG_PEEK | MSG_TRUNC) == sizeof(payload) &&
              reply.msg_flags == MSG_TRUNC && reply.msg_namelen == sizeof(source),
          "wire UDP peek length");
    reply.msg_namelen = sizeof(source);
    check(recvmsg(alias, &reply, 0) == 24 && reply.msg_flags == MSG_TRUNC && !reply.msg_controllen,
          "wire UDP truncation and consumption");
    struct sockaddr_in6 expected = address(lane, 1, 42000 + lane, 0);
    check(!memcmp(&source, &expected, sizeof(source)), "wire UDP sender ownership");
    for (unsigned n = 0; n < 24; n++)
        check(received[n] == (unsigned char)(payload[n] ^ 0x5a), "wire UDP exact bytes");
    int refused = wire_socket(lane, SOCK_DGRAM, 41010 + lane, 43000 + lane, 0);
    for (unsigned n = 0; n < 13; n++)
        payload[n] = n * 3 + lane;
    check(send(refused, payload, 13, 0) == 13, "quoted UDP output");
    readable(refused, POLLERR);
    check(get(refused, SOL_SOCKET, SO_ERROR) == ECONNREFUSED && !get(refused, SOL_SOCKET, SO_ERROR),
          "wire ICMPv6 port error consumed once");
    int scoped = wire_socket(lane, SOCK_DGRAM, 41020 + lane, 44000 + lane, 1);
    for (unsigned n = 0; n < 7; n++)
        payload[n] = n * 9 + lane;
    struct sockaddr_in6 short_scope = address(lane, 1, 44000 + lane, 1);
    short_scope.sin6_scope_id = indices[1 - lane];
    check(sendto(scoped, payload, 7, 0, (struct sockaddr*)&short_scope, 25 + lane) == 7,
          "scoped UDP output ignores a partial foreign scope");
    struct sockaddr_in6 sender;
    socklen_t size = sizeof(sender);
    readable(scoped, POLLIN);
    check(recvfrom(scoped, received, sizeof(received), 0, (struct sockaddr*)&sender, &size) == 7 &&
              size == sizeof(sender),
          "scoped UDP receive");
    expected = address(lane, 1, 44000 + lane, 1);
    check(!memcmp(&sender, &expected, sizeof(sender)) && !memcmp(received, payload, 7),
          "original scoped UDP bytes and interface");
    close(scoped);
    close(refused);
    close(alias);
    close(raw);
    barrier(lane, 2);
    printf("IPV6_SOCKETS_WIRE_PASS lane=%u raw=1 UDP=4 scoped=1 error=1\n", lane);
}

int main(void) {
    int control = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
    check(control >= 0, "fixture interface control");
    for (unsigned lane = 0; lane < 2; lane++) {
        struct ifreq request = {0};
        snprintf(request.ifr_name, sizeof(request.ifr_name), "eth%u", lane);
        check(!ioctl(control, SIOCGIFINDEX, &request), "fixture interface index");
        indices[lane] = request.ifr_ifindex;
        check(!ioctl(control, SIOCGIFHWADDR, &request), "fixture interface MAC");
        memcpy(macs[lane], request.ifr_hwaddr.sa_data, 6);
        request.ifr_flags = IFF_UP;
        check(!ioctl(control, SIOCSIFFLAGS, &request), "fixture interface up");
        packets[lane] = socket(AF_PACKET, SOCK_RAW | SOCK_NONBLOCK | SOCK_CLOEXEC, htons(3));
        check(packets[lane] >= 0, "fixture Ethernet socket");
        struct sockaddr_ll binding = {
            .sll_family = AF_PACKET, .sll_protocol = htons(3), .sll_ifindex = indices[lane]};
        check(!bind(packets[lane], (struct sockaddr*)&binding, sizeof(binding)),
              "fixture Ethernet binding");
        barrier(lane, 0);
        configure(lane, 1);
        configure(lane, 0);
    }
    abi_contract();
    local_contract();
    for (unsigned lane = 0; lane < 2; lane++)
        wire(lane);
    pid_t child = fork();
    check(child >= 0, "socket permission child");
    if (!child) {
        check(!setuid(65534), "drop raw socket permission");
        check(socket(AF_INET6, SOCK_RAW, IPPROTO_ICMPV6) == -1 && errno == EPERM,
              "raw IPv6 creation permission");
        close(create(SOCK_DGRAM));
        _exit(0);
    }
    int status;
    check(waitpid(child, &status, 0) == child && WIFEXITED(status) && !WEXITSTATUS(status),
          "raw IPv6 permission result");
    close(control);
    for (unsigned lane = 0; lane < 2; lane++)
        close(packets[lane]);
    puts("IPV6_SOCKETS_PASS nics=2 raw=1 UDP=1 loopback=1 faults=2 permissions=1");
}
