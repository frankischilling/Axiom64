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
#include <sys/time.h>
#include <unistd.h>

static unsigned snapshots, queries, exchanges, copies;

static void require(int condition, const char* operation) {
    if (!condition) {
        printf("TCP_CONTROL_STATE_FAIL operation=%s errno=%d\n", operation, errno);
        exit(1);
    }
}

static int stream(int family) {
    int fd = socket(family, SOCK_STREAM, IPPROTO_TCP);
    require(fd >= 0, "create stream");
    struct timeval timeout = {5, 0};
    require(!setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)), "receive bound");
    require(!setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout)), "send bound");
    return fd;
}

static void set(int fd, int level, int option, int value) {
    require(!setsockopt(fd, level, option, &value, sizeof(value)), "set control");
}

static int get(int fd, int level, int option) {
    int value = -1;
    socklen_t length = sizeof(value);
    require(!getsockopt(fd, level, option, &value, &length) && length == sizeof(value),
            "get control");
    queries++;
    return value;
}

static void point(const char* family, const char* phase, const char* role, int fd, int ipv6,
                  int hops, int traffic, int ttl, int tos) {
    int actual_hops = ipv6 ? get(fd, IPPROTO_IPV6, IPV6_UNICAST_HOPS) : -2;
    int actual_class = ipv6 ? get(fd, IPPROTO_IPV6, IPV6_TCLASS) : -2;
    int actual_ttl = get(fd, IPPROTO_IP, IP_TTL);
    int actual_tos = get(fd, IPPROTO_IP, IP_TOS);
    int only = ipv6 ? get(fd, IPPROTO_IPV6, IPV6_V6ONLY) : -2;
    int expected_only = ipv6 ? 0 : -2;
    if (!strcmp(family, "ipv6") &&
        (!strcmp(role, "accepted") ||
         (!strcmp(role, "listener") && !strcmp(phase, "listener-updated"))))
        expected_only = 1;
    char record[256];
    int size = snprintf(
        record, sizeof(record),
        "TCP_CONTROL_STATE family=%s phase=%s role=%s hops=%d class=%d ttl=%d tos=%d only=%d\n",
        family, phase, role, actual_hops, actual_class, actual_ttl, actual_tos, only);
    require(size > 0 && (size_t)size < sizeof(record) &&
                write(STDOUT_FILENO, record, (size_t)size) == size,
            "complete control-state observation");
    require(actual_hops == (ipv6 ? hops : -2) && actual_class == (ipv6 ? traffic : -2) &&
                actual_ttl == ttl && actual_tos == tos && only == expected_only,
            "retained control state");
    snapshots++;
}

static void exchange(int client, int accepted) {
    uint8_t request = 0x31 + exchanges, response = 0;
    require(send(client, &request, 1, 0) == 1, "client stream byte");
    require(recv(accepted, &response, 1, 0) == 1 && response == request, "accepted stream byte");
    request ^= 0x5a;
    require(send(accepted, &request, 1, 0) == 1, "accepted stream response");
    require(recv(client, &response, 1, 0) == 1 && response == request, "client stream response");
    exchanges++;
}

static void lifecycle(unsigned kind) {
    int ipv6 = kind != 2, family = ipv6 ? AF_INET6 : AF_INET;
    const char* label = kind == 0 ? "ipv6" : kind == 1 ? "mapped" : "ipv4";
    int listener = stream(family), client = stream(family);
    point(label, "fresh", "listener", listener, ipv6, 64, 0, 64, 0);
    point(label, "fresh", "client", client, ipv6, 64, 0, 64, 0);
    if (ipv6) {
        set(listener, IPPROTO_IPV6, IPV6_V6ONLY, 0);
        set(listener, IPPROTO_IPV6, IPV6_UNICAST_HOPS, 37);
        set(listener, IPPROTO_IPV6, IPV6_TCLASS, 171);
        set(client, IPPROTO_IPV6, IPV6_UNICAST_HOPS, -1);
        set(client, IPPROTO_IPV6, IPV6_TCLASS, 239);
    }
    set(listener, IPPROTO_IP, IP_TTL, 77);
    set(listener, IPPROTO_IP, IP_TOS, 47);
    set(client, IPPROTO_IP, IP_TTL, 91);
    set(client, IPPROTO_IP, IP_TOS, 87);
    point(label, "configured", "listener", listener, ipv6, 37, 168, 77, 44);
    point(label, "configured", "client", client, ipv6, 64, 236, 91, 84);
    struct sockaddr_storage address = {0};
    socklen_t length;
    if (ipv6) {
        struct sockaddr_in6* value = (struct sockaddr_in6*)&address;
        value->sin6_family = AF_INET6;
        require(inet_pton(AF_INET6, kind == 1 ? "::ffff:127.0.0.1" : "::1", &value->sin6_addr) == 1,
                "IPv6 target");
        length = sizeof(*value);
    } else {
        struct sockaddr_in* value = (struct sockaddr_in*)&address;
        value->sin_family = AF_INET;
        value->sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        length = sizeof(*value);
    }
    require(!bind(listener, (struct sockaddr*)&address, length) && !listen(listener, 4),
            "bind and listen");
    require(!getsockname(listener, (struct sockaddr*)&address, &length), "listener address");
    require(!connect(client, (struct sockaddr*)&address, length), "connect client");
    int accepted = accept(listener, NULL, NULL);
    require(accepted >= 0, "accept client");
    point(label, "connected", "client", client, ipv6, 64, 236, 91, 84);
    point(label, "connected", "accepted", accepted, ipv6, 37, 168, 77, 44);
    if (ipv6) {
        set(listener, IPPROTO_IPV6, IPV6_UNICAST_HOPS, 55);
        set(listener, IPPROTO_IPV6, IPV6_TCLASS, 207);
    }
    set(listener, IPPROTO_IP, IP_TTL, 79);
    set(listener, IPPROTO_IP, IP_TOS, 103);
    point(label, "listener-updated", "listener", listener, ipv6, 55, 204, 79, 100);
    point(label, "listener-updated", "accepted", accepted, ipv6, 37, 168, 77, 44);
    if (ipv6)
        set(client, IPPROTO_IPV6, IPV6_TCLASS, 27);
    point(label, "class-updated", "client", client, ipv6, 64, 24, 91, 84);
    exchange(client, accepted);
    point(label, "class-sent", "client", client, ipv6, 64, 24, 91, 84);
    if (ipv6)
        set(client, IPPROTO_IPV6, IPV6_UNICAST_HOPS, 0);
    point(label, "zero-hop", "client", client, ipv6, 0, 24, 91, 84);
    exchange(client, accepted);
    if (ipv6)
        set(client, IPPROTO_IPV6, IPV6_UNICAST_HOPS, -1);
    point(label, "default-restored", "client", client, ipv6, 64, 24, 91, 84);
    set(client, IPPROTO_IP, IP_TOS, 111);
    point(label, "tos-updated", "client", client, ipv6, 64, 24, 91, 108);
    exchange(client, accepted);
    set(client, IPPROTO_IP, IP_TTL, 93);
    point(label, "ttl-updated", "client", client, ipv6, 64, 24, 93, 108);
    struct sockaddr reset = {.sa_family = AF_UNSPEC};
    require(!connect(client, &reset, sizeof(reset)), "disconnect client");
    point(label, "disconnected", "client", client, ipv6, 64, 24, 93, 108);
    require(!close(accepted), "close old accepted");
    require(!connect(client, (struct sockaddr*)&address, length), "reconnect client");
    accepted = accept(listener, NULL, NULL);
    require(accepted >= 0, "accept successor");
    point(label, "reconnected", "client", client, ipv6, 64, 24, 93, 108);
    point(label, "reconnected", "accepted", accepted, ipv6, 55, 204, 79, 100);
    exchange(client, accepted);
    require(!close(client) && !close(accepted) && !close(listener), "close descriptions");
}

static void tos_copies(int family) {
    const uint32_t sizes[] = {0, 1, 2, 3, 4, 5, UINT32_MAX, UINT32_C(0x80000000)};
    const uint8_t input[8] = {0xab, 0xcd, 0xef, 0x12};
    for (unsigned n = 0; n < sizeof(sizes) / sizeof(*sizes); n++) {
        for (unsigned null = 0; null < 2; null++) {
            int fd = stream(family);
            errno = 0;
            long result =
                syscall(SYS_setsockopt, fd, IPPROTO_IP, IP_TOS, null ? NULL : input, sizes[n]);
            int expected = (int32_t)sizes[n] < 0 ? EINVAL : sizes[n] && null ? EFAULT : 0;
            require((result < 0 ? errno : 0) == expected, "TOS setter copy result");
            require(get(fd, IPPROTO_IP, IP_TOS) == (!expected && sizes[n] ? 168 : 0),
                    "TOS setter state");
            require(!close(fd), "TOS setter descriptor");
            copies++;
        }
    }
    int fd = stream(family);
    set(fd, IPPROTO_IP, IP_TOS, 171);
    for (unsigned n = 0; n < sizeof(sizes) / sizeof(*sizes); n++) {
        uint8_t actual[8], expected[8];
        memset(actual, 0xa5, sizeof(actual));
        memset(expected, 0xa5, sizeof(expected));
        socklen_t length = sizes[n];
        int value = 168, failed = (int32_t)length < 0;
        unsigned selected = failed ? length : length >= 4 ? 4 : length ? 1 : 0;
        if (!failed)
            memcpy(expected, &value, selected);
        errno = 0;
        long result = syscall(SYS_getsockopt, fd, IPPROTO_IP, IP_TOS, actual, &length);
        require((result < 0 ? errno : 0) == (failed ? EINVAL : 0), "TOS getter copy result");
        require(length == selected && !memcmp(actual, expected, sizeof(actual)),
                "TOS getter length and guard");
        copies++;
    }
    uint32_t shared = 4;
    require(!syscall(SYS_getsockopt, fd, IPPROTO_IP, IP_TOS, &shared, &shared) && shared == 168,
            "TOS getter publication order");
    require(!close(fd), "TOS getter descriptor");
    copies++;
}

int main(void) {
    setvbuf(stdout, NULL, _IONBF, 0);
    alarm(60);
    for (unsigned family = 0; family < 3; family++)
        lifecycle(family);
    tos_copies(AF_INET);
    tos_copies(AF_INET6);
    char record[160];
    int size = snprintf(record, sizeof(record),
                        "TCP_CONTROL_STATE_PASS loopback_only=1 snapshots=%u queries=%u "
                        "exchanges=%u copy_cases=%u\n",
                        snapshots, queries, exchanges, copies);
    require(size > 0 && (size_t)size < sizeof(record) &&
                write(STDOUT_FILENO, record, (size_t)size) == size,
            "complete control-state result");
    return 0;
}
