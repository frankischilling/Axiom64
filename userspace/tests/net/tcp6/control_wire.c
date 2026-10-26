// SPDX-License-Identifier: GPL-3.0-or-later
#define _GNU_SOURCE
#define IPV6_TEST_LABEL "TCP_CONTROL_FAMILY"
#define IPV6_BARRIER_PROTOCOL 0x88c8
#define IPV6_BARRIER_MAGIC "IP6F"
#include "ipv6_fixture.h"
#include <signal.h>

#ifndef WIRE_FAMILY
#define WIRE_FAMILY 0
#endif
#if WIRE_FAMILY < 0 || WIRE_FAMILY > 2
#error unsupported wire family
#endif

static const char* family_name(void) {
    return WIRE_FAMILY == 0 ? "ipv6" : WIRE_FAMILY == 1 ? "mapped" : "ipv4";
}

static void v6_option(int fd, int name, int value) {
    if (WIRE_FAMILY != 2)
        option(fd, IPPROTO_IPV6, name, value);
}

static void configure_ipv4(int control, unsigned lane) {
    struct ifreq request = {0};
    snprintf(request.ifr_name, sizeof(request.ifr_name), "eth%u", lane);
    struct sockaddr_in value = {.sin_family = AF_INET,
                                .sin_addr.s_addr = htonl(0x0a170102 + (lane << 8))};
    memcpy(&request.ifr_addr, &value, sizeof(value));
    check(!ioctl(control, SIOCSIFADDR, &request), "actual IPv4 interface address");
    value.sin_addr.s_addr = htonl(0xffffff00);
    memcpy(&request.ifr_netmask, &value, sizeof(value));
    check(!ioctl(control, SIOCSIFNETMASK, &request), "actual IPv4 interface prefix");
}

static void endpoint(int fd, unsigned lane, unsigned host, unsigned port, int connecting) {
    struct sockaddr_storage storage = {0};
    socklen_t size;
    if (WIRE_FAMILY == 2) {
        struct sockaddr_in value = {.sin_family = AF_INET,
                                    .sin_port = htons(port),
                                    .sin_addr.s_addr = htonl(0x0a170100 + (lane << 8) + host)};
        memcpy(&storage, &value, sizeof(value));
        size = sizeof(value);
    } else {
        struct sockaddr_in6 value = address(lane, host, port, 0);
        if (WIRE_FAMILY == 1) {
            memset(&value.sin6_addr, 0, sizeof(value.sin6_addr));
            value.sin6_addr.s6_addr[10] = value.sin6_addr.s6_addr[11] = 255;
            uint32_t ipv4 = htonl(0x0a170100 + (lane << 8) + host);
            memcpy(value.sin6_addr.s6_addr + 12, &ipv4, sizeof(ipv4));
        }
        memcpy(&storage, &value, sizeof(value));
        size = sizeof(value);
    }
    check(!(connecting ? connect(fd, (struct sockaddr*)&storage, size)
                       : bind(fd, (struct sockaddr*)&storage, size)),
          "actual family endpoint");
}

static void point(unsigned lane, const char* phase, int fd, int hops, int traffic, int tos) {
    int actual_hops = WIRE_FAMILY == 2 ? -2 : get(fd, IPPROTO_IPV6, IPV6_UNICAST_HOPS);
    int actual_class = WIRE_FAMILY == 2 ? -2 : get(fd, IPPROTO_IPV6, IPV6_TCLASS);
    int actual_ttl = get(fd, IPPROTO_IP, IP_TTL);
    int actual_tos = get(fd, IPPROTO_IP, IP_TOS);
    char record[256];
    int length = snprintf(
        record, sizeof(record),
        "TCP_CONTROL_FAMILY_POINT family=%s lane=%u phase=%s hops=%d class=%d ttl=%d tos=%d\n",
        family_name(), lane, phase, actual_hops, actual_class, actual_ttl, actual_tos);
    check(length > 0 && (size_t)length < sizeof(record) && write(1, record, length) == length,
          "complete actual control observation");
    check(actual_hops == (WIRE_FAMILY == 2 ? -2 : hops) &&
              actual_class == (WIRE_FAMILY == 2 ? -2 : traffic) && actual_ttl == 77 &&
              actual_tos == tos,
          "native-derived retained destination state");
}

static void exchange(unsigned lane, int fd, unsigned tag) {
    unsigned char request[16], reply[16];
    for (unsigned at = 0; at < sizeof(request); at++)
        request[at] = (tag * 17 + lane * 53 + at * 7) & 255;
    check(send(fd, request, sizeof(request), 0) == sizeof(request), "complete real stream send");
    size_t copied = 0;
    while (copied < sizeof(reply)) {
        readable(fd, POLLIN);
        ssize_t length = recv(fd, reply + copied, sizeof(reply) - copied, MSG_DONTWAIT);
        check(length > 0, "complete real stream reply");
        copied += (size_t)length;
    }
    check(!memcmp(request, reply, sizeof(request)), "actual returned stream bytes");
}

static void device(unsigned lane, int fd, int bound) {
    char name[16] = {0};
    if (bound)
        snprintf(name, sizeof(name), "eth%u", lane);
    check(!setsockopt(fd, SOL_SOCKET, SO_BINDTODEVICE, name, strlen(name) + 1),
          "actual device update");
}

static void one(unsigned lane) {
    barrier(lane, 1);
    int fd = socket(WIRE_FAMILY == 2 ? AF_INET : AF_INET6, SOCK_STREAM | SOCK_CLOEXEC, IPPROTO_TCP);
    check(fd >= 0, "actual family stream");
    struct timeval timeout = {5, 0};
    check(!setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)), "receive deadline");
    check(!setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout)), "send deadline");
    device(lane, fd, 1);
    if (WIRE_FAMILY == 0)
        option(fd, IPPROTO_IPV6, IPV6_V6ONLY, 1);
    v6_option(fd, IPV6_TCLASS, 171);
    option(fd, IPPROTO_IP, IP_TTL, 77);
    option(fd, IPPROTO_IP, IP_TOS, 47);
    point(lane, "fresh", fd, 64, 168, 44);
    endpoint(fd, lane, 2, 49880 + lane, 0);
    endpoint(fd, lane, 1, 49890 + lane, 1);
    point(lane, "connected", fd, 41, 168, 44);
    exchange(lane, fd, 0);
    v6_option(fd, IPV6_TCLASS, 27);
    point(lane, "class-cleared", fd, 64, 24, 44);
    exchange(lane, fd, 1);
    point(lane, "class-sent", fd, 41, 24, 44);
    option(fd, IPPROTO_IP, IP_TOS, 111);
    point(lane, "tos-cleared", fd, 64, 24, 108);
    exchange(lane, fd, 2);
    point(lane, "tos-sent", fd, 41, 24, 108);
    v6_option(fd, IPV6_UNICAST_HOPS, 0);
    point(lane, "zero-hop", fd, 0, 24, 108);
    exchange(lane, fd, 3);
    v6_option(fd, IPV6_UNICAST_HOPS, 37);
    point(lane, "explicit-hop", fd, 37, 24, 108);
    exchange(lane, fd, 4);
    barrier(lane, 2);
    point(lane, "router-changed-explicit", fd, 37, 24, 108);
    exchange(lane, fd, 5);
    v6_option(fd, IPV6_UNICAST_HOPS, -1);
    point(lane, "default-restored", fd, 51, 24, 108);
    exchange(lane, fd, 6);
    v6_option(fd, IPV6_TCLASS, 24);
    point(lane, "same-class", fd, 51, 24, 108);
    exchange(lane, fd, 7);
    option(fd, IPPROTO_IP, IP_TOS, 108);
    point(lane, "same-tos", fd, 51, 24, 108);
    exchange(lane, fd, 8);
    device(lane, fd, 0);
    point(lane, "device-cleared", fd, 64, 24, 108);
    exchange(lane, fd, 9);
    point(lane, "device-reselected", fd, 51, 24, 108);
    device(lane, fd, 1);
    point(lane, "device-bound", fd, 64, 24, 108);
    exchange(lane, fd, 10);
    v6_option(fd, IPV6_TCLASS, 171);
    v6_option(fd, IPV6_UNICAST_HOPS, 37);
    point(lane, "closing", fd, 37, 168, 108);
    check(!shutdown(fd, SHUT_WR), "actual application half-close");
    readable(fd, POLLIN);
    char byte;
    check(recv(fd, &byte, 1, 0) == 0 && !close(fd), "actual peer EOF and final descriptor release");
    barrier(lane, 3);
}

int main(int argc, char** argv) {
    signal(SIGPIPE, SIG_IGN);
    alarm(120);
    check(argc == 1 || (argc == 2 && !strcmp(argv[1], "--native")), "known wire probe invocation");
    int control = fixture_interfaces();
    for (unsigned lane = 0; lane < 2; lane++)
        configure_ipv4(control, lane);
    check(!close(control), "actual wire interfaces");
    for (unsigned lane = 0; lane < 2; lane++) {
        one(lane);
        check(!close(packets[lane]), "Ethernet control release");
    }
    char complete[256];
    int length = snprintf(complete, sizeof(complete),
                          "TCP_CONTROL_FAMILY_PASS family=%s lanes=2 exchanges_each=11 "
                          "router_hops=41,51 detached_reply=1\n",
                          family_name());
    check(length > 0 && (size_t)length < sizeof(complete) && write(1, complete, length) == length,
          "complete wire probe result");
    return 0;
}
