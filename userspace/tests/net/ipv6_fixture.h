// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once
#ifndef IPV6_TEST_LABEL
#define IPV6_TEST_LABEL "IPV6_SOCKETS"
#endif
#ifndef IPV6_BARRIER_PROTOCOL
#define IPV6_BARRIER_PROTOCOL 0x88b7
#define IPV6_BARRIER_MAGIC "IP6S"
#endif
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

static inline void check(int value, const char* reason) {
    if (!value) {
        fprintf(stderr, IPV6_TEST_LABEL "_FAIL %s errno=%d\n", reason, errno);
        exit(1);
    }
}

static inline uint64_t now(void) {
    struct timespec value;
    check(!clock_gettime(CLOCK_MONOTONIC, &value), "monotonic socket clock");
    return (uint64_t)value.tv_sec * 1000000000ULL + value.tv_nsec;
}

static inline struct sockaddr_in6 address(unsigned lane, unsigned host, unsigned port, int link) {
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

static inline struct sockaddr_in6 loopback(unsigned port) {
    struct sockaddr_in6 result = {
        .sin6_family = AF_INET6, .sin6_port = htons(port), .sin6_addr = IN6ADDR_LOOPBACK_INIT};
    return result;
}

static inline int create(int type) {
    int fd = socket(AF_INET6, type | SOCK_CLOEXEC, type == SOCK_RAW ? IPPROTO_ICMPV6 : 0);
    check(fd >= 0, "actual IPv6 socket");
    return fd;
}

static inline void option(int fd, int level, int name, int value) {
    check(!setsockopt(fd, level, name, &value, sizeof(value)), "IPv6 socket option");
}

static inline int get(int fd, int level, int name) {
    int value = -1;
    socklen_t length = sizeof(value);
    check(!getsockopt(fd, level, name, &value, &length) && length == sizeof(value),
          "actual IPv6 socket option result");
    return value;
}

static inline void readable(int fd, int events) {
    struct pollfd item = {.fd = fd, .events = events};
    check(poll(&item, 1, 5000) == 1 && (item.revents & events), "finite socket readiness");
}

static inline void bind_address(int fd, struct sockaddr_in6 value) {
    check(!bind(fd, (struct sockaddr*)&value, sizeof(value)), "IPv6 socket binding");
}

static inline void connect_address(int fd, struct sockaddr_in6 value) {
    check(!connect(fd, (struct sockaddr*)&value, sizeof(value)), "IPv6 socket connection");
}

static inline void receive_exact(int fd, void* bytes, size_t size) {
    readable(fd, POLLIN);
    check(recv(fd, bytes, size, MSG_DONTWAIT) == (ssize_t)size, "exact IPv6 datagram size");
}

static inline void ethernet_barrier(unsigned lane, unsigned phase, unsigned protocol,
                                    const char* magic, const char* label) {
    unsigned char frame[60] = {2, 'I', 'P', '6', lane, 0};
    memcpy(frame + 6, macs[lane], 6);
    frame[12] = protocol >> 8;
    frame[13] = protocol & 255;
    memcpy(frame + 14, magic, 4);
    frame[18] = lane;
    frame[19] = phase;
    struct sockaddr_ll target = {.sll_family = AF_PACKET,
                                 .sll_protocol = htons(protocol),
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
        if (size >= 21 && !memcmp(reply, macs[lane], 6) && reply[12] == protocol >> 8 &&
            reply[13] == (protocol & 255) && !memcmp(reply + 14, magic, 4) && reply[18] == lane &&
            reply[19] == phase && reply[20] == 1)
            break;
        check(now() - began < 10000000000ULL, "finite socket barrier");
    }
    printf("%s_PHASE_PASS lane=%u phase=%u\n", label, lane, phase);
}

static inline void barrier(unsigned lane, unsigned phase) {
    ethernet_barrier(lane, phase, IPV6_BARRIER_PROTOCOL, IPV6_BARRIER_MAGIC, IPV6_TEST_LABEL);
}

static inline void configure(unsigned lane, int link) {
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

static inline int wire_socket(unsigned lane, int type, unsigned local_port, unsigned peer_port,
                              int link) {
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

static inline int fixture_interfaces(void) {
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
    return control;
}
