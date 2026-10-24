// SPDX-License-Identifier: GPL-3.0-or-later
#define _GNU_SOURCE
#include "ipv4_unconfigured.h"
#include "ipv4_query.h"
#include <arpa/inet.h>
#include <errno.h>
#include <net/if.h>
#include <netpacket/packet.h>
#include <poll.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/uio.h>
#include <unistd.h>

static void require(int value, const char* message) {
    if (!value) {
        fprintf(stderr, "IPV4_UNCONFIGURED_FAIL %s errno=%d\n", message, errno);
        exit(1);
    }
}

static unsigned checksum(const unsigned char* bytes, size_t length) {
    unsigned total = 0;
    for (size_t n = 0; n < length; n += 2)
        total += (unsigned)bytes[n] * 256 + (n + 1 < length ? bytes[n + 1] : 0);
    while (total >> 16)
        total = (total & 65535) + (total >> 16);
    return (~total) & 65535;
}

static void address(int control, unsigned lane, uint32_t value) {
    struct ifreq request = {0};
    snprintf(request.ifr_name, sizeof(request.ifr_name), "eth%u", lane);
    struct sockaddr_in* ip = (struct sockaddr_in*)&request.ifr_addr;
    ip->sin_family = AF_INET;
    ip->sin_addr.s_addr = htonl(value);
    require(ioctl(control, SIOCSIFADDR, &request) == 0, "set or remove primary address");
    if (value) {
        ip->sin_addr.s_addr = htonl(0xffffff00);
        require(ioctl(control, SIOCSIFNETMASK, &request) == 0, "restore primary prefix");
    }
}

static void barrier(int fd, const unsigned char* hardware, unsigned lane, unsigned phase,
                    unsigned kind) {
    unsigned char frame[60] = {2, 0x55, 0x4e, 0x43, lane, 0};
    memcpy(frame + 6, hardware, 6);
    frame[12] = 0x88;
    frame[13] = 0xb5;
    memcpy(frame + 14, "UNC1", 4);
    frame[18] = lane;
    frame[19] = phase;
    frame[20] = kind;
    for (unsigned n = 22; n < sizeof(frame); n++)
        frame[n] = (unsigned char)(n * 19 + phase * 7 + kind * 31 + lane);
    require(send(fd, frame, sizeof(frame), 0) == sizeof(frame), "send Ethernet barrier");
    unsigned char reply[128], expected[60];
    memcpy(expected, frame, sizeof(expected));
    memcpy(expected, hardware, 6);
    memcpy(expected + 6, frame, 6);
    expected[21] = 1;
    struct pollfd poller = {.fd = fd, .events = POLLIN};
    require(poll(&poller, 1, 3000) == 1 && (poller.revents & POLLIN), "Ethernet barrier deadline");
    require(recv(fd, reply, sizeof(reply), 0) == sizeof(expected) &&
                !memcmp(reply, expected, sizeof(expected)),
            "host independently verified the unconfigured-interface datagram");
}

static void transmit(int link, const unsigned char* hardware, unsigned lane, unsigned phase,
                     unsigned kind, uint32_t source) {
    unsigned explicit_source = phase == 2 || phase == 4 || phase == 6;
    int fd = socket(AF_INET, (kind ? SOCK_RAW : SOCK_DGRAM) | SOCK_CLOEXEC,
                    kind ? IPPROTO_ICMP : IPPROTO_UDP);
    require(fd >= 0, "create fresh description");
    char name[16];
    snprintf(name, sizeof(name), "eth%u", lane);
    require(setsockopt(fd, SOL_SOCKET, SO_BINDTODEVICE, name, strlen(name) + 1) == 0,
            "bind output device");
    int discovery = 2;
    require(setsockopt(fd, IPPROTO_IP, IP_MTU_DISCOVER, &discovery, sizeof(discovery)) == 0,
            "require whole DF output");
    struct sockaddr_in local = {.sin_family = AF_INET,
                                .sin_port = kind ? 0 : htons(49200 + lane * 32 + phase),
                                .sin_addr.s_addr = explicit_source ? htonl(source) : 0};
    if (!kind || explicit_source)
        require(bind(fd, (struct sockaddr*)&local, sizeof(local)) == 0,
                "bind wildcard or explicit other-interface source");
    struct sockaddr_in remote = {.sin_family = AF_INET,
                                 .sin_port = htons(48010),
                                 .sin_addr.s_addr =
                                     htonl(0xc612010a + (lane << 8) + phase * 2 + kind)};
    require(connect(fd, (struct sockaddr*)&remote, sizeof(remote)) == 0,
            "connect without a matching route");
    int limit = 0;
    socklen_t length = sizeof(limit);
    require(getsockopt(fd, IPPROTO_IP, IP_MTU, &limit, &length) == 0 && length == sizeof(limit) &&
                limit == 1500,
            "fresh bound output retains the device limit");
    length = sizeof(local);
    require(getsockname(fd, (struct sockaddr*)&local, &length) == 0 && length == sizeof(local) &&
                local.sin_family == AF_INET && ntohl(local.sin_addr.s_addr) == source &&
                ntohs(local.sin_port) == (kind ? 1 : 49200 + lane * 32 + phase),
            "fresh description reports the native-selected source and port");
    unsigned char bytes[32];
    for (unsigned n = 0; n < sizeof(bytes); n++)
        bytes[n] = (unsigned char)(n * 23 + phase * 17 + kind * 11 + lane);
    if (kind) {
        memcpy(bytes, (unsigned char[]){8, 0, 0, 0, 'U', 'C', lane, phase}, 8);
        unsigned sum = checksum(bytes, sizeof(bytes));
        bytes[2] = sum >> 8;
        bytes[3] = sum;
    } else
        memcpy(bytes, (unsigned char[]){'U', 'C', lane, phase, kind, 0, 0, 0}, 8);
    require(send(fd, bytes, sizeof(bytes), 0) == sizeof(bytes), "send actual owned datagram");
    barrier(link, hardware, lane, phase, kind);
    printf("IPV4_UNCONFIGURED_SOURCE index=%u phase=%u kind=%u source=%08x explicit=%u mtu=1500\n",
           lane + 1, phase, kind, source, explicit_source);
    require(close(fd) == 0, "close fresh description");
}

static void retained_barrier(int link, const unsigned char* hardware, unsigned lane, unsigned phase,
                             unsigned kind, unsigned method) {
    unsigned char frame[60] = {2, 'R', 'S', 'C', lane, 0};
    memcpy(frame + 6, hardware, 6);
    frame[12] = 0x88;
    frame[13] = 0xb6;
    memcpy(frame + 14, "RSC1", 4);
    frame[18] = lane;
    frame[19] = phase;
    frame[20] = kind;
    frame[21] = method;
    for (unsigned n = 23; n < sizeof(frame); n++)
        frame[n] = (unsigned char)(n * 13 + phase * 7 + kind * 31 + method * 17 + lane);
    require(send(link, frame, sizeof(frame), 0) == sizeof(frame), "retained Ethernet barrier");
    unsigned char reply[128], expected[60];
    memcpy(expected, frame, sizeof(expected));
    memcpy(expected, hardware, 6);
    memcpy(expected + 6, frame, 6);
    expected[22] = 1;
    struct pollfd poller = {.fd = link, .events = POLLIN};
    require(poll(&poller, 1, 3000) == 1 && (poller.revents & POLLIN),
            "retained Ethernet barrier deadline");
    require(recv(link, reply, sizeof(reply), 0) == sizeof(expected) &&
                !memcmp(reply, expected, sizeof(expected)),
            "peer verified actual retained-source output");
}

static int retained_socket(unsigned lane, unsigned kind, unsigned target) {
    unsigned raw = kind == 1;
    int fd = socket(AF_INET, (raw ? SOCK_RAW : SOCK_DGRAM) | SOCK_CLOEXEC,
                    raw ? IPPROTO_ICMP : IPPROTO_UDP);
    require(fd >= 0, "create retained source description");
    char name[16];
    snprintf(name, sizeof(name), "eth%u", lane);
    require(setsockopt(fd, SOL_SOCKET, SO_BINDTODEVICE, name, strlen(name) + 1) == 0,
            "bind retained source device");
    int discovery = 2;
    require(setsockopt(fd, IPPROTO_IP, IP_MTU_DISCOVER, &discovery, sizeof(discovery)) == 0,
            "retained source whole DF output");
    if (!raw) {
        struct sockaddr_in local = {
            .sin_family = AF_INET,
            .sin_port = htons(49300 + lane * 32 + (target == 13 ? 2 : target == 12))};
        require(bind(fd, (struct sockaddr*)&local, sizeof(local)) == 0,
                "bind retained UDP port before automatic source selection");
    }
    struct sockaddr_in remote = {.sin_family = AF_INET,
                                 .sin_port = htons(48010),
                                 .sin_addr.s_addr = htonl(0xc6121f00 + (lane << 8) + target)};
    require(connect(fd, (struct sockaddr*)&remote, sizeof(remote)) == 0,
            "connect retained source description");
    return fd;
}

static void retained_limit(int fd, int expected) {
    int value = 0;
    socklen_t length = sizeof(value);
    errno = 0;
    int result = getsockopt(fd, IPPROTO_IP, IP_MTU, &value, &length);
    require(expected ? result == 0 && length == sizeof(value) && value == expected
                     : result == -1 && errno == ENOTCONN,
            "retained shared destination limit");
}

static void retained_transmit(int fd, int link, const unsigned char* hardware, unsigned lane,
                              unsigned phase, unsigned kind, unsigned method) {
    unsigned char bytes[32];
    for (unsigned n = 0; n < sizeof(bytes); n++)
        bytes[n] = (unsigned char)(n * 23 + phase * 17 + kind * 11 + method * 7 + lane);
    if (kind == 1) {
        memcpy(bytes, (unsigned char[]){8, 0, 0, 0, 'R', 'S', phase, method}, 8);
        unsigned sum = checksum(bytes, sizeof(bytes));
        bytes[2] = sum >> 8;
        bytes[3] = sum;
    } else
        memcpy(bytes, (unsigned char[]){'R', 'S', lane, phase, kind, method, 0, 0}, 8);
    unsigned target = phase == 7 ? 12 : kind == 2 ? 13 : (method == 6 ? 20 : 10) + kind;
    struct sockaddr_in remote = {.sin_family = AF_INET,
                                 .sin_port = htons(48010),
                                 .sin_addr.s_addr = htonl(0xc6121f00 + (lane << 8) + target)};
    struct iovec vectors[2] = {{bytes, 5}, {bytes + 5, sizeof(bytes) - 5}};
    struct msghdr message = {.msg_iov = vectors, .msg_iovlen = 2};
    if (method == 5) {
        message.msg_name = &remote;
        message.msg_namelen = sizeof(remote);
    }
    ssize_t result;
    if (phase == 7 && method == 0)
        result = sendto(fd, bytes, sizeof(bytes), 0, (struct sockaddr*)&remote, sizeof(remote));
    else if (method == 1 || method == 5)
        result = sendmsg(fd, &message, 0);
    else if (method == 2)
        result = write(fd, bytes, sizeof(bytes));
    else if (method == 3)
        result = writev(fd, vectors, 2);
    else if (method == 4 || method == 6)
        result = sendto(fd, bytes, sizeof(bytes), 0, (struct sockaddr*)&remote, sizeof(remote));
    else
        result = send(fd, bytes, sizeof(bytes), 0);
    require(result == sizeof(bytes), "retained source write method");
    retained_barrier(link, hardware, lane, phase, kind, method);
    struct sockaddr_in local = {0};
    socklen_t length = sizeof(local);
    uint32_t selected = phase == 7 ? 0x0a170102 + ((1 - lane) << 8) : 0;
    require(getsockname(fd, (struct sockaddr*)&local, &length) == 0 && length == sizeof(local) &&
                local.sin_family == AF_INET && ntohl(local.sin_addr.s_addr) == selected &&
                ntohs(local.sin_port) ==
                    (kind == 1 ? 1 : 49300 + lane * 32 + (kind == 2 ? 2 : phase == 7)),
            "retained source and port survive every output method");
    printf("IPV4_RETAINED_SOURCE index=%u phase=%u kind=%u method=%u local=%08x\n", lane + 1, phase,
           kind, method, selected);
}

static void retained_checks(int control, const unsigned char* hardware, unsigned lane) {
    int releases = ipv4_query_releases();
    printf("IPV4_RETAINED_QUERY_MODEL index=%u model=%s\n", lane + 1,
           releases ? "release" : "read-only");
    int link = socket(AF_PACKET, SOCK_RAW | SOCK_CLOEXEC, htons(0x88b6));
    struct ifreq request = {0};
    snprintf(request.ifr_name, sizeof(request.ifr_name), "eth%u", lane);
    require(link >= 0 && ioctl(control, SIOCGIFINDEX, &request) == 0,
            "create retained Ethernet observer");
    struct sockaddr_ll bound = {
        .sll_family = AF_PACKET, .sll_protocol = htons(0x88b6), .sll_ifindex = request.ifr_ifindex};
    require(bind(link, (struct sockaddr*)&bound, sizeof(bound)) == 0,
            "bind retained Ethernet observer");
    address(control, lane, 0);
    address(control, 1 - lane, 0);
    int descriptors[3], duplicates[3];
    for (unsigned kind = 0; kind < 3; kind++) {
        descriptors[kind] = retained_socket(lane, kind, kind == 2 ? 13 : 10 + kind);
        duplicates[kind] = dup(descriptors[kind]);
        require(duplicates[kind] >= 0, "duplicate retained source description");
    }
    uint32_t own = 0x0a170102 + (lane << 8), other = 0x0a170102 + ((1 - lane) << 8);
    for (unsigned phase = 0; phase < 6; phase++) {
        if (phase == 1 || phase == 5)
            address(control, 1 - lane, other);
        if (phase == 2)
            address(control, lane, own);
        if (phase == 3)
            address(control, lane, 0);
        if (phase == 4)
            address(control, 1 - lane, 0);
        retained_transmit(descriptors[2], link, hardware, lane, phase, 2, 8);
        retained_transmit(duplicates[2], link, hardware, lane, phase, 2, 9);
        retained_limit(descriptors[0], 1500);
        retained_limit(duplicates[0], 1500);
        for (unsigned kind = 0; kind < 2; kind++)
            for (unsigned method = 0; method < 8; method++)
                retained_transmit(method & 1 ? duplicates[kind] : descriptors[kind], link, hardware,
                                  lane, phase, kind, method);
    }
    int selected = retained_socket(lane, 0, 12), duplicate = dup(selected);
    require(duplicate >= 0, "duplicate selected nonzero source");
    address(control, 1 - lane, 0);
    struct sockaddr_in peer = {.sin_family = AF_INET,
                               .sin_port = htons(48010),
                               .sin_addr.s_addr = htonl(0xc6121f0c + (lane << 8))};
    unsigned char payload[32] = {0};
    struct iovec vector = {payload, sizeof(payload)};
    struct msghdr message = {
        .msg_name = &peer, .msg_namelen = sizeof(peer), .msg_iov = &vector, .msg_iovlen = 1};
    errno = 0;
    require(sendto(selected, payload, sizeof(payload), 0, (struct sockaddr*)&peer, sizeof(peer)) ==
                    -1 &&
                errno == ENETUNREACH,
            "removed selected source named sendto error");
    errno = 0;
    require(sendmsg(duplicate, &message, 0) == -1 && errno == ENETUNREACH,
            "removed selected source named sendmsg error");
    int retired = 0;
    socklen_t length = sizeof(retired);
    require(getsockopt(selected, IPPROTO_IP, IP_MTU, &retired, &length) == 0 &&
                length == sizeof(retired) && (retired == 1500 || (!releases && retired == 68)),
            "named failure preserves the retired connected destination");
    if (!releases) {
        int capacity = 65536;
        require(setsockopt(selected, SOL_SOCKET, SO_SNDBUF, &capacity, sizeof(capacity)) == 0,
                "release the shared destination after a read-only native query");
    }
    retained_limit(duplicate, 0);
    retained_barrier(link, hardware, lane, 6, 0, 0);
    printf("IPV4_RETAINED_REMOVED index=%u sendto=101 sendmsg=101 cache=%d,107\n", lane + 1,
           retired);
    address(control, 1 - lane, other);
    retained_transmit(selected, link, hardware, lane, 7, 0, 0);
    retained_limit(duplicate, 0);
    retained_transmit(duplicate, link, hardware, lane, 7, 0, 7);
    retained_limit(selected, 1500);
    require(close(selected) == 0 && close(duplicate) == 0, "close selected source descriptions");
    for (unsigned kind = 0; kind < 3; kind++)
        require(close(descriptors[kind]) == 0 && close(duplicates[kind]) == 0,
                "close retained zero-source descriptions");
    require(close(link) == 0, "close retained Ethernet observer");
    address(control, lane, own);
    printf("IPV4_RETAINED_PASS index=%u protocols=2 phases=6 methods=8 datagrams=110\n", lane + 1);
}

void ipv4_unconfigured_checks(unsigned lane) {
    int control = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
    int link = socket(AF_PACKET, SOCK_RAW | SOCK_CLOEXEC, htons(0x88b5));
    require(control >= 0 && link >= 0, "create configuration and Ethernet descriptions");
    struct ifreq request = {0};
    snprintf(request.ifr_name, sizeof(request.ifr_name), "eth%u", lane);
    require(ioctl(control, SIOCGIFINDEX, &request) == 0, "find actual output device");
    struct sockaddr_ll bound = {
        .sll_family = AF_PACKET, .sll_protocol = htons(0x88b5), .sll_ifindex = request.ifr_ifindex};
    require(bind(link, (struct sockaddr*)&bound, sizeof(bound)) == 0,
            "bind Ethernet barrier device");
    require(ioctl(control, SIOCGIFHWADDR, &request) == 0, "read actual output hardware address");
    unsigned char hardware[6];
    memcpy(hardware, request.ifr_hwaddr.sa_data, sizeof(hardware));
    uint32_t own = 0x0a170102 + (lane << 8), other = 0x0a170102 + ((1 - lane) << 8);
    address(control, lane, 0);
    address(control, 1 - lane, 0);
    for (unsigned phase = 0; phase < 7; phase++) {
        if (phase == 1)
            address(control, 1 - lane, other);
        if (phase == 3)
            address(control, lane, own);
        if (phase == 5)
            address(control, lane, 0);
        uint32_t source = phase == 0 ? 0 : phase == 3 ? own : other;
        for (unsigned kind = 0; kind < 2; kind++)
            transmit(link, hardware, lane, phase, kind, source);
    }
    address(control, lane, own);
    retained_checks(control, hardware, lane);
    require(close(link) == 0 && close(control) == 0,
            "close configuration and Ethernet descriptions");
    printf("IPV4_UNCONFIGURED_PASS index=%u protocols=2 datagrams=14\n", lane + 1);
}
