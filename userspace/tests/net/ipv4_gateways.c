// SPDX-License-Identifier: GPL-3.0-or-later
#define _GNU_SOURCE
#include "ipv4_gateways.h"
#include <arpa/inet.h>
#include <errno.h>
#include <net/if.h>
#include <net/route.h>
#include <poll.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <unistd.h>

static void require(int value, const char* message) {
    if (!value) {
        fprintf(stderr, "IPV4_GATEWAY_FAIL %s errno=%d\n", message, errno);
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

static void option(int fd, int level, int name, int value) {
    require(setsockopt(fd, level, name, &value, sizeof(value)) == 0, "set option");
}

static int mtu(int fd) {
    int value;
    socklen_t size = sizeof(value);
    if (getsockopt(fd, IPPROTO_IP, IP_MTU, &value, &size))
        return -errno;
    require(size == sizeof(value), "MTU result size");
    return value;
}

static void queries(int fd, int duplicate, unsigned lane, unsigned kind, unsigned phase, int first,
                    int shared) {
    int observed = mtu(fd), observed_shared = mtu(duplicate);
    printf("IPV4_GATEWAY_MTU index=%u kind=%u phase=%u first=%d shared=%d\n", lane + 1, kind, phase,
           observed, observed_shared);
    require(observed == first && observed_shared == shared, "shared destination MTU ordering");
}

static void address(int fd, const char* name, uint32_t value, unsigned long operation) {
    struct ifreq request = {0};
    snprintf(request.ifr_name, sizeof(request.ifr_name), "%s", name);
    struct sockaddr_in* ip = (struct sockaddr_in*)&request.ifr_addr;
    ip->sin_family = AF_INET;
    ip->sin_addr.s_addr = htonl(value);
    require(ioctl(fd, operation, &request) == 0, "configure address");
}

static void route(int fd, unsigned lane, uint32_t destination, uint32_t mask, uint32_t gateway,
                  int remove) {
    char name[16];
    snprintf(name, sizeof(name), "eth%u", lane);
    struct rtentry request = {0};
    struct sockaddr_in* ip = (struct sockaddr_in*)&request.rt_dst;
    ip->sin_family = AF_INET;
    ip->sin_addr.s_addr = htonl(destination);
    ip = (struct sockaddr_in*)&request.rt_genmask;
    ip->sin_family = AF_INET;
    ip->sin_addr.s_addr = htonl(mask);
    ip = (struct sockaddr_in*)&request.rt_gateway;
    ip->sin_family = AF_INET;
    ip->sin_addr.s_addr = htonl(gateway);
    request.rt_dev = name;
    request.rt_flags = RTF_UP | RTF_GATEWAY | (mask == UINT32_MAX ? RTF_HOST : 0);
    require(ioctl(fd, remove ? SIOCDELRT : SIOCADDRT, &request) == 0, "change gateway route");
}

static void barrier(int control, unsigned lane, unsigned kind, unsigned phase) {
    unsigned char bytes[32] = {8, 0, 0, 0, 'G', 'W', kind, phase, lane};
    for (unsigned n = 9; n < sizeof(bytes); n++)
        bytes[n] = (unsigned char)(n * 17 + lane * 31);
    unsigned sum = checksum(bytes, sizeof(bytes));
    bytes[2] = sum >> 8;
    bytes[3] = sum;
    require(send(control, bytes, sizeof(bytes), 0) == sizeof(bytes), "send wire barrier");
    struct pollfd poller = {.fd = control, .events = POLLIN};
    require(poll(&poller, 1, 3000) == 1 && (poller.revents & POLLIN), "wire barrier deadline");
    unsigned char reply[128];
    ssize_t size = recv(control, reply, sizeof(reply), 0);
    bytes[0] = bytes[2] = bytes[3] = 0;
    sum = checksum(bytes, sizeof(bytes));
    bytes[2] = sum >> 8;
    bytes[3] = sum;
    require(size == 52 && reply[0] == 0x45 && !checksum(reply, 20) &&
                !memcmp(reply + 20, bytes, sizeof(bytes)),
            "host independently verified the wire datagram");
}

static int data_socket(unsigned lane, unsigned kind, const struct sockaddr_in* target,
                       unsigned port) {
    int fd = socket(AF_INET, (kind ? SOCK_RAW : SOCK_DGRAM) | SOCK_CLOEXEC,
                    kind ? IPPROTO_ICMP : IPPROTO_UDP);
    require(fd >= 0, "create data description");
    char name[16];
    snprintf(name, sizeof(name), "eth%u", lane);
    require(setsockopt(fd, SOL_SOCKET, SO_BINDTODEVICE, name, strlen(name) + 1) == 0,
            "bind data device");
    option(fd, IPPROTO_IP, IP_MTU_DISCOVER, 2);
    struct sockaddr_in local = {.sin_family = AF_INET,
                                .sin_port = htons(port),
                                .sin_addr.s_addr = htonl(0x0a170103 + (lane << 8))};
    require(bind(fd, (const struct sockaddr*)&local, sizeof(local)) == 0, "bind local alias");
    require(connect(fd, (const struct sockaddr*)target, sizeof(*target)) == 0,
            "connect data description");
    return fd;
}

static size_t payload(unsigned char* bytes, unsigned lane, unsigned kind, unsigned phase) {
    size_t length = phase ? 32 : 1100;
    for (unsigned n = 0; n < length; n++)
        bytes[n] = (unsigned char)(n * 31 + phase * 17 + lane * 13);
    if (kind) {
        memcpy(bytes, (unsigned char[]){8, 0, 0, 0, 'G', 'W', kind, phase}, 8);
        unsigned sum = checksum(bytes, length);
        bytes[2] = sum >> 8;
        bytes[3] = sum;
    } else
        memcpy(bytes, (unsigned char[]){'G', 'W', lane, kind, phase, 0, 0, 0}, 8);
    return length;
}

static void transmit(int fd, int control, unsigned lane, unsigned kind, unsigned phase) {
    unsigned char bytes[1100];
    size_t length = payload(bytes, lane, kind, phase);
    require(send(fd, bytes, length, 0) == (ssize_t)length, "send through current next hop");
    barrier(control, lane, kind, phase);
}

void ipv4_gateway_checks(unsigned lane) {
    char name[16], label[16];
    snprintf(name, sizeof(name), "eth%u", lane);
    snprintf(label, sizeof(label), "eth%u:gateway", lane);
    uint32_t primary = 0x0a170102 + (lane << 8), network = 0xc0000200 + (lane << 8);
    int control = socket(AF_INET, SOCK_RAW | SOCK_CLOEXEC, IPPROTO_ICMP);
    require(control >= 0, "control description");
    address(control, name, primary, SIOCSIFADDR);
    address(control, name, 0xffffff00, SIOCSIFNETMASK);
    struct ifreq interface = {0};
    strcpy(interface.ifr_name, name);
    require(ioctl(control, SIOCGIFFLAGS, &interface) == 0, "read link flags");
    interface.ifr_flags |= IFF_UP;
    require(ioctl(control, SIOCSIFFLAGS, &interface) == 0, "enable link");
    interface.ifr_mtu = 1500;
    require(ioctl(control, SIOCSIFMTU, &interface) == 0, "restore link MTU");
    require(setsockopt(control, SOL_SOCKET, SO_BINDTODEVICE, name, strlen(name) + 1) == 0,
            "bind control device");
    option(control, 255, 1, (int)~1u);
    option(control, IPPROTO_IP, IP_MTU_DISCOVER, 3);
    struct sockaddr_in remote = {.sin_family = AF_INET, .sin_addr.s_addr = htonl(primary - 1)};
    require(connect(control, (const struct sockaddr*)&remote, sizeof(remote)) == 0,
            "connect control peer");
    for (unsigned kind = 0; kind < 2; kind++) {
        uint32_t target = network + 10 + kind, gateway = primary + 248;
        address(control, label, primary + 1, SIOCSIFADDR);
        address(control, label, 0xffffff00, SIOCSIFNETMASK);
        route(control, lane, network, 0xffffff00, gateway, 0);
        struct sockaddr_in destination = {.sin_family = AF_INET,
                                          .sin_port = htons(48009 + kind),
                                          .sin_addr.s_addr = htonl(target)};
        int fd = data_socket(lane, kind, &destination, 49100 + lane * 4 + kind),
            duplicate = dup(fd);
        require(duplicate >= 0 && mtu(fd) == 1500, "duplicate initial destination");
        transmit(fd, control, lane, kind, 0);
        int error = -1;
        socklen_t size = sizeof(error);
        require(getsockopt(fd, SOL_SOCKET, SO_ERROR, &error, &size) == 0 && error == EMSGSIZE,
                "owned fragmentation hint error");
        queries(fd, duplicate, lane, kind, 0, 900, 900);
        route(control, lane, target, UINT32_MAX, gateway + 1, 0);
        transmit(duplicate, control, lane, kind, 1);
        queries(fd, duplicate, lane, kind, 1, 1500, 1500);
        route(control, lane, target, UINT32_MAX, gateway + 1, 1);
        transmit(fd, control, lane, kind, 2);
        queries(fd, duplicate, lane, kind, 2, 900, 900);
        route(control, lane, network, 0xffffff00, gateway, 1);
        int fresh = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, IPPROTO_UDP);
        require(fresh >= 0 &&
                    connect(fresh, (const struct sockaddr*)&destination, sizeof(destination)) ==
                        -1 &&
                    errno == ENETUNREACH,
                "unbound fresh destination needs a route");
        require(close(fresh) == 0, "close unbound control");
        fresh = data_socket(lane, kind, &destination, 0);
        require(mtu(fresh) == 1500 && close(fresh) == 0, "fresh device-bound fallback");
        transmit(duplicate, control, lane, kind, 3);
        queries(fd, duplicate, lane, kind, 3, 1500, 1500);
        route(control, lane, network, 0xffffff00, gateway, 0);
        transmit(fd, control, lane, kind, 4);
        queries(fd, duplicate, lane, kind, 4, 1500, 1500);
        address(control, label, 0, SIOCSIFADDR);
        unsigned char bytes[32];
        size_t length = payload(bytes, lane, kind, 5);
        require(send(duplicate, bytes, length, 0) == -1 && errno == ENETUNREACH,
                "removed bound source cannot transmit");
        queries(fd, duplicate, lane, kind, 5, kind ? 1500 : -ENOTCONN, -ENOTCONN);
        barrier(control, lane, kind, 5);
        address(control, label, primary + 1, SIOCSIFADDR);
        address(control, label, 0xffffff00, SIOCSIFNETMASK);
        transmit(duplicate, control, lane, kind, 6);
        queries(fd, duplicate, lane, kind, 6, kind ? -ENOTCONN : 1500, kind ? -ENOTCONN : 1500);
        require(connect(fd, (const struct sockaddr*)&destination, sizeof(destination)) == 0,
                "explicit reconnect restores destination");
        queries(fd, duplicate, lane, kind, 7, 1500, 1500);
        barrier(control, lane, kind, 7);
        require(close(fd) == 0 && close(duplicate) == 0, "close shared descriptions");
        route(control, lane, network, 0xffffff00, gateway, 1);
        address(control, label, 0, SIOCSIFADDR);
        printf("IPV4_GATEWAY_ERROR index=%u kind=%u fresh_unbound=101 removed_source=101\n",
               lane + 1, kind);
    }
    require(close(control) == 0, "close control description");
    printf("IPV4_GATEWAY_PASS index=%u protocols=2 datagrams=12\n", lane + 1);
}
