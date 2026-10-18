// SPDX-License-Identifier: GPL-3.0-or-later
#define _GNU_SOURCE
#include "ipv4_path_mtu.h"
#include <arpa/inet.h>
#include <errno.h>
#include <net/if.h>
#include <netinet/in.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <unistd.h>

static void require(int value, const char* message) {
    if (!value) {
        fprintf(stderr, "IPV4_PATH_MTU_FAIL %s errno=%d\n", message, errno);
        exit(1);
    }
}

static unsigned checksum(const unsigned char* bytes, size_t length) {
    unsigned total = 0;
    while (length >= 2) {
        total += (unsigned)bytes[0] * 256 + bytes[1];
        bytes += 2;
        length -= 2;
    }
    if (length)
        total += (unsigned)*bytes * 256;
    while (total >> 16)
        total = (total & 65535) + (total >> 16);
    return (~total) & 65535;
}

static void option(int fd, int name, int value) {
    require(setsockopt(fd, IPPROTO_IP, name, &value, sizeof(value)) == 0, "set IP option");
}

static int mtu(int fd) {
    int value = 0;
    socklen_t length = sizeof(value);
    require(getsockopt(fd, IPPROTO_IP, IP_MTU, &value, &length) == 0 && length == sizeof(value),
            "read connected path MTU");
    return value;
}

static int pending_error(int fd) {
    int value = -1;
    socklen_t length = sizeof(value);
    require(getsockopt(fd, SOL_SOCKET, SO_ERROR, &value, &length) == 0, "read socket error");
    return value;
}

static void barrier(int fd, unsigned lane, unsigned test, unsigned phase, unsigned policy) {
    unsigned char bytes[32] = {8, 0, 0, 0, 'P', 'M', test, phase, policy, lane};
    for (unsigned n = 10; n < sizeof(bytes); n++)
        bytes[n] = (unsigned char)(n * 17 + lane * 31);
    unsigned sum = checksum(bytes, sizeof(bytes));
    bytes[2] = sum >> 8;
    bytes[3] = sum;
    require(send(fd, bytes, sizeof(bytes), 0) == sizeof(bytes), "send ordered barrier");
    struct pollfd poller = {.fd = fd, .events = POLLIN};
    require(poll(&poller, 1, 3000) == 1 && (poller.revents & POLLIN), "barrier reply deadline");
    unsigned char reply[128];
    ssize_t length = recv(fd, reply, sizeof(reply), 0);
    bytes[0] = 0;
    bytes[2] = bytes[3] = 0;
    sum = checksum(bytes, sizeof(bytes));
    bytes[2] = sum >> 8;
    bytes[3] = sum;
    require(length == 52 && reply[0] == 0x45 && !checksum(reply, 20) &&
                !memcmp(reply + 20, bytes, sizeof(bytes)),
            "exact host-verified barrier reply");
}

static int data_socket(unsigned lane, unsigned test, unsigned policy, int raw,
                       const struct sockaddr_in* peer) {
    int fd = socket(AF_INET, (raw ? SOCK_RAW : SOCK_DGRAM) | SOCK_CLOEXEC,
                    raw ? IPPROTO_ICMP : IPPROTO_UDP);
    require(fd >= 0, "data socket");
    char name[16];
    snprintf(name, sizeof(name), "eth%u", lane);
    require(setsockopt(fd, SOL_SOCKET, SO_BINDTODEVICE, name, strlen(name) + 1) == 0,
            "bind data interface");
    int value;
    socklen_t length = sizeof(value);
    require(getsockopt(fd, IPPROTO_IP, IP_MTU, &value, &length) == -1 && errno == ENOTCONN,
            "unconnected MTU query");
    option(fd, IP_MTU_DISCOVER, policy);
    if (raw) {
        unsigned filter = ~0u;
        require(setsockopt(fd, 255, 1, &filter, sizeof(filter)) == 0, "filter raw error payload");
    } else {
        struct sockaddr_in local = {.sin_family = AF_INET,
                                    .sin_port = htons(49200 + test * 2 + lane)};
        require(bind(fd, (const struct sockaddr*)&local, sizeof(local)) == 0, "UDP test port");
    }
    require(connect(fd, (const struct sockaddr*)peer, sizeof(*peer)) == 0, "connect data peer");
    return fd;
}

void ipv4_path_mtu_checks(unsigned lane) {
    int control = socket(AF_INET, SOCK_RAW | SOCK_CLOEXEC, IPPROTO_ICMP);
    require(control >= 0, "control socket");
    char name[16], address[32];
    snprintf(name, sizeof(name), "eth%u", lane);
    struct ifreq request = {0};
    snprintf(request.ifr_name, sizeof(request.ifr_name), "%s", name);
    struct sockaddr_in* local = (struct sockaddr_in*)&request.ifr_addr;
    local->sin_family = AF_INET;
    snprintf(address, sizeof(address), "10.23.%u.2", lane + 1);
    require(inet_pton(AF_INET, address, &local->sin_addr) == 1, "local address parse");
    require(ioctl(control, SIOCSIFADDR, &request) == 0, "configure local address");
    require(inet_pton(AF_INET, "255.255.255.0", &local->sin_addr) == 1, "netmask parse");
    require(ioctl(control, SIOCSIFNETMASK, &request) == 0, "configure netmask");
    request.ifr_mtu = 1500;
    require(ioctl(control, SIOCSIFMTU, &request) == 0, "configure device MTU");
    require(ioctl(control, SIOCGIFFLAGS, &request) == 0, "read interface flags");
    request.ifr_flags |= IFF_UP;
    require(ioctl(control, SIOCSIFFLAGS, &request) == 0, "enable interface");
    require(setsockopt(control, SOL_SOCKET, SO_BINDTODEVICE, name, strlen(name) + 1) == 0,
            "control interface");
    unsigned filter = ~1u;
    require(setsockopt(control, 255, 1, &filter, sizeof(filter)) == 0, "control reply filter");
    option(control, IP_MTU_DISCOVER, 3);
    struct sockaddr_in peer = {.sin_family = AF_INET,
                               .sin_port = htons(1),
                               .sin_addr.s_addr = htonl(0x0a170101 + (lane << 8))};
    require(connect(control, (const struct sockaddr*)&peer, sizeof(peer)) == 0, "control peer");
    for (unsigned test = 0; test < 18; test++) {
        unsigned policy = test < 12 ? test % 6 : test < 16 ? 1 : test - 12;
        unsigned announced = test < 12 || test >= 16 ? 900
                             : test == 12            ? 68
                             : test == 13            ? 551
                             : test == 14            ? 552
                                                     : 0;
        int expected = policy >= 4 && test < 16 ? 1500 : announced >= 552 ? (int)announced : 552;
        int raw = test < 6 || test >= 16;
        struct sockaddr_in target = {.sin_family = AF_INET,
                                     .sin_port = htons(48000 + test),
                                     .sin_addr.s_addr =
                                         htonl(0x0a170100 + (lane << 8) + 180 + test)};
        int fd = data_socket(lane, test, policy, raw, &target);
        int observer = -1;
        if (test >= 16) {
            observer = socket(AF_INET, SOCK_RAW | SOCK_CLOEXEC, IPPROTO_ICMP);
            require(observer >= 0, "independent wildcard raw observer");
        }
        require(mtu(fd) == 1500, "fresh destination starts at device MTU");
        unsigned char bytes[1100];
        for (unsigned n = 0; n < sizeof(bytes); n++)
            bytes[n] = (unsigned char)(n * 29 + lane * 53 + test * 97);
        if (raw) {
            bytes[0] = 8;
            bytes[1] = bytes[2] = bytes[3] = 0;
            bytes[4] = 'P';
            bytes[5] = 'D';
            bytes[6] = test;
            bytes[7] = lane;
            unsigned sum = checksum(bytes, sizeof(bytes));
            bytes[2] = sum >> 8;
            bytes[3] = sum;
        }
        barrier(control, lane, test, 0, policy);
        require(send(fd, bytes, sizeof(bytes), 0) == sizeof(bytes), "initial quoted datagram");
        barrier(control, lane, test, 1, policy);
        require(mtu(fd) == 1500 && pending_error(fd) == 0,
                "bad outer checksum cannot learn or fail");
        barrier(control, lane, test, 6, policy);
        int observed = mtu(fd);
        // Another raw listener can learn while this socket ignores the hint.
        // Linux may retain this socket's earlier cached route until a lookup;
        // the fresh cross-protocol query below must expose the learned value.
        require(observed == expected || (test >= 16 && observed == 1500),
                "validated hint updates exact path");
        require(pending_error(fd) == (policy ? EMSGSIZE : 0),
                "discovery error notification policy");
        int shared = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, IPPROTO_UDP);
        require(shared >= 0 &&
                    connect(shared, (const struct sockaddr*)&target, sizeof(target)) == 0,
                "fresh protocol shares learned path");
        require(mtu(shared) == expected && close(shared) == 0, "shared cache query and close");
        for (unsigned changed = 0; changed < 6; changed++) {
            option(fd, IP_MTU_DISCOVER, changed);
            barrier(control, lane, test, 2, changed);
            size_t output_length = changed == 1 && expected == 552 ? 300 : sizeof(bytes);
            ssize_t sent = send(fd, bytes, output_length, 0);
            if (changed == 2 && expected < 1120)
                require(sent == -1 && errno == EMSGSIZE, "DO rejects learned-MTU oversize");
            else
                require(sent == (ssize_t)output_length, "policy output succeeds");
            barrier(control, lane, test, 3, changed);
            require(mtu(fd) == expected, "policy override retains queryable shared limit");
        }
        barrier(control, lane, test, 4, policy);
        require(close(fd) == 0, "close data description");
        if (observer >= 0)
            require(close(observer) == 0, "close independent raw observer");
        printf("IPV4_PATH_MTU_CASE index=%u case=%u mtu=%d\n", lane + 1, test, expected);
    }
    barrier(control, lane, 18, 5, 0);
    require(close(control) == 0, "close control description");
    printf("IPV4_PATH_MTU_PASS index=%u cases=18 policies_each=6\n", lane + 1);
}
