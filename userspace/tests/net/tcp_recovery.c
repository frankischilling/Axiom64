// SPDX-License-Identifier: GPL-3.0-or-later
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <net/if.h>
#include <net/route.h>
#include <netinet/tcp.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>

#define CHECK(x)                                                                                   \
    do {                                                                                           \
        if (!(x)) {                                                                                \
            fprintf(stderr, "TCP_RECOVERY_FAIL line=%d errno=%d\n", __LINE__, errno);              \
            exit(1);                                                                               \
        }                                                                                          \
    } while (0)

static int control, streams[2];
static unsigned sent[2], received[2];

static uint64_t milliseconds(void) {
    struct timespec now;
    CHECK(clock_gettime(CLOCK_MONOTONIC, &now) == 0);
    return (uint64_t)now.tv_sec * 1000 + now.tv_nsec / 1000000;
}

static unsigned char pattern(unsigned lane, unsigned at) {
    return (unsigned char)((at * 29) ^ (at >> 7) ^ (lane * 53));
}

static void administrative(unsigned lane, int up) {
    struct ifreq request = {0};
    snprintf(request.ifr_name, sizeof(request.ifr_name), "eth%u", lane);
    CHECK(ioctl(control, SIOCGIFFLAGS, &request) == 0);
    if (up)
        request.ifr_flags |= IFF_UP;
    else
        request.ifr_flags &= ~IFF_UP;
    CHECK(ioctl(control, SIOCSIFFLAGS, &request) == 0);
    printf("TCP_RECOVERY_FLAGS lane=%u up=%d\n", lane, up);
}

static void configure(void) {
    for (unsigned lane = 0; lane < 2; lane++) {
        struct ifreq request = {0};
        snprintf(request.ifr_name, sizeof(request.ifr_name), "eth%u", lane);
        struct sockaddr_in value = {.sin_family = AF_INET,
                                    .sin_addr.s_addr = htonl(0x0a170102 + (lane << 8))};
        memcpy(&request.ifr_addr, &value, sizeof(value));
        CHECK(ioctl(control, SIOCSIFADDR, &request) == 0);
        value.sin_addr.s_addr = htonl(0xffffff00);
        memcpy(&request.ifr_netmask, &value, sizeof(value));
        CHECK(ioctl(control, SIOCSIFNETMASK, &request) == 0);
        administrative(lane, 1);
    }
}

static void transmit(unsigned lane, unsigned length) {
    unsigned char bytes[512];
    CHECK(length <= sizeof(bytes));
    for (unsigned at = 0; at < length; at++)
        bytes[at] = pattern(lane, sent[lane] + at);
    errno = 0;
    ssize_t result = send(streams[lane], bytes, length, MSG_NOSIGNAL);
    printf("TCP_RECOVERY_SEND lane=%u requested=%u result=%zd errno=%d\n", lane, length, result,
           errno);
    CHECK(result == (ssize_t)length);
    sent[lane] += length;
}

static void receive_bytes(unsigned lane, unsigned length) {
    unsigned char bytes[512];
    unsigned total = 0;
    while (total < length) {
        errno = 0;
        ssize_t result = recv(streams[lane], bytes, length - total, 0);
        if (result <= 0)
            printf("TCP_RECOVERY_RECV lane=%u result=%zd errno=%d\n", lane, result, errno);
        CHECK(result > 0 && result <= (ssize_t)(length - total));
        for (ssize_t at = 0; at < result; at++)
            CHECK(bytes[at] == pattern(lane, received[lane] + (unsigned)at));
        received[lane] += (unsigned)result;
        total += (unsigned)result;
    }
}

static void netmask(unsigned lane, uint32_t mask) {
    struct ifreq request = {0};
    snprintf(request.ifr_name, sizeof(request.ifr_name), "eth%u", lane);
    struct sockaddr_in value = {.sin_family = AF_INET, .sin_addr.s_addr = htonl(mask)};
    memcpy(&request.ifr_netmask, &value, sizeof(value));
    CHECK(ioctl(control, SIOCSIFNETMASK, &request) == 0);
    CHECK(ioctl(control, SIOCGIFNETMASK, &request) == 0);
    CHECK(((struct sockaddr_in*)&request.ifr_netmask)->sin_addr.s_addr == htonl(mask));
    printf("TCP_RECOVERY_MASK lane=%u value=%08x\n", lane, mask);
}

static void host_route(unsigned lane, unsigned operation) {
    struct rtentry route = {0};
    struct sockaddr_in destination = {.sin_family = AF_INET,
                                      .sin_addr.s_addr = htonl(0x0a170101 + (lane << 8))};
    struct sockaddr_in mask = {.sin_family = AF_INET, .sin_addr.s_addr = htonl(0xffffffff)};
    struct sockaddr_in gateway = {.sin_family = AF_INET};
    memcpy(&route.rt_dst, &destination, sizeof(destination));
    memcpy(&route.rt_genmask, &mask, sizeof(mask));
    memcpy(&route.rt_gateway, &gateway, sizeof(gateway));
    route.rt_flags = RTF_UP | RTF_HOST;
    char name[16];
    snprintf(name, sizeof(name), "eth%u", lane);
    route.rt_dev = name;
    CHECK(ioctl(control, operation, &route) == 0);
    printf("TCP_RECOVERY_HOST_ROUTE lane=%u add=%u\n", lane, operation == SIOCADDRT);
}

static void route_loss(unsigned lane, unsigned mode) {
    if (mode)
        host_route(lane, SIOCDELRT);
    else
        netmask(lane, 0xffffffff);
    struct sockaddr_in peer = {.sin_family = AF_INET,
                               .sin_port = htons(49000 + lane),
                               .sin_addr.s_addr = htonl(0x0a170101 + (lane << 8))};
    int fresh = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK, 0);
    CHECK(fresh >= 0);
    CHECK(connect(fresh, (struct sockaddr*)&peer, sizeof(peer)) == -1 && errno == ENETUNREACH);
    CHECK(close(fresh) == 0);
    printf("TCP_RECOVERY_ROUTE_FRESH lane=%u mode=%u errno=101\n", lane, mode);
    transmit(lane, 512);
    CHECK(usleep(200000) == 0);
    int error = -1, available = -1;
    socklen_t length = sizeof(error);
    CHECK(getsockopt(streams[lane], SOL_SOCKET, SO_ERROR, &error, &length) == 0);
    CHECK(ioctl(streams[lane], FIONREAD, &available) == 0 && available >= 0 && available <= 512);
    printf("TCP_RECOVERY_ROUTE_ERROR lane=%u mode=%u error=%d available=%d\n", lane, mode, error,
           available);
    transmit(1 - lane, 512);
    receive_bytes(1 - lane, 512);
    if (mode)
        host_route(lane, SIOCADDRT);
    else
        netmask(lane, 0xffffff00);
    receive_bytes(lane, 512);
    CHECK(error == 0 || error == ENETUNREACH || error == EHOSTUNREACH);
    printf("TCP_RECOVERY_ROUTE_PASS lane=%u mode=%u retained=512 companion=512\n", lane, mode);
}

static void carrier_loss(unsigned lane) {
    struct ifreq request = {0};
    snprintf(request.ifr_name, sizeof(request.ifr_name), "eth%u", lane);
    CHECK(ioctl(control, SIOCGIFFLAGS, &request) == 0 && (request.ifr_flags & IFF_UP));
    printf("TCP_RECOVERY_CARRIER_REQUEST lane=%u up=0\n", lane);
    // The host withholds this exact companion echo until physical loss is
    // confirmed. Receiving it acknowledges the transition without a sleep.
    transmit(1 - lane, 512);
    receive_bytes(1 - lane, 512);
    transmit(lane, 512);
    int error = -1, available = -1;
    socklen_t length = sizeof(error);
    CHECK(getsockopt(streams[lane], SOL_SOCKET, SO_ERROR, &error, &length) == 0);
    CHECK(ioctl(streams[lane], FIONREAD, &available) == 0);
    CHECK(ioctl(control, SIOCGIFFLAGS, &request) == 0 && (request.ifr_flags & IFF_UP));
    printf("TCP_RECOVERY_CARRIER_HELD lane=%u error=%d available=%d flags=%x\n", lane, error,
           available, (unsigned short)request.ifr_flags);
    CHECK(error == 0 && available == 0);
    printf("TCP_RECOVERY_CARRIER_REQUEST lane=%u up=1\n", lane);
    receive_bytes(lane, 512);
    CHECK(ioctl(control, SIOCGIFFLAGS, &request) == 0 && (request.ifr_flags & IFF_UP));
    printf("TCP_RECOVERY_CARRIER_PASS lane=%u retained=512 companion=512 administrative_up=1\n",
           lane);
}

int main(int argc, char** argv) {
    setbuf(stdout, NULL);
    signal(SIGPIPE, SIG_IGN);
    alarm(60);
    control = socket(AF_INET, SOCK_DGRAM, 0);
    CHECK(control >= 0);
    if (argc == 1)
        configure();
    else
        CHECK(argc == 2 && !strcmp(argv[1], "--native"));
    puts("TCP_RECOVERY_CONFIG_PASS nics=2");
    for (unsigned lane = 0; lane < 2; lane++) {
        streams[lane] = socket(AF_INET, SOCK_STREAM, 0);
        CHECK(streams[lane] >= 0);
        int one = 1;
        struct timeval timeout = {5, 0};
        CHECK(setsockopt(streams[lane], SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) == 0);
        CHECK(setsockopt(streams[lane], IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one)) == 0);
        struct sockaddr_in local = {.sin_family = AF_INET,
                                    .sin_port = htons(48000 + lane),
                                    .sin_addr.s_addr = htonl(0x0a170102 + (lane << 8))};
        struct sockaddr_in peer = {.sin_family = AF_INET,
                                   .sin_port = htons(49000 + lane),
                                   .sin_addr.s_addr = htonl(0x0a170101 + (lane << 8))};
        CHECK(bind(streams[lane], (struct sockaddr*)&local, sizeof(local)) == 0);
        CHECK(connect(streams[lane], (struct sockaddr*)&peer, sizeof(peer)) == 0);
        transmit(lane, 16);
        receive_bytes(lane, 16);
    }
    for (unsigned lane = 0; lane < 2; lane++) {
        administrative(lane, 0);
        transmit(lane, 512);
        CHECK(usleep(200000) == 0);
        int error = -1;
        socklen_t length = sizeof(error);
        CHECK(getsockopt(streams[lane], SOL_SOCKET, SO_ERROR, &error, &length) == 0);
        printf("TCP_RECOVERY_ERROR lane=%u error=%d\n", lane, error);
        transmit(1 - lane, 512);
        receive_bytes(1 - lane, 512);
        administrative(lane, 1);
        receive_bytes(lane, 512);
        CHECK(error == 0);
        printf("TCP_RECOVERY_RECOVERED lane=%u retained=512 companion=512\n", lane);
    }
    for (unsigned lane = 0; lane < 2; lane++) {
        printf("TCP_RECOVERY_QUEUE_ARM lane=%u\n", lane);
        unsigned char command;
        CHECK(recv(streams[lane], &command, 1, 0) == 1 && command == 'Q');
        transmit(lane, 512);
        CHECK(usleep(100000) == 0);
        printf("TCP_RECOVERY_QUEUE_HELD lane=%u\n", lane);
        // Confirm actual pending output before changing the interface.
        CHECK(recv(streams[lane], &command, 1, 0) == 1 && command == 'H');
        administrative(lane, 0);
        CHECK(usleep(200000) == 0);
        int error = -1;
        socklen_t length = sizeof(error);
        CHECK(getsockopt(streams[lane], SOL_SOCKET, SO_ERROR, &error, &length) == 0);
        printf("TCP_RECOVERY_QUEUE_ERROR lane=%u error=%d\n", lane, error);
        transmit(1 - lane, 512);
        receive_bytes(1 - lane, 512);
        administrative(lane, 1);
        receive_bytes(lane, 512);
        // A retransmit during the native outage can leave an advisory route error.
        CHECK(error == 0 || error == ENETUNREACH);
        printf("TCP_RECOVERY_QUEUE_PASS lane=%u retained=512 companion=512\n", lane);
    }
    for (unsigned lane = 0; lane < 2; lane++) {
        printf("TCP_RECOVERY_EXPIRY_ARM lane=%u\n", lane);
        unsigned char command;
        CHECK(recv(streams[lane], &command, 1, 0) == 1 && command == 'Q');
        transmit(lane, 512);
        CHECK(usleep(100000) == 0);
        printf("TCP_RECOVERY_EXPIRY_HELD lane=%u\n", lane);
        CHECK(recv(streams[lane], &command, 1, 0) == 1 && command == 'H');
        uint64_t start = milliseconds();
        // Keep the interface up and outlast the owned IPv4 copy's full lifetime.
        CHECK(usleep(4500000) == 0);
        uint64_t elapsed = milliseconds() - start;
        CHECK(elapsed >= 4500);
        int error = -1;
        socklen_t length = sizeof(error);
        CHECK(getsockopt(streams[lane], SOL_SOCKET, SO_ERROR, &error, &length) == 0);
        printf("TCP_RECOVERY_EXPIRY_ERROR lane=%u error=%d\n", lane, error);
        transmit(1 - lane, 512);
        receive_bytes(1 - lane, 512);
        printf("TCP_RECOVERY_EXPIRY_RELEASE lane=%u elapsed_ms=%llu\n", lane,
               (unsigned long long)elapsed);
        receive_bytes(lane, 512);
        CHECK(error == 0);
        printf("TCP_RECOVERY_EXPIRY_PASS lane=%u retained=512 companion=512\n", lane);
    }
    for (unsigned lane = 0; lane < 2; lane++)
        route_loss(lane, 0);
    for (unsigned lane = 0; lane < 2; lane++) {
        netmask(lane, 0xffffffff);
        host_route(lane, SIOCADDRT);
        transmit(lane, 64);
        receive_bytes(lane, 64);
    }
    for (unsigned lane = 0; lane < 2; lane++)
        route_loss(lane, 1);
    for (unsigned lane = 0; lane < 2; lane++) {
        host_route(lane, SIOCDELRT);
        netmask(lane, 0xffffff00);
    }
    for (unsigned lane = 0; lane < 2; lane++)
        carrier_loss(lane);
    for (unsigned lane = 0; lane < 2; lane++) {
        CHECK(shutdown(streams[lane], SHUT_WR) == 0);
        unsigned char byte;
        CHECK(recv(streams[lane], &byte, 1, 0) == 0 && close(streams[lane]) == 0);
        CHECK(sent[lane] == 6224 && received[lane] == 6224);
    }
    CHECK(close(control) == 0);
    CHECK(usleep(100000) == 0);
    puts("TCP_RECOVERY_PASS nics=2 exact_each=6224 queued_each=512 expiry_ms=4500 routes_each=2 "
         "carrier_each=1");
    return 0;
}
