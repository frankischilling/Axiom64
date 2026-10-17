// SPDX-License-Identifier: GPL-3.0-or-later
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <netpacket/packet.h>
#include <pthread.h>
#include <stdatomic.h>
#include <net/if.h>
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

enum { transfer_bytes = 4096 };

static uint8_t pattern(size_t at, unsigned lane, unsigned scenario, unsigned direction) {
    return (uint8_t)((at * 29) ^ (at >> 7) ^ (lane * 53) ^ (scenario * 97) ^ (direction * 41));
}

static uint64_t milliseconds(void) {
    struct timespec now;
    if (clock_gettime(CLOCK_MONOTONIC, &now))
        exit(2);
    return (uint64_t)now.tv_sec * 1000 + now.tv_nsec / 1000000;
}

#define CHECK(value)                                                                               \
    do {                                                                                           \
        if (!(value)) {                                                                            \
            fprintf(stderr, "TCP_FAULT_FAIL observer line=%d errno=%d\n", __LINE__, errno);        \
            exit(1);                                                                               \
        }                                                                                          \
    } while (0)
static int native;
static atomic_int stop;
static int observers[2];
static unsigned indices[2], observed[2], ipv4_frames[2];
static pthread_t observer;

static void drain(unsigned lane) {
    for (;;) {
        uint8_t frame[2048];
        struct sockaddr_ll source;
        socklen_t size = sizeof(source);
        ssize_t length = recvfrom(observers[lane], frame, sizeof(frame), MSG_DONTWAIT,
                                  (struct sockaddr*)&source, &size);
        if (length < 0) {
            CHECK(errno == EAGAIN);
            return;
        }
        CHECK(length >= 14 && source.sll_ifindex == (int)indices[lane]);
        observed[lane]++;
        if (frame[12] != 8 || frame[13] != 0)
            continue;
        uint64_t digest = UINT64_C(0xcbf29ce484222325);
        for (ssize_t at = 0; at < length; at++)
            digest = (digest ^ frame[at]) * UINT64_C(0x100000001b3);
        ipv4_frames[lane]++;
        printf("PMTU_FRAME lane=%u index=%u length=%zd kind=%u hash=%016llx monotonic_ms=%llu\n",
               lane, indices[lane], length, source.sll_pkttype, (unsigned long long)digest,
               (unsigned long long)milliseconds());
    }
}

static void* collect(void* unused) {
    (void)unused;
    while (!atomic_load(&stop)) {
        drain(0);
        drain(1);
        CHECK(usleep(2000) == 0);
    }
    drain(0);
    drain(1);
    return NULL;
}

static void capture_start(void) {
    for (unsigned lane = 0; lane < 2; lane++) {
        char name[16];
        snprintf(name, sizeof(name), "eth%u", lane);
        indices[lane] = if_nametoindex(name);
        unsigned protocol = native ? 3 : 0x800;
        observers[lane] =
            socket(AF_PACKET, SOCK_RAW | SOCK_NONBLOCK | SOCK_CLOEXEC, htons(protocol));
        int capacity = 131072, actual;
        socklen_t capacity_size = sizeof(actual);
        CHECK(observers[lane] >= 0 &&
              setsockopt(observers[lane], SOL_SOCKET, SO_RCVBUF, &capacity, sizeof(capacity)) ==
                  0 &&
              getsockopt(observers[lane], SOL_SOCKET, SO_RCVBUF, &actual, &capacity_size) == 0 &&
              capacity_size == sizeof(actual) && actual == capacity * 2);
        struct sockaddr_ll address = {.sll_family = AF_PACKET,
                                      .sll_protocol = htons(protocol),
                                      .sll_ifindex = (int)indices[lane]};
        CHECK(observers[lane] >= 0 && indices[lane] &&
              bind(observers[lane], (struct sockaddr*)&address, sizeof(address)) == 0);
        printf("PMTU_CAPTURE_READY lane=%u index=%u\n", lane, indices[lane]);
    }
    CHECK(pthread_create(&observer, NULL, collect, NULL) == 0);
}

static void capture_stop(void) {
    CHECK(usleep(100000) == 0);
    atomic_store(&stop, 1);
    CHECK(pthread_join(observer, NULL) == 0);
    for (unsigned lane = 0; lane < 2; lane++) {
        unsigned statistics[2];
        socklen_t size = sizeof(statistics);
        CHECK(getsockopt(observers[lane], 263, 6, statistics, &size) == 0 &&
              size == sizeof(statistics) && statistics[0] == observed[lane] && !statistics[1]);
        printf("PMTU_CAPTURE_PASS lane=%u index=%u packets=%u dropped=%u ipv4=%u\n", lane,
               indices[lane], statistics[0], statistics[1], ipv4_frames[lane]);
        CHECK(close(observers[lane]) == 0);
    }
}

static int configure(void) {
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0)
        return -1;
    for (unsigned lane = 0; lane < 2; lane++) {
        struct ifreq request = {0};
        snprintf(request.ifr_name, sizeof(request.ifr_name), "eth%u", lane);
        struct sockaddr_in value = {.sin_family = AF_INET,
                                    .sin_addr.s_addr = htonl(0x0a170102 + (lane << 8))};
        memcpy(&request.ifr_addr, &value, sizeof(value));
        if (ioctl(fd, SIOCSIFADDR, &request))
            return -1;
        value.sin_addr.s_addr = htonl(0xffffff00);
        memcpy(&request.ifr_netmask, &value, sizeof(value));
        if (ioctl(fd, SIOCSIFNETMASK, &request) || ioctl(fd, SIOCGIFFLAGS, &request))
            return -1;
        request.ifr_flags |= IFF_UP;
        if (ioctl(fd, SIOCSIFFLAGS, &request))
            return -1;
    }
    return close(fd);
}

static int flow(unsigned lane, unsigned scenario) {
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    int listener = -1;
    int line = 0, stage = 0;
    uint64_t started = milliseconds();
    size_t sent = 0, received = 0;
    uint8_t bytes[transfer_bytes];
#define REQUIRE(value)                                                                             \
    do {                                                                                           \
        if (!(value)) {                                                                            \
            line = __LINE__;                                                                       \
            goto failed;                                                                           \
        }                                                                                          \
    } while (0)
    REQUIRE(fd >= 0);
    struct timeval timeout = {20, 0};
    int enabled = 1;
    REQUIRE(setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) == 0);
    REQUIRE(setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout)) == 0);
    REQUIRE(setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &enabled, sizeof(enabled)) == 0);
    struct sockaddr_in local = {.sin_family = AF_INET,
                                .sin_port = scenario & 1 ? htons(45000 + scenario * 20 + lane) : 0,
                                .sin_addr.s_addr = htonl(0x0a170102 + (lane << 8))};
    struct sockaddr_in peer = {.sin_family = AF_INET,
                               .sin_port = htons(44000 + scenario * 20 + lane),
                               .sin_addr.s_addr = htonl(0x0a17010a + (lane << 8) + scenario)};
    REQUIRE(bind(fd, (struct sockaddr*)&local, sizeof(local)) == 0);
    if (scenario & 1) {
        REQUIRE(listen(fd, 2) == 0);
        listener = fd;
        printf("TCP_PMTU_LISTEN lane=%u case=%u\n", lane, scenario);
        struct sockaddr_in remote;
        socklen_t length = sizeof(remote);
        fd = accept4(listener, (struct sockaddr*)&remote, &length, SOCK_CLOEXEC);
        REQUIRE(fd >= 0 && length == sizeof(remote) && remote.sin_family == AF_INET &&
                remote.sin_addr.s_addr == peer.sin_addr.s_addr && remote.sin_port == peer.sin_port);
        REQUIRE(close(listener) == 0);
        listener = -1;
    } else {
        REQUIRE(connect(fd, (struct sockaddr*)&peer, sizeof(peer)) == 0);
    }
    stage = 1;
    for (size_t at = 0; at < sizeof(bytes); at++)
        bytes[at] = pattern(at, lane, scenario, 0);
    while (sent < sizeof(bytes)) {
        ssize_t count = send(fd, bytes + sent, sizeof(bytes) - sent, MSG_NOSIGNAL);
        REQUIRE(count > 0 && (size_t)count <= sizeof(bytes) - sent);
        sent += (size_t)count;
    }
    REQUIRE(shutdown(fd, SHUT_WR) == 0);
    stage = 2;
    while (received < sizeof(bytes)) {
        ssize_t count = recv(fd, bytes + received, sizeof(bytes) - received, 0);
        REQUIRE(count > 0 && (size_t)count <= sizeof(bytes) - received);
        received += (size_t)count;
    }
    for (size_t at = 0; at < sizeof(bytes); at++)
        REQUIRE(bytes[at] == pattern(at, lane, scenario, 1));
    REQUIRE(recv(fd, bytes, 1, 0) == 0);
    int error = -1;
    socklen_t length = sizeof(error);
    REQUIRE(getsockopt(fd, SOL_SOCKET, SO_ERROR, &error, &length) == 0 && error == 0);
    REQUIRE(close(fd) == 0);
    printf("TCP_PMTU_FLOW_PASS lane=%u case=%u sent=%zu received=%zu milliseconds=%llu\n", lane,
           scenario, sent, received, (unsigned long long)(milliseconds() - started));
    return 0;
failed:
    printf("TCP_FAULT_FAIL lane=%u case=%u stage=%d line=%d errno=%d sent=%zu received=%zu "
           "milliseconds=%llu\n",
           lane, scenario, stage, line, errno, sent, received,
           (unsigned long long)(milliseconds() - started));
    if (fd >= 0)
        close(fd);
    if (listener >= 0 && listener != fd)
        close(listener);
    return 1;
#undef REQUIRE
}

int main(int argc, char** argv) {
    setvbuf(stdout, NULL, _IONBF, 0);
    signal(SIGPIPE, SIG_IGN);
    alarm(120);
    if (argc == 1) {
        if (configure()) {
            perror("TCP_FAULT_FAIL configure");
            return 2;
        }
        puts("TCP_FAULT_CONFIG_PASS nics=2");
    } else if (argc != 2 || strcmp(argv[1], "--native")) {
        return 2;
    }
    native = argc == 2;
    capture_start();
    int failed = 0;
    for (unsigned lane = 0; lane < 2; lane++)
        for (unsigned scenario = 0; scenario < 12; scenario++)
            failed |= flow(lane, scenario);
    capture_stop();
    if (!failed)
        puts("TCP_PMTU_PASS lanes=2 flows_each=12 bytes_each=4096");
    return failed;
}
