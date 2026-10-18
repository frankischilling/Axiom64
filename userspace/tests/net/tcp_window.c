// SPDX-License-Identifier: GPL-3.0-or-later
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
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

static unsigned lane;
#define CHECK(value)                                                                               \
    do {                                                                                           \
        if (!(value)) {                                                                            \
            fprintf(stderr, "TCP_WINDOW_FAIL lane=%u line=%d errno=%d expression=%s\n", lane,      \
                    __LINE__, errno, #value);                                                      \
            exit(1);                                                                               \
        }                                                                                          \
    } while (0)

static uint64_t milliseconds(void) {
    struct timespec value;
    CHECK(clock_gettime(CLOCK_MONOTONIC, &value) == 0);
    return (uint64_t)value.tv_sec * 1000 + value.tv_nsec / 1000000;
}

static unsigned char pattern(unsigned direction, unsigned at) {
    return (unsigned char)((at * 29) ^ (at >> 7) ^ (lane * 53) ^ (direction * 41));
}

static void configure(void) {
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    CHECK(fd >= 0);
    for (lane = 0; lane < 2; lane++) {
        struct ifreq request = {0};
        snprintf(request.ifr_name, sizeof(request.ifr_name), "eth%u", lane);
        struct sockaddr_in address = {.sin_family = AF_INET,
                                      .sin_addr.s_addr = htonl(0x0a170102 + (lane << 8))};
        memcpy(&request.ifr_addr, &address, sizeof(address));
        CHECK(ioctl(fd, SIOCSIFADDR, &request) == 0);
        address.sin_addr.s_addr = htonl(0xffffff00);
        memcpy(&request.ifr_netmask, &address, sizeof(address));
        CHECK(ioctl(fd, SIOCSIFNETMASK, &request) == 0 && ioctl(fd, SIOCGIFFLAGS, &request) == 0);
        request.ifr_flags |= IFF_UP;
        CHECK(ioctl(fd, SIOCSIFFLAGS, &request) == 0);
    }
    CHECK(close(fd) == 0);
}

int main(int argc, char** argv) {
    setbuf(stdout, NULL);
    signal(SIGPIPE, SIG_IGN);
    alarm(60);
    int native = argc == 2 && !strcmp(argv[1], "--native");
    CHECK(argc == 1 || native);
    if (!native)
        configure();
    puts("TCP_WINDOW_CONFIG_PASS nics=2");
    for (lane = 0; lane < 2; lane++) {
        int fd = socket(AF_INET, SOCK_STREAM, 0), one = 1;
        struct timeval timeout = {5, 0};
        CHECK(fd >= 0 && setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one)) == 0);
        CHECK(setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) == 0 &&
              setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout)) == 0);
        struct sockaddr_in local = {.sin_family = AF_INET,
                                    .sin_port = htons(48500 + lane),
                                    .sin_addr.s_addr = htonl(0x0a170102 + (lane << 8))};
        struct sockaddr_in remote = {.sin_family = AF_INET,
                                     .sin_port = htons(49500 + lane),
                                     .sin_addr.s_addr = htonl(0x0a170101 + (lane << 8))};
        CHECK(bind(fd, (struct sockaddr*)&local, sizeof(local)) == 0 &&
              connect(fd, (struct sockaddr*)&remote, sizeof(remote)) == 0);
        uint64_t began = milliseconds();
        unsigned at = 0;
        while (at < 65536) {
            unsigned char bytes[4096];
            unsigned length = 65536 - at < sizeof(bytes) ? 65536 - at : sizeof(bytes);
            for (unsigned index = 0; index < length; index++)
                bytes[index] = pattern(0, at + index);
            ssize_t actual = send(fd, bytes, length, MSG_NOSIGNAL);
            CHECK(actual > 0 && (unsigned)actual <= length);
            at += (unsigned)actual;
        }
        at = 0;
        while (at < 16) {
            unsigned char bytes[16];
            ssize_t actual = recv(fd, bytes, 16 - at, 0);
            CHECK(actual > 0 && actual <= 16 - (ssize_t)at);
            for (ssize_t index = 0; index < actual; index++)
                CHECK(bytes[index] == pattern(1, at + (unsigned)index));
            at += (unsigned)actual;
        }
        unsigned char byte;
        CHECK(shutdown(fd, SHUT_WR) == 0 && recv(fd, &byte, 1, 0) == 0 && close(fd) == 0);
        printf("TCP_WINDOW_LANE_PASS lane=%u bytes=65536 elapsed_ms=%llu\n", lane,
               (unsigned long long)(milliseconds() - began));
    }
    CHECK(usleep(100000) == 0);
    puts("TCP_WINDOW_PASS nics=2 bytes_each=65536");
    return 0;
}
