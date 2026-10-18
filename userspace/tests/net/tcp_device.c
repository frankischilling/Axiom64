// SPDX-License-Identifier: GPL-3.0-or-later
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <net/if.h>
#include <netinet/tcp.h>
#include <poll.h>
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

#define CHECK(value)                                                                               \
    do {                                                                                           \
        if (!(value)) {                                                                            \
            fprintf(stderr, "TCP_DEVICE_FAIL line=%d errno=%d expression=%s\n", __LINE__, errno,   \
                    #value);                                                                       \
            exit(1);                                                                               \
        }                                                                                          \
    } while (0)

static uint64_t milliseconds(void) {
    struct timespec value;
    CHECK(clock_gettime(CLOCK_MONOTONIC, &value) == 0);
    return (uint64_t)value.tv_sec * 1000 + value.tv_nsec / 1000000;
}

static unsigned char pattern(unsigned lane, unsigned direction, unsigned at) {
    return (unsigned char)((at * 29) ^ (at >> 7) ^ (lane * 53) ^ (direction * 41));
}

static void transfer(int fd, unsigned lane, unsigned* sent, unsigned* received, unsigned size) {
    unsigned char data[512];
    CHECK(size <= sizeof(data));
    for (unsigned at = 0; at < size; at++)
        data[at] = pattern(lane, 0, *sent + at);
    unsigned at = 0;
    while (at < size) {
        ssize_t actual = send(fd, data + at, size - at, MSG_NOSIGNAL);
        CHECK(actual > 0 && actual <= size - (ssize_t)at);
        at += (unsigned)actual;
    }
    *sent += size;
    at = 0;
    while (at < size) {
        ssize_t actual = recv(fd, data, size - at, 0);
        CHECK(actual > 0 && actual <= size - (ssize_t)at);
        for (ssize_t index = 0; index < actual; index++)
            CHECK(data[index] == pattern(lane, 1, *received + (unsigned)index));
        *received += (unsigned)actual;
        at += (unsigned)actual;
    }
}

int main(int argc, char** argv) {
    setbuf(stdout, NULL);
    signal(SIGPIPE, SIG_IGN);
    alarm(60);
    int native = argc == 3 && !strcmp(argv[1], "--native");
    CHECK(argc == 2 || native);
    const char* selection = argv[native ? 2 : 1];
    CHECK((selection[0] == '0' || selection[0] == '1') && !selection[1]);
    unsigned affected = (unsigned)(selection[0] - '0'), healthy = 1 - affected;
    int control = native ? -1 : socket(AF_INET, SOCK_DGRAM, 0), sockets[2];
    unsigned sent[2] = {0}, received[2] = {0};
    CHECK(native || control >= 0);
    for (unsigned lane = 0; lane < 2; lane++) {
        if (!native) {
            struct ifreq request = {0};
            snprintf(request.ifr_name, sizeof(request.ifr_name), "eth%u", lane);
            struct sockaddr_in address = {.sin_family = AF_INET,
                                          .sin_addr.s_addr = htonl(0x0a170102 + (lane << 8))};
            memcpy(&request.ifr_addr, &address, sizeof(address));
            CHECK(ioctl(control, SIOCSIFADDR, &request) == 0);
            address.sin_addr.s_addr = htonl(0xffffff00);
            memcpy(&request.ifr_netmask, &address, sizeof(address));
            CHECK(ioctl(control, SIOCSIFNETMASK, &request) == 0 &&
                  ioctl(control, SIOCGIFFLAGS, &request) == 0);
            request.ifr_flags |= IFF_UP;
            CHECK(ioctl(control, SIOCSIFFLAGS, &request) == 0);
        }
        sockets[lane] = socket(AF_INET, SOCK_STREAM, 0);
        int one = 1, user_timeout = 3000;
        if (native)
            CHECK(setsockopt(sockets[lane], IPPROTO_TCP, TCP_USER_TIMEOUT, &user_timeout,
                             sizeof(user_timeout)) == 0);
        struct timeval timeout = {5, 0};
        CHECK(sockets[lane] >= 0 &&
              setsockopt(sockets[lane], IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one)) == 0);
        CHECK(setsockopt(sockets[lane], SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) == 0 &&
              setsockopt(sockets[lane], SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout)) == 0);
        struct sockaddr_in local = {.sin_family = AF_INET,
                                    .sin_port = htons(48600 + lane),
                                    .sin_addr.s_addr = htonl(0x0a170102 + (lane << 8))};
        struct sockaddr_in remote = {.sin_family = AF_INET,
                                     .sin_port = htons(49600 + lane),
                                     .sin_addr.s_addr = htonl(0x0a170101 + (lane << 8))};
        CHECK(bind(sockets[lane], (struct sockaddr*)&local, sizeof(local)) == 0 &&
              connect(sockets[lane], (struct sockaddr*)&remote, sizeof(remote)) == 0);
        transfer(sockets[lane], lane, &sent[lane], &received[lane], 16);
    }
    if (!native)
        CHECK(close(control) == 0);
    printf("TCP_DEVICE_ARM lane=%u\n", affected);
    unsigned char byte;
    // Keep the selected write within one user page for the exact-frame observer.
    _Alignas(512) unsigned char data[512];
    CHECK(recv(sockets[affected], &byte, 1, 0) == 1 &&
          byte == pattern(affected, 1, received[affected]));
    received[affected]++;
    for (unsigned at = 0; at < sizeof(data); at++)
        data[at] = pattern(affected, 0, sent[affected] + at);
    CHECK(send(sockets[affected], data, sizeof(data), MSG_NOSIGNAL) == sizeof(data));
    printf("TCP_DEVICE_HELD lane=%u queued=512\n", affected);
    transfer(sockets[healthy], healthy, &sent[healthy], &received[healthy], 32);
    printf("TCP_DEVICE_HEALTHY_LIVE lane=%u bytes=%u\n", healthy, sent[healthy]);
    struct pollfd readiness = {.fd = sockets[affected], .events = POLLIN};
    CHECK(poll(&readiness, 1, 5000) == 1 && (readiness.revents & POLLERR));
    errno = 0;
    ssize_t read_result = recv(sockets[affected], &byte, 1, 0);
    int read_error = errno;
    CHECK(read_result == -1 && read_error == (native ? ENETUNREACH : EIO));
    int error = -1;
    socklen_t length = sizeof(error);
    CHECK(getsockopt(sockets[affected], SOL_SOCKET, SO_ERROR, &error, &length) == 0 &&
          error == (native ? ENETUNREACH : 0));
    errno = 0;
    ssize_t second_read = recv(sockets[affected], &byte, 1, 0);
    int second_error = errno;
    CHECK(second_read == 0);
    errno = 0;
    ssize_t send_result = send(sockets[affected], &byte, 1, MSG_NOSIGNAL);
    int send_error = errno;
    CHECK(send_result == -1 && send_error == EPIPE);
    printf("TCP_DEVICE_SYSCALLS native=%d read_bytes=%lld read_errno=%d so_error=%d "
           "second_read_bytes=%lld second_errno=%d send_bytes=%lld send_errno=%d\n",
           native, (long long)read_result, read_error, error, (long long)second_read, second_error,
           (long long)send_result, send_error);
    CHECK(close(sockets[affected]) == 0);
    printf("TCP_DEVICE_FAILED lane=%u revents=%u read_errno=%d send_errno=%d cleared_error=%d\n",
           affected, (unsigned)readiness.revents, read_error, send_error, error);
    uint64_t began = milliseconds();
    do {
        transfer(sockets[healthy], healthy, &sent[healthy], &received[healthy], 64);
        CHECK(usleep(100000) == 0);
    } while (milliseconds() - began < 5000);
    CHECK(shutdown(sockets[healthy], SHUT_WR) == 0 && recv(sockets[healthy], &byte, 1, 0) == 0 &&
          close(sockets[healthy]) == 0);
    printf("TCP_DEVICE_HEALTHY_PASS lane=%u bytes=%u elapsed_ms=%llu\n", healthy, sent[healthy],
           (unsigned long long)(milliseconds() - began));
    printf("TCP_DEVICE_PASS affected=%u queued=512\n", affected);
    return 0;
}
