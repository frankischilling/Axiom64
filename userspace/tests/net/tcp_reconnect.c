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

static unsigned current_lane, current_case, current_phase;
#define CHECK(value)                                                                               \
    do {                                                                                           \
        if (!(value)) {                                                                            \
            fprintf(stderr, "TCP_RECONNECT_FAIL lane=%u case=%u phase=%u line=%d errno=%d\n",      \
                    current_lane, current_case, current_phase, __LINE__, errno);                   \
            exit(1);                                                                               \
        }                                                                                          \
    } while (0)

static uint64_t milliseconds(void) {
    struct timespec now;
    CHECK(clock_gettime(CLOCK_MONOTONIC, &now) == 0);
    return (uint64_t)now.tv_sec * 1000 + now.tv_nsec / 1000000;
}

static uint8_t pattern(size_t at, unsigned direction) {
    return (uint8_t)((at * 29) ^ (at >> 7) ^ (current_lane * 53) ^ (current_case * 97) ^
                     (current_phase * 71) ^ (direction * 41));
}

static void configure(void) {
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    CHECK(fd >= 0);
    for (unsigned lane = 0; lane < 2; lane++) {
        struct ifreq request = {0};
        snprintf(request.ifr_name, sizeof(request.ifr_name), "eth%u", lane);
        struct sockaddr_in value = {.sin_family = AF_INET,
                                    .sin_addr.s_addr = htonl(0x0a170102 + (lane << 8))};
        memcpy(&request.ifr_addr, &value, sizeof(value));
        CHECK(ioctl(fd, SIOCSIFADDR, &request) == 0);
        value.sin_addr.s_addr = htonl(0xffffff00);
        memcpy(&request.ifr_netmask, &value, sizeof(value));
        CHECK(ioctl(fd, SIOCSIFNETMASK, &request) == 0 && ioctl(fd, SIOCGIFFLAGS, &request) == 0);
        request.ifr_flags |= IFF_UP;
        CHECK(ioctl(fd, SIOCSIFFLAGS, &request) == 0);
    }
    CHECK(close(fd) == 0);
}

static void exchange(int fd, size_t total) {
    uint8_t bytes[2048];
    size_t position = 0;
    while (position < total) {
        size_t length = total - position;
        if (length > sizeof(bytes))
            length = sizeof(bytes);
        for (size_t at = 0; at < length; at++)
            bytes[at] = pattern(position + at, 0);
        ssize_t sent = send(fd, bytes, length, MSG_NOSIGNAL);
        CHECK(sent > 0 && (size_t)sent <= length);
        position += (size_t)sent;
    }
    position = 0;
    while (position < 16) {
        ssize_t received = recv(fd, bytes, 16 - position, 0);
        CHECK(received > 0 && (size_t)received <= 16 - position);
        for (ssize_t at = 0; at < received; at++)
            CHECK(bytes[at] == pattern(position + (size_t)at, 1));
        position += (size_t)received;
    }
}

static void flow(void) {
    struct sockaddr_in local = {.sin_family = AF_INET,
                                .sin_port = htons(48000 + current_case * 20 + current_lane),
                                .sin_addr.s_addr = htonl(0x0a170102 + (current_lane << 8))};
    struct sockaddr_in destination = {.sin_family = AF_INET,
                                      .sin_port = htons(49000 + current_case * 20 + current_lane),
                                      .sin_addr.s_addr = htonl(0x0a170101 + (current_lane << 8))};
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    CHECK(fd >= 0 && bind(fd, (struct sockaddr*)&local, sizeof(local)) == 0);
    struct timeval timeout = {5, 0};
    int value = 1;
    CHECK(setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) == 0 &&
          setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout)) == 0 &&
          setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &value, sizeof(value)) == 0);
    size_t total = current_case < 2 ? 32768 : 4096;
    for (current_phase = 0; current_phase < 2; current_phase++) {
        if (current_phase && current_case >= 2) {
            CHECK(connect(fd, (struct sockaddr*)&destination, sizeof(destination)) == -1 &&
                  errno == EADDRNOTAVAIL);
            printf("TCP_RECONNECT_GUARD_PASS lane=%u case=%u errno=%d\n", current_lane,
                   current_case, errno);
            destination.sin_port = htons(49001 + current_case * 20 + current_lane);
        }
        CHECK(connect(fd, (struct sockaddr*)&destination, sizeof(destination)) == 0);
        struct sockaddr_in actual;
        socklen_t length = sizeof(actual);
        CHECK(getsockname(fd, (struct sockaddr*)&actual, &length) == 0 &&
              actual.sin_port == local.sin_port && actual.sin_addr.s_addr == local.sin_addr.s_addr);
        exchange(fd, total);
        if (current_phase || current_case >= 2) {
            uint8_t byte;
            CHECK(shutdown(fd, SHUT_WR) == 0 && recv(fd, &byte, 1, 0) == 0);
        }
        printf("TCP_RECONNECT_PHASE_PASS lane=%u case=%u phase=%u sent=%zu received=16 "
               "monotonic_ms=%llu\n",
               current_lane, current_case, current_phase, total,
               (unsigned long long)milliseconds());
        if (!current_phase) {
            // Observe the acknowledged old stream before its description is reused.
            CHECK(usleep(100000) == 0);
            struct sockaddr unspec = {.sa_family = AF_UNSPEC};
            CHECK(connect(fd, &unspec, sizeof(unspec.sa_family)) == 0);
            length = sizeof(actual);
            CHECK(getpeername(fd, (struct sockaddr*)&actual, &length) == -1 && errno == ENOTCONN);
            length = sizeof(value);
            CHECK(getsockopt(fd, SOL_SOCKET, SO_ERROR, &value, &length) == 0 &&
                  value == (current_case < 2 ? ECONNRESET : 0));
        }
    }
    CHECK(close(fd) == 0);
}

static int queued_sockets[2];
static unsigned queued_phases[2], queued_sent[2], queued_received[2];

static void revisit(void) {
    current_case = 5;
    for (current_lane = 0; current_lane < 2; current_lane++) {
        struct sockaddr_in local = {.sin_family = AF_INET,
                                    .sin_port = htons(48100 + current_lane),
                                    .sin_addr.s_addr = htonl(0x0a170102 + (current_lane << 8))};
        int fd = socket(AF_INET, SOCK_STREAM, 0), one = 1;
        struct timeval timeout = {5, 0};
        CHECK(fd >= 0 && bind(fd, (struct sockaddr*)&local, sizeof(local)) == 0 &&
              setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one)) == 0 &&
              setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) == 0 &&
              setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout)) == 0);
        for (current_phase = 0; current_phase < 3; current_phase++) {
            struct sockaddr_in remote = {
                .sin_family = AF_INET,
                .sin_port = htons(49100 + current_lane + (current_phase == 1)),
                .sin_addr.s_addr = htonl(0x0a170101 + (current_lane << 8))};
            CHECK(connect(fd, (struct sockaddr*)&remote, sizeof(remote)) == 0);
            size_t size = current_phase == 0 ? 262144 : current_phase == 1 ? 16 : 512;
            exchange(fd, size);
            struct sockaddr_in actual;
            socklen_t length = sizeof(actual);
            CHECK(getsockname(fd, (struct sockaddr*)&actual, &length) == 0 &&
                  actual.sin_port == local.sin_port &&
                  actual.sin_addr.s_addr == local.sin_addr.s_addr);
            printf("TCP_RECONNECT_REVISIT_PHASE_PASS lane=%u phase=%u sent=%zu received=16\n",
                   current_lane, current_phase, size);
            if (current_phase < 2) {
                struct sockaddr unspec = {.sa_family = AF_UNSPEC};
                CHECK(connect(fd, &unspec, sizeof(unspec.sa_family)) == 0);
                int error = -1;
                length = sizeof(error);
                CHECK(getsockopt(fd, SOL_SOCKET, SO_ERROR, &error, &length) == 0 &&
                      error == ECONNRESET);
            } else {
                unsigned char byte;
                CHECK(shutdown(fd, SHUT_WR) == 0 && recv(fd, &byte, 1, 0) == 0);
            }
        }
        CHECK(close(fd) == 0);
    }
}

static unsigned char queued_pattern(unsigned lane, unsigned phase, unsigned direction,
                                    unsigned at) {
    return (unsigned char)((at * 29) ^ (at >> 7) ^ (lane * 53) ^ (4 * 97) ^ (phase * 71) ^
                           (direction * 41));
}

static void queued_send(unsigned lane, unsigned length) {
    current_lane = lane;
    current_phase = queued_phases[lane];
    _Alignas(512) unsigned char bytes[512];
    CHECK(length <= sizeof(bytes));
    for (unsigned at = 0; at < length; at++)
        bytes[at] = queued_pattern(lane, queued_phases[lane], 0, queued_sent[lane] + at);
    unsigned position = 0;
    while (position < length) {
        ssize_t actual =
            send(queued_sockets[lane], bytes + position, length - position, MSG_NOSIGNAL);
        CHECK(actual > 0 && (unsigned)actual <= length - position);
        position += (unsigned)actual;
    }
    queued_sent[lane] += length;
}

static void queued_receive(unsigned lane, unsigned length) {
    current_lane = lane;
    current_phase = queued_phases[lane];
    _Alignas(512) unsigned char bytes[512];
    unsigned position = 0;
    while (position < length) {
        ssize_t actual = recv(queued_sockets[lane], bytes, length - position, 0);
        CHECK(actual > 0 && (unsigned)actual <= length - position);
        for (ssize_t at = 0; at < actual; at++)
            CHECK(bytes[at] == queued_pattern(lane, queued_phases[lane], 1,
                                              queued_received[lane] + position + (unsigned)at));
        position += (unsigned)actual;
    }
    queued_received[lane] += length;
}

static void queued_exchange(unsigned lane, unsigned length) {
    queued_send(lane, length);
    queued_receive(lane, length);
}

static struct sockaddr_in queued_destination(unsigned lane) {
    struct sockaddr_in value = {.sin_family = AF_INET,
                                .sin_port = htons(49080 + lane),
                                .sin_addr.s_addr = htonl(0x0a170101 + (lane << 8))};
    return value;
}

static void queued_error(unsigned lane, int expected) {
    int value = -1;
    socklen_t length = sizeof(value);
    CHECK(getsockopt(queued_sockets[lane], SOL_SOCKET, SO_ERROR, &value, &length) == 0 &&
          value == expected);
}

static void queued_cancellation(void) {
    current_case = 4;
    for (unsigned lane = 0; lane < 2; lane++) {
        current_lane = lane;
        queued_sockets[lane] = socket(AF_INET, SOCK_STREAM, 0);
        CHECK(queued_sockets[lane] >= 0);
        int value = 1;
        struct timeval timeout = {5, 0};
        CHECK(setsockopt(queued_sockets[lane], IPPROTO_TCP, TCP_NODELAY, &value, sizeof(value)) ==
                  0 &&
              setsockopt(queued_sockets[lane], SOL_SOCKET, SO_RCVTIMEO, &timeout,
                         sizeof(timeout)) == 0 &&
              setsockopt(queued_sockets[lane], SOL_SOCKET, SO_SNDTIMEO, &timeout,
                         sizeof(timeout)) == 0);
        struct sockaddr_in local = {.sin_family = AF_INET,
                                    .sin_port = htons(48080 + lane),
                                    .sin_addr.s_addr = htonl(0x0a170102 + (lane << 8))};
        struct sockaddr_in remote = queued_destination(lane);
        CHECK(bind(queued_sockets[lane], (struct sockaddr*)&local, sizeof(local)) == 0 &&
              connect(queued_sockets[lane], (struct sockaddr*)&remote, sizeof(remote)) == 0);
        queued_exchange(lane, 16);
    }
    for (unsigned lane = 0; lane < 2; lane++) {
        current_lane = lane;
        printf("TCP_RECONNECT_QUEUED_ARM lane=%u old_prefix=%u\n", lane, queued_sent[lane]);
        unsigned char control;
        CHECK(recv(queued_sockets[lane], &control, 1, 0) == 1 && control == 'Q');
        queued_send(lane, 512);
        uint64_t began = milliseconds();
        printf("TCP_RECONNECT_QUEUED_HELD lane=%u queued=512\n", lane);
        queued_exchange(1 - lane, 16);
        queued_error(lane, 0);
        int available = -1;
        CHECK(ioctl(queued_sockets[lane], FIONREAD, &available) == 0 && !available);
        struct sockaddr unspec = {.sa_family = AF_UNSPEC};
        CHECK(connect(queued_sockets[lane], &unspec, sizeof(unspec.sa_family)) == 0);
        queued_error(lane, ECONNRESET);
        struct sockaddr_in actual;
        socklen_t length = sizeof(actual);
        CHECK(getpeername(queued_sockets[lane], (struct sockaddr*)&actual, &length) == -1 &&
              errno == ENOTCONN);
        length = sizeof(actual);
        CHECK(getsockname(queued_sockets[lane], (struct sockaddr*)&actual, &length) == 0 &&
              actual.sin_port == htons(48080 + lane) &&
              actual.sin_addr.s_addr == htonl(0x0a170102 + (lane << 8)));
        printf("TCP_RECONNECT_QUEUED_UNSPEC lane=%u\n", lane);
        queued_exchange(1 - lane, 16);
        struct sockaddr_in remote = queued_destination(lane);
        CHECK(connect(queued_sockets[lane], (struct sockaddr*)&remote, sizeof(remote)) == 0);
        queued_phases[lane] = 1;
        queued_sent[lane] = queued_received[lane] = 0;
        queued_exchange(lane, 512);
        uint64_t elapsed = milliseconds() - began;
        while (elapsed < 11000) {
            uint64_t remaining = 11000 - elapsed;
            if (remaining > 100)
                remaining = 100;
            CHECK(usleep((useconds_t)remaining * 1000) == 0);
            elapsed = milliseconds() - began;
        }
        queued_exchange(1 - lane, 16);
        queued_exchange(lane, 16);
        queued_error(lane, 0);
        queued_error(1 - lane, 0);
        printf("TCP_RECONNECT_QUEUED_DONE lane=%u elapsed_ms=%llu successor=528\n", lane,
               (unsigned long long)(milliseconds() - began));
    }
    for (unsigned lane = 0; lane < 2; lane++) {
        current_lane = lane;
        unsigned char byte;
        CHECK(shutdown(queued_sockets[lane], SHUT_WR) == 0 &&
              recv(queued_sockets[lane], &byte, 1, 0) == 0 && close(queued_sockets[lane]) == 0);
    }
}

int main(int argc, char** argv) {
    setbuf(stdout, NULL);
    signal(SIGPIPE, SIG_IGN);
    alarm(60);
    int native = argc == 2 && !strcmp(argv[1], "--native");
    CHECK(argc == 1 || native);
    if (!native)
        configure();
    puts("TCP_RECONNECT_CONFIG_PASS nics=2");
    for (current_lane = 0; current_lane < 2; current_lane++)
        for (current_case = 0; current_case < 4; current_case++)
            flow();
    revisit();
    queued_cancellation();
    CHECK(usleep(100000) == 0);
    puts("TCP_RECONNECT_PASS nics=2 cases_each=6 ordinary_phases_each=2 revisit_phases=3 "
         "queued_phases_each=2 queued_each=512");
    return 0;
}
