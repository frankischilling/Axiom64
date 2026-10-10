// SPDX-License-Identifier: GPL-3.0-or-later
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <net/if.h>
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
            fprintf(stderr, "TCP_FAULT_FAIL line=%d errno=%d expression=%s\n", __LINE__, errno,    \
                    #value);                                                                       \
            exit(1);                                                                               \
        }                                                                                          \
    } while (0)

enum { transfer_bytes = 65536 };

static uint8_t pattern(size_t position, unsigned lane, unsigned role, unsigned direction) {
    return (uint8_t)((position * 29) ^ (position >> 7) ^ (lane * 53) ^ (role * 97) ^
                     (direction * 41));
}

static uint64_t milliseconds(void) {
    struct timespec value;
    CHECK(clock_gettime(CLOCK_MONOTONIC, &value) == 0);
    return (uint64_t)value.tv_sec * 1000 + value.tv_nsec / 1000000;
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
    puts("TCP_FAULT_CONFIG_PASS nics=2");
}

static void flow(unsigned lane, unsigned role) {
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    CHECK(fd >= 0);
    struct timeval timeout = {20, 0};
    CHECK(setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) == 0);
    CHECK(setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout)) == 0);
    struct sockaddr_in destination = {.sin_family = AF_INET,
                                      .sin_port = htons((role ? 44010 : 44000) + lane),
                                      .sin_addr.s_addr =
                                          htonl((role ? 0x0a170102 : 0x0a170101) + (lane << 8))};
    uint64_t started = milliseconds();
    if (!role) {
        CHECK(connect(fd, (struct sockaddr*)&destination, sizeof(destination)) == 0);
    } else {
        CHECK(bind(fd, (struct sockaddr*)&destination, sizeof(destination)) == 0 &&
              listen(fd, 1) == 0);
        printf("TCP_FAULT_READY lane=%u role=%u\n", lane, role);
        int accepted = accept(fd, NULL, NULL);
        CHECK(accepted >= 0 && close(fd) == 0);
        fd = accepted;
        CHECK(setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) == 0);
        CHECK(setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout)) == 0);
    }
    uint64_t connected = milliseconds();
    CHECK(connected - started >= 850 && connected - started < 20000);
    uint8_t buffer[4096];
    for (size_t position = 0; position < transfer_bytes;) {
        size_t length = sizeof(buffer);
        if (length > transfer_bytes - position)
            length = transfer_bytes - position;
        for (size_t at = 0; at < length; at++)
            buffer[at] = pattern(position + at, lane, role, 0);
        ssize_t sent = send(fd, buffer, length, MSG_NOSIGNAL);
        CHECK(sent > 0 && (size_t)sent <= length);
        position += sent;
    }
    CHECK(shutdown(fd, SHUT_WR) == 0);
    size_t received = 0;
    for (;;) {
        ssize_t count = recv(fd, buffer, sizeof(buffer), 0);
        CHECK(count >= 0 && received + count <= transfer_bytes);
        if (!count)
            break;
        for (ssize_t at = 0; at < count; at++)
            CHECK(buffer[at] == pattern(received + at, lane, role, 1));
        received += count;
    }
    CHECK(received == transfer_bytes && close(fd) == 0);
    printf("TCP_FAULT_FLOW_PASS lane=%u role=%u bytes_each=%u connect_ms=%llu total_ms=%llu\n",
           lane, role, transfer_bytes, (unsigned long long)(connected - started),
           (unsigned long long)(milliseconds() - started));
}

int main(int argc, char** argv) {
    setvbuf(stdout, NULL, _IONBF, 0);
    signal(SIGPIPE, SIG_IGN);
    alarm(120);
    if (argc == 1)
        configure();
    else
        CHECK(argc == 2 && !strcmp(argv[1], "--native"));
    for (unsigned lane = 0; lane < 2; lane++)
        for (unsigned role = 0; role < 2; role++)
            flow(lane, role);
    CHECK(usleep(200000) == 0);
    puts("TCP_FAULT_PASS flows=4 bytes_each=65536");
    return 0;
}
