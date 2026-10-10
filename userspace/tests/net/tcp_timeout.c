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
            fprintf(stderr, "TCP_TIMEOUT_FAIL line=%d errno=%d expression=%s\n", __LINE__, errno,  \
                    #value);                                                                       \
            exit(1);                                                                               \
        }                                                                                          \
    } while (0)

enum { transfer_bytes = 2048, deadline_ms = 2500 };

static uint64_t milliseconds(void) {
    struct timespec value;
    CHECK(clock_gettime(CLOCK_MONOTONIC, &value) == 0);
    return (uint64_t)value.tv_sec * 1000 + value.tv_nsec / 1000000;
}

static int option(int fd, int level, int name) {
    int value = -1;
    socklen_t length = sizeof(value);
    CHECK(getsockopt(fd, level, name, &value, &length) == 0 && length == sizeof(value));
    return value;
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
    puts("TCP_TIMEOUT_CONFIG_PASS nics=2");
}

static void flow(unsigned lane, unsigned role, unsigned control) {
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    CHECK(fd >= 0 && option(fd, IPPROTO_TCP, TCP_USER_TIMEOUT) == 0);
    int invalid = -1;
    errno = 0;
    CHECK(setsockopt(fd, IPPROTO_TCP, TCP_USER_TIMEOUT, &invalid, sizeof(invalid)) == -1 &&
          errno == EINVAL && option(fd, IPPROTO_TCP, TCP_USER_TIMEOUT) == 0);
    int deadline = control ? 0 : deadline_ms;
    CHECK(setsockopt(fd, IPPROTO_TCP, TCP_USER_TIMEOUT, &deadline, sizeof(deadline)) == 0 &&
          option(fd, IPPROTO_TCP, TCP_USER_TIMEOUT) == deadline);
    struct timeval io_timeout = {10, 0};
    CHECK(setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &io_timeout, sizeof(io_timeout)) == 0 &&
          setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &io_timeout, sizeof(io_timeout)) == 0);
    struct sockaddr_in address = {.sin_family = AF_INET,
                                  .sin_port = htons((role ? 44010 : 44000) + lane + control * 20),
                                  .sin_addr.s_addr =
                                      htonl((role ? 0x0a170102 : 0x0a170101) + (lane << 8))};
    if (!role) {
        CHECK(connect(fd, (struct sockaddr*)&address, sizeof(address)) == 0);
    } else {
        CHECK(bind(fd, (struct sockaddr*)&address, sizeof(address)) == 0 && listen(fd, 1) == 0);
        printf("TCP_TIMEOUT_READY lane=%u role=%u control=%u\n", lane, role, control);
        int accepted = accept(fd, NULL, NULL);
        CHECK(accepted >= 0 && close(fd) == 0);
        fd = accepted;
    }
    CHECK(option(fd, IPPROTO_TCP, TCP_USER_TIMEOUT) == deadline &&
          option(fd, SOL_SOCKET, SO_ERROR) == 0);
    uint8_t data[transfer_bytes];
    for (size_t at = 0; at < sizeof(data); at++)
        data[at] = (uint8_t)((at * 29) ^ (at >> 7) ^ (lane * 53) ^ (role * 97) ^ (control * 41));
    uint64_t started = milliseconds();
    for (size_t at = 0; at < sizeof(data);) {
        ssize_t count = send(fd, data + at, sizeof(data) - at, MSG_NOSIGNAL);
        CHECK(count > 0 && (size_t)count <= sizeof(data) - at);
        at += count;
    }
    uint8_t reply;
    if (control) {
        CHECK(recv(fd, &reply, 1, 0) == 1 && reply == 'K');
        CHECK(milliseconds() - started >= 3500 && milliseconds() - started < 10000);
        CHECK(recv(fd, &reply, 1, 0) == 0 && option(fd, SOL_SOCKET, SO_ERROR) == 0);
    } else {
        if (role) {
            struct pollfd pending = {.fd = fd, .events = POLLIN};
            CHECK(poll(&pending, 1, 10000) == 1 && (pending.revents & POLLERR));
            CHECK(option(fd, SOL_SOCKET, SO_ERROR) == ETIMEDOUT);
        } else {
            errno = 0;
            CHECK(recv(fd, &reply, 1, 0) == -1 && errno == ETIMEDOUT);
        }
        uint64_t elapsed = milliseconds() - started;
        CHECK(elapsed >= 2300 && elapsed < 4500);
        CHECK(option(fd, SOL_SOCKET, SO_ERROR) == 0 && recv(fd, &reply, 1, 0) == 0);
        errno = 0;
        CHECK(send(fd, &reply, 1, MSG_NOSIGNAL) == -1 && errno == EPIPE);
    }
    CHECK(close(fd) == 0);
    printf(
        "TCP_TIMEOUT_FLOW_PASS lane=%u role=%u control=%u option_ms=%d queued=%u elapsed_ms=%llu "
        "error=%d consumed=%s\n",
        lane, role, control, deadline, transfer_bytes,
        (unsigned long long)(milliseconds() - started), control ? 0 : ETIMEDOUT,
        control ? "none" : (role ? "SO_ERROR" : "recv"));
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
        for (unsigned control = 0; control < 2; control++)
            for (unsigned role = 0; role < 2; role++)
                flow(lane, role, control);
    CHECK(usleep(200000) == 0);
    puts("TCP_TIMEOUT_PASS flows=8 queued_each=2048");
    return 0;
}
