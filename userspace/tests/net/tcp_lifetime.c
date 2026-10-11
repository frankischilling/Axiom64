// SPDX-License-Identifier: GPL-3.0-or-later
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <net/if.h>
#include <netinet/tcp.h>
#include <poll.h>
#include <signal.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#define CHECK(value)                                                                               \
    do {                                                                                           \
        if (!(value)) {                                                                            \
            fprintf(stderr, "TCP_LIFETIME_FAIL line=%d errno=%d expression=%s\n", __LINE__, errno, \
                    #value);                                                                       \
            exit(1);                                                                               \
        }                                                                                          \
    } while (0)

enum { default_ms = 924600, longer_ms = 984600, cases = 6, flows = 24, recovery_bytes = 2048 };

static void record(const char* format, ...) {
    char buffer[512];
    va_list arguments;
    va_start(arguments, format);
    int length = vsnprintf(buffer, sizeof(buffer), format, arguments);
    va_end(arguments);
    CHECK(length > 0 && (size_t)length < sizeof(buffer));
    // A single bounded write keeps concurrently completed musl records intact.
    CHECK(write(STDOUT_FILENO, buffer, (size_t)length) == length);
}

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
    puts("TCP_LIFETIME_CONFIG_PASS nics=2");
    uint64_t started = milliseconds();
    CHECK(usleep(1200000) == 0 && milliseconds() - started >= 1200);
    record("TCP_LIFETIME_SETUP_WAIT_PASS elapsed_ms=%llu\n",
           (unsigned long long)(milliseconds() - started));
}

static void flow(unsigned lane, unsigned role, unsigned kind, int native) {
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    CHECK(fd >= 0 && option(fd, IPPROTO_TCP, TCP_USER_TIMEOUT) == 0);
    int deadline = kind == 4 ? longer_ms : (kind == 5 ? 2500 : 0);
    if (deadline)
        CHECK(setsockopt(fd, IPPROTO_TCP, TCP_USER_TIMEOUT, &deadline, sizeof(deadline)) == 0);
    struct timeval io_timeout;
    socklen_t io_length = sizeof(io_timeout);
    CHECK(getsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &io_timeout, &io_length) == 0 &&
          io_length == sizeof(io_timeout) && !io_timeout.tv_sec && !io_timeout.tv_usec);
    struct sockaddr_in address = {.sin_family = AF_INET,
                                  .sin_port = htons((role ? 44010 : 44000) + lane + kind * 20),
                                  .sin_addr.s_addr =
                                      htonl((role ? 0x0a170102 : 0x0a170101) + (lane << 8))};
    if (!role) {
        CHECK(connect(fd, (struct sockaddr*)&address, sizeof(address)) == 0);
    } else {
        CHECK(bind(fd, (struct sockaddr*)&address, sizeof(address)) == 0 && listen(fd, 1) == 0);
        record("TCP_LIFETIME_READY lane=%u role=1 kind=%u\n", lane, kind);
        int accepted = accept(fd, NULL, NULL);
        CHECK(accepted >= 0 && close(fd) == 0);
        fd = accepted;
    }
    CHECK(option(fd, IPPROTO_TCP, TCP_USER_TIMEOUT) == deadline &&
          option(fd, SOL_SOCKET, SO_ERROR) == 0);
    struct sockaddr_in local;
    socklen_t local_length = sizeof(local);
    CHECK(getsockname(fd, (struct sockaddr*)&local, &local_length) == 0 &&
          local_length == sizeof(local));
    uint8_t data[recovery_bytes];
    for (size_t at = 0; at < sizeof(data); at++)
        data[at] = (uint8_t)((at * 29) ^ (at >> 7) ^ (lane * 53) ^ (role * 97) ^ (kind * 41));
    uint64_t started = milliseconds();
    if (kind == 1 || kind == 5) {
        CHECK(shutdown(fd, SHUT_WR) == 0);
    } else {
        size_t size = kind == 3 ? sizeof(data) : 1;
        CHECK(send(fd, data, size, MSG_NOSIGNAL) == (ssize_t)size);
    }
    record("TCP_LIFETIME_STARTED lane=%u role=%u kind=%u option_ms=%d\n", lane, role, kind,
           deadline);
    uint8_t reply = 0;
    if (kind == 3) {
        uint8_t recovered[256];
        size_t received = 0;
        while (received < sizeof(data)) {
            ssize_t count = recv(fd, recovered, sizeof(recovered), 0);
            CHECK(count > 0 && received + count <= sizeof(data));
            for (ssize_t at = 0; at < count; at++)
                CHECK(recovered[at] == (uint8_t)(data[received + at] ^ 0xa5));
            received += count;
        }
        CHECK(milliseconds() - started >= longer_ms && milliseconds() - started < 1400000);
        CHECK(recv(fd, &reply, 1, 0) == 0 && option(fd, SOL_SOCKET, SO_ERROR) == 0);
        CHECK(shutdown(fd, SHUT_WR) == 0 && close(fd) == 0);
    } else {
        if (role) {
            struct pollfd pending = {.fd = fd, .events = POLLIN};
            CHECK(poll(&pending, 1, 1500000) == 1 && (pending.revents & POLLERR));
            CHECK(option(fd, SOL_SOCKET, SO_ERROR) == ETIMEDOUT);
        } else {
            errno = 0;
            CHECK(recv(fd, &reply, 1, 0) == -1 && errno == ETIMEDOUT);
        }
        uint64_t elapsed = milliseconds() - started;
        uint64_t minimum = kind == 5 ? 2300 : (kind == 4 ? longer_ms - 100 : default_ms - 100);
        uint64_t maximum = kind == 5 ? 6000 : (native ? 1400000 : 1010000);
        CHECK(elapsed >= minimum && elapsed < maximum);
        CHECK(option(fd, SOL_SOCKET, SO_ERROR) == 0 && recv(fd, &reply, 1, 0) == 0);
        errno = 0;
        CHECK(send(fd, &reply, 1, MSG_NOSIGNAL) == -1 && errno == EPIPE);
        CHECK(close(fd) == 0);
        int reused = socket(AF_INET, SOCK_STREAM, 0);
        CHECK(reused >= 0 && bind(reused, (struct sockaddr*)&local, sizeof(local)) == 0 &&
              listen(reused, 1) == 0 && close(reused) == 0);
    }
    record("TCP_LIFETIME_FLOW_PASS lane=%u role=%u kind=%u option_ms=%d elapsed_ms=%llu error=%d "
           "consumed=%s reclaimed=%u\n",
           lane, role, kind, deadline, (unsigned long long)(milliseconds() - started),
           kind == 3 ? 0 : ETIMEDOUT, kind == 3 ? "none" : (role ? "SO_ERROR" : "recv"), kind != 3);
}

int main(int argc, char** argv) {
    setvbuf(stdout, NULL, _IONBF, 0);
    signal(SIGPIPE, SIG_IGN);
    alarm(1600);
    int native = argc == 2;
    if (!native)
        CHECK(argc == 1);
    else
        CHECK(!strcmp(argv[1], "--native"));
    if (!native)
        configure();
    pid_t children[flows];
    unsigned count = 0;
    for (unsigned lane = 0; lane < 2; lane++) {
        for (unsigned kind = 0; kind < cases; kind++) {
            for (unsigned role = 0; role < 2; role++) {
                pid_t child = fork();
                CHECK(child >= 0);
                if (!child) {
                    alarm(1600);
                    flow(lane, role, kind, native);
                    return 0;
                }
                children[count++] = child;
            }
        }
    }
    for (unsigned at = 0; at < count; at++) {
        int status;
        CHECK(waitpid(children[at], &status, 0) == children[at] && WIFEXITED(status) &&
              WEXITSTATUS(status) == 0);
    }
    CHECK(usleep(200000) == 0);
    puts("TCP_LIFETIME_PASS flows=24 default_ms=924600 longer_ms=984600");
    return 0;
}
