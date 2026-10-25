// SPDX-License-Identifier: GPL-3.0-or-later
#define _GNU_SOURCE
#include "tcp_icmp_cases.h"
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <net/if.h>
#include <netpacket/packet.h>
#include <netinet/tcp.h>
#include <poll.h>
#include <pthread.h>
#include <signal.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/ioctl.h>
#ifdef __GLIBC__
#include <linux/sockios.h>
#endif
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

#define CHECK(value)                                                                               \
    do {                                                                                           \
        if (!(value)) {                                                                            \
            fprintf(stderr, "TCP_ICMP_FAIL line=%d errno=%d expression=%s\n", __LINE__, errno,     \
                    #value);                                                                       \
            exit(1);                                                                               \
        }                                                                                          \
    } while (0)

static int native;
static volatile sig_atomic_t interrupted;
static atomic_int stop;
static int observers[2];
static unsigned indices[2], observed[2], ipv4_frames[2];
static pthread_t observer;
static int companions[2][2], listeners[2];
static int passive_listeners[2][ICMP_CASES];
static unsigned companion_checks[2][2];
static uint64_t capture_before, capture_realtime, capture_after;

static uint64_t nanoseconds(clockid_t clock) {
    struct timespec stamp;
    CHECK(clock_gettime(clock, &stamp) == 0 && stamp.tv_sec >= 0 && stamp.tv_nsec >= 0 &&
          stamp.tv_nsec < 1000000000);
    return (uint64_t)stamp.tv_sec * 1000000000 + stamp.tv_nsec;
}

static void capture_clock(const char* phase) {
    uint64_t before = nanoseconds(CLOCK_MONOTONIC);
    uint64_t realtime = nanoseconds(CLOCK_REALTIME);
    uint64_t after = nanoseconds(CLOCK_MONOTONIC);
    CHECK(after >= before && after - before <= 100000000);
    if (!strcmp(phase, "begin")) {
        capture_before = before;
        capture_realtime = realtime;
        capture_after = after;
    }
    printf("ICMP_CAPTURE_CLOCK phase=%s monotonic_before_ns=%llu realtime_ns=%llu "
           "monotonic_after_ns=%llu\n",
           phase, (unsigned long long)before, (unsigned long long)realtime,
           (unsigned long long)after);
}

static uint64_t milliseconds(void) {
    struct timespec stamp;
    CHECK(clock_gettime(CLOCK_MONOTONIC, &stamp) == 0);
    return (uint64_t)stamp.tv_sec * 1000 + stamp.tv_nsec / 1000000;
}

static int error(int fd) {
    int value = -1;
    socklen_t size = sizeof(value);
    CHECK(getsockopt(fd, SOL_SOCKET, SO_ERROR, &value, &size) == 0 && size == sizeof(value));
    return value;
}

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
        if (frame[12] != 8 || frame[13] != 0) {
            uint64_t digest = UINT64_C(0xcbf29ce484222325);
            for (ssize_t at = 0; at < length; at++)
                digest = (digest ^ frame[at]) * UINT64_C(0x100000001b3);
            printf("ICMP_LINK_FRAME lane=%u index=%u length=%zd kind=%u ether_type=%02x%02x "
                   "hash=%016llx monotonic_ms=%llu\n",
                   lane, indices[lane], length, source.sll_pkttype, frame[12], frame[13],
                   (unsigned long long)digest, (unsigned long long)milliseconds());
            continue;
        }
        struct timespec arrival;
        CHECK(ioctl(observers[lane], SIOCGSTAMPNS, &arrival) == 0 && arrival.tv_sec >= 0 &&
              arrival.tv_nsec >= 0 && arrival.tv_nsec < 1000000000);
        uint64_t realtime = (uint64_t)arrival.tv_sec * 1000000000 + arrival.tv_nsec;
        uint64_t dequeue = milliseconds();
        __int128 mapped = (__int128)realtime - capture_realtime + capture_before +
                          (capture_after - capture_before) / 2;
        CHECK(mapped >= 0 && mapped <= UINT64_MAX);
        uint64_t digest = UINT64_C(0xcbf29ce484222325);
        for (ssize_t at = 0; at < length; at++)
            digest = (digest ^ frame[at]) * UINT64_C(0x100000001b3);
        ipv4_frames[lane]++;
        printf("ICMP_FRAME lane=%u index=%u length=%zd kind=%u hash=%016llx monotonic_ms=%llu "
               "packet_realtime_ns=%llu dequeue_ms=%llu\n",
               lane, indices[lane], length, source.sll_pkttype, (unsigned long long)digest,
               (unsigned long long)(mapped / 1000000), (unsigned long long)realtime,
               (unsigned long long)dequeue);
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
    capture_clock("begin");
    for (unsigned lane = 0; lane < 2; lane++) {
        char name[16];
        snprintf(name, sizeof(name), "eth%u", lane);
        indices[lane] = if_nametoindex(name);
        // Outgoing packets are delivered only to ETH_P_ALL observers.
        unsigned protocol = 3;
        observers[lane] =
            socket(AF_PACKET, SOCK_RAW | SOCK_NONBLOCK | SOCK_CLOEXEC, htons(protocol));
        struct sockaddr_ll address = {.sll_family = AF_PACKET,
                                      .sll_protocol = htons(protocol),
                                      .sll_ifindex = (int)indices[lane]};
        CHECK(observers[lane] >= 0 && indices[lane] &&
              bind(observers[lane], (struct sockaddr*)&address, sizeof(address)) == 0);
        // Linux enables per-packet stamping on the first timestamp query.
        struct timespec initial;
        CHECK(ioctl(observers[lane], SIOCGSTAMPNS, &initial) == -1 && errno == ENOENT);
        printf("ICMP_CAPTURE_READY lane=%u index=%u timestamp_error=%d\n", lane, indices[lane],
               errno);
    }
    CHECK(pthread_create(&observer, NULL, collect, NULL) == 0);
}

static void capture_stop(void) {
    CHECK(usleep(100000) == 0);
    atomic_store(&stop, 1);
    CHECK(pthread_join(observer, NULL) == 0);
    for (unsigned lane = 0; lane < 2; lane++) {
        // Stop future arrivals before draining packets queued after the collector.
        struct sockaddr_ll retired = {.sll_family = AF_PACKET,
                                      .sll_protocol = htons(0x88b6),
                                      .sll_ifindex = (int)indices[lane]};
        CHECK(bind(observers[lane], (struct sockaddr*)&retired, sizeof(retired)) == 0);
        drain(lane);
    }
    capture_clock("end");
    for (unsigned lane = 0; lane < 2; lane++) {
        unsigned statistics[2];
        socklen_t size = sizeof(statistics);
        CHECK(getsockopt(observers[lane], 263, 6, statistics, &size) == 0 &&
              size == sizeof(statistics) && statistics[0] == observed[lane] && !statistics[1]);
        printf("ICMP_CAPTURE_PASS lane=%u index=%u packets=%u dropped=%u ipv4=%u\n", lane,
               indices[lane], statistics[0], statistics[1], ipv4_frames[lane]);
        CHECK(close(observers[lane]) == 0);
    }
}

static void configure(void) {
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    CHECK(fd >= 0);
    for (unsigned lane = 0; lane < 2; lane++) {
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

static int complete_native_error(int fd, int value, uint64_t began, unsigned timeout,
                                 unsigned* empty_reads) {
    while (native && !value && milliseconds() - began < timeout) {
        (*empty_reads)++;
        CHECK(usleep(1000) == 0);
        value = error(fd);
    }
    return value;
}

static unsigned wait_error(int fd, int expected) {
    uint64_t began = milliseconds();
    struct pollfd item = {.fd = fd, .events = POLLOUT};
    CHECK(poll(&item, 1, 3000) == 1 && (item.revents & POLLERR));
    unsigned empty_reads = 0;
    int first = complete_native_error(fd, error(fd), began, 3000, &empty_reads);
    int second = first == expected ? error(fd) : -1;
    if (first != expected || second)
        fprintf(stderr,
                "ICMP_ERROR_READ fd=%d expected=%d events=%x first=%d second=%d empty_reads=%u\n",
                fd, expected, item.revents, first, second, empty_reads);
    CHECK(first == expected && second == 0);
    return empty_reads;
}

static void native_error_order(void) {
    int fd = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK, 0);
    // Linux software transmit timestamps deliberately wake POLLERR before the quoted error.
    int timestamps = (1 << 1) | (1 << 4) | (1 << 11);
    struct sockaddr_in address = {
        .sin_family = AF_INET, .sin_port = htons(49000), .sin_addr.s_addr = htonl(0x0a170101)};
    struct sockaddr_in local = {
        .sin_family = AF_INET, .sin_port = htons(41000), .sin_addr.s_addr = htonl(0x0a170102)};
    CHECK(fd >= 0 && setsockopt(fd, SOL_SOCKET, 37, &timestamps, sizeof(timestamps)) == 0 &&
          bind(fd, (struct sockaddr*)&local, sizeof(local)) == 0 &&
          connect(fd, (struct sockaddr*)&address, sizeof(address)) == -1 && errno == EINPROGRESS);
    struct pollfd ready = {.fd = fd, .events = POLLOUT};
    CHECK(poll(&ready, 1, 3000) == 1 && !(ready.revents & POLLERR) && error(fd) == 0 &&
          send(fd, "one", 3, MSG_NOSIGNAL) == 3);
    uint64_t began = milliseconds();
    unsigned empty_reads = wait_error(fd, ECONNREFUSED);
    CHECK(empty_reads && close(fd) == 0);
    printf("ICMP_ERROR_ORDER_PASS empty_reads=%u error=111 cleared=0 elapsed_ms=%llu\n",
           empty_reads, (unsigned long long)(milliseconds() - began));
}

static void companions_start(void) {
    for (unsigned lane = 0; lane < 2; lane++) {
        struct sockaddr_in address = {.sin_family = AF_INET,
                                      .sin_port = htons(39000 + lane * 1000),
                                      .sin_addr.s_addr = htonl(0x0a170102 + (lane << 8))};
        listeners[lane] = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK, 0);
        CHECK(listeners[lane] >= 0 &&
              bind(listeners[lane], (struct sockaddr*)&address, sizeof(address)) == 0 &&
              listen(listeners[lane], 2) == 0);
        printf("ICMP_COMPANION_LISTEN_READY lane=%u\n", lane);
        struct pollfd ready = {.fd = listeners[lane], .events = POLLIN};
        CHECK(poll(&ready, 1, 3000) == 1 && error(listeners[lane]) == 0);
        socklen_t size = sizeof(address);
        companions[lane][1] =
            accept4(listeners[lane], (struct sockaddr*)&address, &size, SOCK_NONBLOCK);
        CHECK(companions[lane][1] >= 0 && ntohs(address.sin_port) == 57000 + lane * 1000);
        address.sin_port = htons(47000 + lane * 1000);
        address.sin_addr.s_addr = htonl(0x0a170101 + (lane << 8));
        companions[lane][0] = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK, 0);
        CHECK(companions[lane][0] >= 0 &&
              connect(companions[lane][0], (struct sockaddr*)&address, sizeof(address)) == -1 &&
              errno == EINPROGRESS);
        ready.fd = companions[lane][0];
        ready.events = POLLOUT;
        CHECK(poll(&ready, 1, 3000) == 1 && !(ready.revents & POLLERR) && error(ready.fd) == 0);
    }
}

static void companions_check(unsigned lane) {
    struct pollfd listener = {.fd = listeners[lane], .events = POLLIN};
    CHECK(error(listener.fd) == 0 && poll(&listener, 1, 0) == 0);
    for (unsigned role = 0; role < 2; role++) {
        int fd = companions[lane][role];
        struct pollfd ready = {.fd = fd, .events = POLLIN};
        CHECK(error(fd) == 0 && poll(&ready, 1, 0) == 0);
        CHECK(send(fd, "S", 1, MSG_NOSIGNAL) == 1 && poll(&ready, 1, 3000) == 1 &&
              !(ready.revents & POLLERR));
        char byte;
        CHECK(recv(fd, &byte, 1, 0) == 1 && byte == 'Q' && error(fd) == 0);
        companion_checks[lane][role]++;
    }
}

static void companions_stop(void) {
    for (unsigned lane = 0; lane < 2; lane++) {
        for (unsigned role = 0; role < 2; role++) {
            CHECK(companion_checks[lane][role] == ICMP_CASES + 10 &&
                  close(companions[lane][role]) == 0);
            printf("ICMP_COMPANION_PASS lane=%u role=%u checkpoints=%u\n", lane, role,
                   companion_checks[lane][role]);
        }
        CHECK(close(listeners[lane]) == 0);
    }
}

struct operation {
    int fd, result, failure;
    struct sockaddr_in address;
    atomic_int started;
    pthread_t target;
};

static void* connector(void* opaque) {
    struct operation* value = opaque;
    atomic_store(&value->started, 1);
    value->result = connect(value->fd, (struct sockaddr*)&value->address, sizeof(value->address));
    value->failure = errno;
    return NULL;
}

static void* interrupter(void* opaque) {
    struct operation* value = opaque;
    CHECK(usleep(100000) == 0 && pthread_kill(value->target, SIGUSR1) == 0);
    return NULL;
}

static void on_signal(int number) {
    (void)number;
    interrupted++;
}

static void case_complete(unsigned lane, unsigned ordinal, uint64_t began) {
    uint64_t ended = milliseconds();
    printf("ICMP_CASE_PASS lane=%u case=%u name=%s elapsed_ms=%llu start_ms=%llu end_ms=%llu\n",
           lane, ordinal, icmp_cases[ordinal].name, (unsigned long long)(ended - began),
           (unsigned long long)began, (unsigned long long)ended);
}

static void active_case(unsigned lane, unsigned ordinal) {
    const struct icmp_case* test = &icmp_cases[ordinal];
    int blocking =
        test->mode == ICMP_BLOCKING || test->mode == ICMP_INTERRUPT || test->mode == ICMP_RETAINED;
    int fd = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC | (blocking ? 0 : SOCK_NONBLOCK), 0);
    CHECK(fd >= 0);
    if (!strcmp(test->mutation, "other-bound-device")) {
        char name[16];
        snprintf(name, sizeof(name), "eth%u", lane);
        CHECK(setsockopt(fd, SOL_SOCKET, SO_BINDTODEVICE, name, strlen(name) + 1) == 0);
        if (native) {
            // An earlier active connection must not take a later passive test's port.
            for (unsigned passive = 0; passive < ICMP_CASES; passive++) {
                if (icmp_cases[passive].mode != ICMP_PASSIVE_KEEP &&
                    icmp_cases[passive].mode != ICMP_PASSIVE_DROP)
                    continue;
                struct sockaddr_in local = {.sin_family = AF_INET,
                                            .sin_port = htons(40000 + lane * 1000 + passive),
                                            .sin_addr.s_addr = htonl(0x0a170102 + (lane << 8))};
                CHECK(bind(fd, (struct sockaddr*)&local, sizeof(local)) == -1 &&
                      errno == EADDRINUSE);
            }
            printf("ICMP_RESERVED_PORTS_PASS lane=%u\n", lane);
        }
    }
    struct sockaddr_in address = {.sin_family = AF_INET,
                                  .sin_port = htons(48000 + lane * 1000 + ordinal),
                                  .sin_addr.s_addr = htonl(0x0a170101 + (lane << 8))};
    uint64_t began = milliseconds();
    if (test->mode == ICMP_RETAINED) {
        struct operation value = {.fd = fd, .address = address};
        pthread_t thread;
        CHECK(pthread_create(&thread, NULL, connector, &value) == 0);
        while (!atomic_load(&value.started))
            CHECK(usleep(1000) == 0);
        CHECK(usleep(100000) == 0 && close(fd) == 0);
        int reused = open("/dev/null", O_RDONLY | O_CLOEXEC);
        CHECK(reused == fd && pthread_join(thread, NULL) == 0 && value.result == -1 &&
              value.failure == test->error && close(reused) == 0);
        fd = -1;
    } else if (test->mode == ICMP_INTERRUPT) {
        interrupted = 0;
        struct operation value = {.target = pthread_self()};
        pthread_t thread;
        CHECK(pthread_create(&thread, NULL, interrupter, &value) == 0);
        CHECK(connect(fd, (struct sockaddr*)&address, sizeof(address)) == -1 && errno == EINTR);
        CHECK(pthread_join(thread, NULL) == 0 && interrupted == 1);
        wait_error(fd, test->error);
    } else if (blocking) {
        CHECK(connect(fd, (struct sockaddr*)&address, sizeof(address)) == -1 &&
              errno == test->error);
        CHECK(error(fd) == 0);
    } else {
        CHECK(connect(fd, (struct sockaddr*)&address, sizeof(address)) == -1 &&
              errno == EINPROGRESS);
        int held = dup(fd);
        CHECK(held >= 0 && close(fd) == 0);
        fd = held;
        if (test->mode == ICMP_PENDING || test->mode == ICMP_RETRY) {
            int epoll = epoll_create1(EPOLL_CLOEXEC);
            struct epoll_event interest = {.events = EPOLLOUT, .data.fd = fd}, ready;
            CHECK(epoll >= 0 && epoll_ctl(epoll, EPOLL_CTL_ADD, fd, &interest) == 0 &&
                  epoll_wait(epoll, &ready, 1, 3000) == 1 && (ready.events & EPOLLERR) &&
                  ready.data.fd == fd && close(epoll) == 0);
            wait_error(fd, test->error);
            if (test->mode == ICMP_RETRY) {
                CHECK(connect(fd, (struct sockaddr*)&address, sizeof(address)) == -1 &&
                      errno == ECONNABORTED);
                CHECK(connect(fd, (struct sockaddr*)&address, sizeof(address)) == -1 &&
                      errno == EINPROGRESS);
                struct pollfd item = {.fd = fd, .events = POLLOUT};
                uint64_t deadline = milliseconds() + 3000;
                int ready, reported;
                do {
                    CHECK(milliseconds() < deadline);
                    ready = poll(&item, 1, (int)(deadline - milliseconds()));
                    reported = error(fd);
                    CHECK(ready == 1 && !reported);
                    if (!(item.revents & POLLOUT)) {
                        // Linux can retain an asynchronous error readiness flag
                        // after SO_ERROR was consumed and a new connect began.
                        printf("ICMP_RETRY_EVENT lane=%u events=%x error=%d\n", lane, item.revents,
                               reported);
                        CHECK(usleep(1000) == 0);
                    }
                } while (!(item.revents & POLLOUT));
                printf("ICMP_RETRY_RESULT lane=%u poll=%d events=%x error=%d\n", lane, ready,
                       item.revents, reported);
                CHECK(ready == 1 && (item.revents & POLLOUT) && !reported);
            }
        } else if (test->mode == ICMP_IGNORE) {
            struct pollfd item = {.fd = fd, .events = POLLOUT};
            int ready = poll(&item, 1, 200);
            int reported = error(fd);
            if (native && ready == 1 && (item.revents & POLLERR)) {
                unsigned empty_reads = 0;
                reported = complete_native_error(fd, reported, began, 200, &empty_reads);
            }
            printf("ICMP_QUOTE_RESULT lane=%u case=%u native=%d poll=%d events=%x error=%d "
                   "elapsed_ms=%llu\n",
                   lane, ordinal, native, ready, item.revents, reported,
                   (unsigned long long)(milliseconds() - began));
            if (native && reported) {
                CHECK(reported == ECONNREFUSED && ready == 1 && (item.revents & POLLERR));
            } else {
                CHECK(ready == 0 && !reported);
                CHECK(poll(&item, 1, 3000) == 1 && !(item.revents & POLLERR) && error(fd) == 0);
            }
        } else {
            struct pollfd connected = {.fd = fd, .events = POLLOUT};
            CHECK(poll(&connected, 1, 3000) == 1 && !(connected.revents & POLLERR) &&
                  error(fd) == 0);
            if (test->mode == ICMP_TIME_WAIT) {
                CHECK(shutdown(fd, SHUT_WR) == 0);
                struct pollfd ended = {.fd = fd, .events = POLLIN};
                CHECK(poll(&ended, 1, 3000) == 1);
                char byte;
                CHECK(recv(fd, &byte, 1, 0) == 0 && usleep(250000) == 0 && error(fd) == 0);
                CHECK(send(fd, "x", 1, MSG_NOSIGNAL) == -1 && errno == EPIPE);
                goto completed;
            }
            int timeout = 2500;
            CHECK(setsockopt(fd, IPPROTO_TCP, TCP_USER_TIMEOUT, &timeout, sizeof(timeout)) == 0);
            CHECK(send(fd, "one", 3, MSG_NOSIGNAL) == 3);
            struct pollfd input = {.fd = fd, .events = POLLIN};
            CHECK(poll(&input, 1, 300) == 0);
            if (test->mode == ICMP_CONSUME) {
                if (!native) {
                    socklen_t size = sizeof(int);
                    volatile uintptr_t denied = 1;
                    CHECK(getsockopt(fd, SOL_SOCKET, SO_ERROR, (void*)denied, &size) == -1 &&
                          errno == EFAULT);
                }
                int reported = error(fd);
                CHECK(reported == ECONNREFUSED && error(fd) == 0);
                printf("ICMP_SOFT_CONSUMED lane=%u error=%d\n", lane, reported);
            }
            if (test->mode == ICMP_RECOVER) {
                CHECK(poll(&input, 1, 3000) == 1 && !(input.revents & POLLERR));
                char reply;
                CHECK(recv(fd, &reply, 1, 0) == 1 && reply == 'K' && error(fd) == 0);
                CHECK(send(fd, "two", 3, MSG_NOSIGNAL) == 3);
            }
            uint64_t pending = milliseconds();
            char byte;
            if (lane == 0 && !strcmp(test->name, "soft-port")) {
                int flags = fcntl(fd, F_GETFL);
                CHECK(flags >= 0 && fcntl(fd, F_SETFL, flags & ~O_NONBLOCK) == 0);
                CHECK(recv(fd, &byte, 1, 0) == -1 && errno == test->error);
                printf("ICMP_BLOCKED_READ_PASS lane=%u error=%d\n", lane, test->error);
            } else {
                CHECK(poll(&input, 1, 5000) == 1 && (input.revents & POLLERR));
                CHECK(error(fd) == test->error);
            }
            int diagnostic = error(fd);
            CHECK(diagnostic == (test->mode == ICMP_SOFT ? test->error : 0));
            CHECK(error(fd) == 0 && milliseconds() - pending >= 1500);
            printf("ICMP_TERMINAL_ERRORS lane=%u case=%u hard=%d diagnostic=%d\n", lane, ordinal,
                   test->error, diagnostic);
            CHECK(recv(fd, &byte, 1, 0) == 0);
            CHECK(send(fd, "x", 1, MSG_NOSIGNAL) == -1 && errno == EPIPE);
        }
    }
completed:
    if (fd >= 0)
        CHECK(close(fd) == 0);
    case_complete(lane, ordinal, began);
}

static void passive_start(void) {
    // Reserve fixed passive ports before any active connection can select one.
    for (unsigned lane = 0; lane < 2; lane++) {
        for (unsigned ordinal = 0; ordinal < ICMP_CASES; ordinal++) {
            if (icmp_cases[ordinal].mode != ICMP_PASSIVE_KEEP &&
                icmp_cases[ordinal].mode != ICMP_PASSIVE_DROP)
                continue;
            int listener = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK, 0);
            struct sockaddr_in address = {.sin_family = AF_INET,
                                          .sin_port = htons(40000 + lane * 1000 + ordinal),
                                          .sin_addr.s_addr = htonl(0x0a170102 + (lane << 8))};
            CHECK(listener >= 0 &&
                  bind(listener, (struct sockaddr*)&address, sizeof(address)) == 0 &&
                  listen(listener, 2) == 0);
            passive_listeners[lane][ordinal] = listener;
        }
    }
}

static void passive_case(unsigned lane, unsigned ordinal) {
    int listener = passive_listeners[lane][ordinal];
    struct sockaddr_in address;
    printf("ICMP_LISTEN_READY lane=%u case=%u\n", lane, ordinal);
    uint64_t began = milliseconds();
    struct pollfd ready = {.fd = listener, .events = POLLIN};
    CHECK(poll(&ready, 1, 3000) == 1 && error(listener) == 0);
    socklen_t size = sizeof(address);
    int fd = accept4(listener, (struct sockaddr*)&address, &size, SOCK_CLOEXEC);
    unsigned replacement = icmp_cases[ordinal].mode == ICMP_PASSIVE_DROP;
    CHECK(fd >= 0 && ntohs(address.sin_port) == 56000 + lane * 1000 + ordinal * 2 + replacement);
    CHECK(error(fd) == 0 && send(fd, "P", 1, MSG_NOSIGNAL) == 1 && close(fd) == 0 &&
          close(listener) == 0);
    case_complete(lane, ordinal, began);
}

static void cycles(void) {
    int baseline = open("/dev/null", O_RDONLY);
    CHECK(baseline >= 0 && close(baseline) == 0);
    for (unsigned cycle = 0; cycle < ICMP_CYCLES; cycle++) {
        uint64_t began = milliseconds();
        unsigned lane = cycle & 1;
        int fd = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK, 0);
        struct sockaddr_in address = {.sin_family = AF_INET,
                                      .sin_port = htons(49000 + lane * 1000),
                                      .sin_addr.s_addr = htonl(0x0a170101 + (lane << 8))};
        struct sockaddr_in local = {.sin_family = AF_INET,
                                    .sin_port = htons(41000 + lane),
                                    .sin_addr.s_addr = htonl(0x0a170102 + (lane << 8))};
        CHECK(fd == baseline && bind(fd, (struct sockaddr*)&local, sizeof(local)) == 0 &&
              connect(fd, (struct sockaddr*)&address, sizeof(address)) == -1 &&
              errno == EINPROGRESS);
        struct pollfd pending = {.fd = fd, .events = POLLOUT};
        CHECK(poll(&pending, 1, 75) == 0 && error(fd) == 0);
        uint64_t ignored = milliseconds();
        wait_error(fd, ECONNREFUSED);
        CHECK(close(fd) == 0);
        printf("ICMP_CYCLE_PASS cycle=%u lane=%u fd=%d start_ms=%llu ignored_ms=%llu end_ms=%llu\n",
               cycle, lane, baseline, (unsigned long long)began, (unsigned long long)ignored,
               (unsigned long long)milliseconds());
        if (cycle % 16 == 15) {
            companions_check(0);
            companions_check(1);
        }
    }
    puts("ICMP_RECLAMATION_PASS cycles=128");
}

int main(int argc, char** argv) {
    setvbuf(stdout, NULL, _IONBF, 0);
    CHECK(argc == 1 || (argc == 2 && (!strcmp(argv[1], "--native") ||
                                      !strcmp(argv[1], "--native-error-order-check"))));
    native = argc == 2;
    signal(SIGPIPE, SIG_IGN);
    struct sigaction action = {.sa_handler = on_signal};
    CHECK(sigemptyset(&action.sa_mask) == 0 && sigaction(SIGUSR1, &action, NULL) == 0);
    alarm(210);
    if (native && !strcmp(argv[1], "--native-error-order-check")) {
        native_error_order();
        return 0;
    }
    if (!native)
        configure();
    capture_start();
    puts("TCP_ICMP_CONFIG_PASS nics=2");
    passive_start();
    companions_start();
    for (unsigned lane = 0; lane < 2; lane++) {
        for (unsigned ordinal = 0; ordinal < ICMP_CASES; ordinal++) {
            if (icmp_cases[ordinal].mode == ICMP_PASSIVE_KEEP ||
                icmp_cases[ordinal].mode == ICMP_PASSIVE_DROP)
                passive_case(lane, ordinal);
            else
                active_case(lane, ordinal);
            companions_check(lane);
            if (!strncmp(icmp_cases[ordinal].mutation, "other-", 6))
                companions_check(1 - lane);
        }
    }
    cycles();
    companions_stop();
    capture_stop();
    printf("TCP_ICMP_PASS cases=%zu nics=2 cycles=%u\n", ICMP_CASES, ICMP_CYCLES);
}
