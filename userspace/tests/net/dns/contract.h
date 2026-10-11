#ifndef AXIOM64_TEST_DNS_CONTRACT_H
#define AXIOM64_TEST_DNS_CONTRACT_H
// SPDX-License-Identifier: GPL-3.0-or-later
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <net/if.h>
#include <netdb.h>
#include <netpacket/packet.h>
#include <poll.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

#ifndef DNS_LINKAGE
#define DNS_LINKAGE "static"
#endif

#ifndef DNS_CAPTURE_FRAMES
#define DNS_CAPTURE_FRAMES 1024
#endif

static void check(int condition, const char* label) {
    if (!condition) {
        fprintf(stderr, "DNS_FAIL linkage=%s label=%s errno=%d\n", DNS_LINKAGE, label, errno);
        exit(1);
    }
}

static long milliseconds(void) {
    struct timespec now;
    check(clock_gettime(CLOCK_MONOTONIC, &now) == 0, "monotonic clock");
    return now.tv_sec * 1000L + now.tv_nsec / 1000000;
}

struct capture {
    int descriptors[2];
    unsigned indices[2], packets[2];
    atomic_int stop;
    pthread_t thread;
    unsigned count;

    struct {
        unsigned lane, length, kind;
        unsigned long long hash;
        long milliseconds;
    } frames[DNS_CAPTURE_FRAMES];
};

static void capture_drain(struct capture* state, unsigned lane) {
    for (;;) {
        unsigned char frame[2048];
        struct sockaddr_ll source;
        socklen_t length = sizeof(source);
        ssize_t size = recvfrom(state->descriptors[lane], frame, sizeof(frame), MSG_DONTWAIT,
                                (struct sockaddr*)&source, &length);
        if (size < 0) {
            check(errno == EAGAIN, "capture queue drain");
            return;
        }
        check(size >= 14 && size <= (ssize_t)sizeof(frame) && length == sizeof(source) &&
                  source.sll_family == AF_PACKET &&
                  source.sll_ifindex == (int)state->indices[lane] &&
                  source.sll_protocol == htons(0x800) && source.sll_halen == 6,
              "actual IPv4 frame metadata");
        unsigned long long hash = 0xcbf29ce484222325ULL;
        for (ssize_t i = 0; i < size; i++)
            hash = (hash ^ frame[i]) * 0x100000001b3ULL;
        check(state->count < sizeof(state->frames) / sizeof(state->frames[0]),
              "bounded frame receipts");
        state->frames[state->count].lane = lane;
        state->frames[state->count].length = (unsigned)size;
        state->frames[state->count].kind = source.sll_pkttype;
        state->frames[state->count].hash = hash;
        state->frames[state->count++].milliseconds = milliseconds();
        state->packets[lane]++;
    }
}

static void* capture_run(void* opaque) {
    struct capture* state = opaque;
    struct pollfd wait[2] = {{.fd = state->descriptors[0], .events = POLLIN},
                             {.fd = state->descriptors[1], .events = POLLIN}};
    long stopping = 0, quiet = 0;
    for (;;) {
        check(poll(wait, 2, 10) >= 0, "capture poll");
        unsigned before = state->count;
        for (unsigned lane = 0; lane < 2; lane++)
            capture_drain(state, lane);
        if (atomic_load(&state->stop)) {
            long now = milliseconds();
            if (!stopping)
                stopping = quiet = now;
            if (state->count != before)
                quiet = now;
            // Closing resolver sockets can complete their TCP handshake asynchronously.
            check(now - stopping <= 2000, "bounded final driver observer drain");
            if (now - quiet >= 100)
                break;
        }
    }
    return NULL;
}

static void capture_start(struct capture* state) {
    for (unsigned lane = 0; lane < 2; lane++) {
        char name[IF_NAMESIZE];
        snprintf(name, sizeof(name), "eth%u", lane);
        state->indices[lane] = if_nametoindex(name);
        check(state->indices[lane] != 0, "capture interface index");
        state->descriptors[lane] =
            socket(AF_PACKET, SOCK_RAW | SOCK_NONBLOCK | SOCK_CLOEXEC, htons(0x800));
        struct sockaddr_ll address = {.sll_family = AF_PACKET,
                                      .sll_protocol = htons(0x800),
                                      .sll_ifindex = (int)state->indices[lane]};
        check(state->descriptors[lane] >= 0 &&
                  bind(state->descriptors[lane], (struct sockaddr*)&address, sizeof(address)) == 0,
              "capture IPv4 socket binding");
    }
    check(pthread_create(&state->thread, NULL, capture_run, state) == 0, "capture thread");
}

static void capture_stop(struct capture* state) {
    atomic_store(&state->stop, 1);
    check(pthread_join(state->thread, NULL) == 0, "capture join");
    for (unsigned i = 0; i < state->count; i++)
        printf("DNS_FRAME linkage=%s index=%u length=%u hash=%016llx packet_type=%u "
               "monotonic_ms=%ld\n",
               DNS_LINKAGE, state->frames[i].lane + 1, state->frames[i].length,
               state->frames[i].hash, state->frames[i].kind, state->frames[i].milliseconds);
    for (unsigned lane = 0; lane < 2; lane++) {
        uint32_t statistics[2] = {0};
        socklen_t length = sizeof(statistics);
        int status = getsockopt(state->descriptors[lane], SOL_PACKET, PACKET_STATISTICS, statistics,
                                &length);
        if (status || length != sizeof(statistics) || statistics[1] ||
            statistics[0] != state->packets[lane])
            fprintf(
                stderr,
                "DNS_CAPTURE_FAIL index=%u status=%d length=%u packets=%u received=%u dropped=%u\n",
                lane + 1, status, length, statistics[0], state->packets[lane], statistics[1]);
        check(status == 0 && length == sizeof(statistics) && statistics[1] == 0 &&
                  statistics[0] == state->packets[lane],
              "capture retains every actual frame");
        check(close(state->descriptors[lane]) == 0, "capture close");
        printf("DNS_CAPTURE_PASS linkage=%s index=%u packets=%u dropped=%u\n", DNS_LINKAGE,
               lane + 1, statistics[0], statistics[1]);
    }
}

static void configure(void) {
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    check(fd >= 0, "configuration socket");
    for (unsigned lane = 0; lane < 2; lane++) {
        struct ifreq request = {0};
        snprintf(request.ifr_name, sizeof(request.ifr_name), "eth%u", lane);
        struct sockaddr_in value = {.sin_family = AF_INET,
                                    .sin_addr.s_addr = htonl(0x0a170102 + (lane << 8))};
        memcpy(&request.ifr_addr, &value, sizeof(value));
        check(ioctl(fd, SIOCSIFADDR, &request) == 0, "interface address");
        value.sin_addr.s_addr = htonl(0xffffff00);
        memcpy(&request.ifr_netmask, &value, sizeof(value));
        check(ioctl(fd, SIOCSIFNETMASK, &request) == 0, "interface mask");
        check(ioctl(fd, SIOCGIFFLAGS, &request) == 0, "interface flags");
        request.ifr_flags |= IFF_UP;
        check(ioctl(fd, SIOCSIFFLAGS, &request) == 0, "interface up");
    }
    check(close(fd) == 0, "configuration close");
}

static void resolver_options(unsigned lane, int both, const char* search, unsigned timeout) {
    FILE* file = fopen("/etc/resolv.conf", "w");
    check(file != NULL, "private fixture resolver file");
    if (both)
        check(fputs("nameserver 10.23.1.1\nnameserver 10.23.2.1\n", file) >= 0, "two nameservers");
    else
        check(fprintf(file, "nameserver 10.23.%u.1\n", lane + 1) > 0, "nameserver");
    if (search)
        check(fprintf(file, "search %s\n", search) > 0, "search domains");
    check(fprintf(file, "options ndots:2 attempts:2 timeout:%u\n", timeout) > 0 &&
              fclose(file) == 0,
          "resolver options and close");
}

static void resolver(unsigned lane, int both, const char* search) {
    resolver_options(lane, both, search, 1);
}

static void lookup(const char* label, const char* name, int expected_error, unsigned expected,
                   unsigned count, const char* canonical, long minimum, long maximum, int report) {
    struct addrinfo hints = {.ai_family = AF_INET,
                             .ai_socktype = SOCK_STREAM,
                             .ai_flags = AI_CANONNAME | AI_NUMERICSERV};
    struct addrinfo* result = NULL;
    long started = milliseconds();
    int error = getaddrinfo(name, "8080", &hints, &result);
    long elapsed = milliseconds() - started;
    if (error != expected_error) {
        fprintf(stderr, "DNS_FAIL linkage=%s label=%s gai=%d expected=%d elapsed_ms=%ld\n",
                DNS_LINKAGE, label, error, expected_error, elapsed);
        exit(1);
    }
    check(elapsed >= minimum && elapsed <= maximum, label);
    unsigned actual = 0;
    uint64_t addresses = 0;
    for (struct addrinfo* item = result; item; item = item->ai_next) {
        check(item->ai_family == AF_INET && item->ai_socktype == SOCK_STREAM &&
                  item->ai_protocol == IPPROTO_TCP &&
                  item->ai_addrlen == sizeof(struct sockaddr_in),
              "address metadata");
        const struct sockaddr_in* address = (const struct sockaddr_in*)item->ai_addr;
        unsigned ip = ntohl(address->sin_addr.s_addr);
        check(address->sin_family == AF_INET && ntohs(address->sin_port) == 8080,
              "address and service");
        check(ip >= expected && ip - expected < count && count < 64, "fixture address bytes");
        uint64_t bit = UINT64_C(1) << (ip - expected);
        check(!(addresses & bit), "unique addresses");
        addresses |= bit;
        actual++;
    }
    check(actual == count && (!count || addresses == ((UINT64_C(1) << count) - 1)),
          "complete result list");
    if (canonical)
        check(result && result->ai_canonname && strcmp(result->ai_canonname, canonical) == 0,
              "canonical name");
    if (result)
        freeaddrinfo(result);
    if (report)
        printf("DNS_CASE_PASS linkage=%s case=%s gai=%d addresses=%u elapsed_ms=%ld\n", DNS_LINKAGE,
               label, error, actual, elapsed);
}

#endif
