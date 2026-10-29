// SPDX-License-Identifier: GPL-3.0-or-later
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <net/if.h>
#include <netinet/icmp6.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <unistd.h>

static unsigned cases, sent_id;
static const int options[3] = {IPV6_RECVPKTINFO, IPV6_RECVHOPLIMIT, IPV6_RECVTCLASS};

static void check(int condition, const char* reason) {
    if (!condition) {
        fprintf(stderr, "IPV6_CONTROL_FAIL case=%u %s errno=%d\n", cases, reason, errno);
        exit(1);
    }
}

static void configure(int fd, unsigned mask) {
    for (unsigned n = 0; n < 3; n++) {
        int value = mask & (1u << n) ? -7 : 0;
        check(!setsockopt(fd, IPPROTO_IPV6, options[n], &value, sizeof(value)), "receive option");
        socklen_t length = sizeof(value);
        check(!getsockopt(fd, IPPROTO_IPV6, options[n], &value, &length) &&
                  length == sizeof(value) && value == !!(mask & (1u << n)),
              "shared normalized receive option");
    }
}

static void ready(int fd) {
    struct pollfd value = {.fd = fd, .events = POLLIN};
    check(poll(&value, 1, 1000) == 1 && value.revents == POLLIN, "actual local data available");
}

static void emit(int fd, int kind, const struct sockaddr_in6* destination, unsigned id) {
    sent_id = id;
    unsigned char data[32] = {0};
    data[0] = 128;
    data[4] = 0x6d;
    data[5] = 0x43;
    data[6] = id >> 8;
    data[7] = id;
    check(sendto(fd, data, sizeof(data), 0, (const struct sockaddr*)destination,
                 sizeof(*destination)) == sizeof(data),
          kind ? "actual raw loopback send" : "actual UDP loopback send");
}

static void sample(int fd, int kind, unsigned mask, unsigned mode, size_t capacity,
                   unsigned char* control, size_t visible, unsigned flags, size_t wanted,
                   unsigned char* payload) {
    unsigned char output[32] = {0};
    struct iovec vector = {.iov_base = payload ? payload : output, .iov_len = wanted};
    struct msghdr message = {
        .msg_iov = &vector, .msg_iovlen = 1, .msg_control = control, .msg_controllen = capacity};
    ready(fd);
    errno = 0;
    long result = recvmsg(fd, &message, flags | MSG_DONTWAIT);
    int error = result < 0 ? errno : 0;
    printf("IPV6_CONTROL_LOCAL case=%u kind=%d mask=%u mode=%u capacity=%zu visible=%zu "
           "input_flags=%u wanted=%zu result=%ld errno=%d length=%zu flags=%u bytes=",
           cases++, kind, mask, mode, capacity, visible, flags, wanted, result, error,
           (size_t)message.msg_controllen, (unsigned)message.msg_flags);
    for (size_t n = 0; n < visible; n++)
        printf("%02x", control[n]);
    printf(" data=");
    if (!payload) {
        check(result == (long)((flags & MSG_TRUNC) ? 32 : wanted),
              "actual received payload length");
        for (size_t n = 0; n < wanted; n++) {
            unsigned value = n == 0   ? 128
                             : n == 4 ? 0x6d
                             : n == 5 ? 0x43
                             : n == 6 ? sent_id >> 8
                             : n == 7 ? sent_id & 255
                                      : 0;
            check((kind && (n == 2 || n == 3)) || output[n] == value,
                  "received bytes belong to the actual controlled send");
            printf("%02x", output[n]);
        }
        if (kind && wanted == sizeof(output)) {
            unsigned sum = 32 + IPPROTO_ICMPV6 + 2;
            for (unsigned n = 0; n < sizeof(output); n += 2)
                sum += ((unsigned)output[n] << 8) | output[n + 1];
            while (sum >> 16)
                sum = (sum & 65535) + (sum >> 16);
            check(sum == 65535, "actual raw loopback checksum");
        }
    } else
        check(result == -1 && error == EFAULT, "actual payload guard fault");
    puts("");
}

static void local_contract(int kind) {
    int fd = socket(AF_INET6, kind ? SOCK_RAW : SOCK_DGRAM, kind ? IPPROTO_ICMPV6 : IPPROTO_UDP);
    check(fd >= 0, "local metadata socket");
    struct sockaddr_in6 destination = {.sin6_family = AF_INET6, .sin6_addr = IN6ADDR_LOOPBACK_INIT};
    check(!bind(fd, (struct sockaddr*)&destination, sizeof(destination)), "local metadata bind");
    socklen_t size = sizeof(destination);
    check(!getsockname(fd, (struct sockaddr*)&destination, &size), "local destination");
    int sender = kind ? fd : socket(AF_INET6, SOCK_DGRAM, IPPROTO_UDP);
    check(sender >= 0, "local metadata sender");
    if (kind) {
        struct icmp6_filter filter;
        ICMP6_FILTER_SETBLOCKALL(&filter);
        ICMP6_FILTER_SETPASS(ICMP6_ECHO_REQUEST, &filter);
        check(!setsockopt(fd, IPPROTO_ICMPV6, ICMP6_FILTER, &filter, sizeof(filter)),
              "isolate actual raw echo requests");
        destination.sin6_port = 0;
    }
    unsigned char control[128];
    static const unsigned capacities[] = {0,  1,  7,  15, 16, 17, 19, 20, 23, 24, 31, 32,
                                          35, 36, 37, 39, 40, 41, 55, 56, 59, 60, 63, 64,
                                          65, 79, 80, 83, 84, 85, 87, 88, 89, 96};
    for (unsigned mask = 0; mask < 8; mask++) {
        configure(fd, mask);
        for (unsigned n = 0; n < sizeof(capacities) / sizeof(capacities[0]); n++) {
            memset(control, 0xa5, sizeof(control));
            emit(sender, kind, &destination, cases);
            sample(fd, kind, mask, 0, capacities[n], control, sizeof(control), 0, 32, NULL);
        }
    }
    unsigned char* pages =
        mmap(NULL, 8192, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    check(pages != MAP_FAILED && !mprotect(pages + 4096, 4096, PROT_NONE), "control copy guard");
    static const unsigned prefixes[] = {0,  1,  7,  8,  9,  11, 12, 13, 15, 16, 17, 19, 20, 23,
                                        24, 25, 31, 32, 33, 35, 36, 37, 39, 40, 41, 47, 48, 55,
                                        56, 63, 64, 67, 79, 80, 83, 84, 87, 88, 89, 96};
    configure(fd, 7);
    for (unsigned n = 0; n < sizeof(prefixes) / sizeof(prefixes[0]); n++) {
        memset(pages, 0xa5, 4096);
        emit(sender, kind, &destination, cases);
        sample(fd, kind, 7, 1, 96, pages + 4096 - prefixes[n], prefixes[n], 0, 32, NULL);
    }
    for (unsigned mode = 2; mode < 4; mode++) {
        emit(sender, kind, &destination, cases);
        sample(fd, kind, 7, mode, 96, mode == 2 ? NULL : (unsigned char*)1, 0, 0, 32, NULL);
    }
    for (unsigned flags = 0; flags < 4; flags++) {
        memset(control, 0xa5, sizeof(control));
        emit(sender, kind, &destination, cases);
        unsigned value = (flags & 1 ? MSG_PEEK : 0) | (flags & 2 ? MSG_TRUNC : 0);
        sample(fd, kind, 7, 4, 96, control, sizeof(control), value, 8, NULL);
        if (value & MSG_PEEK) {
            memset(control, 0xa5, sizeof(control));
            sample(fd, kind, 7, 4, 96, control, sizeof(control), 0, 32, NULL);
        }
    }
    int alias = dup(fd);
    check(alias >= 0, "shared metadata alias");
    configure(fd, 0);
    emit(sender, kind, &destination, cases);
    ready(fd);
    configure(alias, 7);
    memset(control, 0xa5, sizeof(control));
    sample(fd, kind, 7, 5, 96, control, sizeof(control), 0, 32, NULL);
    emit(sender, kind, &destination, cases);
    ready(fd);
    configure(alias, 0);
    memset(control, 0xa5, sizeof(control));
    sample(fd, kind, 0, 5, 96, control, sizeof(control), 0, 32, NULL);
    check(!close(alias), "close metadata alias");
    for (unsigned peek = 0; peek < 2; peek++) {
        configure(fd, 7);
        memset(control, 0xa5, sizeof(control));
        emit(sender, kind, &destination, cases);
        sample(fd, kind, 7, 6, 96, control, sizeof(control), peek ? MSG_PEEK : 0, 32, pages + 4096);
        struct pollfd pending = {.fd = fd, .events = POLLIN};
        check(poll(&pending, 1, 0) == (int)peek, "payload fault queue ownership");
        if (peek) {
            memset(control, 0xa5, sizeof(control));
            sample(fd, kind, 7, 6, 96, control, sizeof(control), 0, 32, NULL);
        }
    }
    check(!munmap(pages, 8192), "release control guards");
    if (sender != fd)
        check(!close(sender), "close metadata sender");
    check(!close(fd), "final metadata description release");
}

#ifdef IPV6_CONTROLS_INTEGRATED
int ipv6_controls_local(void) {
#else
int main(void) {
#endif
    unsigned index = if_nametoindex("lo");
    check(index && index < 256, "actual loopback interface index");
    printf("IPV6_CONTROL_INTERFACE loopback=%u\n", index);
    local_contract(0);
    local_contract(1);
    printf("IPV6_CONTROL_LOCAL_DONE cases=%u transports=2 capacities=34 guards=40\n", cases);
    return 0;
}
