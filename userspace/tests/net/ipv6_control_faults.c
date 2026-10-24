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

static unsigned cases;

static void check(int condition, const char* message) {
    if (!condition) {
        fprintf(stderr, "IPV6_CONTROL_FAULT_FAIL case=%u %s errno=%d\n", cases, message, errno);
        exit(1);
    }
}

static void bytes(const unsigned char* data, size_t size) {
    for (size_t at = 0; at < size; at++)
        printf("%02x", data[at]);
}

static void observe(int fd, int sender, int raw, struct sockaddr_in6* destination,
                    unsigned char* pages, unsigned char* length_pages, unsigned operation,
                    unsigned peek, unsigned prefix, unsigned length_mode) {
    unsigned id = cases;
    unsigned char sent[32] = {128, 0, 0, 0, 0x72, 0x43, id >> 8, id};
    check(sendto(sender, sent, sizeof(sent), 0, (struct sockaddr*)destination,
                 sizeof(*destination)) == sizeof(sent),
          "actual send");
    struct pollfd ready = {.fd = fd, .events = POLLIN};
    check(poll(&ready, 1, 1000) == 1 && ready.revents == POLLIN, "actual queued data");
    unsigned char control[96], payload[32], drain[32];
    memset(control, 0xa5, sizeof(control));
    memset(payload, 0xa5, sizeof(payload));
    memset(drain, 0xa5, sizeof(drain));
    memset(pages, 0xa5, 4096);
    unsigned char* name = length_mode == 3 ? NULL : pages + 4096 - prefix;
    struct iovec vector = {.iov_base = payload, .iov_len = sizeof(payload)};
    struct msghdr message = {.msg_name = name,
                             .msg_namelen = 40,
                             .msg_iov = &vector,
                             .msg_iovlen = 1,
                             .msg_control = control,
                             .msg_controllen = sizeof(control),
                             .msg_flags = 0x5a5a};
    socklen_t* length = &message.msg_namelen;
    if (length_mode) {
        check(!mprotect(length_pages + 4096, 4096, PROT_READ | PROT_WRITE),
              "prepare readable length");
        length = (socklen_t*)(length_pages + 4096);
        *length = 40;
        check(!mprotect(length_pages + 4096, 4096, PROT_READ), "read-only output length");
    }
    unsigned flags = MSG_DONTWAIT | (peek ? MSG_PEEK : 0);
    errno = 0;
    long result =
        operation ? recvfrom(fd, payload, sizeof(payload), flags, (struct sockaddr*)name, length)
                  : recvmsg(fd, &message, flags);
    int error = result < 0 ? errno : 0;
    errno = 0;
    long queued = recv(fd, drain, sizeof(drain), MSG_DONTWAIT);
    int queue_error = queued < 0 ? errno : 0;
    printf("IPV6_CONTROL_FAULT case=%u kind=%d operation=%u peek=%u prefix=%u length_mode=%u "
           "result=%ld errno=%d name_length=%u length=%zu flags=%u queued=%ld queue_errno=%d "
           "name=",
           cases++, raw, operation, peek, prefix, length_mode, result, error, *length,
           (size_t)message.msg_controllen, (unsigned)message.msg_flags, queued, queue_error);
    bytes(name, prefix);
    printf(" control=");
    bytes(control, sizeof(control));
    printf(" payload=");
    bytes(payload, sizeof(payload));
    printf(" drain=");
    bytes(drain, sizeof(drain));
    puts("");
    check(poll(&ready, 1, 0) == 0, "fault and peek queue ownership");
}

static void contract(int raw) {
    int fd = socket(AF_INET6, raw ? SOCK_RAW : SOCK_DGRAM, raw ? IPPROTO_ICMPV6 : IPPROTO_UDP);
    check(fd >= 0, "receive socket");
    struct sockaddr_in6 destination = {.sin6_family = AF_INET6, .sin6_addr = IN6ADDR_LOOPBACK_INIT};
    check(!bind(fd, (struct sockaddr*)&destination, sizeof(destination)), "receive bind");
    socklen_t length = sizeof(destination);
    check(!getsockname(fd, (struct sockaddr*)&destination, &length), "receive address");
    int sender = raw ? fd : socket(AF_INET6, SOCK_DGRAM, IPPROTO_UDP);
    check(sender >= 0, "actual sender");
    if (raw) {
        struct icmp6_filter filter;
        ICMP6_FILTER_SETBLOCKALL(&filter);
        ICMP6_FILTER_SETPASS(ICMP6_ECHO_REQUEST, &filter);
        check(!setsockopt(fd, IPPROTO_ICMPV6, ICMP6_FILTER, &filter, sizeof(filter)), "raw filter");
        destination.sin6_port = 0;
    } else {
        struct sockaddr_in6 source = {
            .sin6_family = AF_INET6, .sin6_port = htons(53567), .sin6_addr = IN6ADDR_LOOPBACK_INIT};
        check(!bind(sender, (struct sockaddr*)&source, sizeof(source)), "owned sender port");
    }
    const int options[] = {IPV6_RECVPKTINFO, IPV6_RECVHOPLIMIT, IPV6_RECVTCLASS};
    for (unsigned n = 0; n < sizeof(options) / sizeof(options[0]); n++) {
        int enabled = 1;
        check(!setsockopt(fd, IPPROTO_IPV6, options[n], &enabled, sizeof(enabled)),
              "receive control");
    }
    unsigned char* pages =
        mmap(NULL, 8192, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    check(pages != MAP_FAILED && !mprotect(pages + 4096, 4096, PROT_NONE), "name guard");
    unsigned char* length_pages =
        mmap(NULL, 8192, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    check(length_pages != MAP_FAILED, "length guard pages");
    const unsigned prefixes[] = {0, 1, 4, 7, 8, 15, 16, 23, 24, 27, 28, 40};
    for (unsigned operation = 0; operation < 2; operation++)
        for (unsigned peek = 0; peek < 2; peek++)
            for (unsigned n = 0; n < sizeof(prefixes) / sizeof(prefixes[0]); n++)
                observe(fd, sender, raw, &destination, pages, length_pages, operation, peek,
                        prefixes[n], 0);
    const unsigned length_prefixes[] = {40, 1, 0};
    for (unsigned peek = 0; peek < 2; peek++)
        for (unsigned mode = 1; mode < 4; mode++)
            observe(fd, sender, raw, &destination, pages, length_pages, 1, peek,
                    length_prefixes[mode - 1], mode);
    check(!munmap(pages, 8192) && !munmap(length_pages, 8192), "release guards");
    if (sender != fd)
        check(!close(sender), "close sender");
    check(!close(fd), "close receiver");
}

#ifdef IPV6_CONTROLS_INTEGRATED
int ipv6_controls_name_faults(void) {
#else
int main(void) {
#endif
    unsigned index = if_nametoindex("lo");
    check(index && index < 256, "actual loopback index");
    printf("IPV6_CONTROL_FAULT_INTERFACE loopback=%u\n", index);
    contract(0);
    contract(1);
    printf("IPV6_CONTROL_FAULT_DONE cases=%u transports=2 prefixes=12 peek=2 operations=2 "
           "length_faults=12\n",
           cases);
    return 0;
}
