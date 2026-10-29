// SPDX-License-Identifier: GPL-3.0-or-later
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <net/if.h>
#include <netinet/icmp6.h>
#include <stddef.h>
#include <poll.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <unistd.h>

_Static_assert(sizeof(struct msghdr) == 56, "Linux x86-64 message size");
_Static_assert(offsetof(struct msghdr, msg_namelen) == 8, "name length offset");
_Static_assert(offsetof(struct msghdr, msg_controllen) == 40, "control length offset");
_Static_assert(offsetof(struct msghdr, msg_flags) == 48, "flags offset");

static unsigned cases;

static void check(int condition, const char* message) {
    if (!condition) {
        fprintf(stderr, "IPV6_CONTROL_HEADER_FAIL case=%u %s errno=%d\n", cases, message, errno);
        exit(1);
    }
}

static void bytes(const void* data, size_t size) {
    const unsigned char* value = data;
    for (size_t at = 0; at < size; at++)
        printf("%02x", value[at]);
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
            .sin6_family = AF_INET6, .sin6_port = htons(53568), .sin6_addr = IN6ADDR_LOOPBACK_INIT};
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
    check(pages != MAP_FAILED, "header pages");
    const unsigned prefixes[] = {0,  1,  4,  7,  8,  9,  11, 12, 15, 16,
                                 39, 40, 41, 47, 48, 49, 51, 52, 55, 56};
    for (unsigned peek = 0; peek < 2; peek++) {
        for (unsigned n = 0; n < 24; n++) {
            unsigned mode = n < 20 ? 0 : n - 19;
            unsigned prefix = n < 20 ? prefixes[n] : 56;
            unsigned id = cases;
            unsigned char sent[32] = {128, 0, 0, 0, 0x73, 0x44, id >> 8, id};
            check(sendto(sender, sent, sizeof(sent), 0, (struct sockaddr*)&destination,
                         sizeof(destination)) == sizeof(sent),
                  "actual send");
            struct pollfd ready = {.fd = fd, .events = POLLIN};
            check(poll(&ready, 1, 1000) == 1 && ready.revents == POLLIN, "actual queued data");
            unsigned char control[96], payload[32], drain[32], name[40];
            memset(control, 0xa5, sizeof(control));
            memset(payload, 0xa5, sizeof(payload));
            memset(drain, 0xa5, sizeof(drain));
            memset(name, 0xa5, sizeof(name));
            check(!mprotect(pages + 4096, 4096, PROT_READ | PROT_WRITE), "prepare header");
            memset(pages, 0xa5, 8192);
            struct iovec vector = {.iov_base = payload, .iov_len = sizeof(payload)};
            struct msghdr before;
            memset(&before, 0xa5, sizeof(before));
            before.msg_name = mode == 1 || mode == 2 ? NULL : mode == 3 ? pages + 8192 : name;
            before.msg_namelen = mode >= 2 ? 0 : sizeof(name);
            before.msg_iov = &vector;
            before.msg_iovlen = 1;
            before.msg_control = control;
            before.msg_controllen = sizeof(control);
            before.msg_flags = 0x5a5a;
            // Populate both complete Linux size slots, including musl's reserved halves.
            uint64_t vector_count = 1, control_capacity = sizeof(control);
            memcpy((unsigned char*)&before + 24, &vector_count, sizeof(vector_count));
            memcpy((unsigned char*)&before + 40, &control_capacity, sizeof(control_capacity));
            unsigned char* header = pages + 4096 - prefix;
            memcpy(header, &before, sizeof(before));
            // Argument capture can read both pages; only result stores may fault.
            check(!mprotect(pages + 4096, 4096, PROT_READ), "readable result guard");
            errno = 0;
            long result = syscall(SYS_recvmsg, fd, header, MSG_DONTWAIT | (peek ? MSG_PEEK : 0));
            int error = result < 0 ? errno : 0;
            struct msghdr after;
            memcpy(&after, header, sizeof(after));
            errno = 0;
            long queued = recv(fd, drain, sizeof(drain), MSG_DONTWAIT);
            int queue_error = queued < 0 ? errno : 0;
            printf("IPV6_CONTROL_HEADER case=%u kind=%d peek=%u mode=%u prefix=%u result=%ld "
                   "errno=%d name_length=%u length=%zu flags=%u queued=%ld queue_errno=%d "
                   "before_header=",
                   cases++, raw, peek, mode, prefix, result, error, after.msg_namelen,
                   (size_t)after.msg_controllen, (unsigned)after.msg_flags, queued, queue_error);
            bytes(&before, sizeof(before));
            printf(" header=");
            bytes(&after, sizeof(after));
            printf(" name=");
            bytes(name, sizeof(name));
            printf(" control=");
            bytes(control, sizeof(control));
            printf(" payload=");
            bytes(payload, sizeof(payload));
            printf(" drain=");
            bytes(drain, sizeof(drain));
            puts("");
            check(poll(&ready, 1, 0) == 0, "fault and peek queue ownership");
        }
    }
    check(!munmap(pages, 8192), "release guard");
    if (sender != fd)
        check(!close(sender), "close sender");
    check(!close(fd), "close receiver");
}

#ifdef IPV6_CONTROLS_INTEGRATED
int ipv6_controls_header_faults(void) {
#else
int main(void) {
#endif
    unsigned index = if_nametoindex("lo");
    check(index && index < 256, "actual loopback index");
    printf("IPV6_CONTROL_HEADER_INTERFACE loopback=%u\n", index);
    contract(0);
    contract(1);
    printf("IPV6_CONTROL_HEADER_DONE cases=%u transports=2 headers=20 names=4 peek=2\n", cases);
    return 0;
}
