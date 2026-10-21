// SPDX-License-Identifier: GPL-3.0-or-later
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <net/if.h>
#include <poll.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <time.h>
#include <unistd.h>

static unsigned cases;
static unsigned char *control_pages, *name_pages, *header_pages;
static const int options[] = {IPV6_RECVPKTINFO, IPV6_RECVHOPLIMIT, IPV6_RECVTCLASS};

static void check(int ok, const char* reason) {
    if (!ok) {
        fprintf(stderr, "IPV6_ERROR_CONTROLS_FAIL case=%u %s errno=%d\n", cases, reason, errno);
        exit(1);
    }
}

static void bytes(const void* pointer, size_t size) {
    const unsigned char* value = pointer;
    for (size_t at = 0; at < size; at++)
        printf("%02x", value[at]);
}

static void configure(int fd, unsigned mask) {
    for (unsigned at = 0; at < 3; at++) {
        int value = !!(mask & (1u << at));
        check(!setsockopt(fd, IPPROTO_IPV6, options[at], &value, sizeof(value)), "receive option");
    }
}

static void observe(unsigned kind, unsigned peek, unsigned mode, unsigned mask, unsigned capacity,
                    unsigned prefix) {
    int fd = socket(AF_INET6, SOCK_DGRAM, 0), enabled = 1;
    check(fd >= 0 && !setsockopt(fd, IPPROTO_IPV6, IPV6_RECVERR, &enabled, sizeof(enabled)),
          "error description");
    int alias = dup(fd);
    check(alias >= 0, "error description alias");
    configure(fd, mode == 8 ? 0 : mode == 9 ? 7 : mask);
    struct sockaddr_in6 target = {
        .sin6_family = AF_INET6, .sin6_port = htons(59999), .sin6_addr = IN6ADDR_LOOPBACK_INIT};
    check(!connect(fd, (struct sockaddr*)&target, sizeof(target)), "error destination");
    if (kind) {
        int mtu = 1280, policy = IPV6_PMTUDISC_DO;
        check(!setsockopt(fd, IPPROTO_IPV6, IPV6_MTU, &mtu, sizeof(mtu)) &&
                  !setsockopt(fd, IPPROTO_IPV6, IPV6_MTU_DISCOVER, &policy, sizeof(policy)),
              "local MTU error policy");
    } else {
        struct timespec delay = {0, 100000000};
        check(!nanosleep(&delay, NULL), "real ICMP diagnostic budget interval");
    }
    unsigned char sent[1400], payload[32], drain[32], name[40], control[192];
    for (size_t at = 0; at < sizeof(sent); at++)
        sent[at] = at * 7 + 3;
    errno = 0;
    long written = send(fd, sent, kind ? sizeof(sent) : 32, 0);
    check(kind ? written == -1 && errno == EMSGSIZE : written == 32, "actual queued error input");
    struct pollfd ready = {.fd = fd, .events = POLLERR};
    check(poll(&ready, 1, 5000) == 1 && ready.revents & POLLERR, "actual error readiness");
    if (mode == 8 || mode == 9)
        configure(alias, mask);
    for (unsigned at = 0; at < 3; at++) {
        int value = -1;
        socklen_t size = sizeof(value);
        check(!getsockopt(alias, IPPROTO_IPV6, options[at], &value, &size) &&
                  size == sizeof(value) && value == !!(mask & (1u << at)),
              "options survive error queueing and aliases");
    }
    memset(payload, 0xa5, sizeof(payload));
    memset(drain, 0xa5, sizeof(drain));
    memset(name, 0xa5, sizeof(name));
    memset(control, 0xa5, sizeof(control));
    memset(control_pages, 0xa5, 4096);
    memset(name_pages, 0xa5, 4096);
    check(!mprotect(header_pages + 4096, 4096, PROT_READ | PROT_WRITE), "prepare result pages");
    memset(header_pages, 0xa5, 8192);
    struct iovec vector = {.iov_base = mode == 4 ? name_pages + 4096 : payload, .iov_len = 32};
    struct msghdr before;
    memset(&before, 0xa5, sizeof(before));
    before.msg_name = mode == 5    ? NULL
                      : mode == 2  ? name_pages + 4096 - prefix
                      : mode == 10 ? name_pages + 4095
                                   : name;
    before.msg_namelen = mode == 6 ? 0 : sizeof(name);
    before.msg_iov = &vector;
    before.msg_iovlen = 1;
    before.msg_control = mode == 1 ? control_pages + 4096 - prefix : control;
    before.msg_controllen = capacity;
    before.msg_flags = 0x5a5a;
    uint64_t count = 1, full_capacity = capacity;
    memcpy((unsigned char*)&before + 24, &count, sizeof(count));
    memcpy((unsigned char*)&before + 40, &full_capacity, sizeof(full_capacity));
    unsigned char* header = mode == 3 ? header_pages + 4096 - prefix : header_pages;
    memcpy(header, &before, sizeof(before));
    socklen_t* length = (socklen_t*)(header_pages + 4096);
    unsigned operation = mode == 7 || mode == 10;
    if (operation)
        *length = 40;
    check(!mprotect(header_pages + 4096, 4096, PROT_READ), "readable protected result fields");
    unsigned flags = MSG_ERRQUEUE | MSG_DONTWAIT | (peek ? MSG_PEEK : 0);
    errno = 0;
    long result = operation ? syscall(SYS_recvfrom, fd, payload, sizeof(payload), flags,
                                      before.msg_name, length)
                            : syscall(SYS_recvmsg, fd, header, flags);
    int error = result < 0 ? errno : 0;
    struct msghdr after;
    memcpy(&after, header, sizeof(after));
    struct iovec remaining = {.iov_base = drain, .iov_len = sizeof(drain)};
    struct msghdr empty = {.msg_iov = &remaining, .msg_iovlen = 1};
    errno = 0;
    long queued = recvmsg(fd, &empty, MSG_ERRQUEUE | MSG_DONTWAIT);
    int queue_error = queued < 0 ? errno : 0;
    unsigned visible = mode == 1 ? prefix : sizeof(control);
    unsigned name_visible = mode == 2 ? prefix : mode == 10 ? 1 : 0;
    printf("IPV6_ERROR_CONTROLS case=%u kind=%u peek=%u mode=%u mask=%u capacity=%u prefix=%u "
           "operation=%u result=%ld errno=%d name_length=%u length=%zu flags=%u queued=%ld "
           "queue_errno=%d control_visible=%u name_visible=%u before_header=",
           cases++, kind, peek, mode, mask, capacity, prefix, operation, result, error,
           operation ? *length : after.msg_namelen, (size_t)after.msg_controllen,
           (unsigned)after.msg_flags, queued, queue_error, visible, name_visible);
    bytes(&before, sizeof(before));
    printf(" header=");
    bytes(&after, sizeof(after));
    printf(" name=");
    bytes(name, sizeof(name));
    printf(" name_prefix=");
    bytes(before.msg_name, name_visible);
    printf(" control=");
    bytes(before.msg_control, visible);
    printf(" payload=");
    bytes(payload, sizeof(payload));
    printf(" drain=");
    bytes(drain, sizeof(drain));
    puts("");
    check(queued == -1 && queue_error == EAGAIN, "error dequeue survives peeking and copy faults");
    check(!close(alias) && !close(fd), "retire error descriptions");
}

#ifdef IPV6_ERROR_CONTROLS_INTEGRATED
int ipv6_error_controls_local(void) {
#else
int main(void) {
#endif
    unsigned index = if_nametoindex("lo");
    check(index > 0 && index < 256, "actual loopback interface");
    printf("IPV6_ERROR_CONTROLS_INTERFACE loopback=%u\n", index);
    control_pages = mmap(NULL, 8192, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    name_pages = mmap(NULL, 8192, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    header_pages = mmap(NULL, 8192, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    check(control_pages != MAP_FAILED && name_pages != MAP_FAILED && header_pages != MAP_FAILED &&
              !mprotect(control_pages + 4096, 4096, PROT_NONE) &&
              !mprotect(name_pages + 4096, 4096, PROT_NONE),
          "owned error receive guards");
    const unsigned capacities[] = {0,  1,  7,  15, 16, 17, 19, 20, 23, 24,  35,  36,
                                   37, 39, 40, 55, 56, 63, 64, 87, 88, 151, 152, 192};
    const unsigned controls[] = {0,  1,  7,  8,  9,   11,  12,  13,  15,  16,  17, 19,
                                 20, 23, 24, 25, 31,  32,  33,  35,  36,  37,  39, 40,
                                 41, 47, 48, 55, 56,  63,  64,  67,  79,  80,  83, 84,
                                 87, 88, 89, 96, 103, 104, 127, 128, 151, 152, 160};
    const unsigned names[] = {0, 1, 4, 7, 8, 15, 16, 23, 24, 27, 28, 40};
    const unsigned headers[] = {0,  1,  4,  7,  8,  9,  11, 12, 15, 16,
                                39, 40, 41, 47, 48, 49, 51, 52, 55, 56};
    for (unsigned kind = 0; kind < 2; kind++)
        for (unsigned peek = 0; peek < 2; peek++) {
            for (unsigned mask = 0; mask < 8; mask++)
                observe(kind, peek, 0, mask, 192, 0);
            for (unsigned at = 0; at < sizeof(capacities) / sizeof(capacities[0]); at++)
                observe(kind, peek, 0, 7, capacities[at], 0);
            for (unsigned at = 0; at < sizeof(controls) / sizeof(controls[0]); at++)
                observe(kind, peek, 1, 7, 192, controls[at]);
            for (unsigned at = 0; at < sizeof(names) / sizeof(names[0]); at++)
                observe(kind, peek, 2, 7, 192, names[at]);
            for (unsigned at = 0; at < sizeof(headers) / sizeof(headers[0]); at++)
                observe(kind, peek, 3, 7, 192, headers[at]);
            for (unsigned mode = 4; mode <= 10; mode++)
                observe(kind, peek, mode, mode == 9 ? 0 : 7, 192, 0);
        }
    check(!munmap(control_pages, 8192) && !munmap(name_pages, 8192) && !munmap(header_pages, 8192),
          "release error receive guards");
    printf("IPV6_ERROR_CONTROLS_DONE cases=%u origins=2 masks=8 capacities=24 controls=47 "
           "names=12 headers=20 peek=2\n",
           cases);
    return 0;
}
