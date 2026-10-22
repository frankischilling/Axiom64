// SPDX-License-Identifier: GPL-3.0-or-later
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <linux/if_addr.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <net/if.h>
#include <poll.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/utsname.h>
#include <time.h>
#include <unistd.h>

static unsigned serial;

static void check(int value, const char* what) {
    if (!value) {
        fprintf(stderr, "IPV6_LIFETIME_FAIL %s errno=%d\n", what, errno);
        exit(1);
    }
}

static uint64_t now(void) {
    struct timespec value;
    check(!clock_gettime(CLOCK_MONOTONIC, &value), "monotonic observation");
    return (uint64_t)value.tv_sec * 1000000000 + value.tv_nsec;
}

static void wait_until(uint64_t deadline) {
    for (;;) {
        uint64_t current = now();
        if (current >= deadline)
            return;
        uint64_t left = deadline - current;
        struct timespec value = {(time_t)(left / 1000000000), (long)(left % 1000000000)};
        check(!nanosleep(&value, NULL) || errno == EINTR, "real elapsed observation");
    }
}

static void hex(const void* input, size_t size) {
    const unsigned char* bytes = input;
    for (size_t at = 0; at < size; at++)
        printf("%02x", bytes[at]);
}

static int channel(void) {
    int fd = socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE);
    check(fd >= 0, "netlink description");
    struct sockaddr_nl local = {.nl_family = AF_NETLINK};
    check(!bind(fd, (struct sockaddr*)&local, sizeof(local)), "owned netlink port");
    return fd;
}

static void submit(int fd, void* message, size_t size) {
    struct sockaddr_nl kernel = {.nl_family = AF_NETLINK};
    check(sendto(fd, message, size, 0, (struct sockaddr*)&kernel, sizeof(kernel)) == (ssize_t)size,
          "complete netlink request");
}

static size_t attribute(unsigned char* bytes, size_t at, unsigned type, const void* data,
                        size_t size) {
    struct rtattr header = {.rta_len = (unsigned short)(size + 4),
                            .rta_type = (unsigned short)type};
    memcpy(bytes + at, &header, 4);
    memcpy(bytes + at + 4, data, size);
    return at + RTA_ALIGN(size + 4);
}

static int change(unsigned index, const struct in6_addr* address, unsigned prefix, unsigned flags,
                  int remove, int cached, uint32_t preferred, uint32_t valid, unsigned cache_size,
                  unsigned address_flags) {
    _Alignas(8) unsigned char bytes[256] = {0};
    struct nlmsghdr* header = (void*)bytes;
    *header = (struct nlmsghdr){.nlmsg_type = remove ? RTM_DELADDR : RTM_NEWADDR,
                                .nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK | flags,
                                .nlmsg_seq = ++serial};
    struct ifaddrmsg value = {.ifa_family = AF_INET6,
                              .ifa_prefixlen = (unsigned char)prefix,
                              .ifa_flags = (unsigned char)address_flags,
                              .ifa_index = index};
    memcpy(bytes + sizeof(*header), &value, sizeof(value));
    size_t size = attribute(bytes, sizeof(*header) + sizeof(value), IFA_ADDRESS, address, 16);
    size = attribute(bytes, size, IFA_FLAGS, &address_flags, 4);
    if (cached) {
        unsigned char cache[32];
        memset(cache, 0xa5, sizeof(cache));
        struct ifa_cacheinfo lifetime = {.ifa_prefered = preferred,
                                         .ifa_valid = valid,
                                         .cstamp = 0x12345678,
                                         .tstamp = 0x87654321};
        memcpy(cache, &lifetime, sizeof(lifetime));
        check(cache_size <= sizeof(cache), "bounded cache input");
        size = attribute(bytes, size, IFA_CACHEINFO, cache, cache_size);
    }
    header->nlmsg_len = (unsigned)size;
    int fd = channel();
    submit(fd, bytes, size);
    int result = -999;
    for (;;) {
        _Alignas(8) unsigned char response[8192];
        ssize_t got = recv(fd, response, sizeof(response), 0);
        check(got >= 16, "netlink acknowledgment");
        int left = (int)got;
        for (struct nlmsghdr* row = (void*)response; NLMSG_OK(row, left);
             row = NLMSG_NEXT(row, left)) {
            if (row->nlmsg_seq != serial || row->nlmsg_type != NLMSG_ERROR)
                continue;
            check(row->nlmsg_len >= NLMSG_LENGTH(sizeof(struct nlmsgerr)),
                  "complete acknowledgment body");
            struct nlmsgerr error;
            memcpy(&error, NLMSG_DATA(row), sizeof(error));
            result = error.error;
        }
        if (result != -999)
            break;
    }
    check(!close(fd), "release netlink request");
    return result;
}

struct observation {
    unsigned present, prefix, flags, cache_present;
    struct ifa_cacheinfo cache;
};

static struct observation observe(unsigned index, const struct in6_addr* wanted) {
    struct {
        struct nlmsghdr header;
        struct ifaddrmsg address;
    } request = {.header = {.nlmsg_len = sizeof(request),
                            .nlmsg_type = RTM_GETADDR,
                            .nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP,
                            .nlmsg_seq = ++serial},
                 .address = {.ifa_family = AF_INET6}};

    int fd = channel(), complete = 0;
    struct observation output = {0};
    submit(fd, &request, sizeof(request));
    while (!complete) {
        _Alignas(8) unsigned char bytes[8192];
        ssize_t got = recv(fd, bytes, sizeof(bytes), 0);
        check(got >= 16, "address inventory response");
        int left = (int)got;
        for (struct nlmsghdr* row = (void*)bytes; NLMSG_OK(row, left);
             row = NLMSG_NEXT(row, left)) {
            check(row->nlmsg_seq == serial, "inventory sequence");
            if (row->nlmsg_type == NLMSG_DONE) {
                complete = 1;
                continue;
            }
            check(row->nlmsg_type == RTM_NEWADDR &&
                      row->nlmsg_len >= NLMSG_LENGTH(sizeof(struct ifaddrmsg)),
                  "address inventory record");
            struct ifaddrmsg* address = NLMSG_DATA(row);
            if (address->ifa_family != AF_INET6 || address->ifa_index != index)
                continue;
            struct observation candidate = {.prefix = address->ifa_prefixlen,
                                            .flags = address->ifa_flags};
            int matches = 0, length = IFA_PAYLOAD(row);
            for (struct rtattr* field = IFA_RTA(address); RTA_OK(field, length);
                 field = RTA_NEXT(field, length)) {
                if (field->rta_type == IFA_ADDRESS && RTA_PAYLOAD(field) == 16)
                    matches = !memcmp(RTA_DATA(field), wanted, 16);
                if (field->rta_type == IFA_FLAGS && RTA_PAYLOAD(field) == 4)
                    memcpy(&candidate.flags, RTA_DATA(field), 4);
                if (field->rta_type == IFA_CACHEINFO &&
                    RTA_PAYLOAD(field) == sizeof(candidate.cache)) {
                    memcpy(&candidate.cache, RTA_DATA(field), sizeof(candidate.cache));
                    candidate.cache_present++;
                }
            }
            if (matches) {
                check(!output.present, "one address inventory owner");
                candidate.present = 1;
                output = candidate;
            }
        }
    }
    check(!close(fd), "release address inventory");
    return output;
}

static void report(unsigned lane, unsigned number, const char* kind, int result,
                   struct observation value) {
    printf("IPV6_LIFETIME_CASE lane=%u case=%u kind=%s result=%d present=%u prefix=%u flags=%u "
           "cache=%u preferred=%u valid=%u cstamp=%u tstamp=%u raw=",
           lane, number, kind, result, value.present, value.prefix, value.flags,
           value.cache_present, value.cache.ifa_prefered, value.cache.ifa_valid, value.cache.cstamp,
           value.cache.tstamp);
    hex(&value.cache, sizeof(value.cache));
    puts("");
}

static struct in6_addr make_address(unsigned lane, unsigned number) {
    struct in6_addr address;
    char text[80];
    snprintf(text, sizeof(text), "2001:db8:%x::%x", 0x420 + lane, number + 1);
    check(inet_pton(AF_INET6, text, &address) == 1, "owned address bytes");
    return address;
}

static void source(unsigned lane, unsigned stage, int fd, const struct sockaddr_in6* peer) {
    int result = 0, error = 0;
    if (fd < 0) {
        fd = socket(AF_INET6, SOCK_DGRAM, 0);
        check(fd >= 0, "fresh source description");
        errno = 0;
        result = connect(fd, (const struct sockaddr*)peer, sizeof(*peer));
        error = errno;
    }
    struct sockaddr_in6 local = {0};
    socklen_t length = sizeof(local);
    errno = 0;
    int got = getsockname(fd, (struct sockaddr*)&local, &length), get_error = errno;
    printf("IPV6_LIFETIME_SOURCE lane=%u stage=%u result=%d errno=%d got=%d get_errno=%d length=%u "
           "address=",
           lane, stage, result, error, got, get_error, (unsigned)length);
    hex(&local.sin6_addr, 16);
    puts("");
    check(!close(fd), "release source description");
}

static int wire_endpoint(unsigned lane, unsigned kind, const struct in6_addr* selected,
                         const struct sockaddr_in6* peer) {
    int fd = socket(AF_INET6, SOCK_DGRAM, 0);
    check(fd >= 0, "lifetime wire description");
    struct sockaddr_in6 local = {.sin6_family = AF_INET6,
                                 .sin6_port = htons(59000 + kind * 100 + lane)};
    if (selected)
        local.sin6_addr = *selected;
    check(!bind(fd, (struct sockaddr*)&local, sizeof(local)), "lifetime wire bind");
    check(!connect(fd, (const struct sockaddr*)peer, sizeof(*peer)), "lifetime wire connect");
    return fd;
}

static void wire_barrier(unsigned lane, unsigned kind, int fd) {
    unsigned char payload[16] = {'L', 'I', 'F', 'B', lane, 2, kind, 0x5a};
    for (unsigned at = 8; at < sizeof(payload); at++)
        payload[at] = at * 17 + lane + 2 + kind;
    check(send(fd, payload, sizeof(payload), MSG_DONTWAIT) == sizeof(payload),
          "complete permanent-source lifetime barrier");
    struct pollfd ready = {.fd = fd, .events = POLLIN};
    check(poll(&ready, 1, 300) == 1 && ready.revents == POLLIN,
          "permanent-source lifetime barrier acknowledgment");
    unsigned char reply[32] = {0};
    check(recv(fd, reply, sizeof(reply), MSG_DONTWAIT) == sizeof(payload) &&
              !memcmp(reply, payload, sizeof(payload)),
          "exact lifetime barrier bytes precede expired-source input check");
    printf("IPV6_LIFETIME_BARRIER lane=%u stage=2 kind=%u passed=1\n", lane, kind);
}

static void wire_exchange(unsigned lane, unsigned stage, unsigned kind, int fd, uint64_t began,
                          int barrier_fd) {
    unsigned char payload[16] = {'L', 'I', 'F', '6', lane, stage, kind, 0x5a};
    for (unsigned at = 8; at < sizeof(payload); at++)
        payload[at] = at * 17 + lane + stage + kind;
    errno = 0;
    int sent = send(fd, payload, sizeof(payload), MSG_DONTWAIT), send_error = errno;
    if (stage == 2 && kind < 2)
        wire_barrier(lane, kind, barrier_fd);
    struct pollfd ready = {.fd = fd, .events = POLLIN};
    int polled = sent < 0 ? -1 : poll(&ready, 1, 300);
    unsigned char reply[32] = {0};
    errno = 0;
    int received = recv(fd, reply, sizeof(reply), MSG_DONTWAIT), receive_error = errno;
    struct sockaddr_in6 local = {0};
    socklen_t length = sizeof(local);
    check(!getsockname(fd, (struct sockaddr*)&local, &length), "lifetime wire local identity");
    printf("IPV6_LIFETIME_WIRE lane=%u stage=%u kind=%u elapsed_ns=%llu sent=%d errno=%d polled=%d "
           "events=%d received=%d receive_errno=%d exact=%u source=",
           lane, stage, kind, (unsigned long long)(now() - began), sent, send_error, polled,
           ready.revents, received, receive_error,
           received == sizeof(payload) && !memcmp(reply, payload, sizeof(payload)));
    hex(&local.sin6_addr, 16);
    puts("");
}

void ipv6_address_lifetimes(void) {
    struct utsname kernel;
    check(!uname(&kernel), "actual kernel");
    printf("IPV6_LIFETIME_KERNEL release=%s\n", kernel.release);
    unsigned count = 0;
    static const uint32_t lifetimes[][2] = {{UINT32_MAX, UINT32_MAX},
                                            {10, 10},
                                            {0, 10},
                                            {11, 10},
                                            {0, 0},
                                            {1, 0},
                                            {UINT32_MAX, 10},
                                            {10, UINT32_MAX},
                                            {UINT32_MAX - 1, UINT32_MAX - 1}};
    static const unsigned request_flags[] = {
        NLM_F_CREATE | NLM_F_EXCL,    NLM_F_CREATE, NLM_F_REPLACE,
        NLM_F_CREATE | NLM_F_REPLACE, NLM_F_EXCL,   0};
    for (unsigned lane = 0; lane < 2; lane++) {
        char name[8];
        snprintf(name, sizeof(name), "eth%u", lane);
        unsigned index = if_nametoindex(name);
        check(index, "actual adapter index");
        for (unsigned n = 0; n < sizeof(lifetimes) / sizeof(lifetimes[0]); n++) {
            struct in6_addr address = make_address(lane, n);
            int result = change(index, &address, 64, NLM_F_CREATE | NLM_F_EXCL, 0, 1,
                                lifetimes[n][0], lifetimes[n][1], 16, IFA_F_NODAD);
            struct observation value = observe(index, &address);
            report(lane, count++, "lifetime", result, value);
            if (value.present)
                check(!change(index, &address, value.prefix, 0, 1, 0, 0, 0, 0, 0),
                      "cleanup lifetime address");
        }
        for (unsigned mode = 0; mode < 2; mode++)
            for (unsigned n = 0; n < 6; n++) {
                struct in6_addr address = make_address(lane, 32 + mode * 6 + n);
                if (mode)
                    check(!change(index, &address, 64, NLM_F_CREATE | NLM_F_EXCL, 0, 0, 0, 0, 0,
                                  IFA_F_NODAD),
                          "existing address seed");
                int result = change(index, &address, 96, request_flags[n], 0, 1, 0, 10, 16,
                                    IFA_F_NODAD | IFA_F_NOPREFIXROUTE);
                struct observation value = observe(index, &address);
                report(lane, count++, mode ? "replace" : "create", result, value);
                if (value.present)
                    check(!change(index, &address, value.prefix, 0, 1, 0, 0, 0, 0, 0),
                          "cleanup replacement address");
            }
        for (unsigned n = 0; n < 5; n++) {
            unsigned sizes[] = {0, 12, 15, 17, 24};
            struct in6_addr address = make_address(lane, 64 + n);
            int result = change(index, &address, 64, NLM_F_CREATE | NLM_F_EXCL, 0, 1, 2, 5,
                                sizes[n], IFA_F_NODAD);
            struct observation value = observe(index, &address);
            report(lane, count++, "cache-size", result, value);
            if (value.present)
                check(!change(index, &address, value.prefix, 0, 1, 0, 0, 0, 0, 0),
                      "cleanup cache-size address");
        }
        struct in6_addr permanent = make_address(lane, 128), finite = make_address(lane, 129);
        check(!change(index, &permanent, 64, NLM_F_CREATE | NLM_F_EXCL, 0, 0, 0, 0, 0, IFA_F_NODAD),
              "permanent temporal companion");
        int result =
            change(index, &finite, 96, NLM_F_CREATE | NLM_F_EXCL, 0, 1, 2, 8, 16, IFA_F_NODAD);
        uint64_t began = now();
        struct sockaddr_in6 peer = {.sin6_family = AF_INET6,
                                    .sin6_port = htons(55123),
                                    .sin6_addr = make_address(lane, 255)};
        int automatic = wire_endpoint(lane, 0, NULL, &peer);
        int explicit_fd = wire_endpoint(lane, 1, &finite, &peer);
        int barrier_fd = wire_endpoint(lane, 3, &permanent, &peer);
        for (unsigned stage = 0; stage < 3; stage++) {
            wait_until(began + (stage == 0 ? 0 : stage == 1 ? 4200000000ULL : 9200000000ULL));
            struct observation value = observe(index, &finite);
            printf("IPV6_LIFETIME_SAMPLE lane=%u stage=%u elapsed_ns=%llu present=%u prefix=%u "
                   "flags=%u cache=%u preferred=%u valid=%u cstamp=%u tstamp=%u raw=",
                   lane, stage, (unsigned long long)(now() - began), value.present, value.prefix,
                   value.flags, value.cache_present, value.cache.ifa_prefered,
                   value.cache.ifa_valid, value.cache.cstamp, value.cache.tstamp);
            hex(&value.cache, sizeof(value.cache));
            puts("");
            // The fixed sample remains visible even when Linux's delayed worker is late.
            // Wait for the state transition without renewing either configured lifetime.
            while ((stage == 1 && !(value.flags & IFA_F_DEPRECATED)) ||
                   (stage == 2 && value.present)) {
                uint64_t limit = began + (stage == 1 ? 7900000000ULL : 15000000000ULL);
                check((stage != 1 || value.present) && now() < limit,
                      "bounded address lifecycle convergence");
                wait_until(now() + 20000000ULL);
                value = observe(index, &finite);
            }
            uint64_t elapsed = now() - began;
            check(stage == 0 || elapsed <= (stage == 1 ? 8000000000ULL : 15000000000ULL),
                  "complete lifecycle observation within its bound");
            printf("IPV6_LIFETIME_TIME lane=%u stage=%u elapsed_ns=%llu\n", lane, stage,
                   (unsigned long long)elapsed);
            report(lane, count++, "temporal", result, value);
            source(lane, stage, -1, &peer);
            wire_exchange(lane, stage, 0, automatic, began, barrier_fd);
            wire_exchange(lane, stage, 1, explicit_fd, began, barrier_fd);
            int fresh = wire_endpoint(lane, 2, NULL, &peer);
            wire_exchange(lane, stage, 2, fresh, began, -1);
            check(!close(fresh), "release fresh lifetime wire description");
        }
        check(!close(automatic) && !close(explicit_fd) && !close(barrier_fd),
              "release retained lifetime descriptions");
        struct observation final = observe(index, &finite);
        if (final.present)
            check(!change(index, &finite, final.prefix, 0, 1, 0, 0, 0, 0, 0),
                  "cleanup remaining finite address");
        check(!change(index, &permanent, 64, 0, 1, 0, 0, 0, 0, 0), "cleanup temporal companion");
    }
    puts("IPV6_LIFETIME_WIRE_DONE observations=18");
    printf("IPV6_LIFETIME_DONE cases=%u samples=6\n", count);
}
