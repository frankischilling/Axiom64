// SPDX-License-Identifier: GPL-3.0-or-later
#define _GNU_SOURCE
#include <poll.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

static int pair_socket(int, int, int);
static int pair_close(int);
static ssize_t pair_sendto(int, const void*, size_t, int, const struct sockaddr*, socklen_t);
static ssize_t pair_recv(int, void*, size_t, int);
static int pair_poll(struct pollfd*, nfds_t, int);
static int pair_clock(clockid_t, struct timespec*);
static ssize_t pair_write(int, const void*, size_t);

#define main owner_application_main
#define socket pair_socket
#define close pair_close
#define sendto pair_sendto
#define recv pair_recv
#define poll pair_poll
#define clock_gettime pair_clock
#define write pair_write
#include "ipv6_address_ownership.c"
#undef main
#undef socket
#undef close
#undef sendto
#undef recv
#undef poll
#undef clock_gettime
#undef write

static uint64_t model_clock = 100000000000ULL;
static unsigned sent_count, first_wait_count, request_type[32], request_sequence[32], next_fd;
static unsigned char sent[2][60];
static struct in6_addr identities[2];
static int link_case;

static int pair_socket(int domain, int type, int protocol) {
    (void)type;
    (void)protocol;
    check(domain == AF_NETLINK && next_fd < 32, "unit uses only owned netlink descriptors");
    return 100 + next_fd++;
}

static int pair_close(int fd) {
    check(fd >= 100 && fd < 132, "unit closes only its netlink descriptor");
    return 0;
}

static int pair_clock(clockid_t which, struct timespec* result) {
    check(which == CLOCK_MONOTONIC, "unit observes original monotonic call");
    result->tv_sec = model_clock / 1000000000ULL;
    result->tv_nsec = model_clock % 1000000000ULL;
    return 0;
}

static ssize_t pair_write(int fd, const void* bytes, size_t length) {
    (void)bytes;
    check(fd == STDOUT_FILENO, "unit retains normal control record output");
    return length;
}

static ssize_t pair_sendto(int fd, const void* bytes, size_t length, int flags,
                           const struct sockaddr* address_, socklen_t size) {
    (void)flags;
    (void)address_;
    (void)size;
    if (fd >= 100) {
        const struct nlmsghdr* header = bytes;
        check(fd < 132 && (header->nlmsg_type == RTM_GETADDR || header->nlmsg_type == RTM_GETROUTE),
              "unit actual netlink query type");
        request_type[fd - 100] = header->nlmsg_type;
        request_sequence[fd - 100] = header->nlmsg_seq;
    } else {
        check((fd == 20 || fd == 21) && length == 60, "unit actual Ethernet query envelope");
        unsigned lane = fd - 20;
        memcpy(sent[lane], bytes, 60);
        sent_count++;
    }
    return length;
}

static int pair_poll(struct pollfd* items, nfds_t count, int timeout) {
    check(count == 1 && (timeout == 100 || timeout == 5000), "unit original finite poll bound");
    if (items[0].fd == 20 && !first_wait_count) {
        first_wait_count = sent_count;
        // Replay the recorded cross-adapter wait; this is a unit model.
        // Real packet clocks, DAD timers and runtime acceptance are separate.
        model_clock += 2047797729ULL;
    }
    items[0].revents = POLLIN;
    return 1;
}

static unsigned append_address(unsigned char* bytes, unsigned at, unsigned lane, unsigned seq) {
    struct {
        struct nlmsghdr header;
        struct ifaddrmsg message;
        struct rtattr address_field;
        struct in6_addr address_;
        struct rtattr flags_field;
        uint32_t flags;
        struct rtattr cache_field;
        struct ifa_cacheinfo cache;
    } row = {0};

    unsigned current = link_case ? 0x8c0 : 0x40;
    if (model_clock >= 101000000000ULL)
        current &= ~IFA_F_TENTATIVE;
    row.header = (struct nlmsghdr){sizeof(row), RTM_NEWADDR, 0, seq, 0};
    row.message = (struct ifaddrmsg){AF_INET6, 64, current, 0, indices[lane]};
    row.address_field = (struct rtattr){20, IFA_ADDRESS};
    row.address_ = identities[lane];
    row.flags_field = (struct rtattr){8, IFA_FLAGS};
    row.flags = current;
    row.cache_field = (struct rtattr){20, IFA_CACHEINFO};
    row.cache.ifa_prefered = link_case ? UINT32_MAX : 2;
    row.cache.ifa_valid = link_case ? UINT32_MAX : 8;
    memcpy(bytes + at, &row, sizeof(row));
    return at + sizeof(row);
}

static ssize_t pair_recv(int fd, void* bytes, size_t length, int flags) {
    (void)flags;
    if (fd >= 100) {
        check(fd < 132 && length >= 256, "unit bounded netlink response");
        unsigned at = 0, seq = request_sequence[fd - 100];
        if (request_type[fd - 100] == RTM_GETADDR)
            for (unsigned lane = 0; lane < 2; lane++)
                at = append_address(bytes, at, lane, seq);
        struct nlmsghdr done = {sizeof(done), NLMSG_DONE, 0, seq, 0};
        memcpy((unsigned char*)bytes + at, &done, sizeof(done));
        return at + sizeof(done);
    }
    check((fd == 20 || fd == 21) && length >= 60, "unit bounded physical acknowledgment");
    unsigned lane = fd - 20;
    unsigned char answer[60] = {0};
    memcpy(answer, macs[lane], 6);
    memcpy(answer + 6, sent[lane], 6);
    memcpy(answer + 12, sent[lane] + 12, 8);
    answer[20] = 1;
    memcpy(bytes, answer, 60);
    return 60;
}

int main(int argc, char** argv) {
    check(argc == 2 && (!strcmp(argv[1], "link") || !strcmp(argv[1], "global")),
          "known paired query model");
    link_case = !strcmp(argv[1], "link");
    struct address_record values[2] = {0};
    struct in6_addr previous[2][4] = {0};
    for (unsigned lane = 0; lane < 2; lane++) {
        indices[lane] = lane + 1;
        packets[lane] = 20 + lane;
        memcpy(macs[lane], (unsigned char[6]){0x52, 0x54, 0, 0x12, 0x34, 0x10 + lane}, 6);
        identities[lane] = prefix_address(lane, link_case ? 7 : 8, 0);
        if (link_case) {
            memset(identities[lane].s6_addr, 0, 8);
            identities[lane].s6_addr[0] = 0xfe;
            identities[lane].s6_addr[1] = 0x80;
        }
        identities[lane].s6_addr[15] = 0x23;
        values[lane].address = identities[lane];
    }
    lifecycle_conflict(link_case ? 7 : 8, link_case ? 1 : 0, link_case, values, previous);
    printf("{\"first_wait_sent\":%u,\"frames\":[", first_wait_count);
    for (unsigned lane = 0; lane < 2; lane++) {
        printf("%s\"", lane ? "," : "");
        for (unsigned at = 0; at < 60; at++)
            printf("%02x", sent[lane][at]);
        printf("\"");
    }
    puts("],\"synthetic_timing_unit_model\":true}");
    return 0;
}
