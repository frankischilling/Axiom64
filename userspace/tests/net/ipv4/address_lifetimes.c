// SPDX-License-Identifier: GPL-3.0-or-later
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
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
#include <time.h>
#include <unistd.h>

static unsigned serial;
static const char* phase;
static unsigned lane;

static void check(int condition, const char* operation) {
    if (!condition) {
        fprintf(stderr, "IPV4_LIFETIME_FAIL lane=%u phase=%s operation=%s errno=%d\n", lane, phase,
                operation, errno);
        exit(1);
    }
}

static uint64_t clock_ns(clockid_t clock) {
    struct timespec value;
    check(!clock_gettime(clock, &value), "clock observation");
    return (uint64_t)value.tv_sec * 1000000000 + (uint64_t)value.tv_nsec;
}

static void wait_until(uint64_t deadline) {
    for (;;) {
        uint64_t now = clock_ns(CLOCK_MONOTONIC);
        if (now >= deadline)
            return;
        uint64_t left = deadline - now;
        struct timespec delay = {(time_t)(left / 1000000000), (long)(left % 1000000000)};
        check(!nanosleep(&delay, NULL) || errno == EINTR, "real elapsed lifetime");
    }
}

struct observation {
    uint64_t monotonic, realtime;
};

static struct observation observe(void) {
    struct observation value = {clock_ns(CLOCK_MONOTONIC), clock_ns(CLOCK_REALTIME)};
    return value;
}

static void record(const char* direction, const void* data, size_t length,
                   struct observation before, struct observation after) {
    printf("IPV4_LIFETIME_RECORD {\"lane\":%u,\"phase\":\"%s\",\"direction\":\"%s\","
           "\"monotonic_before_ns\":%llu,\"monotonic_after_ns\":%llu,"
           "\"realtime_before_ns\":%llu,\"realtime_after_ns\":%llu,\"bytes\":\"",
           lane, phase, direction, (unsigned long long)before.monotonic,
           (unsigned long long)after.monotonic, (unsigned long long)before.realtime,
           (unsigned long long)after.realtime);
    const unsigned char* bytes = data;
    for (size_t at = 0; at < length; at++)
        printf("%02x", bytes[at]);
    puts("\"}");
}

static size_t attribute(unsigned char* bytes, size_t at, unsigned type, const void* data,
                        size_t length) {
    struct rtattr header = {.rta_len = (unsigned short)(4 + length),
                            .rta_type = (unsigned short)type};
    memcpy(bytes + at, &header, sizeof(header));
    memcpy(bytes + at + 4, data, length);
    return at + RTA_ALIGN(4 + length);
}

static int channel(unsigned* port) {
    int fd = socket(AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC, NETLINK_ROUTE);
    check(fd >= 0, "netlink description");
    struct sockaddr_nl local = {.nl_family = AF_NETLINK};
    check(!bind(fd, (struct sockaddr*)&local, sizeof(local)), "owned netlink port");
    socklen_t size = sizeof(local);
    check(!getsockname(fd, (struct sockaddr*)&local, &size) && size == sizeof(local) &&
              local.nl_pid && !local.nl_groups,
          "netlink port identity");
    *port = local.nl_pid;
    return fd;
}

static void submit(int fd, const void* data, size_t size) {
    struct sockaddr_nl kernel = {.nl_family = AF_NETLINK};
    struct observation before = observe();
    check(sendto(fd, data, size, 0, (struct sockaddr*)&kernel, sizeof(kernel)) == (ssize_t)size,
          "complete request");
    record("request", data, size, before, observe());
}

static size_t receive(int fd, unsigned char* bytes, size_t capacity) {
    struct pollfd ready = {.fd = fd, .events = POLLIN};
    check(poll(&ready, 1, 5000) == 1 && (ready.revents & POLLIN), "bounded netlink reply");
    struct sockaddr_nl sender;
    socklen_t size = sizeof(sender);
    struct observation before = observe();
    ssize_t length = recvfrom(fd, bytes, capacity, 0, (struct sockaddr*)&sender, &size);
    check(length >= (ssize_t)sizeof(struct nlmsghdr) && (size_t)length <= capacity &&
              size == sizeof(sender) && sender.nl_family == AF_NETLINK && !sender.nl_pid &&
              !sender.nl_groups,
          "kernel reply ownership");
    record("reply", bytes, (size_t)length, before, observe());
    return (size_t)length;
}

static int change(unsigned index, uint32_t address, unsigned flags, int remove, int cache_size,
                  uint32_t preferred, uint32_t valid, const char* label) {
    _Alignas(8) unsigned char bytes[256] = {0};
    struct nlmsghdr* header = (void*)bytes;
    *header = (struct nlmsghdr){.nlmsg_type = remove ? RTM_DELADDR : RTM_NEWADDR,
                                .nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK | flags,
                                .nlmsg_seq = ++serial};
    struct ifaddrmsg body = {.ifa_family = AF_INET,
                             .ifa_prefixlen = 24,
                             .ifa_flags = IFA_F_PERMANENT | IFA_F_DEPRECATED | IFA_F_SECONDARY,
                             .ifa_index = index};
    memcpy(bytes + 16, &body, sizeof(body));
    uint32_t network = htonl(address), broadcast = 0;
    size_t size = attribute(bytes, 24, IFA_LOCAL, &network, 4);
    size = attribute(bytes, size, IFA_ADDRESS, &network, 4);
    size = attribute(bytes, size, IFA_BROADCAST, &broadcast, 4);
    if (label)
        size = attribute(bytes, size, IFA_LABEL, label, strlen(label) + 1);
    uint32_t supplied_flags = IFA_F_PERMANENT | IFA_F_DEPRECATED | IFA_F_SECONDARY;
    size = attribute(bytes, size, IFA_FLAGS, &supplied_flags, 4);
    if (cache_size >= 0) {
        unsigned char cache[20];
        memset(cache, 0xa5, sizeof(cache));
        struct ifa_cacheinfo lifetime = {.ifa_prefered = preferred,
                                         .ifa_valid = valid,
                                         .cstamp = 0x12345678,
                                         .tstamp = 0x87654321};
        memcpy(cache, &lifetime, sizeof(lifetime));
        check((unsigned)cache_size <= sizeof(cache), "bounded cache input");
        size = attribute(bytes, size, IFA_CACHEINFO, cache, (size_t)cache_size);
    }
    header->nlmsg_len = (unsigned)size;
    unsigned port;
    int fd = channel(&port);
    submit(fd, bytes, size);
    _Alignas(8) unsigned char reply[512];
    size_t length = receive(fd, reply, sizeof(reply));
    const struct nlmsghdr* ack = (const void*)reply;
    check(length >= 36 && ack->nlmsg_len == length && ack->nlmsg_type == NLMSG_ERROR &&
              ack->nlmsg_seq == serial && ack->nlmsg_pid == port,
          "complete matching acknowledgement");
    int result;
    memcpy(&result, reply + 16, sizeof(result));
    check(!close(fd), "close mutation description");
    return result;
}

struct address_state {
    struct ifa_cacheinfo cache;
    unsigned flags;
    char label[16];
    int present;
};

static struct address_state inventory(unsigned index, uint32_t address) {
    struct {
        struct nlmsghdr header;
        struct ifaddrmsg address;
    } request = {{.nlmsg_len = sizeof(request),
                  .nlmsg_type = RTM_GETADDR,
                  .nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP,
                  .nlmsg_seq = ++serial},
                 {.ifa_family = AF_INET}};

    unsigned port;
    int fd = channel(&port);
    submit(fd, &request, sizeof(request));
    struct address_state result = {0};
    int done = 0;
    while (!done) {
        _Alignas(8) unsigned char bytes[16384];
        size_t length = receive(fd, bytes, sizeof(bytes));
        for (size_t at = 0; at < length;) {
            struct nlmsghdr header;
            check(length - at >= sizeof(header), "complete inventory header");
            memcpy(&header, bytes + at, sizeof(header));
            check(header.nlmsg_len >= 20 && header.nlmsg_len <= length - at &&
                      header.nlmsg_seq == serial && header.nlmsg_pid == port &&
                      (header.nlmsg_flags & NLM_F_MULTI) && !(header.nlmsg_flags & NLM_F_DUMP_INTR),
                  "complete multipart ownership");
            if (header.nlmsg_type == NLMSG_DONE) {
                int status;
                memcpy(&status, bytes + at + 16, 4);
                check(!status && header.nlmsg_len == 20 && at + header.nlmsg_len == length,
                      "successful multipart completion");
                done = 1;
            } else {
                check(header.nlmsg_type == RTM_NEWADDR && header.nlmsg_len >= 24,
                      "address inventory record");
                struct ifaddrmsg body;
                memcpy(&body, bytes + at + 16, sizeof(body));
                uint32_t local = 0, flags = body.ifa_flags;
                struct address_state state = {0};
                unsigned seen = 0;
                for (size_t field = at + 24; field < at + header.nlmsg_len;) {
                    struct rtattr attr;
                    check(at + header.nlmsg_len - field >= 4, "complete attribute header");
                    memcpy(&attr, bytes + field, 4);
                    check(attr.rta_len >= 4 && attr.rta_len <= at + header.nlmsg_len - field,
                          "bounded inventory attribute");
                    if (attr.rta_type < 32) {
                        check(!(seen & (1u << attr.rta_type)), "unique inventory attribute");
                        seen |= 1u << attr.rta_type;
                    }
                    if (attr.rta_type == IFA_LOCAL) {
                        check(attr.rta_len == 8, "local address size");
                        memcpy(&local, bytes + field + 4, 4);
                    } else if (attr.rta_type == IFA_CACHEINFO) {
                        check(attr.rta_len == 20, "cache information size");
                        memcpy(&state.cache, bytes + field + 4, 16);
                    } else if (attr.rta_type == IFA_FLAGS) {
                        check(attr.rta_len == 8, "flags size");
                        memcpy(&flags, bytes + field + 4, 4);
                    } else if (attr.rta_type == IFA_LABEL) {
                        size_t size = attr.rta_len - 4;
                        check(size && size <= sizeof(state.label) &&
                                  !bytes[field + attr.rta_len - 1],
                              "bounded label ownership");
                        memcpy(state.label, bytes + field + 4, size);
                    }
                    field += RTA_ALIGN(attr.rta_len);
                    check(field <= at + header.nlmsg_len, "aligned inventory attribute");
                }
                if (body.ifa_family == AF_INET && body.ifa_index == index &&
                    ntohl(local) == address) {
                    check(!result.present && body.ifa_prefixlen == 24 &&
                              (seen & (1u << IFA_CACHEINFO)),
                          "one complete selected address");
                    state.present = 1;
                    state.flags = flags;
                    result = state;
                }
            }
            at += NLMSG_ALIGN(header.nlmsg_len);
            check(at <= length, "aligned inventory message");
        }
    }
    check(!close(fd), "close inventory description");
    return result;
}

static int policy(const char* scope, int replacement, int write_value) {
    char path[128], bytes[32];
    check(snprintf(path, sizeof(path), "/proc/sys/net/ipv4/conf/%s/promote_secondaries", scope) > 0,
          "policy path");
    int fd = open(path, write_value ? O_WRONLY : O_RDONLY);
    check(fd >= 0, "policy description");
    int result = replacement;
    if (write_value) {
        int size = snprintf(bytes, sizeof(bytes), "%d\n", replacement);
        check(write(fd, bytes, (size_t)size) == size, "policy write");
    } else {
        ssize_t length = read(fd, bytes, sizeof(bytes) - 1);
        check(length > 0, "policy read");
        bytes[length] = 0;
        result = atoi(bytes);
    }
    check(!close(fd), "close policy description");
    printf("IPV4_LIFETIME_POLICY lane=%u phase=%s scope=%s write=%d value=%d\n", lane, phase, scope,
           write_value, result);
    return result;
}

static void check_absent_bind(uint32_t address) {
    int fd = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
    check(fd >= 0, "fresh UDP description");
    struct sockaddr_in local = {.sin_family = AF_INET, .sin_addr = {.s_addr = htonl(address)}};
    errno = 0;
    int status = bind(fd, (struct sockaddr*)&local, sizeof(local));
    check(status == -1 && errno == EADDRNOTAVAIL, "fresh bind rejects expired source");
    printf("IPV4_LIFETIME_BIND lane=%u phase=%s address=%08x result=%d errno=%d\n", lane, phase,
           address, status, errno);
    check(!close(fd), "close fresh UDP description");
}

static int retain_source(const char* interface, uint32_t address, int raw) {
    int fd = socket(AF_INET, (raw ? SOCK_RAW : SOCK_DGRAM) | SOCK_CLOEXEC, raw ? 253 : 0);
    check(fd >= 0, "retained transport description");
    check(!setsockopt(fd, SOL_SOCKET, SO_BINDTODEVICE, interface, strlen(interface) + 1),
          "retained output interface");
    struct sockaddr_in local = {.sin_family = AF_INET, .sin_addr = {.s_addr = htonl(address)}};
    check(!bind(fd, (struct sockaddr*)&local, sizeof(local)), "bind retained source before expiry");
    return fd;
}

static void check_expired_send(int fd, uint32_t peer, int raw) {
    struct sockaddr_in target = {
        .sin_family = AF_INET, .sin_port = htons(49170), .sin_addr = {.s_addr = htonl(peer)}};
    const unsigned char bytes[] = {7, 6, 5, 4, 3, 2, 1, 0};
    errno = 0;
    ssize_t result = sendto(fd, bytes, sizeof(bytes), 0, (struct sockaddr*)&target, sizeof(target));
    check(result == -1 && errno == ENETUNREACH, "later send rejects expired selected source");
    printf("IPV4_LIFETIME_SEND lane=%u phase=%s raw=%d result=%lld errno=%d\n", lane, phase, raw,
           (long long)result, errno);
    check(!close(fd), "close retained transport");
}

static void exercise(const char* interface) {
    unsigned index = if_nametoindex(interface);
    phase = "setup";
    check(index, "actual interface index");
    int original_all = policy("all", 0, 0), original_device = policy(interface, 0, 0);
    policy("all", 0, 1);
    policy(interface, 0, 1);
    uint32_t first = 0xc6122002 + lane * 0x1000, alias = first + 1, permanent = first + 256,
             deprecated = first + 512;
    phase = "finite-create";
    check(!change(index, first, NLM_F_CREATE | NLM_F_EXCL, 0, 16, 1, 3, NULL), "finite insertion");
    uint64_t created = clock_ns(CLOCK_MONOTONIC);
    struct address_state initial = inventory(index, first);
    check(initial.present && !initial.flags && initial.cache.ifa_prefered == 1 &&
              initial.cache.ifa_valid == 3 && initial.cache.cstamp != 0x12345678 &&
              initial.cache.tstamp != 0x87654321,
          "finite normalized state and owned stamps");
    int udp = retain_source(interface, first, 0), raw = retain_source(interface, first, 1);
    phase = "secondary-create";
    check(!change(index, alias, 0, 0, -1, 0, 0, NULL), "compatibility insertion without create");
    phase = "permanent-finite-preferred";
    check(!change(index, permanent, NLM_F_REPLACE, 0, 16, 1, UINT32_MAX, NULL),
          "infinite valid lifetime");
    phase = "permanent-deprecated";
    check(!change(index, deprecated, NLM_F_CREATE, 0, 16, 0, UINT32_MAX, NULL),
          "permanent deprecated insertion");
    phase = "invalid-zero";
    check(change(index, first, NLM_F_REPLACE, 0, 16, 0, 0, NULL) == -EINVAL, "zero valid rejected");
    phase = "invalid-order";
    check(change(index, first, NLM_F_REPLACE, 0, 16, 4, 3, NULL) == -EINVAL,
          "lifetime order rejected");
    phase = "invalid-short";
    check(change(index, first, NLM_F_REPLACE, 0, 12, 1, 3, NULL) == -ERANGE,
          "short cache rejected");
    phase = "exclusive-existing";
    check(change(index, first, NLM_F_REPLACE | NLM_F_EXCL, 0, 16, 1, 3, NULL) == -EEXIST,
          "exclusive replacement rejected");
    phase = "finite-deprecated";
    wait_until(created + 1500000000);
    struct address_state aged = inventory(index, first);
    check(aged.present && aged.flags == IFA_F_DEPRECATED && !aged.cache.ifa_prefered &&
              aged.cache.ifa_valid >= 1 && aged.cache.ifa_valid <= 2 &&
              aged.cache.cstamp == initial.cache.cstamp &&
              aged.cache.tstamp == initial.cache.tstamp,
          "preferred deadline and rejected mutation atomicity");
    struct address_state stable = inventory(index, permanent), old = inventory(index, deprecated);
    check(stable.present && stable.flags == IFA_F_PERMANENT && old.present &&
              old.flags == (IFA_F_PERMANENT | IFA_F_DEPRECATED) &&
              stable.cache.ifa_prefered == UINT32_MAX && stable.cache.ifa_valid == UINT32_MAX &&
              old.cache.ifa_prefered == UINT32_MAX && old.cache.ifa_valid == UINT32_MAX,
          "permanent IPv4 lifetime normalization");
    phase = "finite-renew";
    check(!change(index, first, NLM_F_REPLACE, 0, 20, 2, 4, "ignored"), "extended cache renewal");
    uint64_t renewed = clock_ns(CLOCK_MONOTONIC);
    struct address_state fresh = inventory(index, first);
    check(fresh.present && !fresh.flags && fresh.cache.ifa_prefered == 2 &&
              fresh.cache.ifa_valid == 4 && fresh.cache.cstamp == initial.cache.cstamp &&
              fresh.cache.tstamp != initial.cache.tstamp && !strcmp(fresh.label, initial.label),
          "renewal restores preference and preserves creation and label");
    phase = "renewed-deprecated";
    wait_until(renewed + 2500000000);
    aged = inventory(index, first);
    check(aged.present && aged.flags == IFA_F_DEPRECATED && !aged.cache.ifa_prefered &&
              aged.cache.ifa_valid >= 1 && aged.cache.ifa_valid <= 2,
          "renewed preferred deadline");
    phase = "finite-expired";
    wait_until(renewed + 4500000000);
    check(!inventory(index, first).present && !inventory(index, alias).present &&
              inventory(index, permanent).present && inventory(index, deprecated).present,
          "valid expiry cascades only matching-prefix secondaries");
    check_absent_bind(first);
    check_expired_send(udp, first - 1, 0);
    check_expired_send(raw, first - 1, 1);
    for (unsigned global = 0; global < 2; global++) {
        const char* scope = global ? "all" : interface;
        phase = global ? "global-promote-create" : "device-promote-create";
        policy(scope, 1, 1);
        check(!change(index, first, NLM_F_CREATE | NLM_F_EXCL, 0, 16, 0, 1, NULL),
              "expiring primary");
        uint64_t began = clock_ns(CLOCK_MONOTONIC);
        check(!change(index, alias, NLM_F_CREATE | NLM_F_EXCL, 0, -1, 0, 0, NULL),
              "permanent secondary");
        struct address_state secondary = inventory(index, alias);
        check(secondary.present && secondary.flags == (IFA_F_SECONDARY | IFA_F_PERMANENT),
              "secondary flag");
        phase = global ? "global-promoted" : "device-promoted";
        wait_until(began + 1500000000);
        check(!inventory(index, first).present, "expired promoted primary absent");
        struct address_state promoted = inventory(index, alias);
        check(promoted.present && promoted.flags == IFA_F_PERMANENT &&
                  promoted.cache.cstamp == secondary.cache.cstamp &&
                  promoted.cache.tstamp == secondary.cache.tstamp,
              "promoted secondary preserves lifetime stamps");
        check(!change(index, alias, 0, 1, -1, 0, 0, NULL), "remove promoted address");
        policy(scope, 0, 1);
    }
    phase = "cleanup";
    check(!change(index, permanent, 0, 1, -1, 0, 0, NULL) &&
              !change(index, deprecated, 0, 1, -1, 0, 0, NULL),
          "remove permanent controls");
    policy(interface, original_device, 1);
    policy("all", original_all, 1);
}

int main(int argc, char** argv) {
    phase = "arguments";
    check(argc == 3, "two explicitly selected interfaces");
    for (lane = 0; lane < 2; lane++)
        exercise(argv[lane + 1]);
    puts("IPV4_LIFETIME_PASS interfaces=2 finite permanent renew cacheinfo cascade promote "
         "fresh_bind");
    return 0;
}
